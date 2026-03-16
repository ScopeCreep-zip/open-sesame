//! IPC message envelope.

use core_types::{AgentId, DaemonId, InstallationId, SecurityLevel, Timestamp, TrustVector};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Instant;
use uuid::Uuid;

/// Current wire format version. Increment on any field addition/removal.
///
/// WIRE FORMAT CONTRACT:
///
/// v2 fields: `wire_version`, `msg_id`, `correlation_id`, `sender`,
/// `timestamp`, `payload`, `security_level`, `verified_sender_name`
///
/// All v2 binaries must be deployed atomically (single compilation unit).
/// Adding fields requires incrementing this constant and updating the decode
/// path to handle both old and new versions during rolling upgrades.
pub const WIRE_VERSION: u8 = 3;

/// The IPC bus message envelope wrapping any payload type.
///
/// Debug is manually implemented to delegate to `T`'s Debug impl.
/// When `T = EventKind`, the payload's custom Debug redacts secret fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct Message<T> {
    /// Wire format version. Always serialized first.
    /// Receivers should check this before interpreting remaining fields.
    pub wire_version: u8,
    /// Unique message identifier (UUID v7 for time-ordering).
    pub msg_id: Uuid,
    /// Correlation ID for request-response patterns.
    pub correlation_id: Option<Uuid>,
    /// Sender daemon identity.
    pub sender: DaemonId,
    /// Dual-clock timestamp.
    pub timestamp: Timestamp,
    /// The event or request payload.
    pub payload: T,
    /// Access control level for this message.
    pub security_level: SecurityLevel,
    /// Server-stamped verified sender name from Noise IK registry lookup.
    ///
    /// Set by `route_frame()` in the bus server — never trust client-supplied values.
    /// `None` for unregistered clients (CLI, Open clearance).
    /// Note: no `skip_serializing_if` — postcard uses positional encoding, so the
    /// field must always be present in the wire format for decode compatibility.
    pub verified_sender_name: Option<String>,

    // -- v3 fields (appended for positional encoding safety) --
    /// Installation identity of the sender.
    /// No `skip_serializing_if` — postcard positional encoding requires all fields present.
    pub origin_installation: Option<InstallationId>,
    /// Agent identity of the sender.
    pub agent_id: Option<AgentId>,
    /// Trust snapshot at time of message creation.
    pub trust_snapshot: Option<TrustVector>,
}

/// Context for constructing outbound messages.
///
/// Carries the sender's identity information so that `Message::new()` can
/// populate all v3 fields without callers needing to pass them individually.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContext {
    pub sender: DaemonId,
    pub installation: Option<InstallationId>,
    pub agent_id: Option<AgentId>,
    pub trust_snapshot: Option<TrustVector>,
}

impl MessageContext {
    /// Create a minimal context with just a daemon ID (no v3 fields).
    #[must_use]
    pub fn new(sender: DaemonId) -> Self {
        Self {
            sender,
            installation: None,
            agent_id: None,
            trust_snapshot: None,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Message<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("msg_id", &self.msg_id)
            .field("correlation_id", &self.correlation_id)
            .field("sender", &self.sender)
            .field("security_level", &self.security_level)
            .field("agent_id", &self.agent_id)
            .field(
                "origin_installation",
                &self.origin_installation.as_ref().map(|i| &i.id),
            )
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

impl<T: Serialize> Message<T> {
    /// Create a new message with a fresh UUID v7 and current timestamp.
    #[must_use]
    pub fn new(
        ctx: &MessageContext,
        payload: T,
        security_level: SecurityLevel,
        epoch: Instant,
    ) -> Self {
        Self {
            wire_version: WIRE_VERSION,
            msg_id: Uuid::now_v7(),
            correlation_id: None,
            timestamp: Timestamp::now(epoch),
            sender: ctx.sender,
            payload,
            security_level,
            verified_sender_name: None,
            origin_installation: ctx.installation.clone(),
            agent_id: ctx.agent_id,
            trust_snapshot: ctx.trust_snapshot.clone(),
        }
    }

    /// Set a correlation ID for request-response linking.
    #[must_use]
    pub fn with_correlation(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{DaemonId, EventKind, SecurityLevel};

    fn make_test_ctx() -> MessageContext {
        MessageContext::new(DaemonId::new())
    }

    fn make_test_message() -> Message<EventKind> {
        let ctx = make_test_ctx();
        let payload = EventKind::StatusRequest;
        Message::new(&ctx, payload, SecurityLevel::Internal, Instant::now())
    }

    // SECURITY INVARIANT: Message::new() must always set wire_version to the
    // current WIRE_VERSION constant. A zero or stale version breaks decode
    // compatibility and could bypass version-gated validation.
    #[test]
    fn message_new_sets_wire_version() {
        let msg = make_test_message();
        assert_eq!(msg.wire_version, WIRE_VERSION);
        assert_eq!(msg.wire_version, 3);
    }

    // SECURITY INVARIANT: New messages must have no verified_sender_name (server
    // stamps this) and no correlation_id (only responses have one). A client
    // pre-setting verified_sender_name could impersonate another daemon.
    #[test]
    fn message_new_defaults_are_safe() {
        let msg = make_test_message();
        assert!(msg.verified_sender_name.is_none());
        assert!(msg.correlation_id.is_none());
        assert!(msg.origin_installation.is_none());
        assert!(msg.agent_id.is_none());
        assert!(msg.trust_snapshot.is_none());
    }

    // SECURITY INVARIANT: wire_version must survive postcard encode/decode
    // roundtrip. If positional encoding drops or reorders it, version-gated
    // fields will be misinterpreted.
    #[test]
    fn message_roundtrip_preserves_wire_version() {
        let msg = make_test_message();
        let bytes = crate::framing::encode_frame(&msg).unwrap();
        let decoded: Message<EventKind> = crate::framing::decode_frame(&bytes).unwrap();
        assert_eq!(decoded.wire_version, WIRE_VERSION);
    }

    #[test]
    fn with_correlation_sets_id() {
        let msg = make_test_message();
        let corr_id = Uuid::now_v7();
        let msg = msg.with_correlation(corr_id);
        assert_eq!(msg.correlation_id, Some(corr_id));
    }

    #[test]
    fn v3_fields_populated_roundtrip() {
        let ctx = MessageContext {
            sender: DaemonId::new(),
            installation: Some(InstallationId {
                id: Uuid::from_u128(1),
                org_ns: None,
                namespace: Uuid::from_u128(2),
                machine_binding: None,
            }),
            agent_id: Some(AgentId::from_uuid(Uuid::from_u128(3))),
            trust_snapshot: Some(TrustVector {
                authn_strength: core_types::TrustLevel::High,
                authz_freshness: std::time::Duration::from_secs(30),
                delegation_depth: 1,
                device_posture: 0.9,
                network_exposure: core_types::NetworkTrust::Local,
                agent_type: core_types::AgentType::Human,
            }),
        };
        let msg = Message::new(
            &ctx,
            EventKind::StatusRequest,
            SecurityLevel::Internal,
            Instant::now(),
        );

        let bytes = crate::framing::encode_frame(&msg).unwrap();
        let decoded: Message<EventKind> = crate::framing::decode_frame(&bytes).unwrap();

        assert_eq!(decoded.wire_version, WIRE_VERSION);
        assert_eq!(
            decoded.origin_installation.as_ref().unwrap().id,
            Uuid::from_u128(1)
        );
        assert_eq!(
            decoded.agent_id.unwrap(),
            AgentId::from_uuid(Uuid::from_u128(3))
        );
        assert!(decoded.trust_snapshot.is_some());
        let tv = decoded.trust_snapshot.unwrap();
        assert_eq!(tv.authn_strength, core_types::TrustLevel::High);
        assert_eq!(tv.delegation_depth, 1);
    }

    #[test]
    fn v3_fields_none_roundtrip() {
        let ctx = MessageContext::new(DaemonId::new());
        let msg = Message::new(
            &ctx,
            EventKind::StatusRequest,
            SecurityLevel::Open,
            Instant::now(),
        );

        let bytes = crate::framing::encode_frame(&msg).unwrap();
        let decoded: Message<EventKind> = crate::framing::decode_frame(&bytes).unwrap();

        assert!(decoded.origin_installation.is_none());
        assert!(decoded.agent_id.is_none());
        assert!(decoded.trust_snapshot.is_none());
    }

    #[test]
    fn v3_event_variants_roundtrip() {
        use core_types::*;

        let ctx = MessageContext::new(DaemonId::new());
        let epoch = Instant::now();

        let agent = AgentId::from_uuid(Uuid::from_u128(10));
        let installation = InstallationId {
            id: Uuid::from_u128(20),
            org_ns: None,
            namespace: Uuid::from_u128(30),
            machine_binding: None,
        };
        let req_id = Uuid::from_u128(40);
        let deleg_id = Uuid::from_u128(50);
        let session_id = Uuid::from_u128(60);
        let ts = Timestamp::now(epoch);

        let variants: Vec<EventKind> = vec![
            EventKind::AgentConnected {
                agent_id: agent,
                agent_type: AgentType::Human,
                attestations: vec![AttestationType::UCred],
            },
            EventKind::AgentDisconnected {
                agent_id: agent,
                reason: "done".into(),
            },
            EventKind::InstallationCreated {
                id: installation.clone(),
                org: None,
                machine_binding_present: false,
            },
            EventKind::ProfileIdMigrated {
                name: TrustProfileName::try_from("work").unwrap(),
                old_id: ProfileId::from_uuid(Uuid::from_u128(1)),
                new_id: ProfileId::from_uuid(Uuid::from_u128(2)),
            },
            EventKind::AuthorizationRequired {
                request_id: req_id,
                operation: "secret.read".into(),
                missing_attestations: vec![],
                expires_at: ts.clone(),
            },
            EventKind::AuthorizationGrant {
                request_id: req_id,
                delegator: agent,
                scope: CapabilitySet::empty(),
                ttl_seconds: 300,
                point_of_use_filter: None,
            },
            EventKind::AuthorizationDenied {
                request_id: req_id,
                reason: "nope".into(),
            },
            EventKind::AuthorizationTimeout { request_id: req_id },
            EventKind::DelegationRevoked {
                delegation_id: deleg_id,
                revoker: agent,
                reason: "expired".into(),
            },
            EventKind::HeartbeatRenewed {
                delegation_id: deleg_id,
                renewal_source: agent,
                next_deadline: ts,
            },
            EventKind::FederationSessionEstablished {
                session_id,
                remote_installation: installation,
            },
            EventKind::FederationSessionTerminated {
                session_id,
                reason: "closed".into(),
            },
            EventKind::PostureEvaluated {
                secure_boot: Some(true),
                disk_encrypted: Some(true),
                screen_locked: None,
                composite_score: 0.95,
            },
        ];

        for (i, variant) in variants.into_iter().enumerate() {
            let msg = Message::new(&ctx, variant, SecurityLevel::Internal, epoch);
            let bytes = crate::framing::encode_frame(&msg)
                .unwrap_or_else(|e| panic!("encode failed for variant {i}: {e}"));
            let decoded: Message<EventKind> = crate::framing::decode_frame(&bytes)
                .unwrap_or_else(|e| panic!("decode failed for variant {i}: {e}"));
            assert_eq!(
                decoded.wire_version, WIRE_VERSION,
                "variant {i} wire version mismatch"
            );
        }
    }
}
