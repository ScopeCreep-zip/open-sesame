//! IPC message envelope.

use core_types::{DaemonId, SecurityLevel, Timestamp};
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
pub const WIRE_VERSION: u8 = 2;

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
}

impl<T: fmt::Debug> fmt::Debug for Message<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("msg_id", &self.msg_id)
            .field("correlation_id", &self.correlation_id)
            .field("sender", &self.sender)
            .field("security_level", &self.security_level)
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

impl<T: Serialize> Message<T> {
    /// Create a new message with a fresh UUID v7 and current timestamp.
    #[must_use]
    pub fn new(sender: DaemonId, payload: T, security_level: SecurityLevel, epoch: Instant) -> Self {
        Self {
            wire_version: WIRE_VERSION,
            msg_id: Uuid::now_v7(),
            correlation_id: None,
            timestamp: Timestamp::now(epoch),
            sender,
            payload,
            security_level,
            verified_sender_name: None,
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

    fn make_test_message() -> Message<EventKind> {
        let sender = DaemonId::new();
        let payload = EventKind::StatusRequest;
        Message::new(sender, payload, SecurityLevel::Internal, Instant::now())
    }

    // SECURITY INVARIANT: Message::new() must always set wire_version to the
    // current WIRE_VERSION constant. A zero or stale version breaks decode
    // compatibility and could bypass version-gated validation.
    #[test]
    fn message_new_sets_wire_version() {
        let msg = make_test_message();
        assert_eq!(msg.wire_version, WIRE_VERSION);
        assert_eq!(msg.wire_version, 2);
    }

    // SECURITY INVARIANT: New messages must have no verified_sender_name (server
    // stamps this) and no correlation_id (only responses have one). A client
    // pre-setting verified_sender_name could impersonate another daemon.
    #[test]
    fn message_new_defaults_are_safe() {
        let msg = make_test_message();
        assert!(msg.verified_sender_name.is_none());
        assert!(msg.correlation_id.is_none());
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
}
