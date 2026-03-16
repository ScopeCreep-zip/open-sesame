//! Profile schema, context-driven activation, isolation contracts, and atomic switching.
//!
//! Phase 1: schema types (`ProfileState`, `ContextSignal`, `AuditEntry`).
//! Phase 2: runtime logic (`ContextEngine`, `AuditLogger` with BLAKE3 hash chain).
#![forbid(unsafe_code)]

pub mod audit;
pub mod context;

use core_types::{AgentId, AgentType, AppId, InstallationId, ProfileId, TrustProfileName};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use audit::{AuditLogger, verify_chain};
pub use context::ContextEngine;

// ============================================================================
// Profile State Machine
// ============================================================================

/// The lifecycle state of an individual profile.
///
/// Multiple profiles may be active concurrently. Each profile has its own
/// independent state — there is no global "active profile" singleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileState {
    /// Profile is inactive (vault closed, no secrets served).
    Inactive,
    /// Profile is active (vault open, serving secrets).
    Active(ProfileId),
    /// Profile activation or deactivation is in progress.
    Transitioning(ProfileId),
}

// ============================================================================
// Context Signals
// ============================================================================

/// Signals that can trigger profile activation rule evaluation.
#[derive(Debug, Clone)]
pub enum ContextSignal {
    SsidChanged(String),
    AppFocused(AppId),
    UsbDeviceAttached(String),
    UsbDeviceDetached(String),
    HardwareKeyPresent(String),
    TimeWindowEntered(String),
    GeolocationChanged(f64, f64),
}

// ============================================================================
// Isolation Contracts
// ============================================================================

/// Resources that can be isolated between profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolatedResource {
    Clipboard,
    Secrets,
    Frecency,
    Extensions,
    WindowList,
}

// ============================================================================
// Audit Log Entry
// ============================================================================

/// A hash-chained audit log entry for profile operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Wall clock timestamp (ms since epoch).
    pub timestamp_ms: u64,
    /// The profile operation that occurred.
    pub action: AuditAction,
    /// BLAKE3 hash of the previous entry (hex string). Empty for first entry.
    pub prev_hash: String,
    /// Optional agent identity that triggered this action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<core_types::AgentId>,
}

/// Auditable profile actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditAction {
    ProfileActivated {
        target: ProfileId,
        duration_ms: u32,
    },
    ProfileDeactivated {
        target: ProfileId,
        duration_ms: u32,
    },
    ProfileActivationFailed {
        target: ProfileId,
        reason: String,
    },
    DefaultProfileChanged {
        previous: ProfileId,
        current: ProfileId,
    },
    IsolationViolationAttempt {
        from_profile: core_types::TrustProfileName,
        resource: IsolatedResource,
    },
    SecretAccessed {
        profile_id: ProfileId,
        secret_ref: String,
    },
    KeyRotationStarted {
        daemon_name: String,
        generation: u64,
    },
    KeyRotationCompleted {
        daemon_name: String,
        generation: u64,
    },
    KeyRevoked {
        daemon_name: String,
        reason: String,
        generation: u64,
    },
    /// A secret operation was performed (or denied). Logged for forensic audit trail.
    SecretOperationAudited {
        action: String,
        profile: core_types::TrustProfileName,
        key: Option<String>,
        requester: core_types::DaemonId,
        requester_name: Option<String>,
        outcome: String,
    },
    AgentConnected {
        agent_id: AgentId,
        agent_type: AgentType,
    },
    AgentDisconnected {
        agent_id: AgentId,
        reason: String,
    },
    InstallationCreated {
        id: InstallationId,
        org: Option<String>,
        machine_binding_present: bool,
    },
    ProfileIdMigrated {
        name: TrustProfileName,
        old_id: ProfileId,
        new_id: ProfileId,
    },
    AuthorizationRequired {
        request_id: Uuid,
        operation: String,
    },
    AuthorizationGranted {
        request_id: Uuid,
        delegator: AgentId,
        scope: String,
    },
    AuthorizationDenied {
        request_id: Uuid,
        reason: String,
    },
    AuthorizationTimeout {
        request_id: Uuid,
    },
    DelegationRevoked {
        delegation_id: Uuid,
        revoker: AgentId,
        reason: String,
    },
    HeartbeatRenewed {
        delegation_id: Uuid,
        renewal_source: AgentId,
    },
    FederationSessionEstablished {
        session_id: Uuid,
        remote_installation: InstallationId,
    },
    FederationSessionTerminated {
        session_id: Uuid,
        reason: String,
    },
    PostureEvaluated {
        composite_score: f64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn profile_state_active() {
        let id = ProfileId::from_uuid(Uuid::from_u128(1));
        let state = ProfileState::Active(id);
        assert!(matches!(state, ProfileState::Active(_)));
    }

    #[test]
    fn audit_entry_serializes() {
        let entry = AuditEntry {
            sequence: 1,
            timestamp_ms: 1_000_000,
            action: AuditAction::ProfileActivated {
                target: ProfileId::from_uuid(Uuid::from_u128(1)),
                duration_ms: 42,
            },
            prev_hash: String::new(),
            agent_id: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sequence, 1);
    }

    #[test]
    fn isolated_resource_roundtrips() {
        for resource in [
            IsolatedResource::Clipboard,
            IsolatedResource::Secrets,
            IsolatedResource::Frecency,
            IsolatedResource::Extensions,
            IsolatedResource::WindowList,
        ] {
            let json = serde_json::to_string(&resource).unwrap();
            let decoded: IsolatedResource = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, resource);
        }
    }
}
