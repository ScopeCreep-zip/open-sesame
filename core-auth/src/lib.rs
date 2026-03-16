//! Pluggable authentication backends for vault unlock.
//!
//! Provides a trait-based dispatch system for vault authentication methods.
//! The `AuthDispatcher` tries non-interactive backends (SSH-agent, future TPM)
//! first, falling back to password entry when no automatic method is available.
//!
//! The SSH-agent backend is currently a stub — actual agent communication is
//! future work. The trait and types are defined to establish the contract.
#![forbid(unsafe_code)]

mod backend;
mod dispatcher;
mod password;
mod ssh;
mod ssh_types;

pub use backend::{AuthInteraction, IpcUnlockStrategy, UnlockOutcome, VaultAuthBackend};
pub use dispatcher::AuthDispatcher;
pub use password::PasswordBackend;
pub use ssh::SshAgentBackend;
pub use ssh_types::{ENROLLMENT_VERSION, EnrollmentBlob, SshKeyType};

/// Errors from authentication backends.
///
/// Does not implement `Clone` because the `Io` variant wraps `std::io::Error`
/// which is not `Clone`. If clonability is needed for IPC forwarding, the
/// error should be converted to a string representation first.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("backend not applicable: {0}")]
    BackendNotApplicable(String),
    #[error("enrollment not found for profile '{0}'")]
    NotEnrolled(String),
    #[error("SSH agent unavailable: {0}")]
    AgentUnavailable(String),
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("key unwrap failed (wrong key or tampered blob)")]
    UnwrapFailed,
    #[error("enrollment blob invalid: {0}")]
    InvalidBlob(String),
    #[error("no eligible SSH key found in agent")]
    NoEligibleKey,
    #[error("SSH agent protocol error: {0}")]
    AgentProtocolError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
