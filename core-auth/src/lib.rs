//! Pluggable authentication backends for vault unlock.
//!
//! One `VaultAuthBackend` per factor, registered in `AuthDispatcher`. A
//! client unlocks a vault by walking the factors daemon-secrets reports it
//! still requires (`remaining_factors`), providing each through its
//! backend, and reading daemon-secrets' answer to each submission
//! (`FactorProgress`).
//!
//! Vault file locations come from `core_layout::Layout::vault_file`; files
//! holding key material are written and destroyed through
//! `core_layout::file` (owner-only).
#![forbid(unsafe_code)]

mod agent;
mod backend;
mod dispatcher;
mod keyring;
mod password;
mod progress;
pub mod salt;
mod ssh;
mod ssh_types;
#[cfg(test)]
mod test_support;
mod vault_meta;
mod wrapped_key;

pub use backend::{
    AuthInteraction, FactorContribution, UnlockOutcome, VaultAuthBackend, combine_factor_pieces,
};
pub use dispatcher::AuthDispatcher;
pub use keyring::{KEYRING_SERVICE, PlatformKeyringBackend, keyring_credential};
pub use password::PasswordBackend;
pub use progress::{FactorProgress, ResponseError, remaining_factors};
pub use ssh::{AgentKey, SshAgentBackend, eligible_agent_keys, same_fingerprint};
pub use ssh_types::{ENROLLMENT_VERSION, EnrollmentBlob, SshKeyType};
pub use vault_meta::{
    EnrolledFactor, VAULT_META_VERSION, VaultAlgorithms, VaultKeying, VaultMetadata,
};
pub use wrapped_key::{WRAPPED_KEY_VERSION, WrappedKey};

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
    #[error("vault '{0}' is not initialized: it has no salt (run `sesame init`)")]
    NotInitialized(String),
    #[error("SSH agent unavailable: {0}")]
    AgentUnavailable(String),
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("key unwrap failed (wrong key or tampered blob)")]
    UnwrapFailed,
    #[error("enrollment blob invalid: {0}")]
    InvalidBlob(String),
    /// A vault file that is not an enrollment (the metadata, the salt) is
    /// corrupt, of another format version, or cannot be serialized; the
    /// message names the file.
    #[error("{0}")]
    InvalidVaultFile(String),
    /// The platform keyring holds something other than a 32-byte KEK under
    /// a vault's credential; the message names the credential.
    #[error("{0}")]
    MalformedKek(String),
    #[error("SSH key {0} is not loaded in the agent (list loaded keys with `ssh-add -l`)")]
    KeyNotInAgent(String),
    #[error("SSH agent protocol error: {0}")]
    AgentProtocolError(String),
    #[error("the platform keyring holds no {0} (re-enroll with `sesame keyring enroll`)")]
    KeyringEntryMissing(String),
    #[error("platform keyring: {0}")]
    Keyring(#[from] core_types::CredentialError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Publication state of a vault-file write. A published but non-durable
    /// write must not be retried as though the destination were unchanged.
    #[error(transparent)]
    Write(#[from] core_layout::file::WriteError),
    #[error(transparent)]
    Layout(#[from] core_layout::Error),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(std::time::SystemTimeError),
    /// A primitive of `core_crypto` failed (the OS random source, or an
    /// encryption that is not an unwrap).
    #[error(transparent)]
    Crypto(#[from] core_types::Error),
}

impl AuthError {
    /// This error of reading the file at `path`: a blob that does not
    /// parse is named by the file it was read from.
    pub(crate) fn in_file(self, path: &std::path::Path) -> Self {
        match self {
            Self::InvalidBlob(reason) => Self::InvalidBlob(format!("{}: {reason}", path.display())),
            other => other,
        }
    }
}

impl From<AuthError> for core_types::Error {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Io(io) => Self::Io(io),
            AuthError::Write(write) => Self::Io(write.into()),
            AuthError::Layout(layout) => layout.into(),
            AuthError::Crypto(crypto) => crypto,
            other => Self::Secrets(other.to_string()),
        }
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    fn publication_state_survives_authentication_and_core_error_boundaries() {
        for published in [false, true] {
            let source = std::io::Error::other("directory sync failed");
            let write = if published {
                core_layout::file::WriteError::PublishedNotDurable(source)
            } else {
                core_layout::file::WriteError::NotPublished(source)
            };
            let auth = AuthError::from(write);
            assert!(matches!(&auth, AuthError::Write(_)));
            let core_types::Error::Io(io) = core_types::Error::from(auth) else {
                panic!("write publication state lost");
            };
            let write = io
                .get_ref()
                .unwrap()
                .downcast_ref::<core_layout::file::WriteError>()
                .unwrap();
            assert_eq!(
                matches!(write, core_layout::file::WriteError::PublishedNotDurable(_)),
                published,
            );
        }
    }
}
