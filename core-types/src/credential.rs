use std::fmt;

use crate::{BoxFuture, SensitiveBytes};

/// One credential in a [`CredentialStore`]: the application `service` and
/// the `account` within it. On the Secret Service these are the `service`
/// and `username` item attributes (the libsecret and keyring-rs
/// convention, so `secret-tool lookup service <s> username <a>` finds the
/// item); on the macOS Keychain and the Windows Credential Manager they are
/// the service and account names of a generic password.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialId {
    pub service: String,
    pub account: String,
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.service, self.account)
    }
}

/// How long a [`CredentialStore`] keeps what it stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPersistence {
    /// Until the user's session ends.
    UntilLogout,
    /// Until the machine restarts.
    UntilReboot,
    /// Until the credential is deleted.
    UntilDelete,
}

/// Why a [`CredentialStore`] operation failed. A credential that does not
/// exist is not an error: [`CredentialStore::get`] answers `None` and
/// [`CredentialStore::delete`] answers `false`.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// No store is reachable (no session bus, no keyring service, no
    /// portal).
    #[error("credential store unavailable: {0}")]
    Unavailable(String),
    /// The store, or the collection holding the credential, is locked and
    /// was not unlocked.
    #[error("credential store is locked: {0}")]
    Locked(String),
    /// The user dismissed the store's unlock or access prompt.
    #[error("the credential store's prompt was dismissed")]
    Dismissed,
    /// More than one credential carries the id: the store holds items the
    /// caller did not write, and choosing one would be a guess.
    #[error("{count} credentials match {id}; expected at most one")]
    Ambiguous { id: CredentialId, count: usize },
    /// The store failed the operation.
    #[error("credential store failure: {0}")]
    Platform(String),
}

/// The operating system's store of per-user secrets: the freedesktop
/// Secret Service (or, sandboxed, the Secret portal) on Linux, the
/// Keychain on macOS, the Credential Manager on Windows. Each platform
/// crate implements it; consumers hold an `Arc<dyn CredentialStore>` and
/// never name a platform type.
pub trait CredentialStore: Send + Sync {
    /// The implementation, for logs and diagnostics.
    fn vendor(&self) -> &'static str;

    /// How long stored credentials last.
    fn persistence(&self) -> CredentialPersistence;

    /// The secret of `id`, in protected memory; `None` when no credential
    /// carries it. A locked store is unlocked first, which may prompt the
    /// user.
    fn get<'a>(
        &'a self,
        id: &'a CredentialId,
    ) -> BoxFuture<'a, Result<Option<SensitiveBytes>, CredentialError>>;

    /// Store `secret` as `id`, labelled `label` for the store's own UI,
    /// replacing the credential that carries `id`.
    fn set<'a>(
        &'a self,
        id: &'a CredentialId,
        label: &'a str,
        secret: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CredentialError>>;

    /// Delete the credentials carrying `id`; whether one existed.
    fn delete<'a>(&'a self, id: &'a CredentialId) -> BoxFuture<'a, Result<bool, CredentialError>>;
}
