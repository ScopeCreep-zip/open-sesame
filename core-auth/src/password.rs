//! Password authentication backend.
//!
//! Exists for trait uniformity. Password bytes are collected by the overlay
//! and sent via `UnlockRequest` directly — the actual KDF happens in
//! daemon-secrets. This backend's `unlock()` returns an error because it
//! should never be called directly.

use crate::AuthError;
use crate::backend::{AuthInteraction, UnlockOutcome, VaultAuthBackend};
use core_crypto::SecureBytes;
use core_types::TrustProfileName;
use std::path::Path;

/// Password-based vault authentication.
///
/// Always enrolled (password is universally available). The actual unlock
/// flow is handled by the overlay collecting keystrokes into a `SecureVec`
/// and sending them via `EventKind::UnlockRequest`.
pub struct PasswordBackend;

impl PasswordBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for PasswordBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl VaultAuthBackend for PasswordBackend {
    fn name(&self) -> &str {
        "Password"
    }

    fn backend_id(&self) -> &str {
        "password"
    }

    fn is_enrolled(&self, _profile: &TrustProfileName, _config_dir: &Path) -> bool {
        true
    }

    async fn can_unlock(&self, _profile: &TrustProfileName, _config_dir: &Path) -> bool {
        true
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::PasswordEntry
    }

    async fn unlock(
        &self,
        _profile: &TrustProfileName,
        _config_dir: &Path,
        _salt: &[u8],
    ) -> Result<UnlockOutcome, AuthError> {
        Err(AuthError::BackendNotApplicable(
            "password backend does not perform unlock directly; use UnlockRequest IPC".into(),
        ))
    }

    async fn enroll(
        &self,
        _profile: &TrustProfileName,
        _master_key: &SecureBytes,
        _config_dir: &Path,
        _salt: &[u8],
        _selected_key_index: Option<usize>,
    ) -> Result<(), AuthError> {
        Err(AuthError::BackendNotApplicable(
            "password backend requires no enrollment".into(),
        ))
    }

    async fn revoke(
        &self,
        _profile: &TrustProfileName,
        _config_dir: &Path,
    ) -> Result<(), AuthError> {
        Err(AuthError::BackendNotApplicable(
            "password backend cannot be revoked".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> TrustProfileName {
        TrustProfileName::try_from("test-profile").unwrap()
    }

    #[test]
    fn is_always_enrolled() {
        let backend = PasswordBackend::new();
        let profile = test_profile();
        assert!(backend.is_enrolled(&profile, std::path::Path::new("/tmp")));
    }

    #[test]
    fn requires_password_entry() {
        let backend = PasswordBackend::new();
        assert_eq!(
            backend.requires_interaction(),
            AuthInteraction::PasswordEntry
        );
    }

    #[test]
    fn backend_id_is_password() {
        let backend = PasswordBackend::new();
        assert_eq!(backend.backend_id(), "password");
    }

    #[tokio::test]
    async fn can_always_unlock() {
        let backend = PasswordBackend::new();
        let profile = test_profile();
        assert!(
            backend
                .can_unlock(&profile, std::path::Path::new("/tmp"))
                .await
        );
    }

    #[tokio::test]
    async fn unlock_returns_error() {
        let backend = PasswordBackend::new();
        let profile = test_profile();
        let result = backend
            .unlock(&profile, std::path::Path::new("/tmp"), &[0; 16])
            .await;
        assert!(result.is_err());
    }
}
