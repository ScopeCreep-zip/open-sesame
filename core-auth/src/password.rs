//! Password authentication backend.
//!
//! Derives the vault's password KEK client-side
//! (`core_crypto::derive_password_key` under the vault's KDF), then unwraps
//! the master key from the `.password-wrap` file (`WrappedKey`). Enrollment
//! wraps the master key under the same KEK and writes the file.
//!
//! Password bytes are injected via `with_password()` before calling
//! `unlock()` or `enroll()`.

use crate::AuthError;
use crate::backend::{AuthInteraction, UnlockOutcome, VaultAuthBackend};
use crate::vault_meta::VaultKeying;
use crate::wrapped_key::WrappedKey;
use core_crypto::{EncryptionKey, SecureBytes, SecureVec};
use core_layout::{Layout, VaultFile};
use core_types::{AuthFactorId, TrustProfileName};
use std::collections::BTreeMap;

/// The vault file holding the password-wrapped master key.
const FILE: VaultFile = VaultFile::PasswordWrap;

/// Password-based vault authentication.
///
/// Password bytes must be injected via `with_password()` before calling
/// `unlock()` or `enroll()`.
pub struct PasswordBackend {
    /// Password bytes, set via `with_password()`. Zeroized on drop.
    password: Option<SecureVec>,
}

impl PasswordBackend {
    #[must_use]
    pub fn new() -> Self {
        Self { password: None }
    }

    /// Inject password bytes for the next unlock/enroll operation.
    ///
    /// The password is stored in a `SecureVec` (mlock'd, zeroize-on-drop).
    #[must_use]
    pub fn with_password(mut self, password: SecureVec) -> Self {
        self.password = Some(password);
        self
    }

    /// The vault's password KEK, from the injected password.
    fn kek(&self, keying: &VaultKeying) -> Result<EncryptionKey, AuthError> {
        let password = self.password.as_ref().ok_or_else(|| {
            AuthError::BackendNotApplicable(
                "password backend requires password bytes via with_password()".into(),
            )
        })?;
        Ok(core_crypto::derive_password_key(
            keying.algorithms.kdf,
            password.as_bytes(),
            &keying.salt,
        )?)
    }
}

impl Default for PasswordBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl VaultAuthBackend for PasswordBackend {
    fn factor_id(&self) -> AuthFactorId {
        AuthFactorId::Password
    }

    fn name(&self) -> &'static str {
        "Password"
    }

    fn backend_id(&self) -> &'static str {
        "password"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, layout: &Layout) -> Result<bool, AuthError> {
        Ok(core_layout::file::exists(&WrappedKey::path(
            layout, profile, FILE,
        )?)?)
    }

    async fn can_unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
    ) -> Result<bool, AuthError> {
        Ok(self.password.is_some() && self.is_enrolled(profile, layout)?)
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::PasswordEntry
    }

    async fn unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
        keying: &VaultKeying,
    ) -> Result<UnlockOutcome, AuthError> {
        let kek = self.kek(keying)?;
        let master_key = WrappedKey::load(layout, profile, FILE)?
            .ok_or_else(|| AuthError::NotEnrolled(profile.to_string()))?
            .unwrap(&kek)?;
        Ok(UnlockOutcome {
            master_key,
            audit_metadata: BTreeMap::from([("backend".into(), "password".into())]),
            factor_id: AuthFactorId::Password,
        })
    }

    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        layout: &Layout,
        keying: &VaultKeying,
        _credential: Option<&str>,
    ) -> Result<(), AuthError> {
        WrappedKey::wrap(master_key, &self.kek(keying)?)?.save(layout, profile, FILE)?;
        tracing::info!(profile = %profile, "password enrollment created");
        Ok(())
    }

    async fn revoke(&self, profile: &TrustProfileName, layout: &Layout) -> Result<(), AuthError> {
        if core_layout::file::destroy(&WrappedKey::path(layout, profile, FILE)?)? {
            tracing::info!(profile = %profile, "password enrollment revoked");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{layout, test_profile};
    use core_types::{HkdfAlgorithm, KdfAlgorithm};

    fn password(text: &str) -> SecureVec {
        let mut sv = SecureVec::for_password();
        for ch in text.chars() {
            sv.push_char(ch);
        }
        sv
    }

    fn backend(text: &str) -> PasswordBackend {
        PasswordBackend::new().with_password(password(text))
    }

    fn keying(kdf: KdfAlgorithm) -> VaultKeying {
        crate::test_support::keying(0xAA, kdf, HkdfAlgorithm::Blake3)
    }

    fn write_wrap_file(layout: &Layout, contents: &[u8]) -> std::path::PathBuf {
        let path = WrappedKey::path(layout, &test_profile(), FILE).unwrap();
        core_layout::file::write(&path, contents, core_layout::file::Mode::OwnerOnly).unwrap();
        path
    }

    #[test]
    fn is_enrolled_checks_wrap_file() {
        let (_root, layout) = layout();
        let backend = PasswordBackend::new();
        let profile = test_profile();

        assert!(!backend.is_enrolled(&profile, &layout).unwrap());
        write_wrap_file(&layout, b"blob");
        assert!(backend.is_enrolled(&profile, &layout).unwrap());
    }

    #[test]
    fn identifies_as_the_interactive_password_factor() {
        let backend = PasswordBackend::new();
        assert_eq!(
            backend.requires_interaction(),
            AuthInteraction::PasswordEntry
        );
        assert_eq!(backend.factor_id(), AuthFactorId::Password);
        assert_eq!(backend.backend_id(), "password");
    }

    #[tokio::test]
    async fn enroll_and_unlock_round_trip_under_each_kdf() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let master_key = SecureBytes::new(vec![0x42u8; 32]);

        for kdf in [KdfAlgorithm::Argon2id, KdfAlgorithm::Pbkdf2Sha256] {
            backend("test-password")
                .enroll(&profile, &master_key, &layout, &keying(kdf), None)
                .await
                .unwrap();
            let outcome = backend("test-password")
                .unlock(&profile, &layout, &keying(kdf))
                .await
                .unwrap();
            assert_eq!(outcome.master_key.as_bytes(), master_key.as_bytes());
            assert_eq!(outcome.factor_id, AuthFactorId::Password);
        }
    }

    #[tokio::test]
    async fn unlock_fails_under_the_other_kdf() {
        let (_root, layout) = layout();
        let profile = test_profile();
        backend("test-password")
            .enroll(
                &profile,
                &SecureBytes::new(vec![0x42u8; 32]),
                &layout,
                &keying(KdfAlgorithm::Argon2id),
                None,
            )
            .await
            .unwrap();
        let result = backend("test-password")
            .unlock(&profile, &layout, &keying(KdfAlgorithm::Pbkdf2Sha256))
            .await;
        assert!(matches!(result, Err(AuthError::UnwrapFailed)));
    }

    #[tokio::test]
    async fn unlock_fails_wrong_password() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let keying = keying(KdfAlgorithm::Argon2id);
        backend("test-password")
            .enroll(
                &profile,
                &SecureBytes::new(vec![0x42u8; 32]),
                &layout,
                &keying,
                None,
            )
            .await
            .unwrap();
        let result = backend("wrong-password")
            .unlock(&profile, &layout, &keying)
            .await;
        assert!(matches!(result, Err(AuthError::UnwrapFailed)));
    }

    #[tokio::test]
    async fn unlock_fails_no_password_set() {
        let (_root, layout) = layout();
        let result = PasswordBackend::new()
            .unlock(&test_profile(), &layout, &keying(KdfAlgorithm::Argon2id))
            .await;
        assert!(matches!(result, Err(AuthError::BackendNotApplicable(_))));
    }

    #[tokio::test]
    async fn revoke_removes_wrap_file() {
        let (_root, layout) = layout();
        let path = write_wrap_file(&layout, b"blob");

        let backend = PasswordBackend::new();
        backend.revoke(&test_profile(), &layout).await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn revoke_noop_when_no_file() {
        let (_root, layout) = layout();
        let backend = PasswordBackend::new();
        backend.revoke(&test_profile(), &layout).await.unwrap();
    }

    #[tokio::test]
    async fn can_unlock_requires_enrollment_and_password() {
        let (_root, layout) = layout();
        let profile = test_profile();

        assert!(
            !PasswordBackend::new()
                .can_unlock(&profile, &layout)
                .await
                .unwrap()
        );
        assert!(
            !backend("test-password")
                .can_unlock(&profile, &layout)
                .await
                .unwrap()
        );
        write_wrap_file(&layout, b"x");
        assert!(
            backend("test-password")
                .can_unlock(&profile, &layout)
                .await
                .unwrap()
        );
    }
}
