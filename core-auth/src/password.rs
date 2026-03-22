//! Password authentication backend.
//!
//! Runs Argon2id client-side to derive a KEK, then unwraps the master key
//! from the `.password-wrap` blob. For enrollment, wraps the master key
//! under the Argon2id-derived KEK and writes the blob to disk.
//!
//! Password bytes are injected via `with_password()` before calling
//! `unlock()` or `enroll()`.

use crate::AuthError;
use crate::backend::{AuthInteraction, IpcUnlockStrategy, UnlockOutcome, VaultAuthBackend};
use crate::password_wrap::PasswordWrapBlob;
use core_crypto::{SecureBytes, SecureVec};
use core_types::{AuthFactorId, TrustProfileName};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroize;

/// Password-based vault authentication.
///
/// Uses Argon2id to derive a KEK from password bytes, then wraps/unwraps
/// the master key via AES-256-GCM in a `.password-wrap` blob.
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

    /// Set password bytes on an existing instance.
    pub fn set_password(&mut self, password: SecureVec) {
        self.password = Some(password);
    }

    /// Derive KEK from password bytes and salt via Argon2id.
    ///
    /// Salt must be exactly 16 bytes.
    fn derive_kek(password: &[u8], salt: &[u8]) -> Result<[u8; 32], AuthError> {
        let salt_arr: [u8; 16] = salt.try_into().map_err(|_| {
            AuthError::InvalidBlob(format!("salt must be 16 bytes, got {}", salt.len()))
        })?;
        let secure = core_crypto::derive_key_argon2(password, &salt_arr).map_err(|e| {
            AuthError::BackendNotApplicable(format!("Argon2id derivation failed: {e}"))
        })?;
        let mut kek = [0u8; 32];
        let bytes = secure.as_bytes();
        kek.copy_from_slice(&bytes[..32]);
        Ok(kek)
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
    fn factor_id(&self) -> AuthFactorId {
        AuthFactorId::Password
    }

    fn name(&self) -> &str {
        "Password"
    }

    fn backend_id(&self) -> &str {
        "password"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, config_dir: &Path) -> bool {
        PasswordWrapBlob::path(config_dir, profile).exists()
    }

    async fn can_unlock(&self, profile: &TrustProfileName, config_dir: &Path) -> bool {
        self.is_enrolled(profile, config_dir) && self.password.is_some()
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::PasswordEntry
    }

    async fn unlock(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
        salt: &[u8],
    ) -> Result<UnlockOutcome, AuthError> {
        // We need mutable access to take the password; use interior trick
        // via the self reference. Since this is &self, we need a workaround.
        // The trait requires &self for unlock, but we need to consume the password.
        // We'll read the password without taking it (it gets zeroized on drop anyway).
        let password_bytes = self
            .password
            .as_ref()
            .ok_or_else(|| {
                AuthError::BackendNotApplicable(
                    "password backend requires password bytes via with_password()".into(),
                )
            })?
            .as_bytes();

        // Read the password-wrap blob.
        let blob = PasswordWrapBlob::load(config_dir, profile)?;

        // Derive KEK via Argon2id.
        let mut kek = Self::derive_kek(password_bytes, salt)?;

        // Unwrap master key.
        let master_key = blob.unwrap(&mut kek)?;

        let mut audit_metadata = BTreeMap::new();
        audit_metadata.insert("backend".into(), "password".into());

        Ok(UnlockOutcome {
            master_key,
            audit_metadata,
            ipc_strategy: IpcUnlockStrategy::DirectMasterKey,
            factor_id: AuthFactorId::Password,
        })
    }

    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        config_dir: &Path,
        salt: &[u8],
        _selected_key_index: Option<usize>,
    ) -> Result<(), AuthError> {
        let password_bytes = self
            .password
            .as_ref()
            .ok_or_else(|| {
                AuthError::BackendNotApplicable(
                    "password backend requires password bytes via with_password()".into(),
                )
            })?
            .as_bytes();

        // Derive KEK via Argon2id.
        let mut kek = Self::derive_kek(password_bytes, salt)?;

        // Wrap master key under KEK.
        let blob = PasswordWrapBlob::wrap(master_key.as_bytes(), &mut kek)?;

        // Write to disk.
        blob.save(config_dir, profile)?;

        tracing::info!(
            profile = %profile,
            "password enrollment created"
        );

        Ok(())
    }

    async fn revoke(&self, profile: &TrustProfileName, config_dir: &Path) -> Result<(), AuthError> {
        let path = PasswordWrapBlob::path(config_dir, profile);
        if path.exists() {
            // Overwrite with zeros before deletion.
            #[allow(clippy::cast_possible_truncation)]
            let file_len = std::fs::metadata(&path)
                .map(|m| m.len() as usize)
                .unwrap_or(64);
            let mut zeros = vec![0u8; file_len];
            let _ = std::fs::write(&path, &zeros);
            zeros.zeroize();
            std::fs::remove_file(&path)?;

            tracing::info!(
                profile = %profile,
                "password enrollment revoked"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> TrustProfileName {
        TrustProfileName::try_from("test-profile").unwrap()
    }

    fn make_password() -> SecureVec {
        let mut sv = SecureVec::for_password();
        for ch in "test-password".chars() {
            sv.push_char(ch);
        }
        sv
    }

    #[test]
    fn is_enrolled_checks_wrap_file() {
        let dir = tempfile::tempdir().unwrap();
        let backend = PasswordBackend::new();
        let profile = test_profile();

        assert!(!backend.is_enrolled(&profile, dir.path()));

        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        std::fs::write(vaults.join("test-profile.password-wrap"), b"blob").unwrap();

        assert!(backend.is_enrolled(&profile, dir.path()));
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
    fn factor_id_is_password() {
        let backend = PasswordBackend::new();
        assert_eq!(backend.factor_id(), AuthFactorId::Password);
    }

    #[test]
    fn backend_id_is_password() {
        let backend = PasswordBackend::new();
        assert_eq!(backend.backend_id(), "password");
    }

    #[tokio::test]
    async fn enroll_and_unlock_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();
        let salt = [0xAA; 16];

        // Generate a random master key.
        let master_key_bytes = vec![0x42u8; 32];
        let master_key = SecureBytes::new(master_key_bytes.clone());

        // Enroll.
        let backend = PasswordBackend::new().with_password(make_password());
        backend
            .enroll(&profile, &master_key, dir.path(), &salt, None)
            .await
            .unwrap();

        // Verify enrollment file exists.
        assert!(PasswordWrapBlob::path(dir.path(), &profile).exists());

        // Unlock.
        let backend2 = PasswordBackend::new().with_password(make_password());
        let outcome = backend2.unlock(&profile, dir.path(), &salt).await.unwrap();

        assert_eq!(outcome.master_key.as_bytes(), &master_key_bytes);
        assert_eq!(outcome.factor_id, AuthFactorId::Password);
        assert_eq!(outcome.ipc_strategy, IpcUnlockStrategy::DirectMasterKey);
    }

    #[tokio::test]
    async fn unlock_fails_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();
        let salt = [0xAA; 16];

        let master_key = SecureBytes::new(vec![0x42u8; 32]);

        // Enroll with correct password.
        let backend = PasswordBackend::new().with_password(make_password());
        backend
            .enroll(&profile, &master_key, dir.path(), &salt, None)
            .await
            .unwrap();

        // Try unlock with wrong password.
        let mut wrong_pw = SecureVec::for_password();
        for ch in "wrong-password".chars() {
            wrong_pw.push_char(ch);
        }
        let backend2 = PasswordBackend::new().with_password(wrong_pw);
        let result = backend2.unlock(&profile, dir.path(), &salt).await;
        assert!(matches!(result, Err(AuthError::UnwrapFailed)));
    }

    #[tokio::test]
    async fn unlock_fails_no_password_set() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();
        let backend = PasswordBackend::new();
        let result = backend.unlock(&profile, dir.path(), &[0; 16]).await;
        assert!(matches!(result, Err(AuthError::BackendNotApplicable(_))));
    }

    #[tokio::test]
    async fn revoke_removes_wrap_file() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();
        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        let path = vaults.join("test-profile.password-wrap");
        std::fs::write(&path, b"blob").unwrap();
        assert!(path.exists());

        let backend = PasswordBackend::new();
        backend.revoke(&profile, dir.path()).await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn revoke_noop_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let backend = PasswordBackend::new();
        backend.revoke(&test_profile(), dir.path()).await.unwrap();
    }

    #[tokio::test]
    async fn can_unlock_requires_enrollment_and_password() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();

        let backend = PasswordBackend::new();
        assert!(!backend.can_unlock(&profile, dir.path()).await);

        let backend2 = PasswordBackend::new().with_password(make_password());
        assert!(!backend2.can_unlock(&profile, dir.path()).await);

        // Create enrollment file.
        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        std::fs::write(vaults.join("test-profile.password-wrap"), b"x").unwrap();

        let backend3 = PasswordBackend::new().with_password(make_password());
        assert!(backend3.can_unlock(&profile, dir.path()).await);
    }
}
