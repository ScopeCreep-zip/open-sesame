//! Platform keyring authentication backend.
//!
//! Enrollment draws a random 256-bit KEK, stores it in the operating
//! system's credential store (`core_types::CredentialStore`: the Secret
//! Service on Linux) as credential `open-sesame` / `vault-kek:<profile>`,
//! and writes the master key wrapped under it to the vault's
//! `.keyring-enrollment` file (`WrappedKey`). Unlock reads the KEK back
//! and unwraps.
//!
//! Neither half alone yields the master key: the enrollment file is
//! useless without the keyring item, and the keyring item is a random key
//! that decrypts nothing but that file. The KEK is never derived from a
//! password, so there is nothing to brute-force offline.

use crate::AuthError;
use crate::backend::{AuthInteraction, UnlockOutcome, VaultAuthBackend};
use crate::vault_meta::VaultKeying;
use crate::wrapped_key::WrappedKey;
use core_crypto::{EncryptionKey, SecureBytes};
use core_layout::{Layout, VaultFile};
use core_types::{AuthFactorId, CredentialId, CredentialStore, TrustProfileName};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The vault file holding the keyring-wrapped master key.
const FILE: VaultFile = VaultFile::KeyringEnrollment;

/// The credential-store service every vault KEK is filed under.
pub const KEYRING_SERVICE: &str = "open-sesame";

/// The credential holding `profile`'s vault KEK.
#[must_use]
pub fn keyring_credential(profile: &TrustProfileName) -> CredentialId {
    CredentialId {
        service: KEYRING_SERVICE.into(),
        account: format!("vault-kek:{profile}"),
    }
}

/// Vault authentication by a KEK the platform credential store holds.
pub struct PlatformKeyringBackend {
    store: Arc<dyn CredentialStore>,
}

impl PlatformKeyringBackend {
    /// The backend over `store`.
    #[must_use]
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self { store }
    }

    /// The KEK of `profile`'s vault from the store.
    async fn kek(&self, profile: &TrustProfileName) -> Result<EncryptionKey, AuthError> {
        let id = keyring_credential(profile);
        let secret = self
            .store
            .get(&id)
            .await?
            .ok_or_else(|| AuthError::KeyringEntryMissing(id.to_string()))?;
        let bytes: &[u8; 32] = secret.as_bytes().try_into().map_err(|_| {
            AuthError::MalformedKek(format!(
                "keyring credential {id} holds {} bytes, expected a 32-byte KEK",
                secret.len()
            ))
        })?;
        Ok(EncryptionKey::from_bytes(bytes))
    }
}

#[async_trait::async_trait]
impl VaultAuthBackend for PlatformKeyringBackend {
    fn factor_id(&self) -> AuthFactorId {
        AuthFactorId::PlatformKeyring
    }

    fn name(&self) -> &'static str {
        "Platform Keyring"
    }

    fn backend_id(&self) -> &'static str {
        "platform-keyring"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, layout: &Layout) -> Result<bool, AuthError> {
        Ok(core_layout::file::exists(&WrappedKey::path(
            layout, profile, FILE,
        )?)?)
    }

    /// Enrolled. Whether the store answers, and is unlocked, is learned by
    /// [`unlock`](Self::unlock): a store query may prompt the user and does
    /// not fit the 100 ms budget.
    async fn can_unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
    ) -> Result<bool, AuthError> {
        self.is_enrolled(profile, layout)
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::None
    }

    async fn unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
        _keying: &VaultKeying,
    ) -> Result<UnlockOutcome, AuthError> {
        let wrapped = WrappedKey::load(layout, profile, FILE)?
            .ok_or_else(|| AuthError::NotEnrolled(profile.to_string()))?;
        let master_key = wrapped.unwrap(&self.kek(profile).await?)?;
        Ok(UnlockOutcome {
            master_key,
            audit_metadata: BTreeMap::from([
                ("backend".into(), "platform-keyring".into()),
                ("store".into(), self.store.vendor().into()),
            ]),
            factor_id: AuthFactorId::PlatformKeyring,
        })
    }

    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        layout: &Layout,
        _keying: &VaultKeying,
        _credential: Option<&str>,
    ) -> Result<(), AuthError> {
        let kek = Zeroizing::new(core_crypto::random_bytes::<32>()?);
        let wrapped = WrappedKey::wrap(master_key, &EncryptionKey::from_bytes(&kek))?;
        let id = keyring_credential(profile);
        // The KEK is stored before the file is written: a file without its
        // KEK would be an enrollment no unlock can use. A file that cannot
        // be written takes the stored KEK back out.
        self.store
            .set(&id, &format!("Open Sesame vault key ({profile})"), &*kek)
            .await?;
        if let Err(e) = wrapped.save(layout, profile, FILE) {
            if let Err(rollback) = self.store.delete(&id).await {
                tracing::error!(profile = %profile, credential = %id, error = %rollback, "the KEK of a failed enrollment stays in the keyring");
            }
            return Err(e);
        }
        tracing::info!(profile = %profile, store = self.store.vendor(), credential = %id, "platform keyring enrollment created");
        Ok(())
    }

    /// The enrollment file is destroyed first, so the factor stops working
    /// even when the store cannot be reached to delete the KEK.
    async fn revoke(&self, profile: &TrustProfileName, layout: &Layout) -> Result<(), AuthError> {
        let removed = core_layout::file::destroy(&WrappedKey::path(layout, profile, FILE)?)?;
        let id = keyring_credential(profile);
        let deleted = self.store.delete(&id).await?;
        if removed || deleted {
            tracing::info!(profile = %profile, credential = %id, file_removed = removed, kek_deleted = deleted, "platform keyring enrollment revoked");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{layout, test_profile};
    use core_types::{
        BoxFuture, CredentialError, CredentialPersistence, HkdfAlgorithm, KdfAlgorithm,
        SensitiveBytes,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// The store the tests run against: credentials in memory; a `locked`
    /// store refuses reads as a locked keyring does.
    #[derive(Default)]
    struct MemoryStore {
        items: Mutex<HashMap<CredentialId, Vec<u8>>>,
        locked: bool,
    }

    impl CredentialStore for MemoryStore {
        fn vendor(&self) -> &'static str {
            "memory"
        }

        fn persistence(&self) -> CredentialPersistence {
            CredentialPersistence::UntilDelete
        }

        fn get<'a>(
            &'a self,
            id: &'a CredentialId,
        ) -> BoxFuture<'a, Result<Option<SensitiveBytes>, CredentialError>> {
            Box::pin(async move {
                if self.locked {
                    return Err(CredentialError::Locked("test".into()));
                }
                Ok(self
                    .items
                    .lock()
                    .unwrap()
                    .get(id)
                    .map(|v| SensitiveBytes::from_slice(v)))
            })
        }

        fn set<'a>(
            &'a self,
            id: &'a CredentialId,
            _label: &'a str,
            secret: &'a [u8],
        ) -> BoxFuture<'a, Result<(), CredentialError>> {
            Box::pin(async move {
                self.items
                    .lock()
                    .unwrap()
                    .insert(id.clone(), secret.to_vec());
                Ok(())
            })
        }

        fn delete<'a>(
            &'a self,
            id: &'a CredentialId,
        ) -> BoxFuture<'a, Result<bool, CredentialError>> {
            Box::pin(async move { Ok(self.items.lock().unwrap().remove(id).is_some()) })
        }
    }

    fn keying() -> VaultKeying {
        crate::test_support::keying(0x11, KdfAlgorithm::Argon2id, HkdfAlgorithm::Blake3)
    }

    fn master_key() -> SecureBytes {
        SecureBytes::from_slice(&[0x5A; 32])
    }

    #[tokio::test]
    async fn enroll_and_unlock_round_trip_through_the_store() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let store = Arc::new(MemoryStore::default());
        let backend = PlatformKeyringBackend::new(store.clone());
        assert!(!backend.can_unlock(&profile, &layout).await.unwrap());

        backend
            .enroll(&profile, &master_key(), &layout, &keying(), None)
            .await
            .unwrap();
        assert!(backend.can_unlock(&profile, &layout).await.unwrap());
        let kek = store.items.lock().unwrap()[&keyring_credential(&profile)].clone();
        assert_eq!(kek.len(), 32);
        assert_ne!(
            kek,
            master_key().as_bytes(),
            "the store holds a KEK, not the key"
        );

        let outcome = backend.unlock(&profile, &layout, &keying()).await.unwrap();
        assert_eq!(outcome.master_key.as_bytes(), master_key().as_bytes());
        assert_eq!(outcome.factor_id, AuthFactorId::PlatformKeyring);
        assert_eq!(outcome.audit_metadata["store"], "memory");
    }

    #[tokio::test]
    async fn each_enrollment_draws_a_fresh_kek() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let store = Arc::new(MemoryStore::default());
        let backend = PlatformKeyringBackend::new(store.clone());
        let mut keks = Vec::new();
        for _ in 0..2 {
            backend
                .enroll(&profile, &master_key(), &layout, &keying(), None)
                .await
                .unwrap();
            keks.push(store.items.lock().unwrap()[&keyring_credential(&profile)].clone());
        }
        assert_ne!(keks[0], keks[1]);
    }

    #[tokio::test]
    async fn a_missing_keyring_item_is_named_not_treated_as_a_wrong_key() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let store = Arc::new(MemoryStore::default());
        let backend = PlatformKeyringBackend::new(store.clone());
        backend
            .enroll(&profile, &master_key(), &layout, &keying(), None)
            .await
            .unwrap();
        store.items.lock().unwrap().clear();
        let result = backend.unlock(&profile, &layout, &keying()).await;
        assert!(
            matches!(&result, Err(AuthError::KeyringEntryMissing(id)) if id.contains("vault-kek:test-profile")),
            "{:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn a_locked_store_is_reported_as_locked() {
        let (_root, layout) = layout();
        let profile = test_profile();
        PlatformKeyringBackend::new(Arc::new(MemoryStore::default()))
            .enroll(&profile, &master_key(), &layout, &keying(), None)
            .await
            .unwrap();
        let locked = PlatformKeyringBackend::new(Arc::new(MemoryStore {
            locked: true,
            ..MemoryStore::default()
        }));
        let result = locked.unlock(&profile, &layout, &keying()).await;
        assert!(
            matches!(result, Err(AuthError::Keyring(CredentialError::Locked(_)))),
            "{:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn another_kek_does_not_unwrap_the_enrollment() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let store = Arc::new(MemoryStore::default());
        let backend = PlatformKeyringBackend::new(store.clone());
        backend
            .enroll(&profile, &master_key(), &layout, &keying(), None)
            .await
            .unwrap();
        store
            .items
            .lock()
            .unwrap()
            .insert(keyring_credential(&profile), vec![0; 32]);
        assert!(matches!(
            backend.unlock(&profile, &layout, &keying()).await,
            Err(AuthError::UnwrapFailed)
        ));
    }

    #[tokio::test]
    async fn a_keyring_item_that_is_not_a_kek_is_named() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let store = Arc::new(MemoryStore::default());
        let backend = PlatformKeyringBackend::new(store.clone());
        backend
            .enroll(&profile, &master_key(), &layout, &keying(), None)
            .await
            .unwrap();
        store
            .items
            .lock()
            .unwrap()
            .insert(keyring_credential(&profile), vec![0; 31]);
        let result = backend.unlock(&profile, &layout, &keying()).await;
        assert!(
            matches!(&result, Err(AuthError::MalformedKek(m)) if m.contains("31 bytes")),
            "{:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn revoke_removes_the_file_and_the_kek() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let store = Arc::new(MemoryStore::default());
        let backend = PlatformKeyringBackend::new(store.clone());
        backend
            .enroll(&profile, &master_key(), &layout, &keying(), None)
            .await
            .unwrap();
        backend.revoke(&profile, &layout).await.unwrap();
        assert!(!backend.is_enrolled(&profile, &layout).unwrap());
        assert!(store.items.lock().unwrap().is_empty());
        backend.revoke(&profile, &layout).await.unwrap();
    }

    #[test]
    fn identifies_as_the_non_interactive_keyring_factor() {
        let backend = PlatformKeyringBackend::new(Arc::new(MemoryStore::default()));
        assert_eq!(backend.requires_interaction(), AuthInteraction::None);
        assert_eq!(backend.factor_id(), AuthFactorId::PlatformKeyring);
        assert_eq!(
            keyring_credential(&test_profile()).to_string(),
            "open-sesame/vault-kek:test-profile"
        );
    }
}
