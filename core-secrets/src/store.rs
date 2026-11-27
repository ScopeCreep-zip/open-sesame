//! `SecretsStore` trait — dyn-compatible async secret CRUD over encrypted
//! storage.
//!
//! Implementations wrap `SQLCipher` databases keyed with per-profile vault
//! keys. The store operates on an already-derived vault key provided at
//! construction time.

use core_crypto::SecureBytes;
use core_types::BoxFuture;

/// Encrypted secret storage backend.
///
/// Each implementation manages a single profile's encrypted vault.
/// Cross-profile isolation is enforced cryptographically: each profile
/// gets a different vault key, so one profile's key cannot decrypt
/// another's data.
///
/// Methods return a [`BoxFuture`] for dyn-compatibility.
pub trait SecretsStore: Send + Sync {
    /// Retrieve a secret by key. Returns error if key does not exist.
    fn get(&self, key: &str) -> BoxFuture<'_, core_types::Result<SecureBytes>>;

    /// Store a secret. Overwrites if key already exists.
    fn set(&self, key: &str, value: &[u8]) -> BoxFuture<'_, core_types::Result<()>>;

    /// Delete a secret by key. Returns error if key does not exist.
    fn delete(&self, key: &str) -> BoxFuture<'_, core_types::Result<()>>;

    /// List all keys in this store. Values are NOT returned (no bulk decryption).
    fn list_keys(&self) -> BoxFuture<'_, core_types::Result<Vec<String>>>;
}

/// The not-found error of `key`, shared by every store.
pub(crate) fn not_found(key: &str) -> core_types::Error {
    core_types::Error::NotFound(format!("secret key: {key}"))
}

/// In-memory store: the compliance suite's reference implementation.
/// Values are `SecureBytes` (mlock'd, zeroize-on-drop).
#[cfg(test)]
#[derive(Default)]
pub(crate) struct InMemoryStore {
    data: tokio::sync::RwLock<std::collections::HashMap<String, SecureBytes>>,
}

#[cfg(test)]
impl SecretsStore for InMemoryStore {
    fn get(&self, key: &str) -> BoxFuture<'_, core_types::Result<SecureBytes>> {
        let key = key.to_owned();
        Box::pin(async move {
            self.data
                .read()
                .await
                .get(&key)
                .cloned()
                .ok_or_else(|| not_found(&key))
        })
    }

    fn set(&self, key: &str, value: &[u8]) -> BoxFuture<'_, core_types::Result<()>> {
        let key = key.to_owned();
        let value = SecureBytes::from_slice(value);
        Box::pin(async move {
            self.data.write().await.insert(key, value);
            Ok(())
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, core_types::Result<()>> {
        let key = key.to_owned();
        Box::pin(async move {
            self.data
                .write()
                .await
                .remove(&key)
                .map(drop)
                .ok_or_else(|| not_found(&key))
        })
    }

    fn list_keys(&self) -> BoxFuture<'_, core_types::Result<Vec<String>>> {
        Box::pin(async move { Ok(self.data.read().await.keys().cloned().collect()) })
    }
}
