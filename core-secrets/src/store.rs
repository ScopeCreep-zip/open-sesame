//! SecretsStore trait — dyn-compatible async secret CRUD over encrypted storage.
//!
//! Implementations wrap SQLCipher databases keyed with per-profile HKDF-derived
//! vault keys. The store never sees plaintext platform keyring secrets; it
//! operates on already-decrypted vault keys provided at construction time.

use core_crypto::SecureBytes;
use std::future::Future;
use std::pin::Pin;

/// Dyn-compatible boxed future (same pattern as platform-linux::compositor).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Encrypted secret storage backend.
///
/// Each implementation manages a single profile's encrypted vault.
/// Cross-profile isolation is enforced cryptographically: each profile
/// gets a different HKDF-derived vault key, so even if two profiles share
/// the same SQLCipher file, they cannot decrypt each other's data.
///
/// Uses `Pin<Box<dyn Future>>` instead of `async fn` for dyn-compatibility
/// (RPITIT is not object-safe).
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

/// In-memory encrypted store for testing and CI environments.
///
/// Secrets are held in a `HashMap` protected by a `RwLock`. All values are
/// stored as `SecureBytes` (mlock'd, zeroize-on-drop). This store does NOT
/// persist to disk — it exists only for compliance testing and ephemeral use.
pub struct InMemoryStore {
    data: tokio::sync::RwLock<std::collections::HashMap<String, SecureBytes>>,
}

impl InMemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretsStore for InMemoryStore {
    fn get(&self, key: &str) -> BoxFuture<'_, core_types::Result<SecureBytes>> {
        let key = key.to_owned();
        Box::pin(async move {
            let data = self.data.read().await;
            data.get(&key)
                .cloned()
                .ok_or_else(|| core_types::Error::NotFound(format!("secret key: {key}")))
        })
    }

    fn set(&self, key: &str, value: &[u8]) -> BoxFuture<'_, core_types::Result<()>> {
        let key = key.to_owned();
        let value = SecureBytes::new(value.to_vec());
        Box::pin(async move {
            let mut data = self.data.write().await;
            data.insert(key, value);
            Ok(())
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, core_types::Result<()>> {
        let key = key.to_owned();
        Box::pin(async move {
            let mut data = self.data.write().await;
            data.remove(&key)
                .map(|_| ())
                .ok_or_else(|| core_types::Error::NotFound(format!("secret key: {key}")))
        })
    }

    fn list_keys(&self) -> BoxFuture<'_, core_types::Result<Vec<String>>> {
        Box::pin(async move {
            let data = self.data.read().await;
            Ok(data.keys().cloned().collect())
        })
    }
}
