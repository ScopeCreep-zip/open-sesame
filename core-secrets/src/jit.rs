//! JIT (Just-In-Time) secret delivery with TTL cache.
//!
//! Wraps a `SecretsStore` with a time-limited in-memory cache.
//! Cache entries are `SecureBytes` (mlock'd, zeroize-on-drop).
//! Flush zeroes all cached secrets — called on profile deactivation.

use core_crypto::SecureBytes;

use crate::SecretsStore;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

struct CachedSecret {
    value: SecureBytes,
    fetched_at: Instant,
}

/// TTL-cached wrapper around any `SecretsStore`.
///
/// Secrets are fetched from the underlying store on first access or after
/// TTL expiry. The cache holds `SecureBytes` clones — both the cache entry
/// and the returned value independently zeroize on drop.
pub struct JitDelivery<S: SecretsStore> {
    store: S,
    cache: tokio::sync::RwLock<HashMap<String, CachedSecret>>,
    ttl: Duration,
}

impl<S: SecretsStore> JitDelivery<S> {
    pub fn new(store: S, ttl: Duration) -> Self {
        Self {
            store,
            cache: tokio::sync::RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Resolve a secret by key, using cache if valid.
    pub fn resolve<'a>(&'a self, key: &'a str) -> BoxFuture<'a, core_types::Result<SecureBytes>> {
        Box::pin(async move {
            // Check cache
            {
                let cache = self.cache.read().await;
                if let Some(cached) = cache.get(key)
                    && cached.fetched_at.elapsed() < self.ttl
                {
                    return Ok(cached.value.clone());
                }
            }

            // Fetch from underlying store
            let value = self.store.get(key).await?;

            // Cache the result
            {
                let mut cache = self.cache.write().await;
                cache.insert(
                    key.to_owned(),
                    CachedSecret {
                        value: value.clone(),
                        fetched_at: Instant::now(),
                    },
                );
            }

            Ok(value)
        })
    }

    /// Flush all cached secrets. SecureBytes are zeroed on drop.
    /// Called on profile deactivation (ADR-SEC-002).
    pub async fn flush(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Access the underlying store directly (bypassing cache).
    pub fn store(&self) -> &S {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

    #[tokio::test]
    async fn resolve_caches_value() {
        let store = InMemoryStore::new();
        store.set("key1", b"secret").await.unwrap();

        let jit = JitDelivery::new(store, Duration::from_secs(60));
        let v1 = jit.resolve("key1").await.unwrap();
        assert_eq!(v1.as_bytes(), b"secret");

        // Modify underlying store — cache should still return old value
        jit.store().set("key1", b"modified").await.unwrap();
        let v2 = jit.resolve("key1").await.unwrap();
        assert_eq!(v2.as_bytes(), b"secret"); // cached
    }

    #[tokio::test]
    async fn flush_clears_cache() {
        let store = InMemoryStore::new();
        store.set("key1", b"secret").await.unwrap();

        let jit = JitDelivery::new(store, Duration::from_secs(60));
        let _ = jit.resolve("key1").await.unwrap();

        // Modify underlying, then flush
        jit.store().set("key1", b"rotated").await.unwrap();
        jit.flush().await;

        let val = jit.resolve("key1").await.unwrap();
        assert_eq!(val.as_bytes(), b"rotated"); // fresh fetch after flush
    }

    #[tokio::test]
    async fn ttl_expiry_refetches() {
        let store = InMemoryStore::new();
        store.set("key1", b"v1").await.unwrap();

        let jit = JitDelivery::new(store, Duration::from_millis(1));
        let _ = jit.resolve("key1").await.unwrap();

        // Wait for TTL expiry
        tokio::time::sleep(Duration::from_millis(10)).await;

        jit.store().set("key1", b"v2").await.unwrap();
        let val = jit.resolve("key1").await.unwrap();
        assert_eq!(val.as_bytes(), b"v2"); // refetched after TTL
    }
}
