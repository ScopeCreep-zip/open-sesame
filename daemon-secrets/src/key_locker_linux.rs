//! SecretServiceKeyLocker — Linux KeyLocker implementation.
//!
//! Wraps `platform_linux::dbus::SecretServiceProxy` (raw D-Bus calls)
//! with the `core_secrets::KeyLocker` trait (returns SecureBytes).
//!
//! See ADR: KeyLocker Implementation in daemon-secrets, Not platform-linux.
//!
//! Wired into the unlock flow: after Argon2id key derivation, the master
//! key is stored in the platform keyring (best-effort) so it persists
//! across daemon restarts while the user's login session is active.
//! On lock, the keyring entry is deleted.

use core_crypto::SecureBytes;
use core_secrets::KeyLocker;
use platform_linux::dbus::{SecretServiceProxy, SessionBus};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::OnceCell;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// KeyLocker implementation backed by the Linux Secret Service D-Bus API.
///
/// Stores ONLY the wrapped master key blob (ADR-SEC-001). The Secret Service
/// collection being unlocked at login does NOT expose individual secrets —
/// it exposes one encrypted blob that requires the master password to unwrap.
pub struct SecretServiceKeyLocker {
    bus: Arc<SessionBus>,
    proxy: OnceCell<SecretServiceProxy>,
}

impl SecretServiceKeyLocker {
    /// Create a new KeyLocker that will lazily connect to the Secret Service.
    pub fn new(bus: Arc<SessionBus>) -> Self {
        Self {
            bus,
            proxy: OnceCell::new(),
        }
    }

    /// Get or initialize the Secret Service proxy.
    async fn proxy(&self) -> core_types::Result<&SecretServiceProxy> {
        self.proxy
            .get_or_try_init(|| async { SecretServiceProxy::new(&self.bus).await })
            .await
    }
}

impl KeyLocker for SecretServiceKeyLocker {
    fn store_wrapped_key(
        &self,
        service: &str,
        account: &str,
        wrapped_key: &[u8],
    ) -> BoxFuture<'_, core_types::Result<()>> {
        let service = service.to_owned();
        let account = account.to_owned();
        let wrapped_key = wrapped_key.to_vec();
        Box::pin(async move {
            let proxy = self.proxy().await?;
            proxy
                .store(&service, &account, "PDS Master Key (wrapped)", &wrapped_key)
                .await
        })
    }

    fn retrieve_wrapped_key(
        &self,
        service: &str,
        account: &str,
    ) -> BoxFuture<'_, core_types::Result<SecureBytes>> {
        let service = service.to_owned();
        let account = account.to_owned();
        Box::pin(async move {
            let proxy = self.proxy().await?;
            let bytes = proxy.retrieve(&service, &account).await?;
            Ok(SecureBytes::new(bytes))
        })
    }

    fn delete_wrapped_key(
        &self,
        service: &str,
        account: &str,
    ) -> BoxFuture<'_, core_types::Result<()>> {
        let service = service.to_owned();
        let account = account.to_owned();
        Box::pin(async move {
            let proxy = self.proxy().await?;
            proxy.delete(&service, &account).await
        })
    }

    fn has_wrapped_key(
        &self,
        service: &str,
        account: &str,
    ) -> BoxFuture<'_, core_types::Result<bool>> {
        let service = service.to_owned();
        let account = account.to_owned();
        Box::pin(async move {
            let proxy = self.proxy().await?;
            proxy.has(&service, &account).await
        })
    }
}
