//! KeyLocker trait — platform keyring abstraction for KEK storage.
//!
//! ADR-SEC-001: Platform keyrings store ONLY the key-encrypting-key (KEK).
//! The KEK wraps (encrypts) the Argon2id-derived master key at rest.
//! When the daemon starts, it retrieves the wrapped master key from the
//! platform keyring, unwraps it with the KEK, and caches the master key
//! in SecureBytes for the session.
//!
//! Implementations:
//! - platform-linux: Secret Service D-Bus (zbus)
//! - platform-macos: Keychain (security-framework)
//! - platform-windows: Credential Manager (DPAPI)

use core_crypto::SecureBytes;
use std::future::Future;
use std::pin::Pin;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Platform keyring abstraction for storing/retrieving the wrapped master key.
///
/// The KEK itself is managed by the platform keyring (unlocked at OS login).
/// This trait does NOT handle individual secrets — only the single wrapped
/// master key blob per user.
pub trait KeyLocker: Send + Sync {
    /// Store the wrapped master key in the platform keyring.
    ///
    /// `service` identifies the application (e.g., "pds").
    /// `account` identifies the user/instance.
    /// `wrapped_key` is the AES-256-GCM encrypted master key.
    fn store_wrapped_key(
        &self,
        service: &str,
        account: &str,
        wrapped_key: &[u8],
    ) -> BoxFuture<'_, core_types::Result<()>>;

    /// Retrieve the wrapped master key from the platform keyring.
    ///
    /// Returns the encrypted blob. Caller must decrypt with the KEK
    /// (derived from user's master password or biometric).
    fn retrieve_wrapped_key(
        &self,
        service: &str,
        account: &str,
    ) -> BoxFuture<'_, core_types::Result<SecureBytes>>;

    /// Delete the wrapped master key from the platform keyring.
    ///
    /// Used during key rotation or account removal.
    fn delete_wrapped_key(
        &self,
        service: &str,
        account: &str,
    ) -> BoxFuture<'_, core_types::Result<()>>;

    /// Check if a wrapped master key exists in the platform keyring.
    fn has_wrapped_key(
        &self,
        service: &str,
        account: &str,
    ) -> BoxFuture<'_, core_types::Result<bool>>;
}
