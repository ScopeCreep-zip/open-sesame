//! Core trait and types for pluggable authentication backends.

use crate::AuthError;
use core_crypto::SecureBytes;
use core_types::TrustProfileName;
use std::collections::BTreeMap;
use std::path::Path;

/// What kind of user interaction a backend requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthInteraction {
    /// No interaction -- backend can unlock silently (SSH software key, TPM, keyring).
    None,
    /// Password/PIN entry required (keyboard input).
    PasswordEntry,
    /// Physical touch on hardware token required (FIDO2, PIV with touch policy).
    HardwareTouch,
}

/// How the master key should be sent to daemon-secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcUnlockStrategy {
    /// Use existing `UnlockRequest` with password field.
    /// daemon-secrets performs the KDF.
    PasswordUnlock,
    /// Use `SshUnlockRequest` with pre-derived master key.
    /// Used by SSH-agent and future backends that derive/unwrap the key client-side.
    DirectMasterKey,
}

/// Result of a successful backend unlock.
pub struct UnlockOutcome {
    /// The 32-byte master key (for `DirectMasterKey`) or password bytes (for `PasswordUnlock`).
    pub master_key: SecureBytes,
    /// Backend-specific metadata for audit logging.
    pub audit_metadata: BTreeMap<String, String>,
    /// Which IPC message type to use.
    pub ipc_strategy: IpcUnlockStrategy,
}

/// A pluggable authentication backend for vault unlock.
#[async_trait::async_trait]
pub trait VaultAuthBackend: Send + Sync {
    /// Human-readable name for audit logs and overlay display.
    fn name(&self) -> &str;

    /// Short identifier for IPC messages and config.
    fn backend_id(&self) -> &str;

    /// Check whether this backend has a valid enrollment for the profile.
    fn is_enrolled(&self, profile: &TrustProfileName, config_dir: &Path) -> bool;

    /// Check whether this backend can currently perform an unlock.
    /// Must be fast (< 100ms).
    async fn can_unlock(&self, profile: &TrustProfileName, config_dir: &Path) -> bool;

    /// What kind of user interaction this backend requires.
    fn requires_interaction(&self) -> AuthInteraction;

    /// Attempt to derive/unwrap the master key for a profile.
    async fn unlock(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
        salt: &[u8],
    ) -> Result<UnlockOutcome, AuthError>;

    /// Enroll this backend for a profile. Requires the master key.
    ///
    /// `selected_key_index` is an optional index into the list of eligible keys
    /// returned by the backend. If `None`, the backend picks the first eligible key.
    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        config_dir: &Path,
        salt: &[u8],
        selected_key_index: Option<usize>,
    ) -> Result<(), AuthError>;

    /// Remove enrollment for this backend.
    async fn revoke(&self, profile: &TrustProfileName, config_dir: &Path) -> Result<(), AuthError>;
}
