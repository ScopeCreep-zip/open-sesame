//! Vault state management: VaultState, PartialUnlock, and related types.
//!
//! Central runtime state for the secrets daemon. Individual profiles are
//! unlocked/locked independently — there is no global "locked" state.

use core_crypto::SecureBytes;
use core_secrets::{JitDelivery, SqlCipherStore};
use core_types::{AuthFactorId, TrustProfileName};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

/// Timeout for partial multi-factor unlock state (seconds).
pub(crate) const PARTIAL_UNLOCK_TIMEOUT_SECS: u64 = 120;

/// Interval for sweeping expired partial unlock state (seconds).
pub(crate) const PARTIAL_UNLOCK_SWEEP_INTERVAL_SECS: u64 = 30;

/// BLAKE3 key derivation context prefix for combining factor pieces in `All` mode.
/// The full context is `"{ALL_MODE_KDF_CONTEXT} {profile_name}"`.
pub(crate) const ALL_MODE_KDF_CONTEXT: &str = "pds v2 combined-master-key";

/// Partial unlock state for a profile awaiting additional factors.
pub(crate) struct PartialUnlock {
    /// Master key candidates from factors received so far.
    /// For any/policy mode: each factor independently unwraps to the same master key.
    /// For all mode: factor pieces collected here, combined when all present.
    pub(crate) received_factors: HashMap<AuthFactorId, SecureBytes>,
    /// Which factors are still needed.
    pub(crate) remaining_required: HashSet<AuthFactorId>,
    /// How many additional factors are still needed (beyond required).
    pub(crate) remaining_additional: u32,
    /// Deadline after which partial state is discarded.
    pub(crate) deadline: tokio::time::Instant,
}

impl PartialUnlock {
    /// Check if the unlock policy is fully satisfied.
    pub(crate) fn is_complete(&self) -> bool {
        self.remaining_required.is_empty() && self.remaining_additional == 0
    }

    /// Check if the deadline has passed.
    pub(crate) fn is_expired(&self) -> bool {
        tokio::time::Instant::now() >= self.deadline
    }
}

/// Runtime state for the secrets daemon.
///
/// Always present after daemon init (as an empty container). Individual profiles
/// are unlocked/locked independently — there is no global "locked" state.
pub(crate) struct VaultState {
    /// Per-profile master keys. Each derived independently from its own password+salt.
    /// Key: profile name. Value: master key (mlock'd, zeroize-on-drop).
    pub(crate) master_keys: HashMap<TrustProfileName, SecureBytes>,
    /// Trust profile name -> JitDelivery wrapping SqlCipherStore.
    /// Multiple vaults may be open concurrently.
    pub(crate) vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>,
    /// Profiles explicitly authorized for secret access.
    /// This is the security boundary — vault_for() refuses profiles not in this set.
    /// Distinct from `vaults.keys()`: a profile may be authorized before its vault
    /// is lazily opened, or a vault may be open while deactivation is in progress.
    pub(crate) active_profiles: HashSet<TrustProfileName>,
    /// In-progress multi-factor unlocks. At most one per profile.
    pub(crate) partial_unlocks: HashMap<TrustProfileName, PartialUnlock>,
    /// JIT TTL from CLI.
    pub(crate) ttl: Duration,
    /// Config directory for vault DB storage.
    pub(crate) config_dir: PathBuf,
}

impl VaultState {
    /// Get or lazily open a vault for the given trust profile.
    ///
    /// Refuses access if the profile is not in the active_profiles authorization set
    /// or if the profile's vault has not been unlocked.
    ///
    /// Vault opening uses `spawn_blocking` to avoid blocking the tokio event loop
    /// during synchronous SQLCipher I/O (PRAGMA key, schema migration).
    pub(crate) async fn vault_for(
        &mut self,
        profile: &TrustProfileName,
    ) -> core_types::Result<&JitDelivery<SqlCipherStore>> {
        if !self.active_profiles.contains(profile) {
            return Err(core_types::Error::Secrets(format!(
                "profile '{}' is not active — access denied",
                profile
            )));
        }
        let master_key = self.master_keys.get(profile).ok_or_else(|| {
            core_types::Error::Secrets(format!(
                "profile '{}' is not unlocked — run: sesame unlock --profile {}",
                profile, profile
            ))
        })?;
        if !self.vaults.contains_key(profile) {
            let vault_key = core_crypto::derive_vault_key(master_key.as_bytes(), profile);
            let db_path = self.config_dir.join("vaults").join(format!("{profile}.db"));

            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    core_types::Error::Secrets(format!(
                        "failed to create vault directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            // Wrap synchronous SQLCipher open in spawn_blocking to avoid blocking
            // the event loop during PRAGMA key + schema migration.
            // Defensive timeout: if the blocking thread is killed (e.g. seccomp
            // SIGSYS), the JoinHandle hangs forever. The timeout ensures the
            // event loop recovers instead of freezing until watchdog kills us.
            let db_path_clone = db_path.clone();
            let store = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::task::spawn_blocking(move || {
                    SqlCipherStore::open(&db_path_clone, &vault_key)
                }),
            )
            .await
            .map_err(|_| {
                core_types::Error::Secrets(
                    "vault open timed out (10s) — possible seccomp violation on blocking thread"
                        .into(),
                )
            })?
            .map_err(|e| core_types::Error::Secrets(format!("spawn_blocking join error: {e}")))??;

            let jit = JitDelivery::new(store, self.ttl);
            self.vaults.insert(profile.clone(), jit);
            tracing::info!(profile = %profile, path = %db_path.display(), "vault opened");
        }
        Ok(self.vaults.get(profile).expect("just inserted"))
    }

    /// Authorize a profile for secret access. Must be called before vault_for().
    pub(crate) fn activate_profile(&mut self, profile: &TrustProfileName) {
        self.active_profiles.insert(profile.clone());
        tracing::info!(profile = %profile, "profile authorized for secret access");
    }

    /// Deactivate a trust profile: deauthorize, flush JIT cache, close vault.
    ///
    /// Idempotent: deactivating an already-inactive profile is not an error.
    /// Deauthorization (removing from active_profiles) is the security operation
    /// and happens FIRST — before vault close.
    pub(crate) async fn deactivate_profile(&mut self, profile: &TrustProfileName) {
        self.active_profiles.remove(profile);
        if let Some(vault) = self.vaults.remove(profile) {
            vault.flush().await;
            vault.store().pragma_rekey_clear();
            drop(vault);
            tracing::info!(profile = %profile, "vault deactivated and key material zeroized");
        }
    }

    /// Names of all profiles authorized for secret access.
    ///
    /// Returns the authorization set, NOT the set of open vaults.
    /// These can diverge: a profile may be authorized before its vault
    /// is lazily opened.
    pub(crate) fn active_profiles(&self) -> Vec<TrustProfileName> {
        self.active_profiles.iter().cloned().collect()
    }

    /// Get the per-profile IPC encryption key (ADR-SEC-006, defense-in-depth).
    ///
    /// Used to encrypt secret values before placing them on the IPC bus,
    /// providing per-field encryption on top of Noise transport encryption.
    /// Per-field IPC encryption (ADR-SEC-006, feature-gated).
    ///
    /// Defense-in-depth: AES-256-GCM per secret value on the IPC bus, layered
    /// on top of Noise IK transport encryption. Gated behind `ipc-field-encryption`
    /// feature because:
    /// - The Noise transport is already the security boundary (matching
    ///   ssh-agent, 1Password, Vault, gpg-agent precedent)
    /// - CLI clients lack the master key needed for per-field encryption
    /// - The per-field key derives from the same master key that transits
    ///   inside the Noise channel (not an independent trust root)
    ///
    /// Enable for research into daemon-to-daemon relay defense-in-depth.
    #[cfg(feature = "ipc-field-encryption")]
    fn ipc_encryption_key(
        &self,
        profile: &TrustProfileName,
    ) -> core_types::Result<core_crypto::EncryptionKey> {
        let master_key = self.master_keys.get(profile).ok_or_else(|| {
            core_types::Error::Secrets(format!(
                "profile '{}' not unlocked for IPC encryption",
                profile
            ))
        })?;
        let key_bytes = core_crypto::derive_ipc_encryption_key(master_key.as_bytes(), profile);
        let key_array: &[u8; 32] = key_bytes
            .as_bytes()
            .try_into()
            .map_err(|_| core_types::Error::Crypto("IPC encryption key is not 32 bytes".into()))?;
        core_crypto::EncryptionKey::from_bytes(key_array)
    }

    #[cfg(feature = "ipc-field-encryption")]
    pub(crate) fn encrypt_for_ipc(
        &self,
        profile: &TrustProfileName,
        plaintext: &[u8],
    ) -> core_types::Result<Vec<u8>> {
        let enc_key = self.ipc_encryption_key(profile)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| core_types::Error::Crypto(format!("nonce generation failed: {e}")))?;
        let ciphertext = enc_key.encrypt(&nonce, plaintext)?;
        let mut wire = Vec::with_capacity(12 + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend(ciphertext);
        Ok(wire)
    }

    #[cfg(feature = "ipc-field-encryption")]
    pub(crate) fn decrypt_from_ipc(
        &self,
        profile: &TrustProfileName,
        wire: &[u8],
    ) -> core_types::Result<Vec<u8>> {
        if wire.len() < 12 {
            return Err(core_types::Error::Crypto(
                "IPC-encrypted value too short (missing nonce)".into(),
            ));
        }
        let nonce: [u8; 12] = wire[..12]
            .try_into()
            .map_err(|_| core_types::Error::Crypto("nonce extraction failed".into()))?;
        let ciphertext = &wire[12..];
        let enc_key = self.ipc_encryption_key(profile)?;
        let plaintext = enc_key.decrypt(&nonce, ciphertext)?;
        Ok(plaintext.as_bytes().to_vec())
    }
}

/// Result of a successful profile unlock.
pub(crate) struct UnlockResult {
    /// Per-profile master key (mlock'd, zeroize-on-drop).
    pub(crate) master_key: SecureBytes,
    /// Pre-verified vault store, if a vault DB existed at unlock time.
    /// Cached to avoid redundant SQLCipher open on first ProfileActivate.
    pub(crate) verified_store: Option<SqlCipherStore>,
}
