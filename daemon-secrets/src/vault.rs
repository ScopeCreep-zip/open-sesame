//! Vault state management: `VaultState`, `PartialUnlock`, and related types.
//!
//! Central runtime state for the secrets daemon. Individual profiles are
//! unlocked/locked independently — there is no global "locked" state.

use core_crypto::{KeyContext, SecureBytes};
use core_layout::{Layout, VaultFile};
use core_secrets::{JitDelivery, SqlCipherStore};
use core_types::{AuthFactorId, HkdfAlgorithm, TrustProfileName};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

/// How long a partial multi-factor unlock waits for its remaining factors.
pub(crate) const PARTIAL_UNLOCK_TIMEOUT: Duration = Duration::from_mins(2);

/// How often expired partial unlocks are swept.
pub(crate) const PARTIAL_UNLOCK_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Longest wait for a vault open. A blocking thread killed by seccomp
/// (SIGSYS) never completes its join handle; the bound returns control to
/// the event loop instead of freezing it until the watchdog fires.
const VAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a vault database could not be opened.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VaultOpenError {
    /// `SQLCipher` refused the database: wrong key, corrupt file, or an
    /// unreadable path.
    #[error("vault {path} rejected: {source}")]
    Rejected {
        path: PathBuf,
        source: core_types::Error,
    },
    #[error(
        "vault {path} open timed out after {VAULT_OPEN_TIMEOUT:?} (possible seccomp violation on the blocking thread)"
    )]
    TimedOut { path: PathBuf },
    #[error("vault {path} open task failed: {source}")]
    Join {
        path: PathBuf,
        source: tokio::task::JoinError,
    },
}

impl From<VaultOpenError> for core_types::Error {
    fn from(e: VaultOpenError) -> Self {
        Self::Secrets(e.to_string())
    }
}

/// A vault's master key and the derivation (its metadata's `hkdf`) every
/// key of the vault is derived with.
pub(crate) struct MasterKey {
    pub(crate) key: SecureBytes,
    pub(crate) hkdf: HkdfAlgorithm,
}

/// Open the `SQLCipher` database at `path` with the vault key derived from
/// `master` for `profile`. `SQLCipher` I/O (PRAGMA key, schema migration)
/// runs on a blocking thread, bounded by [`VAULT_OPEN_TIMEOUT`].
pub(crate) async fn open_vault(
    path: PathBuf,
    master: &MasterKey,
    profile: &TrustProfileName,
) -> Result<SqlCipherStore, VaultOpenError> {
    let hkdf = master.hkdf;
    let vault_key =
        core_crypto::derive_key(hkdf, &KeyContext::Vault(profile), master.key.as_bytes());
    let db_path = path.clone();
    match tokio::time::timeout(
        VAULT_OPEN_TIMEOUT,
        tokio::task::spawn_blocking(move || SqlCipherStore::open(&db_path, &vault_key, hkdf)),
    )
    .await
    {
        Ok(Ok(Ok(store))) => Ok(store),
        Ok(Ok(Err(source))) => Err(VaultOpenError::Rejected { path, source }),
        Ok(Err(source)) => Err(VaultOpenError::Join { path, source }),
        Err(_) => Err(VaultOpenError::TimedOut { path }),
    }
}

/// The profile's vault database path when the database exists.
///
/// # Errors
///
/// The layout errors, and an I/O error when the database's presence
/// cannot be determined.
pub(crate) fn existing_vault(
    layout: &Layout,
    profile: &TrustProfileName,
) -> core_types::Result<Option<PathBuf>> {
    let path = layout.vault_file(profile, VaultFile::Database)?;
    Ok(path.try_exists()?.then_some(path))
}

/// Close an open vault: flush its JIT cache, then drop it, closing the
/// `SQLCipher` connection, whose codec teardown overwrites `SQLCipher`'s
/// copies of the key, HMAC key, and passphrase. Every vault close is this
/// one.
async fn close(vault: JitDelivery<SqlCipherStore>) {
    vault.flush().await;
    drop(vault);
}

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
    /// Per-profile master keys, installed when a vault's auth policy is
    /// satisfied by submitted factors (`unlock::handle_factor_submit`).
    /// Key: profile name. Value: master key (mlock'd, zeroize-on-drop).
    pub(crate) master_keys: HashMap<TrustProfileName, MasterKey>,
    /// Each open vault's JIT cache over its `SqlCipherStore`. Multiple
    /// vaults may be open concurrently.
    pub(crate) vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>,
    /// Profiles explicitly authorized for secret access: the security
    /// boundary — `vault_for` refuses profiles not in this set. Distinct
    /// from `vaults.keys()`: a profile may be authorized before its vault
    /// is lazily opened.
    pub(crate) active_profiles: HashSet<TrustProfileName>,
    /// In-progress multi-factor unlocks. At most one per profile.
    pub(crate) partial_unlocks: HashMap<TrustProfileName, PartialUnlock>,
    /// JIT TTL from CLI.
    pub(crate) ttl: Duration,
    /// Location of vault databases, salts, and metadata.
    pub(crate) layout: Layout,
}

impl VaultState {
    /// Inventory comes from persisted vault files and held runtime state,
    /// never from configuration profiles. Listing failures are not emptiness.
    pub(crate) fn inventory(
        &self,
    ) -> core_types::Result<std::collections::BTreeMap<TrustProfileName, bool>> {
        let dir = self.layout.vaults_dir()?;
        let mut names = std::collections::BTreeSet::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(core_types::Error::Secrets(format!(
                    "{}: {error}",
                    dir.display()
                )));
            }
        };
        if let Some(entries) = entries {
            for entry in entries {
                let path = entry?.path();
                if !VaultFile::ALL
                    .iter()
                    .any(|kind| path.extension().is_some_and(|ext| ext == kind.extension()))
                {
                    continue;
                }
                let name = path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        core_types::Error::Secrets(format!(
                            "{}: invalid vault filename",
                            path.display()
                        ))
                    })?;
                let profile = TrustProfileName::try_from(name)?;
                if !std::fs::metadata(&path)?.is_file() {
                    return Err(core_types::Error::Secrets(format!(
                        "{}: vault entry is not a file",
                        path.display()
                    )));
                }
                names.insert(profile);
            }
        }
        names.extend(self.master_keys.keys().cloned());
        names.extend(self.vaults.keys().cloned());
        names.extend(self.partial_unlocks.keys().cloned());
        names.extend(self.active_profiles.iter().cloned());
        Ok(names
            .into_iter()
            .map(|profile| {
                let locked = !self.master_keys.contains_key(&profile);
                (profile, locked)
            })
            .collect())
    }

    /// Every vault locked, under `layout`, caching secrets for `ttl`.
    pub(crate) fn new(layout: Layout, ttl: Duration) -> Self {
        Self {
            master_keys: HashMap::new(),
            vaults: HashMap::new(),
            active_profiles: HashSet::new(),
            partial_unlocks: HashMap::new(),
            ttl,
            layout,
        }
    }

    /// Get or lazily open a vault for the given trust profile.
    ///
    /// Refuses access if the profile is not in the `active_profiles`
    /// authorization set or its vault has not been unlocked. The vault is
    /// opened through [`open_vault`].
    pub(crate) async fn vault_for(
        &mut self,
        profile: &TrustProfileName,
    ) -> core_types::Result<&JitDelivery<SqlCipherStore>> {
        if !self.active_profiles.contains(profile) {
            return Err(core_types::Error::Secrets(format!(
                "profile '{profile}' is not active — access denied"
            )));
        }
        let master_key = self.master_keys.get(profile).ok_or_else(|| {
            core_types::Error::Secrets(format!(
                "profile '{profile}' is not unlocked — run: sesame unlock --profile {profile}"
            ))
        })?;
        match self.vaults.entry(profile.clone()) {
            Entry::Occupied(open) => Ok(open.into_mut()),
            Entry::Vacant(slot) => {
                let db_path = self.layout.vault_file(profile, VaultFile::Database)?;
                if let Some(parent) = db_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        core_types::Error::Secrets(format!(
                            "failed to create vault directory {}: {e}",
                            parent.display()
                        ))
                    })?;
                }
                let store = open_vault(db_path.clone(), master_key, profile).await?;
                tracing::info!(profile = %profile, path = %db_path.display(), "vault opened");
                Ok(slot.insert(JitDelivery::new(store, self.ttl)))
            }
        }
    }

    /// Authorize a profile for secret access. Must be called before `vault_for`.
    pub(crate) fn activate_profile(&mut self, profile: &TrustProfileName) {
        self.active_profiles.insert(profile.clone());
        tracing::info!(profile = %profile, "profile authorized for secret access");
    }

    /// Deactivate a trust profile: deauthorize, then close its vault.
    ///
    /// Idempotent: deactivating an already-inactive profile is not an error.
    /// Deauthorization is the security operation and happens first.
    pub(crate) async fn deactivate_profile(&mut self, profile: &TrustProfileName) {
        self.active_profiles.remove(profile);
        if let Some(vault) = self.vaults.remove(profile) {
            close(vault).await;
            tracing::info!(profile = %profile, "vault deactivated and key material zeroized");
        }
    }

    /// Lock `profile`: deactivate it and zeroize its master key and any
    /// partial unlock.
    pub(crate) async fn lock(&mut self, profile: &TrustProfileName) {
        self.deactivate_profile(profile).await;
        self.master_keys.remove(profile);
        self.partial_unlocks.remove(profile);
        tracing::info!(profile = %profile, "vault locked, key material zeroized");
    }

    /// Lock every vault; the profiles that were unlocked.
    pub(crate) async fn lock_all(&mut self) -> Vec<TrustProfileName> {
        let unlocked: Vec<TrustProfileName> = self.master_keys.keys().cloned().collect();
        self.active_profiles.clear();
        for (_, vault) in self.vaults.drain() {
            close(vault).await;
        }
        self.master_keys.clear();
        self.partial_unlocks.clear();
        tracing::info!(
            vaults = unlocked.len(),
            "all vaults locked, key material zeroized"
        );
        unlocked
    }

    /// Discard every partial unlock past its deadline.
    pub(crate) fn sweep_expired_partials(&mut self) {
        self.partial_unlocks.retain(|profile, partial| {
            let expired = partial.is_expired();
            if expired {
                tracing::info!(%profile, "expired partial unlock state removed");
            }
            !expired
        });
    }

    /// Names of all profiles authorized for secret access.
    ///
    /// Returns the authorization set, NOT the set of open vaults.
    /// These can diverge: a profile may be authorized before its vault
    /// is lazily opened.
    pub(crate) fn active_profiles(&self) -> Vec<TrustProfileName> {
        self.active_profiles.iter().cloned().collect()
    }

    /// The per-profile IPC encryption key (ADR-SEC-006, defense-in-depth,
    /// feature `ipc-field-encryption`): AES-256-GCM per secret value on the
    /// IPC bus, layered on top of Noise IK transport encryption.
    ///
    /// Feature-gated because the Noise transport is already the security
    /// boundary (matching ssh-agent, 1Password, Vault, gpg-agent
    /// precedent), CLI clients lack the master key needed for per-field
    /// encryption, and the per-field key derives from the same master key
    /// that transits inside the Noise channel (not an independent trust
    /// root). Enable for research into daemon-to-daemon relay
    /// defense-in-depth.
    #[cfg(feature = "ipc-field-encryption")]
    fn ipc_encryption_key(
        &self,
        profile: &TrustProfileName,
    ) -> core_types::Result<core_crypto::EncryptionKey> {
        let master_key = self.master_keys.get(profile).ok_or_else(|| {
            core_types::Error::Secrets(format!(
                "profile '{profile}' not unlocked for IPC encryption"
            ))
        })?;
        Ok(core_crypto::derive_encryption_key(
            master_key.hkdf,
            &KeyContext::IpcEncryption(profile),
            master_key.key.as_bytes(),
        ))
    }

    /// `plaintext` sealed under `profile`'s IPC encryption key.
    #[cfg(feature = "ipc-field-encryption")]
    pub(crate) fn encrypt_for_ipc(
        &self,
        profile: &TrustProfileName,
        plaintext: &[u8],
    ) -> core_types::Result<Vec<u8>> {
        self.ipc_encryption_key(profile)?.seal_wire(plaintext)
    }

    /// `wire` opened with `profile`'s IPC encryption key.
    #[cfg(feature = "ipc-field-encryption")]
    pub(crate) fn decrypt_from_ipc(
        &self,
        profile: &TrustProfileName,
        wire: &[u8],
    ) -> core_types::Result<SecureBytes> {
        self.ipc_encryption_key(profile)?.open_wire(wire)
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;

    #[test]
    fn disk_inventory_recognizes_every_vault_artifact_without_config_profiles() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let dir = layout.vaults_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let state = VaultState::new(layout, Duration::from_secs(30));
        for (index, kind) in VaultFile::ALL.into_iter().enumerate() {
            std::fs::write(dir.join(format!("vault{index}.{}", kind.extension())), []).unwrap();
        }
        std::fs::write(dir.join("ignored.db-wal"), []).unwrap();
        std::fs::write(dir.join("ignored.tmp"), []).unwrap();
        let inventory = state.inventory().unwrap();
        assert_eq!(inventory.len(), VaultFile::ALL.len());
        for index in 0..VaultFile::ALL.len() {
            let profile = TrustProfileName::try_from(format!("vault{index}").as_str()).unwrap();
            assert_eq!(inventory.get(&profile), Some(&true));
        }
    }

    #[test]
    fn missing_directory_preserves_runtime_inventory() {
        let root = tempfile::tempdir().unwrap();
        let mut state = VaultState::new(Layout::under(root.path()), Duration::from_secs(30));
        let profile = TrustProfileName::try_from("runtime").unwrap();
        state.active_profiles.insert(profile.clone());
        assert_eq!(state.inventory().unwrap().get(&profile), Some(&true));
    }

    #[test]
    fn inventory_errors_are_not_empty_successes() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let dir = layout.vaults_dir().unwrap();
        std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
        std::fs::write(&dir, []).unwrap();
        let state = VaultState::new(layout, Duration::from_secs(30));
        assert!(state.inventory().is_err());
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir_all(dir.join("invalid.db")).unwrap();
        assert!(state.inventory().is_err());
    }
}
