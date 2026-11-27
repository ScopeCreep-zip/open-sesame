//! Vault metadata: enrolled factors, auth policy, and the vault's key
//! derivation algorithms.
//!
//! Stored as JSON at `Layout::vault_file(profile, VaultFile::Metadata)`.
//! JSON is used (not TOML) to distinguish machine-managed metadata from
//! user-editable configuration.

use crate::AuthError;
use crate::salt::SALT_LEN;
use core_layout::{Layout, VaultFile};
use core_types::{AuthCombineMode, AuthFactorId, CryptoConfig, HkdfAlgorithm, KdfAlgorithm};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The metadata format version this release reads and writes. A vault of
/// any other version is re-created by a factory reset.
pub const VAULT_META_VERSION: u32 = 2;

/// Persistent metadata for a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Metadata format version.
    pub version: u32,
    /// Which auth methods are enrolled.
    pub enrolled_factors: Vec<EnrolledFactor>,
    /// The unlock policy for this vault.
    pub auth_policy: AuthCombineMode,
    /// The algorithms the vault's keys derive under (`kdf`, `hkdf`).
    #[serde(flatten)]
    pub algorithms: VaultAlgorithms,
    /// Timestamp of vault creation (Unix epoch seconds).
    pub created_at: u64,
    /// Timestamp of last policy change.
    pub policy_changed_at: u64,
}

/// Record of an enrolled authentication factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledFactor {
    /// Which factor type.
    pub factor_id: AuthFactorId,
    /// Human-readable label (e.g., SSH key fingerprint, "master password").
    pub label: String,
    /// When this factor was enrolled (Unix epoch seconds).
    pub enrolled_at: u64,
}

/// The algorithms a vault's keys derive under, fixed at its creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAlgorithms {
    /// The password KDF of the vault's password factor.
    pub kdf: KdfAlgorithm,
    /// The derivation of every key derived from key material: vault key,
    /// IPC key, entry key, SSH challenge and KEK, combined master key.
    pub hkdf: HkdfAlgorithm,
}

/// What a backend derives a vault's keys from: its salt and its
/// algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultKeying {
    pub salt: [u8; SALT_LEN],
    pub algorithms: VaultAlgorithms,
}

/// The version field alone, read before the rest of the file.
#[derive(Deserialize)]
struct Version {
    version: u32,
}

/// The current Unix epoch timestamp. Enrollment and policy times are audit
/// evidence, so a clock before the epoch is an error.
fn now_epoch() -> Result<u64, AuthError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(AuthError::Clock)?
        .as_secs())
}

impl VaultMetadata {
    /// Metadata for a new vault enrolled with `factors` (each with its
    /// label), all stamped with the creation time, deriving its keys with
    /// the algorithms `crypto` selects.
    ///
    /// # Errors
    ///
    /// `AuthError::Clock` when the system clock is before the Unix epoch.
    pub fn new(
        factors: Vec<(AuthFactorId, String)>,
        auth_policy: AuthCombineMode,
        crypto: &CryptoConfig,
    ) -> Result<Self, AuthError> {
        let now = now_epoch()?;
        Ok(Self {
            version: VAULT_META_VERSION,
            enrolled_factors: factors
                .into_iter()
                .map(|(factor_id, label)| EnrolledFactor {
                    factor_id,
                    label,
                    enrolled_at: now,
                })
                .collect(),
            auth_policy,
            algorithms: VaultAlgorithms {
                kdf: crypto.kdf,
                hkdf: crypto.hkdf,
            },
            created_at: now,
            policy_changed_at: now,
        })
    }

    /// Path to the metadata file for a profile.
    ///
    /// # Errors
    ///
    /// The layout errors.
    pub fn path(
        layout: &Layout,
        profile: &core_types::TrustProfileName,
    ) -> Result<PathBuf, AuthError> {
        Ok(layout.vault_file(profile, VaultFile::Metadata)?)
    }

    /// Read metadata from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, is unreadable,
    /// unparseable, or is not [`VAULT_META_VERSION`].
    pub fn load(
        layout: &Layout,
        profile: &core_types::TrustProfileName,
    ) -> Result<Self, AuthError> {
        let path = Self::path(layout, profile)?;
        let data = std::fs::read_to_string(&path).map_err(|e| {
            AuthError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read vault metadata {}: {e}", path.display()),
            ))
        })?;
        let corrupt = |e: serde_json::Error| {
            AuthError::InvalidVaultFile(format!("corrupt vault metadata {}: {e}", path.display()))
        };
        let Version { version } = serde_json::from_str(&data).map_err(corrupt)?;
        if version != VAULT_META_VERSION {
            return Err(AuthError::InvalidVaultFile(format!(
                "vault metadata {} is version {version}; this release reads version \
                 {VAULT_META_VERSION}. Re-create the vault: sesame init --wipe-reset-destroy-all-data",
                path.display()
            )));
        }
        serde_json::from_str(&data).map_err(corrupt)
    }

    /// Write metadata to disk atomically with owner-only permissions.
    ///
    /// # Errors
    ///
    /// The layout errors, a serialization failure, and the
    /// `core_layout::file::write` errors.
    pub fn save(
        &self,
        layout: &Layout,
        profile: &core_types::TrustProfileName,
    ) -> Result<(), AuthError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            AuthError::InvalidVaultFile(format!("failed to serialize vault metadata: {e}"))
        })?;
        core_layout::file::write(
            &Self::path(layout, profile)?,
            json.as_bytes(),
            core_layout::file::Mode::OwnerOnly,
        )?;
        Ok(())
    }

    /// The keying of this vault with `salt`.
    #[must_use]
    pub fn keying(&self, salt: [u8; SALT_LEN]) -> VaultKeying {
        VaultKeying {
            salt,
            algorithms: self.algorithms,
        }
    }

    /// `profile`'s metadata and the keying its factors derive under (its
    /// salt and algorithms).
    ///
    /// # Errors
    ///
    /// The [`load`](Self::load) and [`crate::salt::require`] errors.
    pub fn load_keying(
        layout: &Layout,
        profile: &core_types::TrustProfileName,
    ) -> Result<(Self, VaultKeying), AuthError> {
        let meta = Self::load(layout, profile)?;
        let keying = meta.keying(crate::salt::require(layout, profile)?);
        Ok((meta, keying))
    }

    /// Check whether a specific factor is enrolled.
    #[must_use]
    pub fn has_factor(&self, factor: AuthFactorId) -> bool {
        self.enrolled_factors.iter().any(|f| f.factor_id == factor)
    }

    /// Add an enrolled factor. Does nothing if already enrolled with the same ID.
    ///
    /// # Errors
    ///
    /// `AuthError::Clock` when the system clock is before the Unix epoch.
    pub fn add_factor(&mut self, factor_id: AuthFactorId, label: String) -> Result<(), AuthError> {
        if self.has_factor(factor_id) {
            return Ok(());
        }
        self.enrolled_factors.push(EnrolledFactor {
            factor_id,
            label,
            enrolled_at: now_epoch()?,
        });
        Ok(())
    }

    /// Remove an enrolled factor by ID.
    pub fn remove_factor(&mut self, factor_id: AuthFactorId) {
        self.enrolled_factors.retain(|f| f.factor_id != factor_id);
    }

    /// What kind of contribution each factor makes under this vault's policy.
    #[must_use]
    pub fn contribution_type(&self) -> crate::FactorContribution {
        match self.auth_policy {
            AuthCombineMode::All => crate::FactorContribution::FactorPiece,
            AuthCombineMode::Any | AuthCombineMode::Policy(_) => {
                crate::FactorContribution::CompleteMasterKey
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{keying, layout, password_vault, test_profile};

    fn write_metadata(layout: &Layout, json: &str) {
        core_layout::file::write(
            &VaultMetadata::path(layout, &test_profile()).unwrap(),
            json.as_bytes(),
            core_layout::file::Mode::OwnerOnly,
        )
        .unwrap();
    }

    #[test]
    fn load_fails_when_no_file() {
        let (_root, layout) = layout();
        let result = VaultMetadata::load(&layout, &test_profile());
        assert!(result.is_err());
    }

    #[test]
    fn save_and_load_round_trip_the_algorithms() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let crypto = CryptoConfig {
            kdf: KdfAlgorithm::Pbkdf2Sha256,
            hkdf: HkdfAlgorithm::HkdfSha256,
            ..CryptoConfig::default()
        };
        password_vault(&crypto).save(&layout, &profile).unwrap();
        let loaded = VaultMetadata::load(&layout, &profile).unwrap();

        assert_eq!(loaded.version, VAULT_META_VERSION);
        assert_eq!(loaded.enrolled_factors.len(), 1);
        assert_eq!(loaded.enrolled_factors[0].factor_id, AuthFactorId::Password);
        assert_eq!(loaded.auth_policy, AuthCombineMode::Any);
        assert_eq!(
            loaded.keying([3; SALT_LEN]),
            keying(3, KdfAlgorithm::Pbkdf2Sha256, HkdfAlgorithm::HkdfSha256)
        );
    }

    #[test]
    fn other_versions_are_refused_with_the_reset_command() {
        let (_root, layout) = layout();
        for version in [1, 999] {
            write_metadata(
                &layout,
                &format!(
                    r#"{{"version":{version},"init_mode":"password","enrolled_factors":[],"auth_policy":"any","created_at":0,"policy_changed_at":0}}"#
                ),
            );
            let err = VaultMetadata::load(&layout, &test_profile()).unwrap_err();
            assert!(matches!(err, AuthError::InvalidVaultFile(_)), "{err:?}");
            let err = err.to_string();
            assert!(err.contains(&format!("version {version}")), "{err}");
            assert!(err.contains("--wipe-reset-destroy-all-data"), "{err}");
            assert!(!err.contains("enrollment blob"), "{err}");
        }
    }

    #[test]
    fn metadata_without_algorithms_is_corrupt() {
        let (_root, layout) = layout();
        write_metadata(
            &layout,
            r#"{"version":2,"enrolled_factors":[],"auth_policy":"any","created_at":0,"policy_changed_at":0}"#,
        );
        let err = VaultMetadata::load(&layout, &test_profile())
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing field `kdf`"), "{err}");
    }

    #[test]
    fn new_stamps_every_factor_with_the_creation_time() {
        let factors = vec![
            (AuthFactorId::Password, "master password".to_string()),
            (AuthFactorId::SshAgent, "SHA256:abc".to_string()),
        ];
        let meta =
            VaultMetadata::new(factors, AuthCombineMode::All, &CryptoConfig::default()).unwrap();
        assert_eq!(meta.enrolled_factors.len(), 2);
        assert!(
            meta.enrolled_factors
                .iter()
                .all(|f| f.enrolled_at == meta.created_at)
        );
        assert_eq!(meta.enrolled_factors[1].label, "SHA256:abc");
        assert_eq!(meta.auth_policy, AuthCombineMode::All);
        assert_eq!(
            meta.algorithms,
            VaultAlgorithms {
                kdf: KdfAlgorithm::Argon2id,
                hkdf: HkdfAlgorithm::Blake3,
            }
        );
    }

    #[test]
    fn keying_loads_with_the_metadata_and_requires_a_salt() {
        let (_root, layout) = layout();
        let profile = test_profile();
        password_vault(&CryptoConfig::default())
            .save(&layout, &profile)
            .unwrap();
        assert!(matches!(
            VaultMetadata::load_keying(&layout, &profile),
            Err(AuthError::NotInitialized(_))
        ));
        let salt = crate::salt::create(&layout, &profile).unwrap();
        let (meta, keying) = VaultMetadata::load_keying(&layout, &profile).unwrap();
        assert_eq!(keying, meta.keying(salt));
    }

    #[test]
    fn has_factor_works() {
        let meta = password_vault(&CryptoConfig::default());
        assert!(meta.has_factor(AuthFactorId::Password));
        assert!(!meta.has_factor(AuthFactorId::SshAgent));
    }

    #[test]
    fn add_factor_idempotent() {
        let mut meta = password_vault(&CryptoConfig::default());

        meta.add_factor(AuthFactorId::Password, "duplicate".into())
            .unwrap();
        assert_eq!(meta.enrolled_factors.len(), 1);

        meta.add_factor(AuthFactorId::SshAgent, "SHA256:abc".into())
            .unwrap();
        assert_eq!(meta.enrolled_factors.len(), 2);
    }

    #[test]
    fn remove_factor_works() {
        let mut meta = password_vault(&CryptoConfig::default());
        meta.add_factor(AuthFactorId::SshAgent, "ssh".into())
            .unwrap();
        assert_eq!(meta.enrolled_factors.len(), 2);

        meta.remove_factor(AuthFactorId::SshAgent);
        assert_eq!(meta.enrolled_factors.len(), 1);
        assert!(!meta.has_factor(AuthFactorId::SshAgent));
    }

    #[test]
    fn policy_mode_serializes_correctly() {
        let meta = VaultMetadata::new(
            vec![],
            AuthCombineMode::Policy(core_types::AuthPolicy {
                required: vec![AuthFactorId::Password],
                additional_required: 1,
            }),
            &CryptoConfig::default(),
        )
        .unwrap();

        let json = serde_json::to_string(&meta).unwrap();
        let parsed: VaultMetadata = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.auth_policy, AuthCombineMode::Policy(_)));
    }
}
