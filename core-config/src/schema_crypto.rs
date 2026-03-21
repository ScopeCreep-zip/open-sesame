//! Cryptographic algorithm configuration types.
//!
//! String-based TOML representation with `to_typed()` conversion to
//! validated `core_types::CryptoConfig` enum variants.

use serde::{Deserialize, Serialize};

/// TOML-level cryptographic algorithm configuration.
///
/// String-based for human-readable config files. Use `to_typed()` to convert
/// to the validated `core_types::CryptoConfig` with enum variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CryptoConfigToml {
    /// Key derivation function: "argon2id" or "pbkdf2-sha256".
    pub kdf: String,
    /// HKDF algorithm: "blake3" or "hkdf-sha256".
    pub hkdf: String,
    /// Noise cipher: "chacha-poly" or "aes-gcm".
    pub noise_cipher: String,
    /// Noise hash: "blake2s" or "sha256".
    pub noise_hash: String,
    /// Audit hash: "blake3" or "sha256".
    pub audit_hash: String,
    /// Minimum crypto profile accepted from peers: "leading-edge", "governance-compatible", "custom".
    pub minimum_peer_profile: String,
}

impl Default for CryptoConfigToml {
    fn default() -> Self {
        Self {
            kdf: "argon2id".into(),
            hkdf: "blake3".into(),
            noise_cipher: "chacha-poly".into(),
            noise_hash: "blake2s".into(),
            audit_hash: "blake3".into(),
            minimum_peer_profile: "leading-edge".into(),
        }
    }
}

impl CryptoConfigToml {
    /// Convert to the validated typed representation.
    ///
    /// # Errors
    ///
    /// Returns an error if any algorithm name is unrecognized.
    pub fn to_typed(&self) -> core_types::Result<core_types::CryptoConfig> {
        let kdf = match self.kdf.as_str() {
            "argon2id" => core_types::KdfAlgorithm::Argon2id,
            "pbkdf2-sha256" => core_types::KdfAlgorithm::Pbkdf2Sha256,
            other => return Err(core_types::Error::Config(format!("unknown kdf: {other}"))),
        };
        let hkdf = match self.hkdf.as_str() {
            "blake3" => core_types::HkdfAlgorithm::Blake3,
            "hkdf-sha256" => core_types::HkdfAlgorithm::HkdfSha256,
            other => return Err(core_types::Error::Config(format!("unknown hkdf: {other}"))),
        };
        let noise_cipher = match self.noise_cipher.as_str() {
            "chacha-poly" => core_types::NoiseCipher::ChaChaPoly,
            "aes-gcm" => core_types::NoiseCipher::AesGcm,
            other => {
                return Err(core_types::Error::Config(format!(
                    "unknown noise_cipher: {other}"
                )));
            }
        };
        let noise_hash = match self.noise_hash.as_str() {
            "blake2s" => core_types::NoiseHash::Blake2s,
            "sha256" => core_types::NoiseHash::Sha256,
            other => {
                return Err(core_types::Error::Config(format!(
                    "unknown noise_hash: {other}"
                )));
            }
        };
        let audit_hash = match self.audit_hash.as_str() {
            "blake3" => core_types::AuditHash::Blake3,
            "sha256" => core_types::AuditHash::Sha256,
            other => {
                return Err(core_types::Error::Config(format!(
                    "unknown audit_hash: {other}"
                )));
            }
        };
        let minimum_peer_profile = match self.minimum_peer_profile.as_str() {
            "leading-edge" => core_types::CryptoProfile::LeadingEdge,
            "governance-compatible" => core_types::CryptoProfile::GovernanceCompatible,
            "custom" => core_types::CryptoProfile::Custom,
            other => {
                return Err(core_types::Error::Config(format!(
                    "unknown crypto profile: {other}"
                )));
            }
        };
        Ok(core_types::CryptoConfig {
            kdf,
            hkdf,
            noise_cipher,
            noise_hash,
            audit_hash,
            minimum_peer_profile,
        })
    }
}
