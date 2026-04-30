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
    /// Network transport KEM: "x25519" (current), "x-wing" or "ml-kem-768" (future PQ).
    /// Only "x25519" is operational. "x-wing" requires migrating from snow to direct
    /// aws-lc-rs state machine. Config field is parsed but not plumbed to the Noise builder.
    pub network_kem: String,
    /// Network transport AEAD: "chacha-poly" (current) or "aes-gcm" (future).
    /// Config field is parsed but not plumbed to the Noise builder — ChaChaPoly is hardcoded.
    pub network_aead: String,
    /// Network transport hash: "blake2s" (current, snow limitation) or "sha256".
    /// Snow only supports BLAKE2s. "blake2b" requires a custom CryptoResolver or
    /// replacing snow. Config field is parsed but not plumbed to the Noise builder.
    pub network_hash: String,
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
            network_kem: "x25519".into(),
            network_aead: "chacha-poly".into(),
            network_hash: "blake2s".into(),
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
        let network_kem = match self.network_kem.as_str() {
            "x-wing" => core_types::NetworkKem::XWing,
            "x25519" => core_types::NetworkKem::X25519,
            "ml-kem-768" => core_types::NetworkKem::MlKem768,
            other => {
                return Err(core_types::Error::Config(format!(
                    "unknown network_kem: {other}"
                )));
            }
        };
        let network_aead = match self.network_aead.as_str() {
            "chacha-poly" => core_types::NetworkAead::ChaChaPoly,
            "aes-gcm" => core_types::NetworkAead::AesGcm,
            other => {
                return Err(core_types::Error::Config(format!(
                    "unknown network_aead: {other}"
                )));
            }
        };
        let network_hash = match self.network_hash.as_str() {
            "blake2b" => core_types::NetworkHash::Blake2b,
            "sha256" => core_types::NetworkHash::Sha256,
            other => {
                return Err(core_types::Error::Config(format!(
                    "unknown network_hash: {other}"
                )));
            }
        };
        Ok(core_types::CryptoConfig {
            kdf,
            hkdf,
            noise_cipher,
            noise_hash,
            audit_hash,
            network_kem,
            network_aead,
            network_hash,
            minimum_peer_profile,
        })
    }
}
