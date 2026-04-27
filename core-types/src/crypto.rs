use serde::{Deserialize, Serialize};

/// Key derivation function algorithm for master password -> master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum KdfAlgorithm {
    /// Argon2id with memory-hard parameters. Leading-edge default.
    #[default]
    Argon2id,
    /// PBKDF2-SHA256 with 600K iterations. NIST/FedRAMP-compatible.
    Pbkdf2Sha256,
}

/// HKDF algorithm for master key -> vault key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum HkdfAlgorithm {
    /// BLAKE3 keyed derivation. Leading-edge default.
    #[default]
    Blake3,
    /// HKDF-SHA256. NIST/FedRAMP-compatible.
    HkdfSha256,
}

/// Noise protocol cipher suite selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum NoiseCipher {
    /// ChaCha20-Poly1305. Leading-edge default.
    #[default]
    ChaChaPoly,
    /// AES-256-GCM. NIST/FedRAMP-compatible.
    AesGcm,
}

/// Noise protocol hash function selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum NoiseHash {
    /// BLAKE2s. Leading-edge default.
    #[default]
    Blake2s,
    /// SHA-256. NIST/FedRAMP-compatible.
    Sha256,
}

/// Network transport AEAD algorithm selection.
///
/// Independent of local IPC Noise cipher (`NoiseCipher`). The network layer
/// uses `aws-lc-rs` primitives; local IPC uses `snow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum NetworkAead {
    /// ChaCha20-Poly1305. Leading-edge default for Noise XX.
    #[default]
    ChaChaPoly,
    /// AES-256-GCM. NIST/FedRAMP-compatible.
    AesGcm,
}

/// Network transport hash algorithm selection.
///
/// Independent of local IPC Noise hash (`NoiseHash`). Selects the hash
/// function for the Noise XX handshake over the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum NetworkHash {
    /// BLAKE2b-512. Leading-edge default for Noise XX.
    #[default]
    Blake2b,
    /// SHA-256. NIST/FedRAMP-compatible.
    Sha256,
}

/// Network transport KEM algorithm selection.
///
/// Selects the key encapsulation mechanism for the Noise XX handshake.
/// Hybrid PQ is the recommended default for secrets managers to defend
/// against harvest-now-decrypt-later attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum NetworkKem {
    /// X25519 only. Classical ECDH.
    X25519,
    /// X25519 + ML-KEM-768 hybrid (X-Wing construction). PQ-resistant default.
    #[default]
    XWing,
    /// ML-KEM-768 only. Post-quantum, no classical fallback.
    MlKem768,
}

/// Hash algorithm for audit log chain integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum AuditHash {
    /// BLAKE3. Leading-edge default.
    #[default]
    Blake3,
    /// SHA-256. NIST/FedRAMP-compatible.
    Sha256,
}

/// Pre-defined cryptographic algorithm profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum CryptoProfile {
    /// Modern algorithms: Argon2id, BLAKE3, ChaCha20-Poly1305, BLAKE2s.
    #[default]
    LeadingEdge,
    /// NIST/FedRAMP-compatible: PBKDF2-SHA256, HKDF-SHA256, AES-GCM, SHA-256.
    GovernanceCompatible,
    /// Individual algorithm selection via `CryptoConfig` fields.
    Custom,
}

/// Complete cryptographic algorithm configuration.
///
/// Determines which algorithms are used for key derivation, HKDF, Noise
/// transport, and audit hashing. `CryptoProfile::LeadingEdge` is the default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub kdf: KdfAlgorithm,
    pub hkdf: HkdfAlgorithm,
    pub noise_cipher: NoiseCipher,
    pub noise_hash: NoiseHash,
    pub audit_hash: AuditHash,
    /// Network transport KEM. Hybrid PQ default for harvest-now-decrypt-later defence.
    pub network_kem: NetworkKem,
    /// Network transport AEAD. Independent of local IPC Noise cipher.
    pub network_aead: NetworkAead,
    /// Network transport hash. Independent of local IPC Noise hash.
    pub network_hash: NetworkHash,
    /// Minimum crypto profile accepted from federation peers.
    pub minimum_peer_profile: CryptoProfile,
}
