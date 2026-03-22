//! BLAKE3 key derivation for the multi-layer key hierarchy.
//!
//! Uses BLAKE3's built-in `derive_key` mode (KDF) which provides the same
//! extract-then-expand semantics as HKDF but with BLAKE3's performance
//! (5-14x faster than SHA-256, hardware-accelerated via AVX2/AVX512/NEON).
//!
//! Key hierarchy (ADR-SEC-002):
//!   User password → Argon2id → Master Key (32 bytes)
//!     → BLAKE3 derive_key → per-profile vault key (encrypts SQLCipher DB)
//!     → BLAKE3 derive_key → per-profile clipboard key (zeroed on profile deactivation)
//!     → BLAKE3 derive_key → per-profile IPC authentication token
//!
//! Domain separation is achieved via BLAKE3's context string parameter,
//! which is hardcoded per purpose and concatenated with the profile ID.

use crate::SecureBytes;
use core_types::HkdfAlgorithm;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Derive a 32-byte key using BLAKE3's KDF mode.
///
/// The `context` string provides domain separation per RFC-style conventions.
/// BLAKE3 internally derives a context key from the context string, then
/// uses it to key the hash of the input keying material.
///
/// Returns `SecureBytes` (mlock'd, zeroize-on-drop). The intermediate stack
/// array is zeroized before the function returns.
fn derive_32(context: &str, ikm: &[u8]) -> SecureBytes {
    let key = zeroize::Zeroizing::new(blake3::derive_key(context, ikm));
    SecureBytes::new(key.to_vec())
}

/// Build the BLAKE3 context string: `"pds <version> <purpose> <profile_id>"`.
///
/// Context strings should be globally unique and hardcoded per the BLAKE3
/// spec. We include the version for forward compatibility with key rotation.
fn build_context(purpose: &str, profile_id: &str) -> String {
    format!("pds v2 {purpose} {profile_id}")
}

/// Derive the per-profile vault key for SQLCipher database encryption.
///
/// Returns 32 bytes wrapped in `SecureBytes` (mlock'd, zeroize-on-drop).
pub fn derive_vault_key(master_key: &[u8], profile_id: &str) -> SecureBytes {
    let ctx = build_context("vault-key", profile_id);
    derive_32(&ctx, master_key)
}

/// Derive the per-profile clipboard encryption key.
///
/// This key is zeroed on profile deactivation (ADR-SEC-002).
/// Returns 32 bytes wrapped in `SecureBytes`.
pub fn derive_clipboard_key(master_key: &[u8], profile_id: &str) -> SecureBytes {
    let ctx = build_context("clipboard-key", profile_id);
    derive_32(&ctx, master_key)
}

/// Derive the per-profile IPC authentication token.
///
/// Used to authenticate IPC messages between daemons for a specific profile.
/// Returns 32 bytes wrapped in `SecureBytes`.
pub fn derive_ipc_auth_token(master_key: &[u8], profile_id: &str) -> SecureBytes {
    let ctx = build_context("ipc-auth-token", profile_id);
    derive_32(&ctx, master_key)
}

/// Derive the per-profile IPC encryption key (ADR-SEC-006).
///
/// Used for defense-in-depth per-field encryption of secret values on the
/// IPC bus, layered ON TOP of Noise IK transport encryption. Even if the
/// transport layer is somehow compromised, individual secret values remain
/// encrypted with a key derived from the master key.
///
/// Returns 32 bytes suitable for AES-256-GCM.
pub fn derive_ipc_encryption_key(master_key: &[u8], profile_id: &str) -> SecureBytes {
    let ctx = build_context("ipc-encryption-key", profile_id);
    derive_32(&ctx, master_key)
}

/// Derive the key-encrypting-key (KEK) for platform keyring storage.
///
/// ADR-SEC-001: The KEK wraps (AES-256-GCM encrypts) the master key before
/// storing it in the platform keyring. The KEK is derived from the user's
/// password + salt via BLAKE3, using a context string that is cryptographically
/// independent from the Argon2id master key derivation path.
///
/// This ensures the raw master key NEVER touches the platform keyring.
/// The keyring blob is: `[12-byte random nonce][AES-256-GCM ciphertext+tag]`
pub fn derive_kek(password: &[u8], salt: &[u8]) -> SecureBytes {
    // Concatenate password and salt as IKM. The BLAKE3 context string
    // provides domain separation from all other derivations.
    let mut ikm = Vec::with_capacity(password.len() + salt.len());
    ikm.extend_from_slice(password);
    ikm.extend_from_slice(salt);
    let key = derive_32("pds v2 key-encrypting-key", &ikm);
    // Zeroize the concatenated IKM before it goes out of scope.
    ikm.zeroize();
    key
}

/// Derive an arbitrary per-purpose key with a custom context string.
///
/// For extensibility — new key purposes can be added without modifying
/// this module. Callers must ensure `purpose` is globally unique.
pub fn derive_key(master_key: &[u8], purpose: &str, profile_id: &str) -> SecureBytes {
    let ctx = build_context(purpose, profile_id);
    derive_32(&ctx, master_key)
}

// ============================================================================
// HKDF-SHA256 alternatives
// ============================================================================

/// Derive a 32-byte key using HKDF-SHA256 (extract-then-expand).
///
/// The `context` string is used as the HKDF info parameter for domain separation.
/// The IKM serves as both the HKDF input keying material and implicit salt.
fn derive_32_hkdf_sha256(context: &str, ikm: &[u8]) -> SecureBytes {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; 32];
    hk.expand(context.as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let result = SecureBytes::new(key.to_vec());
    key.zeroize();
    result
}

/// Derive the per-profile vault key using the specified HKDF algorithm.
pub fn derive_vault_key_with_algorithm(
    algorithm: &HkdfAlgorithm,
    master_key: &[u8],
    profile_id: &str,
) -> SecureBytes {
    let ctx = build_context("vault-key", profile_id);
    match algorithm {
        HkdfAlgorithm::Blake3 => derive_32(&ctx, master_key),
        HkdfAlgorithm::HkdfSha256 => derive_32_hkdf_sha256(&ctx, master_key),
    }
}

/// Derive the per-profile clipboard key using the specified HKDF algorithm.
pub fn derive_clipboard_key_with_algorithm(
    algorithm: &HkdfAlgorithm,
    master_key: &[u8],
    profile_id: &str,
) -> SecureBytes {
    let ctx = build_context("clipboard-key", profile_id);
    match algorithm {
        HkdfAlgorithm::Blake3 => derive_32(&ctx, master_key),
        HkdfAlgorithm::HkdfSha256 => derive_32_hkdf_sha256(&ctx, master_key),
    }
}

/// Derive the per-profile IPC auth token using the specified HKDF algorithm.
pub fn derive_ipc_auth_token_with_algorithm(
    algorithm: &HkdfAlgorithm,
    master_key: &[u8],
    profile_id: &str,
) -> SecureBytes {
    let ctx = build_context("ipc-auth-token", profile_id);
    match algorithm {
        HkdfAlgorithm::Blake3 => derive_32(&ctx, master_key),
        HkdfAlgorithm::HkdfSha256 => derive_32_hkdf_sha256(&ctx, master_key),
    }
}

/// Derive the per-profile IPC encryption key using the specified HKDF algorithm.
pub fn derive_ipc_encryption_key_with_algorithm(
    algorithm: &HkdfAlgorithm,
    master_key: &[u8],
    profile_id: &str,
) -> SecureBytes {
    let ctx = build_context("ipc-encryption-key", profile_id);
    match algorithm {
        HkdfAlgorithm::Blake3 => derive_32(&ctx, master_key),
        HkdfAlgorithm::HkdfSha256 => derive_32_hkdf_sha256(&ctx, master_key),
    }
}

/// Derive an arbitrary per-purpose key using the specified HKDF algorithm.
pub fn derive_key_with_algorithm(
    algorithm: &HkdfAlgorithm,
    master_key: &[u8],
    purpose: &str,
    profile_id: &str,
) -> SecureBytes {
    let ctx = build_context(purpose, profile_id);
    match algorithm {
        HkdfAlgorithm::Blake3 => derive_32(&ctx, master_key),
        HkdfAlgorithm::HkdfSha256 => derive_32_hkdf_sha256(&ctx, master_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    fn test_master_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    #[test]
    fn vault_key_is_32_bytes() {
        let mk = test_master_key();
        let vk = derive_vault_key(&mk, "profile-1");
        assert_eq!(vk.len(), 32);
    }

    #[test]
    fn deterministic_derivation() {
        let mk = test_master_key();
        let k1 = derive_vault_key(&mk, "profile-1");
        let k2 = derive_vault_key(&mk, "profile-1");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_profiles_produce_different_keys() {
        let mk = test_master_key();
        let k1 = derive_vault_key(&mk, "profile-1");
        let k2 = derive_vault_key(&mk, "profile-2");
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_purposes_produce_different_keys() {
        let mk = test_master_key();
        let pid = "profile-1";
        let vault = derive_vault_key(&mk, pid);
        let clip = derive_clipboard_key(&mk, pid);
        let ipc_auth = derive_ipc_auth_token(&mk, pid);
        let ipc_enc = derive_ipc_encryption_key(&mk, pid);
        assert_ne!(vault.as_bytes(), clip.as_bytes());
        assert_ne!(vault.as_bytes(), ipc_auth.as_bytes());
        assert_ne!(vault.as_bytes(), ipc_enc.as_bytes());
        assert_ne!(clip.as_bytes(), ipc_auth.as_bytes());
        assert_ne!(clip.as_bytes(), ipc_enc.as_bytes());
        assert_ne!(ipc_auth.as_bytes(), ipc_enc.as_bytes());
    }

    #[test]
    fn different_master_keys_produce_different_derived_keys() {
        let mut mk1 = test_master_key();
        let mut mk2 = test_master_key();
        mk2[0] = 0xFF;
        let k1 = derive_vault_key(&mk1, "profile-1");
        let k2 = derive_vault_key(&mk2, "profile-1");
        assert_ne!(k1.as_bytes(), k2.as_bytes());
        mk1.zeroize();
        mk2.zeroize();
    }

    #[test]
    fn custom_purpose_derivation() {
        let mk = test_master_key();
        let k = derive_key(&mk, "custom-purpose-v1", "profile-1");
        assert_eq!(k.len(), 32);
        let vault = derive_vault_key(&mk, "profile-1");
        assert_ne!(k.as_bytes(), vault.as_bytes());
    }

    #[test]
    fn end_to_end_argon2_then_blake3_then_encrypt() {
        let password = b"master-password";
        let salt = [0xAA; 16];
        let master_key = crate::derive_key_argon2(password, &salt).unwrap();

        let vault_key = derive_vault_key(master_key.as_bytes(), "work");
        let enc_key =
            crate::EncryptionKey::from_bytes(vault_key.as_bytes().try_into().unwrap()).unwrap();

        let nonce = [0x01; 12];
        let plaintext = b"database encryption key material";
        let ct = enc_key.encrypt(&nonce, plaintext).unwrap();
        let pt = enc_key.decrypt(&nonce, &ct).unwrap();
        assert_eq!(pt.as_bytes(), plaintext);
    }

    #[test]
    fn blake3_and_hkdf_sha256_produce_different_keys() {
        let mk = test_master_key();
        let pid = "profile-1";
        let blake3_key = derive_vault_key_with_algorithm(&HkdfAlgorithm::Blake3, &mk, pid);
        let sha256_key = derive_vault_key_with_algorithm(&HkdfAlgorithm::HkdfSha256, &mk, pid);
        assert_ne!(
            blake3_key.as_bytes(),
            sha256_key.as_bytes(),
            "BLAKE3 and HKDF-SHA256 must produce different keys for the same inputs"
        );
    }

    #[test]
    fn hkdf_sha256_deterministic() {
        let mk = test_master_key();
        let k1 = derive_vault_key_with_algorithm(&HkdfAlgorithm::HkdfSha256, &mk, "profile-1");
        let k2 = derive_vault_key_with_algorithm(&HkdfAlgorithm::HkdfSha256, &mk, "profile-1");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hkdf_sha256_different_profiles_different_keys() {
        let mk = test_master_key();
        let k1 = derive_vault_key_with_algorithm(&HkdfAlgorithm::HkdfSha256, &mk, "profile-1");
        let k2 = derive_vault_key_with_algorithm(&HkdfAlgorithm::HkdfSha256, &mk, "profile-2");
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn dispatch_with_algorithm_matches_direct() {
        let mk = test_master_key();
        let direct = derive_vault_key(&mk, "profile-1");
        let dispatched = derive_vault_key_with_algorithm(&HkdfAlgorithm::Blake3, &mk, "profile-1");
        assert_eq!(direct.as_bytes(), dispatched.as_bytes());
    }

    #[test]
    fn clone_secure_bytes_independence() {
        let mk = test_master_key();
        let k1 = derive_vault_key(&mk, "profile-1");
        let k2 = k1.clone();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
        drop(k1);
        assert_eq!(k2.len(), 32);
    }
}
