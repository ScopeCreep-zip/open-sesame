//! Key derivation functions.
//!
//! Argon2id for password-based key derivation (OWASP recommended).

use crate::SecureBytes;
use argon2::{Algorithm, Argon2, Params, Version};
use core_types::KdfAlgorithm;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// Derive a 32-byte AES-256 key from a password using Argon2id.
///
/// Parameters follow OWASP minimum recommendations:
/// - Algorithm: Argon2id (hybrid, resists both side-channel and GPU attacks)
/// - Memory: 19,456 KiB (19 MiB)
/// - Iterations: 2
/// - Parallelism: 1
///
/// Returns `SecureBytes` (mlock'd, zeroize-on-drop). The intermediate stack
/// array is zeroized before the function returns.
///
/// # Errors
///
/// Returns an error if Argon2 hashing fails (should not happen with valid params).
pub fn derive_key_argon2(password: &[u8], salt: &[u8; 16]) -> core_types::Result<SecureBytes> {
    let params = Params::new(
        19_456, // m_cost: 19 MiB
        2,      // t_cost: 2 iterations
        1,      // p_cost: 1 lane
        Some(32),
    )
    .map_err(|e| core_types::Error::Crypto(format!("argon2 params error: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| core_types::Error::Crypto(format!("argon2 derivation failed: {e}")))?;

    Ok(SecureBytes::from_slice(&*key))
}

/// Derive a 32-byte key from a password using PBKDF2-HMAC-SHA256.
///
/// Uses 600,000 iterations per OWASP recommendations for PBKDF2-SHA256.
/// Returns `SecureBytes` (mlock'd, zeroize-on-drop).
pub fn derive_key_pbkdf2(password: &[u8], salt: &[u8; 16]) -> core_types::Result<SecureBytes> {
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    pbkdf2::<Hmac<Sha256>>(password, salt, 600_000, &mut *key)
        .map_err(|e| core_types::Error::Crypto(format!("pbkdf2 derivation failed: {e}")))?;

    Ok(SecureBytes::from_slice(&*key))
}

/// Dispatch key derivation based on the configured KDF algorithm.
///
/// Routes to either Argon2id or PBKDF2-SHA256 depending on the algorithm.
pub fn derive_key_kdf(
    algorithm: &KdfAlgorithm,
    password: &[u8],
    salt: &[u8; 16],
) -> core_types::Result<SecureBytes> {
    match algorithm {
        KdfAlgorithm::Argon2id => derive_key_argon2(password, salt),
        KdfAlgorithm::Pbkdf2Sha256 => derive_key_pbkdf2(password, salt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_produces_32_byte_key() {
        let password = b"test-password";
        let salt = [0xAA; 16];
        let key = derive_key_argon2(password, &salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn argon2_deterministic() {
        let password = b"deterministic";
        let salt = [0xBB; 16];
        let key1 = derive_key_argon2(password, &salt).unwrap();
        let key2 = derive_key_argon2(password, &salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn argon2_different_passwords_different_keys() {
        let salt = [0xCC; 16];
        let key1 = derive_key_argon2(b"password1", &salt).unwrap();
        let key2 = derive_key_argon2(b"password2", &salt).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn argon2_different_salts_different_keys() {
        let password = b"same-password";
        let key1 = derive_key_argon2(password, &[0xDD; 16]).unwrap();
        let key2 = derive_key_argon2(password, &[0xEE; 16]).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    // ===== Master Password Never Stored =====

    #[test]
    fn derived_key_does_not_contain_password_bytes() {
        let password = b"hunter2";
        let salt = [0xAA; 16];
        let key = derive_key_argon2(password, &salt).unwrap();

        assert_eq!(key.len(), 32);

        // Password bytes must not appear as a substring in the derived key
        for window in key.as_bytes().windows(password.len()) {
            assert_ne!(
                window, password,
                "derived key must not contain plaintext password bytes"
            );
        }

        // Verify strong avalanche: changing one character produces completely different output
        let key2 = derive_key_argon2(b"hunter3", &salt).unwrap();
        let diff_count = key
            .as_bytes()
            .iter()
            .zip(key2.as_bytes().iter())
            .filter(|(a, b)| a != b)
            .count();

        assert!(
            diff_count > 24,
            "Argon2id should exhibit strong avalanche: expected >24 differing bytes, got {diff_count}"
        );
    }

    #[test]
    fn pbkdf2_produces_32_byte_key() {
        let key = derive_key_pbkdf2(b"test-password", &[0xAA; 16]).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn pbkdf2_deterministic() {
        let k1 = derive_key_pbkdf2(b"deterministic", &[0xBB; 16]).unwrap();
        let k2 = derive_key_pbkdf2(b"deterministic", &[0xBB; 16]).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn pbkdf2_different_passwords_different_keys() {
        let salt = [0xCC; 16];
        let k1 = derive_key_pbkdf2(b"password1", &salt).unwrap();
        let k2 = derive_key_pbkdf2(b"password2", &salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn dispatch_argon2id() {
        let salt = [0xDD; 16];
        let direct = derive_key_argon2(b"test", &salt).unwrap();
        let dispatched = derive_key_kdf(&KdfAlgorithm::Argon2id, b"test", &salt).unwrap();
        assert_eq!(direct.as_bytes(), dispatched.as_bytes());
    }

    #[test]
    fn dispatch_pbkdf2() {
        let salt = [0xEE; 16];
        let direct = derive_key_pbkdf2(b"test", &salt).unwrap();
        let dispatched = derive_key_kdf(&KdfAlgorithm::Pbkdf2Sha256, b"test", &salt).unwrap();
        assert_eq!(direct.as_bytes(), dispatched.as_bytes());
    }

    #[test]
    fn end_to_end_derive_then_encrypt() {
        let password = b"my-vault-password";
        let salt = [0xFF; 16];
        let key = derive_key_argon2(password, &salt).unwrap();

        let enc_key = crate::EncryptionKey::from_bytes(key.as_bytes().try_into().unwrap()).unwrap();
        let nonce = [0x01; 12];
        let plaintext = b"vault secret entry";

        let ciphertext = enc_key.encrypt(&nonce, plaintext).unwrap();
        let decrypted = enc_key.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }
}
