//! Password-based key derivation: a password and a vault's salt to the
//! vault's password KEK, under the vault's [`KdfAlgorithm`].

use crate::EncryptionKey;
use argon2::{Algorithm, Argon2, Params, Version};
use core_types::KdfAlgorithm;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The AES-256-GCM key derived from `password` and `salt` under
/// `algorithm`:
/// - `Argon2id`: Argon2id v1.3, 19 MiB memory, 2 iterations, 1 lane
///   (OWASP minimum);
/// - `Pbkdf2Sha256`: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP).
///
/// # Errors
///
/// `core_types::Error::Crypto` when Argon2id rejects its parameters or
/// fails to hash.
pub fn derive_password_key(
    algorithm: KdfAlgorithm,
    password: &[u8],
    salt: &[u8; 16],
) -> core_types::Result<EncryptionKey> {
    let key = derive(algorithm, password, salt)?;
    Ok(EncryptionKey::from_bytes(&key))
}

/// The 32-byte key derived from `password` and `salt` under `algorithm`.
fn derive(
    algorithm: KdfAlgorithm,
    password: &[u8],
    salt: &[u8; 16],
) -> core_types::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    match algorithm {
        KdfAlgorithm::Argon2id => {
            let params = Params::new(19_456, 2, 1, Some(32))
                .map_err(|e| core_types::Error::Crypto(format!("argon2 params error: {e}")))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password, salt, &mut *key)
                .map_err(|e| core_types::Error::Crypto(format!("argon2 derivation failed: {e}")))?;
        }
        KdfAlgorithm::Pbkdf2Sha256 => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, 600_000, &mut *key);
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHMS: [KdfAlgorithm; 2] = [KdfAlgorithm::Argon2id, KdfAlgorithm::Pbkdf2Sha256];

    fn key(algorithm: KdfAlgorithm, password: &[u8], salt: u8) -> [u8; 32] {
        *derive(algorithm, password, &[salt; 16]).unwrap()
    }

    #[test]
    fn keys_are_deterministic() {
        for algorithm in ALGORITHMS {
            assert_eq!(
                key(algorithm, b"password", 0xAA),
                key(algorithm, b"password", 0xAA)
            );
        }
    }

    #[test]
    fn passwords_salts_and_algorithms_separate_keys() {
        for algorithm in ALGORITHMS {
            let base = key(algorithm, b"password1", 0xCC);
            assert_ne!(base, key(algorithm, b"password2", 0xCC));
            assert_ne!(base, key(algorithm, b"password1", 0xDD));
        }
        assert_ne!(
            key(KdfAlgorithm::Argon2id, b"password", 0xEE),
            key(KdfAlgorithm::Pbkdf2Sha256, b"password", 0xEE)
        );
    }

    #[test]
    fn pbkdf2_is_the_rfc8018_construction() {
        let mut expected = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"password", &[0xBB; 16], 600_000, &mut expected);
        assert_eq!(key(KdfAlgorithm::Pbkdf2Sha256, b"password", 0xBB), expected);
    }

    #[test]
    fn derived_key_does_not_contain_password_bytes() {
        let password = b"hunter2";
        let derived = key(KdfAlgorithm::Argon2id, password, 0xAA);
        for window in derived.windows(password.len()) {
            assert_ne!(
                window, password,
                "derived key must not contain plaintext password bytes"
            );
        }
        // Strong avalanche: one changed character changes most bytes.
        let other = key(KdfAlgorithm::Argon2id, b"hunter3", 0xAA);
        let diff_count = derived.iter().zip(&other).filter(|(a, b)| a != b).count();
        assert!(
            diff_count > 24,
            "Argon2id should exhibit strong avalanche: expected >24 differing bytes, got {diff_count}"
        );
    }

    #[test]
    fn password_keys_are_the_derived_keys() {
        for algorithm in ALGORITHMS {
            let sealed = derive_password_key(algorithm, b"my-vault-password", &[0xFF; 16])
                .unwrap()
                .encrypt(&[0x01; 12], b"vault secret entry")
                .unwrap();
            let expected = EncryptionKey::from_bytes(&key(algorithm, b"my-vault-password", 0xFF));
            assert_eq!(
                expected.decrypt(&[0x01; 12], &sealed).unwrap().as_bytes(),
                b"vault secret entry"
            );
        }
    }
}
