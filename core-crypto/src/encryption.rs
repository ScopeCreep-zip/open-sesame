//! AES-256-GCM authenticated encryption.
//!
//! Uses RustCrypto aes-gcm (NCC Group audited, CVE-2023-42811 patched in >= 0.10.3).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::secure_bytes::SecureBytes;

/// AES-256-GCM encryption key.
///
/// Wraps a 32-byte key for authenticated encryption/decryption.
pub struct EncryptionKey {
    cipher: Aes256Gcm,
}

impl EncryptionKey {
    /// Create an encryption key from raw 32-byte key material.
    ///
    /// # Errors
    ///
    /// This cannot fail for a correctly-sized key, but returns an error
    /// for API consistency with fallible key derivation paths.
    pub fn from_bytes(key_bytes: &[u8; 32]) -> core_types::Result<Self> {
        Ok(Self {
            cipher: Aes256Gcm::new(key_bytes.into()),
        })
    }

    /// Encrypt plaintext with the given 12-byte nonce.
    ///
    /// Returns ciphertext with appended 16-byte authentication tag.
    ///
    /// # Nonce Safety
    ///
    /// Nonce reuse catastrophically breaks both confidentiality and authenticity.
    /// Callers MUST ensure nonces are unique per encryption with the same key.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (should not happen with valid inputs).
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> core_types::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| core_types::Error::Crypto("encryption failed".into()))
    }

    /// Decrypt ciphertext (with appended tag) using the given 12-byte nonce.
    ///
    /// Returns the plaintext wrapped in `SecureBytes` (mlock'd, zeroize-on-drop).
    ///
    /// # Errors
    ///
    /// Returns an error if the tag does not verify (tampered or wrong key/nonce).
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> core_types::Result<SecureBytes> {
        let nonce = Nonce::from_slice(nonce);
        let plaintext = self.cipher.decrypt(nonce, ciphertext).map_err(|_| {
            core_types::Error::Crypto("decryption failed: tag verification error".into())
        })?;
        Ok(SecureBytes::new(plaintext))
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptionKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0x42;
        key[31] = 0xFF;
        key
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::from_bytes(&test_key()).unwrap();
        let nonce = [1u8; 12];
        let plaintext = b"sensitive data here";

        let ciphertext = key.encrypt(&nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = key.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = EncryptionKey::from_bytes(&test_key()).unwrap();
        let mut wrong_key_bytes = test_key();
        wrong_key_bytes[0] = 0x00;
        let key2 = EncryptionKey::from_bytes(&wrong_key_bytes).unwrap();

        let nonce = [2u8; 12];
        let ciphertext = key1.encrypt(&nonce, b"secret").unwrap();

        let result = key2.decrypt(&nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_with_wrong_nonce_fails() {
        let key = EncryptionKey::from_bytes(&test_key()).unwrap();
        let ciphertext = key.encrypt(&[1u8; 12], b"secret").unwrap();

        let result = key.decrypt(&[2u8; 12], &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = EncryptionKey::from_bytes(&test_key()).unwrap();
        let nonce = [3u8; 12];
        let mut ciphertext = key.encrypt(&nonce, b"secret").unwrap();

        // Flip a bit
        ciphertext[0] ^= 0x01;

        let result = key.decrypt(&nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let key = EncryptionKey::from_bytes(&test_key()).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42"));
    }
}
