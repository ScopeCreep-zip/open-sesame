//! AES-256-GCM authenticated encryption.
//!
//! Uses `RustCrypto` aes-gcm (NCC Group audited, CVE-2023-42811 patched in >= 0.10.3).

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};

use crate::secure_bytes::SecureBytes;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// AES-256-GCM encryption key.
///
/// Wraps a 32-byte key for authenticated encryption/decryption.
pub struct EncryptionKey {
    cipher: Aes256Gcm,
}

impl EncryptionKey {
    /// Create an encryption key from raw 32-byte key material.
    #[must_use]
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key_bytes.into()),
        }
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
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> core_types::Result<Vec<u8>> {
        let nonce: &Nonce<Aes256Gcm> = nonce.into();
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| core_types::Error::Crypto("encryption failed".into()))
    }

    /// Encrypt `plaintext` under a fresh random nonce. Returns the nonce and
    /// the ciphertext with its appended tag; a nonce is never reused.
    ///
    /// # Errors
    ///
    /// The [`crate::random_bytes`] errors, and an encryption failure.
    pub fn seal(&self, plaintext: &[u8]) -> core_types::Result<([u8; NONCE_LEN], Vec<u8>)> {
        let nonce = crate::random_bytes::<NONCE_LEN>()?;
        let ciphertext = self.encrypt(&nonce, plaintext)?;
        Ok((nonce, ciphertext))
    }

    /// [`seal`](Self::seal) as one buffer: `nonce || ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// The [`seal`](Self::seal) errors.
    pub fn seal_wire(&self, plaintext: &[u8]) -> core_types::Result<Vec<u8>> {
        let (nonce, ciphertext) = self.seal(plaintext)?;
        let mut wire = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend(ciphertext);
        Ok(wire)
    }

    /// Decrypt a [`seal_wire`](Self::seal_wire) buffer.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Crypto` when the buffer is shorter than a nonce
    /// and a tag, and the [`decrypt`](Self::decrypt) errors.
    pub fn open_wire(&self, wire: &[u8]) -> core_types::Result<SecureBytes> {
        match wire.split_first_chunk::<NONCE_LEN>() {
            Some((nonce, ciphertext)) if ciphertext.len() >= TAG_LEN => {
                self.decrypt(nonce, ciphertext)
            }
            _ => Err(core_types::Error::Crypto(format!(
                "sealed value is {} bytes, shorter than a nonce and tag ({})",
                wire.len(),
                NONCE_LEN + TAG_LEN
            ))),
        }
    }

    /// Decrypt ciphertext (with appended tag) using the given 12-byte nonce.
    ///
    /// Returns the plaintext wrapped in `SecureBytes` (mlock'd, zeroize-on-drop).
    ///
    /// # Errors
    ///
    /// Returns an error if the tag does not verify (tampered or wrong key/nonce).
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> core_types::Result<SecureBytes> {
        let nonce: &Nonce<Aes256Gcm> = nonce.into();
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
        let key = EncryptionKey::from_bytes(&test_key());
        let nonce = [1u8; 12];
        let plaintext = b"sensitive data here";

        let ciphertext = key.encrypt(&nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = key.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = EncryptionKey::from_bytes(&test_key());
        let mut wrong_key_bytes = test_key();
        wrong_key_bytes[0] = 0x00;
        let key2 = EncryptionKey::from_bytes(&wrong_key_bytes);

        let nonce = [2u8; 12];
        let ciphertext = key1.encrypt(&nonce, b"secret").unwrap();

        let result = key2.decrypt(&nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_with_wrong_nonce_fails() {
        let key = EncryptionKey::from_bytes(&test_key());
        let ciphertext = key.encrypt(&[1u8; 12], b"secret").unwrap();

        let result = key.decrypt(&[2u8; 12], &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = EncryptionKey::from_bytes(&test_key());
        let nonce = [3u8; 12];
        let mut ciphertext = key.encrypt(&nonce, b"secret").unwrap();

        // Flip a bit
        ciphertext[0] ^= 0x01;

        let result = key.decrypt(&nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn sealed_values_open_and_never_share_a_nonce() {
        let key = EncryptionKey::from_bytes(&test_key());
        let a = key.seal_wire(b"secret").unwrap();
        let b = key.seal_wire(b"secret").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_eq!(key.open_wire(&a).unwrap().as_bytes(), b"secret");
        assert_eq!(key.open_wire(&b).unwrap().as_bytes(), b"secret");
    }

    #[test]
    fn short_or_tampered_wire_is_rejected() {
        let key = EncryptionKey::from_bytes(&test_key());
        assert!(key.open_wire(&[0u8; NONCE_LEN + TAG_LEN - 1]).is_err());
        let mut wire = key.seal_wire(b"secret").unwrap();
        *wire.last_mut().unwrap() ^= 1;
        assert!(key.open_wire(&wire).is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let key = EncryptionKey::from_bytes(&test_key());
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42"));
    }
}
