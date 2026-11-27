//! A wrapped master key: the vault's master key sealed with AES-256-GCM
//! under a factor's KEK, in one of the vault files that holds such a key
//! (`VaultFile::PasswordWrap`, the password KEK; `VaultFile::KeyringEnrollment`,
//! the platform keyring's KEK).
//!
//! Binary format:
//! ```text
//! Version byte (1 byte): 0x01
//! Nonce (12 bytes): random
//! Ciphertext + GCM tag (48 bytes): AES-256-GCM(KEK, master_key)
//! ```
//!
//! Total: 61 bytes.

use crate::AuthError;
use core_crypto::{EncryptionKey, NONCE_LEN, SecureBytes, TAG_LEN};
use core_layout::{Layout, VaultFile};
use core_types::TrustProfileName;
use std::path::PathBuf;

/// Version of the wrapped-key format.
pub const WRAPPED_KEY_VERSION: u8 = 0x01;

/// Expected ciphertext length: 32-byte master key + 16-byte GCM tag.
const CIPHERTEXT_LEN: usize = 32 + TAG_LEN;

/// Total blob size: version, nonce, ciphertext.
const BLOB_LEN: usize = 1 + NONCE_LEN + CIPHERTEXT_LEN;

/// A wrapped master key.
pub struct WrappedKey {
    nonce: [u8; NONCE_LEN],
    /// 32 bytes master key + 16 bytes GCM tag.
    ciphertext: Vec<u8>,
}

impl WrappedKey {
    /// Serialize to the binary format.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(BLOB_LEN);
        buf.push(WRAPPED_KEY_VERSION);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from the binary format.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidBlob` if the data is not [`BLOB_LEN`]
    /// bytes or has an unsupported version.
    pub fn deserialize(data: &[u8]) -> Result<Self, AuthError> {
        let Some((&version, rest)) = data.split_first() else {
            return Err(Self::wrong_length(data));
        };
        let Some((nonce, ciphertext)) = rest.split_first_chunk::<NONCE_LEN>() else {
            return Err(Self::wrong_length(data));
        };
        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(Self::wrong_length(data));
        }
        if version != WRAPPED_KEY_VERSION {
            return Err(AuthError::InvalidBlob(format!(
                "unsupported wrapped-key version {version:#04x}, expected {WRAPPED_KEY_VERSION:#04x}"
            )));
        }
        Ok(Self {
            nonce: *nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }

    fn wrong_length(data: &[u8]) -> AuthError {
        AuthError::InvalidBlob(format!(
            "wrapped key is {} bytes, expected {BLOB_LEN}",
            data.len()
        ))
    }

    /// Wrap `master_key` under `kek` with a fresh nonce.
    ///
    /// # Errors
    ///
    /// `AuthError::Crypto` when the random nonce or the encryption fails.
    pub fn wrap(master_key: &SecureBytes, kek: &EncryptionKey) -> Result<Self, AuthError> {
        let (nonce, ciphertext) = kek.seal(master_key.as_bytes())?;
        Ok(Self { nonce, ciphertext })
    }

    /// Unwrap the master key with `kek`.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::UnwrapFailed` if the KEK is wrong (GCM auth fails).
    pub fn unwrap(&self, kek: &EncryptionKey) -> Result<SecureBytes, AuthError> {
        kek.decrypt(&self.nonce, &self.ciphertext)
            .map_err(|_| AuthError::UnwrapFailed)
    }

    /// The path of `profile`'s wrapped key in vault file `file`.
    ///
    /// # Errors
    ///
    /// The layout errors.
    pub fn path(
        layout: &Layout,
        profile: &TrustProfileName,
        file: VaultFile,
    ) -> Result<PathBuf, AuthError> {
        Ok(layout.vault_file(profile, file)?)
    }

    /// The wrapped key in `profile`'s vault file `file`, or `None` when the
    /// file does not exist.
    ///
    /// # Errors
    ///
    /// The layout errors, an unreadable file, and the
    /// [`deserialize`](Self::deserialize) errors, each naming the file.
    pub fn load(
        layout: &Layout,
        profile: &TrustProfileName,
        file: VaultFile,
    ) -> Result<Option<Self>, AuthError> {
        let path = Self::path(layout, profile, file)?;
        match std::fs::read(&path) {
            Ok(data) => Self::deserialize(&data)
                .map(Some)
                .map_err(|e| e.in_file(&path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AuthError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read wrapped key {}: {e}", path.display()),
            ))),
        }
    }

    /// Write the wrapped key to `profile`'s vault file `file`, atomically
    /// and owner-only.
    ///
    /// # Errors
    ///
    /// The layout errors, and the `core_layout::file::write` errors.
    pub fn save(
        &self,
        layout: &Layout,
        profile: &TrustProfileName,
        file: VaultFile,
    ) -> Result<(), AuthError> {
        core_layout::file::write(
            &Self::path(layout, profile, file)?,
            &self.serialize(),
            core_layout::file::Mode::OwnerOnly,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master_key() -> SecureBytes {
        SecureBytes::from_slice(&[0x42; 32])
    }

    fn kek(byte: u8) -> EncryptionKey {
        EncryptionKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn round_trip_serialize() {
        let blob = WrappedKey::wrap(&master_key(), &kek(0xDE)).unwrap();
        let data = blob.serialize();
        assert_eq!(data.len(), BLOB_LEN);
        assert_eq!(data[0], WRAPPED_KEY_VERSION);

        let parsed = WrappedKey::deserialize(&data).unwrap();
        assert_eq!(parsed.serialize(), data);
        assert_eq!(parsed.unwrap(&kek(0xDE)).unwrap().as_bytes(), &[0x42; 32]);
    }

    #[test]
    fn rejects_any_other_length() {
        let data = WrappedKey::wrap(&master_key(), &kek(0xDE))
            .unwrap()
            .serialize();
        for len in [0, 10, BLOB_LEN - 1] {
            assert!(matches!(
                WrappedKey::deserialize(&data[..len]),
                Err(AuthError::InvalidBlob(_))
            ));
        }
        let mut long = data;
        long.push(0);
        assert!(matches!(
            WrappedKey::deserialize(&long),
            Err(AuthError::InvalidBlob(_))
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut data = vec![0xFF];
        data.extend_from_slice(&[0u8; NONCE_LEN + CIPHERTEXT_LEN]);
        let result = WrappedKey::deserialize(&data);
        assert!(matches!(result, Err(AuthError::InvalidBlob(_))));
    }

    #[test]
    fn a_malformed_file_is_named_in_its_error() {
        let (_root, layout) = crate::test_support::layout();
        let profile = crate::test_support::test_profile();
        let path = WrappedKey::path(&layout, &profile, VaultFile::KeyringEnrollment).unwrap();
        core_layout::file::write(&path, b"short", core_layout::file::Mode::OwnerOnly).unwrap();
        let err = WrappedKey::load(&layout, &profile, VaultFile::KeyringEnrollment)
            .err()
            .unwrap();
        assert!(matches!(err, AuthError::InvalidBlob(_)), "{err:?}");
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let blob = WrappedKey::wrap(&master_key(), &kek(0xDE)).unwrap();
        assert!(matches!(
            blob.unwrap(&kek(0xAB)),
            Err(AuthError::UnwrapFailed)
        ));
    }

    #[test]
    fn each_vault_file_holds_its_own_wrapped_key() {
        let (_root, layout) = crate::test_support::layout();
        let profile = crate::test_support::test_profile();
        for (file, byte) in [
            (VaultFile::PasswordWrap, 0xDE),
            (VaultFile::KeyringEnrollment, 0xAD),
        ] {
            assert!(WrappedKey::load(&layout, &profile, file).unwrap().is_none());
            WrappedKey::wrap(&master_key(), &kek(byte))
                .unwrap()
                .save(&layout, &profile, file)
                .unwrap();
        }
        for (file, byte) in [
            (VaultFile::PasswordWrap, 0xDE),
            (VaultFile::KeyringEnrollment, 0xAD),
        ] {
            let loaded = WrappedKey::load(&layout, &profile, file).unwrap().unwrap();
            assert_eq!(loaded.unwrap(&kek(byte)).unwrap().as_bytes(), &[0x42; 32]);
        }
    }
}
