//! Key derivation from key material: every 32-byte key derived from a
//! master key, a vault key, a salt, a signature, or factor pieces.
//!
//! One derivation under the vault's [`HkdfAlgorithm`]:
//! - `Blake3`: BLAKE3 `derive_key` with the context string;
//! - `HkdfSha256`: HKDF-SHA256 (RFC 5869) with no salt and the context
//!   string as `info`.
//!
//! [`derive_key`] returns the key as bytes (a `SQLCipher` page key, a
//! challenge, a master key); [`derive_encryption_key`] returns it as an
//! AES-256-GCM key for a key that only encrypts.
//!
//! The context is a [`KeyContext`]: one variant per purpose, scoped to a
//! profile where the purpose is per-profile. Its string is
//! `"pds v2 <purpose>[ <profile>]"`.

use crate::{EncryptionKey, SecureBytes};
use core_types::{HkdfAlgorithm, TrustProfileName};
use zeroize::Zeroizing;

/// What a key is derived for: the domain-separating context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyContext<'a> {
    /// A profile's `SQLCipher` page key, from its master key.
    Vault(&'a TrustProfileName),
    /// A profile's per-field IPC encryption key, from its master key.
    IpcEncryption(&'a TrustProfileName),
    /// An `All`-policy vault's master key, from its factor pieces.
    CombinedMasterKey(&'a TrustProfileName),
    /// The challenge an SSH agent signs for a profile, from its salt.
    SshChallenge(&'a TrustProfileName),
    /// The KEK of a profile's SSH enrollment, from the challenge signature.
    SshVaultKek(&'a TrustProfileName),
    /// The per-entry AES-256-GCM key of a vault database, from its page key.
    SqlCipherEntry,
}

impl KeyContext<'_> {
    /// The context string: `"pds v2 <purpose>"`, followed by the profile
    /// for a per-profile purpose.
    fn string(&self) -> String {
        let (purpose, profile) = match self {
            Self::Vault(p) => ("vault-key", Some(p)),
            Self::IpcEncryption(p) => ("ipc-encryption-key", Some(p)),
            Self::CombinedMasterKey(p) => ("combined-master-key", Some(p)),
            Self::SshChallenge(p) => ("ssh-challenge", Some(p)),
            Self::SshVaultKek(p) => ("ssh-vault-kek", Some(p)),
            Self::SqlCipherEntry => ("entry-encryption-key", None),
        };
        match profile {
            Some(profile) => format!("pds v2 {purpose} {profile}"),
            None => format!("pds v2 {purpose}"),
        }
    }
}

/// The 32-byte key for `context` derived from `ikm` under `algorithm`.
fn derive(algorithm: HkdfAlgorithm, context: &KeyContext<'_>, ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let context = context.string();
    match algorithm {
        HkdfAlgorithm::Blake3 => Zeroizing::new(blake3::derive_key(&context, ikm)),
        HkdfAlgorithm::HkdfSha256 => {
            let mut key = Zeroizing::new([0u8; 32]);
            hkdf::Hkdf::<sha2::Sha256>::new(None, ikm)
                .expand(context.as_bytes(), &mut *key)
                .expect("32 bytes is within the HKDF-SHA256 output limit of 8160");
            key
        }
    }
}

/// The 32-byte key for `context` derived from `ikm` under `algorithm`,
/// in protected memory (mlock'd, zeroized on drop).
///
/// # Panics
///
/// Never: HKDF-SHA256 expands to at most 8160 bytes, and the key is 32.
#[must_use]
pub fn derive_key(algorithm: HkdfAlgorithm, context: &KeyContext<'_>, ikm: &[u8]) -> SecureBytes {
    let key = derive(algorithm, context, ikm);
    SecureBytes::from_slice(&*key)
}

/// [`derive_key`] as an AES-256-GCM key, for a key that only encrypts.
///
/// # Panics
///
/// Never: HKDF-SHA256 expands to at most 8160 bytes, and the key is 32.
#[must_use]
pub fn derive_encryption_key(
    algorithm: HkdfAlgorithm,
    context: &KeyContext<'_>,
    ikm: &[u8],
) -> EncryptionKey {
    let key = derive(algorithm, context, ikm);
    EncryptionKey::from_bytes(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHMS: [HkdfAlgorithm; 2] = [HkdfAlgorithm::Blake3, HkdfAlgorithm::HkdfSha256];
    const IKM: [u8; 32] = [7; 32];

    fn profile(name: &str) -> TrustProfileName {
        TrustProfileName::try_from(name).unwrap()
    }

    #[test]
    fn contexts_are_the_documented_strings() {
        let work = profile("work");
        for (context, string) in [
            (KeyContext::Vault(&work), "pds v2 vault-key work"),
            (
                KeyContext::IpcEncryption(&work),
                "pds v2 ipc-encryption-key work",
            ),
            (
                KeyContext::CombinedMasterKey(&work),
                "pds v2 combined-master-key work",
            ),
            (KeyContext::SshChallenge(&work), "pds v2 ssh-challenge work"),
            (KeyContext::SshVaultKek(&work), "pds v2 ssh-vault-kek work"),
            (KeyContext::SqlCipherEntry, "pds v2 entry-encryption-key"),
        ] {
            assert_eq!(context.string(), string);
        }
    }

    #[test]
    fn blake3_is_derive_key_with_the_context() {
        let work = profile("work");
        assert_eq!(
            derive_key(HkdfAlgorithm::Blake3, &KeyContext::Vault(&work), &IKM).as_bytes(),
            &blake3::derive_key("pds v2 vault-key work", &IKM)
        );
    }

    #[test]
    fn hkdf_sha256_is_rfc5869_with_the_context_as_info() {
        let work = profile("work");
        let mut expected = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &IKM)
            .expand(b"pds v2 vault-key work", &mut expected)
            .unwrap();
        assert_eq!(
            derive_key(HkdfAlgorithm::HkdfSha256, &KeyContext::Vault(&work), &IKM).as_bytes(),
            &expected
        );
    }

    #[test]
    fn algorithms_profiles_purposes_and_inputs_separate_keys() {
        let (work, home) = (profile("work"), profile("home"));
        let keys = [
            derive_key(HkdfAlgorithm::Blake3, &KeyContext::Vault(&work), &IKM),
            derive_key(HkdfAlgorithm::HkdfSha256, &KeyContext::Vault(&work), &IKM),
            derive_key(HkdfAlgorithm::Blake3, &KeyContext::Vault(&home), &IKM),
            derive_key(
                HkdfAlgorithm::Blake3,
                &KeyContext::IpcEncryption(&work),
                &IKM,
            ),
            derive_key(HkdfAlgorithm::Blake3, &KeyContext::Vault(&work), &[8; 32]),
        ];
        for (i, a) in keys.iter().enumerate() {
            assert_eq!(a.len(), 32);
            for b in &keys[i + 1..] {
                assert_ne!(a.as_bytes(), b.as_bytes());
            }
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let work = profile("work");
        for algorithm in ALGORITHMS {
            let a = derive_key(algorithm, &KeyContext::SshVaultKek(&work), &IKM);
            let b = derive_key(algorithm, &KeyContext::SshVaultKek(&work), &IKM);
            assert_eq!(a.as_bytes(), b.as_bytes());
        }
    }

    #[test]
    fn encryption_keys_are_the_derived_keys() {
        let work = profile("work");
        for algorithm in ALGORITHMS {
            let context = KeyContext::SshVaultKek(&work);
            let bytes = derive_key(algorithm, &context, &IKM);
            let expected = EncryptionKey::from_bytes(bytes.as_bytes().try_into().unwrap());
            let sealed = derive_encryption_key(algorithm, &context, &IKM)
                .encrypt(&[1; 12], b"secret")
                .unwrap();
            assert_eq!(
                expected.decrypt(&[1; 12], &sealed).unwrap().as_bytes(),
                b"secret"
            );
        }
    }
}
