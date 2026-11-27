//! Fixtures shared by the crate's tests.

use crate::vault_meta::{VaultAlgorithms, VaultKeying};
use core_layout::Layout;
use core_types::{HkdfAlgorithm, KdfAlgorithm, TrustProfileName};

/// The profile named `name`.
pub(crate) fn profile(name: &str) -> TrustProfileName {
    TrustProfileName::try_from(name).unwrap()
}

/// The profile most tests operate on.
pub(crate) fn test_profile() -> TrustProfileName {
    profile("test-profile")
}

/// A layout under a fresh temporary root, which lives as long as the
/// returned guard.
pub(crate) fn layout() -> (tempfile::TempDir, Layout) {
    let root = tempfile::tempdir().unwrap();
    let layout = Layout::under(root.path());
    (root, layout)
}

/// Metadata of a vault whose only factor is the password, under the
/// policy `Any` and `crypto`'s algorithms.
pub(crate) fn password_vault(crypto: &core_types::CryptoConfig) -> crate::VaultMetadata {
    crate::VaultMetadata::new(
        vec![(core_types::AuthFactorId::Password, "master password".into())],
        core_types::AuthCombineMode::Any,
        crypto,
    )
    .unwrap()
}

/// A keying of salt bytes `salt` under `kdf` and `hkdf`.
pub(crate) fn keying(salt: u8, kdf: KdfAlgorithm, hkdf: HkdfAlgorithm) -> VaultKeying {
    VaultKeying {
        salt: [salt; crate::salt::SALT_LEN],
        algorithms: VaultAlgorithms { kdf, hkdf },
    }
}
