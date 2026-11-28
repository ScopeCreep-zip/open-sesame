//! Per-profile key-derivation salt (`Layout::vault_file(profile,
//! VaultFile::Salt)`): the only reader and writer of salt files.

use crate::AuthError;
use core_layout::{Layout, VaultFile};
use core_types::TrustProfileName;

/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// The profile's salt, or `None` when the profile has none yet.
///
/// # Errors
///
/// The layout errors, an unreadable salt file, and
/// `AuthError::InvalidVaultFile` for a salt file that is not exactly
/// [`SALT_LEN`] bytes.
pub fn load(
    layout: &Layout,
    profile: &TrustProfileName,
) -> Result<Option<[u8; SALT_LEN]>, AuthError> {
    let path = layout.vault_file(profile, VaultFile::Salt)?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AuthError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read salt {}: {e}", path.display()),
            )));
        }
    };
    let len = bytes.len();
    bytes.try_into().map(Some).map_err(|_| {
        AuthError::InvalidVaultFile(format!(
            "salt {} is {len} bytes, expected {SALT_LEN}",
            path.display()
        ))
    })
}

/// The salt of `profile`'s initialized vault.
///
/// # Errors
///
/// The [`load`] errors, and `AuthError::NotInitialized` when the profile has
/// no salt (its vault was never initialized).
pub fn require(layout: &Layout, profile: &TrustProfileName) -> Result<[u8; SALT_LEN], AuthError> {
    load(layout, profile)?.ok_or_else(|| AuthError::NotInitialized(profile.to_string()))
}

/// Generate a random salt for `profile` and persist it owner-only.
///
/// # Errors
///
/// The layout errors, a random-source failure, and [`AuthError::Write`].
/// `PublishedNotDurable` leaves the generated salt published and stops
/// initialization; callers must not regenerate or remove it on that error.
pub fn create(layout: &Layout, profile: &TrustProfileName) -> Result<[u8; SALT_LEN], AuthError> {
    let salt = core_crypto::random_bytes::<SALT_LEN>()?;
    core_layout::file::write(
        &layout.vault_file(profile, VaultFile::Salt)?,
        &salt,
        core_layout::file::Mode::OwnerOnly,
    )?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{layout, test_profile};

    #[test]
    fn absent_salt_is_none() {
        let (_root, layout) = layout();
        assert_eq!(load(&layout, &test_profile()).unwrap(), None);
    }

    #[test]
    fn a_required_salt_must_exist() {
        let (_root, layout) = layout();
        assert!(matches!(
            require(&layout, &test_profile()),
            Err(AuthError::NotInitialized(p)) if p == "test-profile"
        ));
        let salt = create(&layout, &test_profile()).unwrap();
        assert_eq!(require(&layout, &test_profile()).unwrap(), salt);
    }

    #[test]
    fn created_salt_loads_back_owner_only() {
        let (_root, layout) = layout();
        let salt = create(&layout, &test_profile()).unwrap();
        assert_eq!(load(&layout, &test_profile()).unwrap(), Some(salt));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = layout.vault_file(&test_profile(), VaultFile::Salt).unwrap();
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn wrong_length_salt_is_an_error() {
        let (_root, layout) = layout();
        let path = layout.vault_file(&test_profile(), VaultFile::Salt).unwrap();
        core_layout::file::write(&path, &[0u8; 15], core_layout::file::Mode::OwnerOnly).unwrap();
        let err = load(&layout, &test_profile()).unwrap_err();
        assert!(matches!(err, AuthError::InvalidVaultFile(_)), "{err:?}");
        let err = err.to_string();
        assert!(err.contains("15 bytes"), "{err}");
        assert!(!err.contains("enrollment blob"), "{err}");
    }
}
