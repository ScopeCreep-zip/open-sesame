//! Secure path management for Open Sesame
//!
//! Provides centralized path management with proper permission enforcement.
//! All runtime data goes into ~/.cache/open-sesame/ with 700 permissions.
//! Configuration data uses ~/.config/open-sesame/ via dirs::config_dir().

use crate::util::{Error, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Secure directory permissions (owner read/write/execute only)
const SECURE_DIR_MODE: u32 = 0o700;

/// Returns the open-sesame cache directory, creating with secure permissions if needed.
///
/// Returns ~/.cache/open-sesame/ with 700 permissions.
/// Fails when HOME is not set or directory cannot be created with proper permissions.
///
/// # Security
/// - Never falls back to /tmp or other world-accessible locations
/// - Enforces 700 permissions on the directory
/// - Validates permissions on existing directories
pub fn cache_dir() -> Result<PathBuf> {
    let base = dirs::cache_dir()
        .or_else(|| {
            // Fallback to ~/.cache when XDG_CACHE_HOME not set
            dirs::home_dir().map(|h| h.join(".cache"))
        })
        .ok_or_else(|| {
            Error::Other(
                "Cannot determine cache directory: HOME environment variable not set".to_string(),
            )
        })?;

    let cache_path = base.join("open-sesame");
    ensure_secure_dir(&cache_path)?;
    Ok(cache_path)
}

/// Returns the open-sesame config directory.
///
/// Returns ~/.config/open-sesame/.
/// For COSMIC shortcuts, cosmic_config_dir() provides the appropriate path.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .ok_or_else(|| {
            Error::Other(
                "Cannot determine config directory: HOME environment variable not set".to_string(),
            )
        })?;

    Ok(base.join("open-sesame"))
}

/// Returns the COSMIC shortcuts configuration directory.
///
/// Provides path to COSMIC's custom shortcuts config file.
pub fn cosmic_shortcuts_path() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .ok_or_else(|| {
            Error::Other(
                "Cannot determine config directory: HOME environment variable not set".to_string(),
            )
        })?;

    Ok(base.join("cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom"))
}

/// Returns the lock file path.
///
/// Path: ~/.cache/open-sesame/instance.lock
pub fn lock_file() -> Result<PathBuf> {
    Ok(cache_dir()?.join("instance.lock"))
}

/// Returns the MRU state file path.
///
/// Path: ~/.cache/open-sesame/mru
pub fn mru_file() -> Result<PathBuf> {
    Ok(cache_dir()?.join("mru"))
}

/// Returns the log file path.
///
/// Path: ~/.cache/open-sesame/debug.log
pub fn log_file() -> Result<PathBuf> {
    Ok(cache_dir()?.join("debug.log"))
}

/// Ensures a directory exists with secure permissions (700).
///
/// Creates directory when nonexistent.
/// Validates and fixes permissions when directory exists.
fn ensure_secure_dir(path: &PathBuf) -> Result<()> {
    if path.exists() {
        // Directory verification
        if !path.is_dir() {
            return Err(Error::Other(format!(
                "{} exists but is not a directory",
                path.display()
            )));
        }

        // Permission validation and correction
        let metadata = fs::metadata(path).map_err(|e| {
            Error::Other(format!(
                "Failed to read metadata for {}: {}",
                path.display(),
                e
            ))
        })?;

        let current_mode = metadata.permissions().mode() & 0o777;
        if current_mode != SECURE_DIR_MODE {
            tracing::warn!(
                "Fixing permissions on {} from {:o} to {:o}",
                path.display(),
                current_mode,
                SECURE_DIR_MODE
            );
            fs::set_permissions(path, fs::Permissions::from_mode(SECURE_DIR_MODE)).map_err(
                |e| {
                    Error::Other(format!(
                        "Failed to set permissions on {}: {}",
                        path.display(),
                        e
                    ))
                },
            )?;
        }
    } else {
        // Directory creation with secure permissions
        fs::create_dir_all(path).map_err(|e| {
            Error::Other(format!(
                "Failed to create directory {}: {}",
                path.display(),
                e
            ))
        })?;

        fs::set_permissions(path, fs::Permissions::from_mode(SECURE_DIR_MODE)).map_err(|e| {
            Error::Other(format!(
                "Failed to set permissions on {}: {}",
                path.display(),
                e
            ))
        })?;

        tracing::debug!(
            "Created secure directory: {} (mode {:o})",
            path.display(),
            SECURE_DIR_MODE
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_dir_structure() {
        // Test requires HOME environment variable
        if std::env::var("HOME").is_err() {
            return;
        }

        let cache = cache_dir().expect("Should get cache dir");
        assert!(cache.ends_with("open-sesame"));
        assert!(cache.to_string_lossy().contains(".cache"));
    }

    #[test]
    fn test_lock_file_path() {
        if std::env::var("HOME").is_err() {
            return;
        }

        let lock = lock_file().expect("Should get lock file path");
        assert!(lock.ends_with("instance.lock"));
    }

    #[test]
    fn test_mru_file_path() {
        if std::env::var("HOME").is_err() {
            return;
        }

        let mru = mru_file().expect("Should get MRU file path");
        assert!(mru.ends_with("mru"));
    }
}
