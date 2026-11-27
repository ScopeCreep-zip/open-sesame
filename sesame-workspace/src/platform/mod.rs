//! Platform-specific workspace operations.

use std::path::Path;

use crate::WorkspaceError;

/// Platform-specific workspace directory operations.
pub trait WorkspacePlatform {
    /// Ensure the workspace root directory exists and is usable.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or accessed.
    fn ensure_root(&self, root: &Path) -> Result<(), WorkspaceError>;

    /// Check if the root path is a mount point.
    ///
    /// # Errors
    ///
    /// Returns an error on platforms where detection is not supported.
    fn root_is_mount(&self, root: &Path) -> Result<bool, WorkspaceError>;
}

#[cfg(target_os = "linux")]
pub mod linux;

/// Rename `from` to `to`, failing with `AlreadyExists` instead of
/// replacing an existing `to`.
///
/// `std::fs::rename` replaces an existing empty directory on POSIX, so a
/// check-then-rename can silently drop a directory created in between.
/// `renameat2(RENAME_NOREPLACE)` (Linux, Android) and
/// `renameatx_np(RENAME_EXCL)` (Apple) make the check part of the rename.
///
/// # Errors
///
/// Returns the OS error; `AlreadyExists` when `to` exists, `Unsupported`
/// on platforms without an atomic no-replace rename. There is no
/// fallback to a replacing rename.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(std::io::Error::from)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "no atomic no-replace rename on this platform: {} -> {}",
                from.display(),
                to.display()
            ),
        ))
    }
}

/// Stub for macOS — not yet implemented.
pub struct MacOsPlatform;

impl WorkspacePlatform for MacOsPlatform {
    fn ensure_root(&self, _root: &Path) -> Result<(), WorkspaceError> {
        Err(WorkspaceError::PlatformNotSupported(
            "macOS APFS volume support not yet implemented".into(),
        ))
    }

    fn root_is_mount(&self, _root: &Path) -> Result<bool, WorkspaceError> {
        Err(WorkspaceError::PlatformNotSupported(
            "macOS mount detection not yet implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_noreplace_moves_to_absent_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        rename_noreplace(&dir.path().join("a"), &dir.path().join("b")).unwrap();
        assert!(dir.path().join("b").is_dir());
    }

    #[test]
    fn rename_noreplace_refuses_existing_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        std::fs::create_dir(dir.path().join("b")).unwrap();
        let err = rename_noreplace(&dir.path().join("a"), &dir.path().join("b")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(dir.path().join("a").is_dir());
    }
}
