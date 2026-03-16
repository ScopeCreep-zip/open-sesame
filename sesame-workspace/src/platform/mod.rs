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

    /// Check if `dir/.git` exists as a real directory (not a symlink).
    ///
    /// On Linux, uses `O_NOFOLLOW` to prevent TOCTOU symlink attacks.
    /// On other platforms, falls back to `is_dir()`.
    fn is_git_dir_nofollow(&self, dir: &Path) -> bool {
        dir.join(".git").is_dir()
    }
}

#[cfg(target_os = "linux")]
pub mod linux;

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
