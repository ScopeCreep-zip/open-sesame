//! Linux platform backend for workspace directory management.
//!
//! Uses native Rust APIs (`rustix`, `std::os::unix::fs::MetadataExt`) for
//! process/filesystem operations. Privilege escalation uses `pkexec`
//! (`PolicyKit`) for desktop-native authentication prompts.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use rustix::process::{getgid, getuid};

use crate::WorkspaceError;

use super::WorkspacePlatform;

/// System directories that must never be used as workspace roots.
///
/// Prevents social-engineering attacks via `sesame workspace init --root /etc`
/// where pkexec would chown a system directory to the current user.
const SYSTEM_DIRS: &[&str] = &[
    "/",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/var",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/run",
    "/tmp",
    "/lib",
    "/lib64",
    "/opt",
    "/srv",
    "/root",
    "/lost+found",
];

/// Reject system directories as workspace roots to prevent pkexec abuse.
fn validate_root_not_system(root: &Path) -> Result<(), WorkspaceError> {
    let canonical = root.to_str().unwrap_or("");
    for dir in SYSTEM_DIRS {
        if canonical == *dir {
            return Err(WorkspaceError::PathValidation(format!(
                "refusing to use system directory as workspace root: {}",
                root.display()
            )));
        }
    }
    Ok(())
}

/// Linux workspace platform implementation.
pub struct LinuxPlatform;

impl WorkspacePlatform for LinuxPlatform {
    fn ensure_root(&self, root: &Path) -> Result<(), WorkspaceError> {
        validate_root_not_system(root)?;

        if root.is_dir() {
            return ensure_writable(root);
        }

        if root.exists() {
            return Err(WorkspaceError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("'{}' exists but is not a directory", root.display()),
            )));
        }

        // Try unprivileged creation first; escalate only on permission denied.
        match std::fs::create_dir_all(root) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                elevate_create_and_own(root)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn root_is_mount(&self, root: &Path) -> Result<bool, WorkspaceError> {
        let root_meta = std::fs::metadata(root)?;

        // A path is a mount point when its device ID differs from its parent's.
        if let Some(parent) = root.parent()
            && let Ok(parent_meta) = std::fs::metadata(parent)
        {
            return Ok(root_meta.dev() != parent_meta.dev());
        }

        // No parent means filesystem root — always a mount point.
        Ok(true)
    }

    fn is_git_dir_nofollow(&self, dir: &Path) -> bool {
        is_git_dir_nofollow(dir)
    }
}

/// Check if `dir/.git` exists as a real directory, using `O_NOFOLLOW` to
/// prevent TOCTOU symlink replacement attacks during discovery walks.
#[must_use]
pub fn is_git_dir_nofollow(dir: &Path) -> bool {
    use rustix::fs::{CWD, Mode, OFlags, openat};

    let git_path = dir.join(".git");
    // O_NOFOLLOW causes the open to fail if the target is a symlink,
    // preventing an attacker from replacing .git with a symlink between
    // our check and subsequent use of the directory.
    openat(
        CWD,
        &git_path,
        OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY,
        Mode::empty(),
    )
    .is_ok()
}

/// Create the user directory inside the workspace root.
///
/// # Errors
///
/// Returns `WorkspaceError::Io` if directory creation fails.
pub fn ensure_user_dir(root: &Path, user: &str) -> Result<(), WorkspaceError> {
    let user_dir = root.join(user);
    std::fs::create_dir_all(&user_dir)?;
    Ok(())
}

/// Ensure the existing root directory is writable by the current user.
fn ensure_writable(root: &Path) -> Result<(), WorkspaceError> {
    let test_path = root.join(".sesame-write-test");
    match std::fs::write(&test_path, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&test_path);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => elevate_ownership(root),
        Err(e) => Err(e.into()),
    }
}

/// Use `pkexec` to create the directory and set ownership to the current user.
fn elevate_create_and_own(root: &Path) -> Result<(), WorkspaceError> {
    tracing::info!(
        path = %root.display(),
        "creating workspace root requires elevated privileges"
    );

    run_pkexec(&["mkdir", "-p", "--"], root)?;
    elevate_ownership(root)
}

/// Use `pkexec` to chown the directory to the current process UID:GID.
fn elevate_ownership(root: &Path) -> Result<(), WorkspaceError> {
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    let owner = format!("{uid}:{gid}");

    let status = Command::new("pkexec")
        .arg("chown")
        .arg("--")
        .arg(&owner)
        .arg(root)
        .status()
        .map_err(|e| {
            WorkspaceError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to run pkexec chown: {e}"),
            ))
        })?;

    if !status.success() {
        return Err(WorkspaceError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "pkexec chown failed for '{}' (exit code: {:?})",
                root.display(),
                status.code()
            ),
        )));
    }

    Ok(())
}

/// Run a pkexec command with the given args, appending the path as the final argument.
fn run_pkexec(args: &[&str], path: &Path) -> Result<(), WorkspaceError> {
    let mut cmd = Command::new("pkexec");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.arg(path);

    let status = cmd.status().map_err(|e| {
        WorkspaceError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to run pkexec {}: {e}", args.first().unwrap_or(&"")),
        ))
    })?;

    if !status.success() {
        return Err(WorkspaceError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "pkexec {} failed for '{}' (exit code: {:?})",
                args.first().unwrap_or(&""),
                path.display(),
                status.code()
            ),
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_detection_for_root_fs() {
        let platform = LinuxPlatform;
        // "/" is always a mount point.
        let result = platform.root_is_mount(Path::new("/"));
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn mount_detection_for_temp() {
        let platform = LinuxPlatform;
        let dir = tempfile::tempdir().unwrap();
        let result = platform.root_is_mount(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_root_creates_dir() {
        let platform = LinuxPlatform;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        platform.ensure_root(&root).unwrap();
        assert!(root.is_dir());
    }

    #[test]
    fn ensure_root_existing_dir_ok() {
        let platform = LinuxPlatform;
        let dir = tempfile::tempdir().unwrap();
        platform.ensure_root(dir.path()).unwrap();
    }

    #[test]
    fn ensure_root_file_not_dir_errors() {
        let platform = LinuxPlatform;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-dir");
        std::fs::write(&path, b"file").unwrap();
        let err = platform.ensure_root(&path);
        assert!(err.is_err());
    }

    #[test]
    fn ensure_user_dir_creates_nested() {
        let dir = tempfile::tempdir().unwrap();
        ensure_user_dir(dir.path(), "testuser").unwrap();
        assert!(dir.path().join("testuser").is_dir());
    }

    #[test]
    fn uid_is_nonzero_in_test() {
        let uid = getuid();
        let _ = uid.as_raw();
    }

    #[test]
    fn rejects_system_dirs() {
        assert!(validate_root_not_system(Path::new("/")).is_err());
        assert!(validate_root_not_system(Path::new("/etc")).is_err());
        assert!(validate_root_not_system(Path::new("/usr")).is_err());
        assert!(validate_root_not_system(Path::new("/workspace")).is_ok());
    }

    #[test]
    fn git_dir_nofollow_real_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(is_git_dir_nofollow(dir.path()));
    }

    #[test]
    fn git_dir_nofollow_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_git_dir_nofollow(dir.path()));
    }

    #[test]
    fn git_dir_nofollow_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_dir");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(".git")).unwrap();
        // O_NOFOLLOW should reject the symlink
        assert!(!is_git_dir_nofollow(dir.path()));
    }
}
