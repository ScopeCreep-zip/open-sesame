//! Linux platform backend for workspace directory management.
//!
//! Uses native Rust APIs (`rustix`, `std::os::unix::fs::MetadataExt`) for
//! process/filesystem operations. Privilege escalation uses `pkexec`
//! (`PolicyKit`) for desktop-native authentication prompts.

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
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
///
/// The root is compared as the directory it names once created
/// ([`resolve_created`]), so a symlink to a system directory, a spelling
/// such as `/etc/.`, and a `..` through a missing component
/// (`/absent/../etc`, which `pkexec mkdir -p` creates and `pkexec chown`
/// then resolves to `/etc`) are rejected too.
fn validate_root_not_system(root: &Path) -> Result<(), WorkspaceError> {
    let resolved = resolve_created(root).map_err(|e| WorkspaceError::io_at(root, e))?;
    if SYSTEM_DIRS.iter().any(|dir| resolved == Path::new(dir)) {
        return Err(WorkspaceError::PathValidation(format!(
            "refusing to use system directory as workspace root: {} ({})",
            root.display(),
            resolved.display()
        )));
    }
    Ok(())
}

/// The canonical path `root` resolves to once its missing components are
/// created (`mkdir -p`): the deepest existing ancestor in canonical form,
/// with the missing components applied to it. A missing component is
/// created as a plain directory, so a `..` after it returns to the
/// directory it was created in.
///
/// # Errors
///
/// Canonicalizing the existing ancestor fails other than with `NotFound`
/// (a component that is not a directory, a permission error).
fn resolve_created(root: &Path) -> std::io::Result<PathBuf> {
    let mut existing = root;
    let mut missing = Vec::new();
    loop {
        // A relative root's last ancestor is "", the working directory.
        let probe = if existing.as_os_str().is_empty() {
            Path::new(".")
        } else {
            existing
        };
        match std::fs::canonicalize(probe) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    match component {
                        Component::ParentDir => {
                            resolved.pop();
                        }
                        Component::CurDir => {}
                        other => resolved.push(other),
                    }
                }
                return Ok(resolved);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (Some(parent), Some(last)) =
                    (existing.parent(), existing.components().next_back())
                else {
                    return Err(e);
                };
                missing.push(last);
                existing = parent;
            }
            Err(e) => return Err(e),
        }
    }
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
        let root_meta = std::fs::metadata(root).map_err(|e| WorkspaceError::io_at(root, e))?;

        // A path is a mount point when its device ID differs from its parent's.
        // No parent means filesystem root — always a mount point.
        let Some(parent) = root.parent() else {
            return Ok(true);
        };
        let parent_meta =
            std::fs::metadata(parent).map_err(|e| WorkspaceError::io_at(parent, e))?;
        Ok(root_meta.dev() != parent_meta.dev())
    }
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
            std::fs::remove_file(&test_path).map_err(|e| WorkspaceError::io_at(&test_path, e))
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
    fn ensure_root_leaves_no_write_probe() {
        let dir = tempfile::tempdir().unwrap();
        LinuxPlatform.ensure_root(dir.path()).unwrap();
        assert!(!dir.path().join(".sesame-write-test").exists());
    }

    #[test]
    fn rejects_system_dirs() {
        assert!(validate_root_not_system(Path::new("/")).is_err());
        assert!(validate_root_not_system(Path::new("/etc")).is_err());
        assert!(validate_root_not_system(Path::new("/usr")).is_err());
        assert!(validate_root_not_system(Path::new("/workspace-absent-for-test")).is_ok());
    }

    #[test]
    fn rejects_alternate_spellings_of_system_dirs() {
        assert!(validate_root_not_system(Path::new("/etc/")).is_err());
        assert!(validate_root_not_system(Path::new("/etc/.")).is_err());
        assert!(validate_root_not_system(Path::new("/usr/../etc")).is_err());
    }

    /// `pkexec mkdir -p` creates the missing components and `pkexec chown`
    /// then resolves `..` through them, so a root reaching a system
    /// directory through a missing component would hand it to the user.
    #[test]
    fn rejects_system_dirs_reached_through_missing_components() {
        let absent = "/workspace-absent-for-test";
        assert!(!Path::new(absent).exists());
        for root in [
            format!("{absent}/../etc"),
            format!("{absent}/deeper/../../usr"),
            format!("{absent}/../../.."),
        ] {
            assert!(
                validate_root_not_system(Path::new(&root)).is_err(),
                "{root} reaches a system directory"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("absent/../workspace");
        assert!(validate_root_not_system(&inside).is_ok());
    }

    #[test]
    fn rejects_symlink_to_system_dir() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("root");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        assert!(validate_root_not_system(&link).is_err());
    }
}
