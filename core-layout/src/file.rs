//! The one writer, scrubber, and destroyer of files PDS owns.
//!
//! Every write is atomic: the contents go to `<path>.tmp`, created with the
//! requested [`Mode`], are synced, and are renamed over `path`; the parent
//! directory is then synced so the rename survives a crash. A failed write
//! removes its temporary file and leaves `path` as it was. Missing parent
//! directories are created owner-only.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Who may read a file once written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// 0600: key material, vault state, configuration, identity.
    OwnerOnly,
    /// 0644: files other processes read (the bus endpoint, git link files).
    PublicRead,
}

impl Mode {
    #[cfg(unix)]
    const fn bits(self) -> u32 {
        match self {
            Self::OwnerOnly => 0o600,
            Self::PublicRead => 0o644,
        }
    }
}

/// The temporary sibling a write goes through: `<path>.tmp`.
fn temporary(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn with_path(path: &Path, what: &str, e: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        e.kind(),
        format!("failed to {what} {}: {e}", path.display()),
    )
}

/// Create `dir` and its missing parents owner-only (0700 on Unix), and
/// restrict `dir` itself to its owner when it already exists.
///
/// # Errors
///
/// The I/O error of the failing step, naming the directory.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| with_path(dir, "create", &e))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| with_path(dir, "restrict", &e))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| with_path(dir, "create", &e))
    }
}

/// Write `contents` to `path` atomically with `mode`, creating missing
/// parent directories owner-only.
///
/// # Errors
///
/// The I/O error of the failing step, naming the path. On error `path` is
/// unchanged and no temporary file remains.
pub fn write(path: &Path, contents: &[u8], mode: Mode) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent
        .try_exists()
        .map_err(|e| with_path(parent, "check", &e))?
    {
        create_private_dir(parent)?;
    }
    let tmp = temporary(path);
    let result = write_and_rename(&tmp, path, contents, mode);
    if result.is_err() {
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(with_path(&tmp, "remove", &e)),
        }
    }
    result?;
    sync_dir(parent)
}

fn write_and_rename(tmp: &Path, path: &Path, contents: &[u8], mode: Mode) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode.bits());
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(tmp)
        .map_err(|e| with_path(tmp, "create", &e))?;
    // `open` applies the umask to the mode of a new file; set it exactly.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode.bits()))
            .map_err(|e| with_path(tmp, "set the mode of", &e))?;
    }
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|e| with_path(tmp, "write", &e))?;
    std::fs::rename(tmp, path).map_err(|e| with_path(path, "replace", &e))
}

/// Sync `dir` so a rename into it is durable.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| with_path(dir, "sync", &e))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Overwrite `path`'s existing bytes with zeros in place, keeping its
/// length so the original blocks are rewritten, and sync to disk.
///
/// # Errors
///
/// The I/O error of the failing step, naming the path.
pub fn zero_fill(path: &Path) -> std::io::Result<()> {
    use std::io::Read;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| with_path(path, "open", &e))?;
    let len = file
        .metadata()
        .map_err(|e| with_path(path, "stat", &e))?
        .len();
    std::io::copy(&mut std::io::repeat(0).take(len), &mut file)
        .map_err(|e| with_path(path, "overwrite", &e))?;
    file.sync_all().map_err(|e| with_path(path, "sync", &e))
}

/// Zero-fill and remove `path`. Returns whether a file was removed; an
/// absent file is not an error.
///
/// # Errors
///
/// The [`zero_fill`] errors, and the removal error naming the path. The
/// file is removed only after it is scrubbed; on a zero-fill error it
/// remains.
pub fn destroy(path: &Path) -> std::io::Result<bool> {
    match zero_fill(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    }
    std::fs::remove_file(path).map_err(|e| with_path(path, "remove", &e))?;
    Ok(true)
}

/// Whether `path` exists. A failure to determine it is an error.
///
/// # Errors
///
/// The `try_exists` error, naming the path.
pub fn exists(path: &Path) -> std::io::Result<bool> {
    path.try_exists().map_err(|e| with_path(path, "check", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_creates_owner_only_parents_and_leaves_no_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vaults").join("p.salt");
        write(&path, b"secret", Mode::OwnerOnly).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        assert!(!temporary(&path).exists());
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&path), 0o600);
            assert_eq!(mode_of(path.parent().unwrap()), 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn public_read_files_are_0644() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus.endpoint");
        write(&path, b"x", Mode::PublicRead).unwrap();
        assert_eq!(mode_of(&path), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_sets_the_requested_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"old").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        write(&path, b"new", Mode::OwnerOnly).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn distinct_extensions_use_distinct_temporaries() {
        let a = temporary(Path::new("/d/a.toml"));
        let b = temporary(Path::new("/d/a.json"));
        assert_ne!(a, b);
        assert_eq!(a, Path::new("/d/a.toml.tmp"));
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_target_and_no_temporary() {
        let dir = tempfile::tempdir().unwrap();
        // Renaming a file over a non-empty directory fails.
        let path = dir.path().join("target");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("inside"), b"keep").unwrap();
        assert!(write(&path, b"x", Mode::OwnerOnly).is_err());
        assert!(path.join("inside").exists());
        assert!(!temporary(&path).exists());
    }

    #[test]
    fn zero_fill_overwrites_in_place_without_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let payload = vec![0xA5u8; 200_000]; // spans several 64 KiB chunks
        std::fs::write(&path, &payload).unwrap();
        zero_fill(&path).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), payload.len());
        assert!(after.iter().all(|&b| b == 0));
    }

    #[test]
    fn zero_fill_reports_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let err = zero_fill(&dir.path().join("absent")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("absent"), "{err}");
    }

    #[test]
    fn destroy_removes_and_reports_absence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.password-wrap");
        std::fs::write(&path, b"blob").unwrap();
        assert!(destroy(&path).unwrap());
        assert!(!path.exists());
        assert!(!destroy(&path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn destroy_keeps_a_file_it_cannot_scrub() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.ssh-enrollment");
        std::fs::write(&path, b"blob").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(destroy(&path).is_err());
        assert!(path.exists(), "a file that cannot be scrubbed remains");
    }

    #[cfg(unix)]
    #[test]
    fn private_dirs_are_0700_even_when_they_exist() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&existing).unwrap();
        assert_eq!(mode_of(&existing), 0o700);
    }
}
