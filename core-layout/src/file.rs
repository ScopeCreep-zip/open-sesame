//! The one writer, scrubber, and destroyer of files PDS owns.
//!
//! Every write is atomic: the contents go to a temporary file beside
//! `path`, created exclusively under a unique name with the requested
//! [`Mode`], are synced, and are renamed over `path`; the parent directory
//! is then synced so the rename survives a crash. A write that fails
//! before the rename removes its temporary file and leaves `path` as it was
//! ([`WriteError::NotPublished`]); one whose directory sync fails after the
//! rename has published ([`WriteError::PublishedNotDurable`]). A `path`
//! that is a symlink is managed outside PDS and is not replaced. Missing
//! parent directories are created owner-only.
//!
//! Each write publishes one file. Writers that change several files, or
//! read a file and write it back, coordinate above this layer.

use std::io::Write;
use std::path::Path;

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

fn with_path(path: &Path, what: &str, e: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        e.kind(),
        format!("failed to {what} {}: {e}", path.display()),
    )
}

/// Create `dir` and its missing parents owner-only (0700 on Unix), and
/// restrict `dir` itself to its owner when it already exists with another
/// mode.
///
/// A directory already owner-only is not written to: a daemon's unit
/// mounts the directories it does not write read-only
/// (`ProtectHome=read-only`), where a mode change fails with `EROFS` even
/// when it would change nothing.
///
/// # Errors
///
/// The I/O error of the failing step, naming the directory: an existing
/// directory with another mode that cannot be restricted among them.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = dir;
    while !ancestor.as_os_str().is_empty()
        && !ancestor
            .try_exists()
            .map_err(|e| with_path(ancestor, "inspect", &e))?
    {
        missing.push(ancestor);
        ancestor = ancestor.parent().unwrap_or(Path::new("."));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| with_path(dir, "create", &e))?;
        let mode = std::fs::metadata(dir)
            .map_err(|e| with_path(dir, "inspect", &e))?
            .permissions()
            .mode()
            & 0o7777;
        if mode != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| with_path(dir, "restrict", &e))?;
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| with_path(dir, "create", &e))?;
    }
    // Each directory's name lives in its parent, not in its own inode.
    // Publish ancestors first so a durable child never depends on a
    // directory entry whose persistence has not been established.
    for created in missing.into_iter().rev() {
        let parent = created
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        sync_dir(created)?;
        sync_dir(parent)?;
    }
    Ok(())
}

/// Why a [`write()`] failed: before anything was published, or after.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// This operation did not replace the destination.
    #[error("{0}")]
    NotPublished(std::io::Error),
    /// The new contents are at `path`, but the rename into it could not be
    /// made durable: after a crash `path` may hold either version.
    #[error("{0} (the new contents are published; their durability is unconfirmed)")]
    PublishedNotDurable(std::io::Error),
}

impl From<WriteError> for std::io::Error {
    fn from(e: WriteError) -> Self {
        let kind = match &e {
            WriteError::NotPublished(io) | WriteError::PublishedNotDurable(io) => io.kind(),
        };
        Self::new(kind, e)
    }
}

/// Write `contents` to `path` atomically with `mode`, creating missing
/// parent directories owner-only.
///
/// # Errors
///
/// [`WriteError::NotPublished`] when this operation did not replace `path`;
/// [`WriteError::PublishedNotDurable`] when the new contents
/// are at `path` but the parent directory could not be synced.
pub fn write(path: &Path, contents: &[u8], mode: Mode) -> Result<(), WriteError> {
    write_with(path, contents, mode, sync_dir)
}

/// [`write()`], syncing the parent directory with `sync_parent`.
fn write_with(
    path: &Path,
    contents: &[u8],
    mode: Mode,
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), WriteError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent
        .try_exists()
        .map_err(|e| WriteError::NotPublished(with_path(parent, "check", &e)))?
    {
        create_private_dir(parent).map_err(WriteError::NotPublished)?;
    }
    check_destination(path).map_err(WriteError::NotPublished)?;
    let mut tmp = exclusive_temporary(path, parent).map_err(WriteError::NotPublished)?;
    set_mode(tmp.as_file(), mode)
        .map_err(|e| WriteError::NotPublished(with_path(tmp.path(), "set the mode of", &e)))?;
    tmp.write_all(contents)
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(|e| WriteError::NotPublished(with_path(tmp.path(), "write", &e)))?;
    // A failed rename drops the temporary, which removes it.
    tmp.persist(path)
        .map_err(|e| WriteError::NotPublished(with_path(path, "replace", &e.error)))?;
    sync_parent(parent).map_err(WriteError::PublishedNotDurable)
}

/// Refuse to replace `path` when it is a symlink: the file is managed
/// outside PDS (home-manager links configuration into the Nix store), and a
/// rename over it would replace the link with a regular file. This is a
/// policy for cooperating writers in an owner-only directory, not a
/// security boundary: a same-user process can swap the entry afterwards.
///
/// # Errors
///
/// The destination exists as a symlink or non-regular entry, or cannot be inspected.
pub fn check_destination(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to replace {}: it is a symlink, managed outside PDS",
                path.display()
            ),
        )),
        Ok(meta) if !meta.is_file() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(with_path(path, "inspect", &e)),
    }
}

/// A new temporary file beside `path` in `parent`, created exclusively
/// (`O_CREAT|O_EXCL`) under a unique random name (`.<name>.<random>.tmp`).
/// No existing entry is ever opened, so neither a concurrent writer's
/// temporary nor a symlink planted at a temporary name is written through.
fn exclusive_temporary(path: &Path, parent: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} names no file", path.display()),
        )
    })?;
    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(name);
    prefix.push(".");
    tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| with_path(parent, "create a temporary file in", &e))
}

/// Set `file`'s mode exactly: creation applies the umask.
fn set_mode(file: &std::fs::File, mode: Mode) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode.bits()))
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
        Ok(())
    }
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

/// Remove an entry and sync its parent directory, without scrubbing contents.
///
/// Used to undo newly created configuration files. Repeating a removal still
/// syncs the parent so recovery can finish an interrupted directory sync.
///
/// # Errors
///
/// Removal or parent-directory sync failures.
pub fn remove(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(with_path(path, "remove", &e)),
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    match parent.try_exists() {
        Ok(true) => sync_dir(parent),
        Ok(false) => Ok(()),
        Err(e) => Err(with_path(parent, "inspect", &e)),
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
        assert_eq!(
            leftovers(path.parent().unwrap(), &["p.salt"]),
            Vec::<String>::new()
        );
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

    /// The entries of `dir` other than `keep`: what a write left behind.
    fn leftovers(dir: &Path, keep: &[&str]) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !keep.contains(&n.as_str()))
            .collect();
        names.sort();
        names
    }

    /// Another writer holding the predictable temporary sibling open: its
    /// later writes must not reach the published file.
    #[test]
    fn a_concurrent_writers_open_temporary_never_reaches_the_published_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut other = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.path().join("config.toml.tmp"))
            .unwrap();
        write(&path, b"published", Mode::OwnerOnly).unwrap();
        other.write_all(b"-written-after-publication").unwrap();
        other.sync_all().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"published");
    }

    /// A symlink planted where a temporary would go is neither followed
    /// nor published.
    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_at_the_temporary_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let path = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&victim, dir.path().join("config.toml.tmp")).unwrap();
        write(&path, b"published", Mode::OwnerOnly).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"published");
    }

    /// A target that is a symlink is managed outside PDS (home-manager
    /// links configuration into the Nix store): it is not replaced.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_target_is_refused_and_left_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("managed.toml");
        std::fs::write(&managed, b"managed").unwrap();
        let path = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&managed, &path).unwrap();
        let err = write(&path, b"replacement", Mode::OwnerOnly).unwrap_err();
        assert!(matches!(err, WriteError::NotPublished(_)), "{err}");
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&managed).unwrap(), b"managed");
        assert_eq!(
            leftovers(dir.path(), &["managed.toml", "config.toml"]),
            Vec::<String>::new()
        );
    }

    /// A directory sync that fails after the rename is a published write
    /// whose durability is unconfirmed, not a write that did not happen.
    #[test]
    fn a_failed_directory_sync_reports_publication_without_durability() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.salt");
        let err = write_with(&path, b"salt", Mode::OwnerOnly, |_| {
            Err(std::io::Error::other("injected directory sync failure"))
        })
        .unwrap_err();
        assert!(matches!(err, WriteError::PublishedNotDurable(_)), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"salt");
        let io: std::io::Error = err.into();
        assert!(io.to_string().contains("published"), "{io}");
        assert!(
            matches!(
                io.get_ref()
                    .and_then(|source| source.downcast_ref::<WriteError>()),
                Some(WriteError::PublishedNotDurable(_))
            ),
            "publication state must survive the I/O error boundary"
        );
    }

    /// Concurrent writers of one path each publish whole contents: the
    /// result is exactly one writer's bytes, and no temporary remains.
    #[test]
    fn concurrent_writers_publish_whole_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let a = vec![b'a'; 256 * 1024];
        let b = vec![b'b'; 256 * 1024];
        std::thread::scope(|s| {
            for contents in [&a, &b] {
                let path = &path;
                s.spawn(move || {
                    for _ in 0..50 {
                        write(path, contents, Mode::OwnerOnly).unwrap();
                    }
                });
            }
        });
        let published = std::fs::read(&path).unwrap();
        assert!(published == a || published == b, "a mixture was published");
        assert_eq!(
            leftovers(dir.path(), &["config.toml"]),
            Vec::<String>::new()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_target_and_no_temporary() {
        let dir = tempfile::tempdir().unwrap();
        // Renaming a file over a non-empty directory fails.
        let path = dir.path().join("target");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("inside"), b"keep").unwrap();
        assert!(matches!(
            write(&path, b"x", Mode::OwnerOnly),
            Err(WriteError::NotPublished(_))
        ));
        assert!(path.join("inside").exists());
        assert_eq!(leftovers(dir.path(), &["target"]), Vec::<String>::new());
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

    /// A directory already owner-only is not written to: under a unit's
    /// `ProtectHome=read-only` a mode change fails with `EROFS` even when
    /// it would change nothing. Every `chmod` updates the inode's change
    /// time, so an unchanged ctime shows that none was made.
    #[cfg(unix)]
    #[test]
    fn an_owner_only_directory_is_left_untouched() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("config");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ctime = |path: &Path| {
            let meta = std::fs::metadata(path).unwrap();
            (meta.ctime(), meta.ctime_nsec())
        };
        let before = ctime(&existing);
        // Coarse timestamp clocks tick every few milliseconds; a write after
        // the wait would show as a later ctime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        create_private_dir(&existing).unwrap();
        assert_eq!(
            ctime(&existing),
            before,
            "the directory's inode was written"
        );
        assert_eq!(mode_of(&existing), 0o700);
    }
}
