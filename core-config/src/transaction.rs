//! Optimistic configuration plans with journaled publication.
//!
//! Planning is read-only. Commit serializes cooperating writers, checks the
//! complete read set, durably records undo data, installs the changes, then
//! publishes a stable revision. Dropping a plan never writes anything.
//! Readers reject pending journals; the next writer recovers them under the
//! same lock before planning. Recovery refuses unexpected external edits.
//! External editors do not participate in this protocol: comparison detects
//! observed conflicts but cannot prevent a write after the comparison.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::loader::{path_error, read_optional, utf8};
use core_layout::{Layout, file};
use core_types::Error;
use serde::{Deserialize, Serialize};

const READ_ATTEMPTS: u32 = 50;
const READ_RETRY: Duration = Duration::from_millis(10);

/// A publication record is replaced atomically; pending records contain
/// everything needed to undo an interrupted installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum Revision {
    Stable {
        id: uuid::Uuid,
    },
    Pending {
        id: uuid::Uuid,
        changes: Vec<Change>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Vec<u8>,
}

/// Publication and its attempted recovery both failed.
#[derive(Debug)]
pub struct RecoveryError {
    /// The error that interrupted publication.
    pub publication: Error,
    /// The error that prevented recovery from completing.
    pub recovery: Error,
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "publication failed: {}; recovery failed: {}",
            self.publication, self.recovery
        )
    }
}

impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.publication)
    }
}

/// Replace `path` with `bytes`, owner-only: every destination and marker
/// write of a transaction. The I/O error keeps the typed
/// `file::WriteError`, so whether `path` was published stays decidable.
fn publish(path: &Path, bytes: &[u8]) -> core_types::Result<()> {
    file::write(path, bytes, file::Mode::OwnerOnly).map_err(|e| Error::Io(e.into()))
}

fn revision(layout: &Layout) -> core_types::Result<Option<Revision>> {
    let path = layout.config_revision_file()?;
    read_optional(&path)?
        .map(|bytes| toml::from_str(utf8(&path, &bytes)?).map_err(|e| path_error(&path, e)))
        .transpose()
}

fn write_revision(layout: &Layout, value: &Revision) -> core_types::Result<()> {
    let path = layout.config_revision_file()?;
    let text = toml::to_string(value).map_err(|e| path_error(&path, e))?;
    publish(&path, text.as_bytes())
}

fn pending(revision: Option<&Revision>) -> bool {
    matches!(revision, Some(Revision::Pending { .. }))
}

fn writable_path(layout: &Layout, path: &Path) -> core_types::Result<()> {
    let root = layout.config_dir()?;
    let relative = path.strip_prefix(&root).map_err(|_| {
        path_error(
            path,
            "transaction destination is outside the configuration directory",
        )
    })?;
    if relative
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
        || path.extension().is_none_or(|e| e != "toml")
    {
        return Err(path_error(
            path,
            "transaction destination must be a configuration TOML file",
        ));
    }
    for parent in path
        .ancestors()
        .skip(1)
        .take_while(|parent| parent.starts_with(&root))
    {
        match std::fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(path_error(
                    parent,
                    "transaction parent must be a real directory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(path_error(parent, error)),
        }
    }
    file::check_destination(path)?;
    Ok(())
}

/// Read a stable observation, including errors only when its revision is stable.
///
/// A pending journal is never interpreted as committed data, even when its
/// writer has died. Read-only daemons retain their previous accepted state.
pub(crate) fn consistent<T>(
    layout: &Layout,
    mut read: impl FnMut() -> core_types::Result<T>,
) -> core_types::Result<T> {
    for _ in 0..READ_ATTEMPTS {
        let before = revision(layout)?;
        if !pending(before.as_ref()) {
            let result = read();
            if revision(layout)? == before {
                return result;
            }
        }
        std::thread::sleep(READ_RETRY);
    }
    Err(path_error(
        &layout.config_revision_file()?,
        "no stable configuration revision; publication is active or requires writer recovery",
    ))
}

fn lock(layout: &Layout) -> core_types::Result<std::fs::File> {
    let dir = layout.config_dir()?;
    if !dir.try_exists().map_err(|e| path_error(&dir, e))? {
        file::create_private_dir(&dir)?;
    }
    let path = layout.config_lock_file()?;
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            return Err(path_error(
                &path,
                "configuration lock must be a regular file",
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(path_error(&path, e)),
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(&path).map_err(|e| path_error(&path, e))?;
    file.lock().map_err(|e| path_error(&path, e))?;
    Ok(file)
}

/// Undo is idempotent: each destination must contain either its before or
/// after image. A third value belongs to an external writer and is preserved.
fn recover_locked(layout: &Layout) -> core_types::Result<()> {
    let Some(Revision::Pending { changes, .. }) = revision(layout)? else {
        return Ok(());
    };
    let mut destinations = BTreeSet::new();
    for change in &changes {
        if !destinations.insert(&change.path) {
            return Err(path_error(&change.path, "duplicate journal destination"));
        }
        writable_path(layout, &change.path)?;
        let bytes = read_optional(&change.path)?;
        if bytes != change.before && bytes.as_ref() != Some(&change.after) {
            return Err(path_error(
                &change.path,
                "recovery conflict: external contents preserved",
            ));
        }
    }
    for change in &changes {
        match &change.before {
            Some(bytes) => publish(&change.path, bytes)?,
            None => file::remove(&change.path)?,
        }
    }
    write_revision(
        layout,
        &Revision::Stable {
            id: uuid::Uuid::new_v4(),
        },
    )
}

/// A read-only plan. Writes are staged in memory until explicit commit.
pub struct Transaction<'a> {
    layout: &'a Layout,
    base: Option<Revision>,
    read: BTreeMap<PathBuf, Option<Vec<u8>>>,
    directories: BTreeMap<PathBuf, Vec<PathBuf>>,
    writes: BTreeMap<PathBuf, Vec<u8>>,
}

impl<'a> Transaction<'a> {
    /// Start a read-only plan without creating directories or taking a lock.
    ///
    /// # Errors
    ///
    /// An unreadable revision or an interrupted publication requiring recovery.
    pub fn begin(layout: &'a Layout) -> core_types::Result<Self> {
        let base = revision(layout)?;
        if pending(base.as_ref()) {
            return Err(path_error(
                &layout.config_revision_file()?,
                "publication requires recovery",
            ));
        }
        let mut plan = Self {
            layout,
            base,
            read: BTreeMap::new(),
            directories: BTreeMap::new(),
            writes: BTreeMap::new(),
        };
        for spec in [
            crate::loader::LayerSpec::of(layout)?,
            crate::loader::LayerSpec::workspace(layout)?,
        ] {
            for dir in spec.directories()? {
                plan.directory(&dir)?;
            }
        }
        Ok(plan)
    }

    /// Recover interrupted writes and start a plan for an updating command.
    ///
    /// # Errors
    ///
    /// The recovery and planning errors.
    pub fn for_update(layout: &'a Layout) -> core_types::Result<Self> {
        Self::recover(layout)?;
        Self::begin(layout)
    }

    /// Recover an interrupted publication before starting a writing operation.
    /// This is separate from planning so dry-run never performs recovery writes.
    ///
    /// # Errors
    ///
    /// Lock, journal, durability or external-edit conflicts.
    pub fn recover(layout: &Layout) -> core_types::Result<()> {
        if pending(revision(layout)?.as_ref()) {
            let _lock = lock(layout)?;
            recover_locked(layout)?;
        }
        Ok(())
    }

    /// Read a repeatable value, including earlier staged edits.
    ///
    /// # Errors
    ///
    /// I/O or UTF-8 errors naming the path.
    pub fn read(&mut self, path: &Path) -> core_types::Result<Option<String>> {
        if !self.read.contains_key(path) {
            self.read.insert(path.to_path_buf(), read_optional(path)?);
        }
        let bytes = self.writes.get(path).or_else(|| self.read[path].as_ref());
        bytes.map(|b| utf8(path, b).map(str::to_owned)).transpose()
    }

    /// Record directory membership used to resolve layer precedence.
    ///
    /// # Errors
    ///
    /// An unreadable directory or changed membership on a repeated observation.
    pub(crate) fn directory(&mut self, path: &Path) -> core_types::Result<Vec<PathBuf>> {
        let entries = directory(path)?;
        if let Some(before) = self.directories.get(path) {
            if before != &entries {
                return Err(path_error(path, "directory changed during planning"));
            }
        } else {
            self.directories.insert(path.to_path_buf(), entries.clone());
        }
        Ok(entries)
    }

    /// Stage replacement bytes; the destination must have been read.
    ///
    /// # Errors
    ///
    /// The path was not read, or an external edit is already visible.
    pub fn write(&mut self, path: &Path, contents: &[u8]) -> core_types::Result<()> {
        writable_path(self.layout, path)?;
        let expected = self
            .read
            .get(path)
            .ok_or_else(|| path_error(path, "not read in this transaction"))?;
        if &read_optional(path)? != expected {
            return Err(path_error(
                path,
                "changed since it was read; not overwritten",
            ));
        }
        self.writes.insert(path.to_path_buf(), contents.to_vec());
        Ok(())
    }

    /// The published revision is still the one this plan started from.
    fn check_base(&self, detail: &str) -> core_types::Result<()> {
        if revision(self.layout)? == self.base {
            Ok(())
        } else {
            Err(path_error(&self.layout.config_revision_file()?, detail))
        }
    }

    fn check(&self) -> core_types::Result<()> {
        self.check_base("revision changed; replan")?;
        for (path, expected) in &self.read {
            if &read_optional(path)? != expected {
                return Err(path_error(path, "changed since it was read; replan"));
            }
        }
        for (path, expected) in &self.directories {
            if &directory(path)? != expected {
                return Err(path_error(
                    path,
                    "directory changed since it was read; replan",
                ));
            }
        }
        self.check_base("revision changed while checking observations; replan")
    }

    /// Check a completed plan without publishing it or creating filesystem state.
    ///
    /// # Errors
    ///
    /// A recorded file, directory, or revision changed during planning.
    pub fn validate(self) -> core_types::Result<()> {
        self.check()
    }

    /// Publish the complete plan; an empty plan only checks its observations.
    ///
    /// # Errors
    ///
    /// Conflicts publish nothing. Installation errors trigger undo; if undo
    /// fails the journal remains pending and readers reject it. A final marker
    /// sync failure preserves the typed published-but-not-durable error.
    pub fn commit(self) -> core_types::Result<()> {
        self.commit_with(publish)
    }

    /// [`commit`](Self::commit), installing each destination with `install`.
    fn commit_with(
        self,
        install: impl FnMut(&Path, &[u8]) -> core_types::Result<()>,
    ) -> core_types::Result<()> {
        self.commit_using(install, write_revision)
    }

    /// [`commit`](Self::commit), installing each destination with `install`
    /// and each journal record with `record`.
    fn commit_using(
        self,
        mut install: impl FnMut(&Path, &[u8]) -> core_types::Result<()>,
        mut record: impl FnMut(&Layout, &Revision) -> core_types::Result<()>,
    ) -> core_types::Result<()> {
        if self.writes.is_empty() {
            return self.check();
        }
        let _lock = lock(self.layout)?;
        self.check()?;
        for path in self.writes.keys() {
            writable_path(self.layout, path)?;
        }
        let changes: Vec<Change> = self
            .writes
            .iter()
            .map(|(path, after)| Change {
                path: path.clone(),
                before: self.read[path].clone(),
                after: after.clone(),
            })
            .collect();
        let id = uuid::Uuid::new_v4();
        record(
            self.layout,
            &Revision::Pending {
                id,
                changes: changes.clone(),
            },
        )?;
        for change in &changes {
            if let Err(original) = install(&change.path, &change.after) {
                return Err(rollback(self.layout, original));
            }
        }
        match record(self.layout, &Revision::Stable { id }) {
            Ok(()) => Ok(()),
            Err(original) => {
                // A failed directory sync may have already exposed the stable
                // marker. Undo is permitted only while the journal is pending.
                // recover_locked is a no-op for an exposed stable marker.
                Err(rollback(self.layout, original))
            }
        }
    }
}

fn rollback(layout: &Layout, publication: Error) -> Error {
    match recover_locked(layout) {
        Ok(()) => publication,
        Err(recovery) => Error::Io(std::io::Error::other(RecoveryError {
            publication,
            recovery,
        })),
    }
}

/// The membership of `path` a plan depends on: its sorted entries, without
/// publication metadata and exclusive temporaries, which are not layers.
fn directory(path: &Path) -> core_types::Result<Vec<PathBuf>> {
    Ok(crate::loader::entries(path)?
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .is_some_and(|name| name != ".lock" && name != ".revision")
                && entry.extension().is_none_or(|extension| extension != "tmp")
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        (dir, layout)
    }

    #[test]
    fn abandoning_a_changeset_publishes_nothing() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        {
            let mut txn = Transaction::begin(&layout).unwrap();
            txn.read(&path).unwrap();
            txn.write(&path, b"uncommitted").unwrap();
        }
        assert!(!layout.config_dir().unwrap().exists());
    }

    #[test]
    fn failure_to_publish_the_final_marker_rolls_back() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        publish(&path, b"old").unwrap();
        let mut plan = Transaction::begin(&layout).unwrap();
        plan.read(&path).unwrap();
        plan.write(&path, b"new").unwrap();
        let error = plan
            .commit_using(publish, |layout, revision| match revision {
                Revision::Pending { .. } => write_revision(layout, revision),
                Revision::Stable { .. } => Err(Error::Io(
                    file::WriteError::NotPublished(std::io::Error::other("marker failure")).into(),
                )),
            })
            .unwrap_err();
        assert!(error.to_string().contains("marker failure"));
        assert_eq!(read_optional(&path).unwrap(), Some(b"old".to_vec()));
        assert!(!pending(revision(&layout).unwrap().as_ref()));
    }

    #[test]
    fn exposed_final_marker_is_not_undone_after_sync_failure() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        let mut plan = Transaction::begin(&layout).unwrap();
        plan.read(&path).unwrap();
        plan.write(&path, b"new").unwrap();
        let error = plan
            .commit_using(publish, |layout, revision| {
                write_revision(layout, revision)?;
                if matches!(revision, Revision::Stable { .. }) {
                    return Err(Error::Io(
                        file::WriteError::PublishedNotDurable(std::io::Error::other(
                            "marker sync failure",
                        ))
                        .into(),
                    ));
                }
                Ok(())
            })
            .unwrap_err();
        let Error::Io(error) = error else {
            panic!("lost typed publication error")
        };
        assert!(matches!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<file::WriteError>()),
            Some(file::WriteError::PublishedNotDurable(_))
        ));
        assert_eq!(read_optional(&path).unwrap(), Some(b"new".to_vec()));
        assert!(!pending(revision(&layout).unwrap().as_ref()));
    }

    #[test]
    fn conflicting_plans_cannot_overwrite_a_committed_revision() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        let mut first = Transaction::begin(&layout).unwrap();
        let mut second = Transaction::begin(&layout).unwrap();
        for plan in [&mut first, &mut second] {
            plan.read(&path).unwrap();
        }
        first.write(&path, b"first").unwrap();
        second.write(&path, b"second").unwrap();
        first.commit().unwrap();
        assert!(second.commit().is_err());
        assert_eq!(read_optional(&path).unwrap(), Some(b"first".to_vec()));
    }

    #[test]
    fn publication_and_recovery_errors_keep_both_causes() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        let mut plan = Transaction::begin(&layout).unwrap();
        plan.read(&path).unwrap();
        plan.write(&path, b"ours").unwrap();
        let error = plan
            .commit_with(|path, _| {
                publish(path, b"external").unwrap();
                Err(Error::Io(
                    file::WriteError::NotPublished(std::io::Error::other(
                        "injected publication failure",
                    ))
                    .into(),
                ))
            })
            .unwrap_err();
        let Error::Io(error) = error else {
            panic!("lost compound error")
        };
        let causes = error
            .get_ref()
            .unwrap()
            .downcast_ref::<RecoveryError>()
            .unwrap();
        let Error::Io(publication) = &causes.publication else {
            panic!("lost publication cause")
        };
        assert!(publication.get_ref().unwrap().is::<file::WriteError>());
        assert!(causes.recovery.to_string().contains("recovery conflict"));
        assert_eq!(read_optional(&path).unwrap(), Some(b"external".to_vec()));
        assert!(pending(revision(&layout).unwrap().as_ref()));
    }

    #[test]
    fn duplicate_journal_paths_are_rejected_before_undo() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        publish(&path, b"new").unwrap();
        let change = Change {
            path: path.clone(),
            before: Some(b"old".to_vec()),
            after: b"new".to_vec(),
        };
        write_revision(
            &layout,
            &Revision::Pending {
                id: uuid::Uuid::new_v4(),
                changes: vec![change.clone(), change],
            },
        )
        .unwrap();
        assert!(
            Transaction::recover(&layout)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert_eq!(read_optional(&path).unwrap(), Some(b"new".to_vec()));
        assert!(pending(revision(&layout).unwrap().as_ref()));
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "subprocess crash-test harness owns its isolated root and failure boundary inputs"
    )]
    fn crash_writer_child() {
        let Some(root) = std::env::var_os("SESAME_TEST_TRANSACTION_ROOT") else {
            return;
        };
        let boundary: usize = std::env::var("SESAME_TEST_TRANSACTION_BOUNDARY")
            .unwrap()
            .parse()
            .unwrap();
        let layout = Layout::under(Path::new(&root));
        let mut plan = Transaction::for_update(&layout).unwrap();
        for path in [
            layout.config_file().unwrap(),
            layout.workspaces_file().unwrap(),
        ] {
            plan.read(&path).unwrap();
            plan.write(&path, b"new").unwrap();
        }
        let mut installed = 0;
        plan.commit_using(
            |path, bytes| {
                publish(path, bytes)?;
                installed += 1;
                if installed == boundary {
                    std::process::exit(90);
                }
                Ok(())
            },
            |layout, record| {
                write_revision(layout, record)?;
                if (boundary == 0 && matches!(record, Revision::Pending { .. }))
                    || (boundary == 3 && matches!(record, Revision::Stable { .. }))
                {
                    std::process::exit(90);
                }
                Ok(())
            },
        )
        .unwrap();
        panic!("requested crash boundary was not reached");
    }

    #[test]
    fn process_death_at_each_publication_boundary_recovers_one_revision() {
        for boundary in 0..=3 {
            let (root, layout) = layout();
            let paths = [
                layout.config_file().unwrap(),
                layout.workspaces_file().unwrap(),
            ];
            for path in &paths {
                publish(path, b"old").unwrap();
            }
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "transaction::tests::crash_writer_child",
                    "--nocapture",
                ])
                .env("SESAME_TEST_TRANSACTION_ROOT", root.path())
                .env("SESAME_TEST_TRANSACTION_BOUNDARY", boundary.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(90), "boundary {boundary}");
            if boundary < 3 {
                assert!(
                    consistent(&layout, || Ok(())).is_err(),
                    "boundary {boundary}"
                );
            }
            Transaction::recover(&layout).unwrap();
            let expected = if boundary < 3 { b"old" } else { b"new" };
            for path in &paths {
                assert_eq!(
                    read_optional(path).unwrap().as_deref(),
                    Some(expected.as_slice()),
                    "boundary {boundary}"
                );
            }
            assert!(
                !pending(revision(&layout).unwrap().as_ref()),
                "boundary {boundary}"
            );
        }
    }

    #[test]
    fn an_error_from_an_overlapping_read_is_retried() {
        let (_root, layout) = layout();
        let mut attempts = 0;
        let value = consistent(&layout, || {
            attempts += 1;
            if attempts == 1 {
                write_revision(
                    &layout,
                    &Revision::Stable {
                        id: uuid::Uuid::new_v4(),
                    },
                )?;
                return Err(Error::Config("transient observation".into()));
            }
            Ok(42)
        })
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn a_late_publication_failure_undoes_every_file() {
        let (_root, layout) = layout();
        let a = layout.config_file().unwrap();
        let b = layout.workspaces_file().unwrap();
        publish(&a, b"old").unwrap();
        let mut txn = Transaction::begin(&layout).unwrap();
        txn.read(&a).unwrap();
        txn.read(&b).unwrap();
        txn.write(&a, b"new").unwrap();
        txn.write(&b, b"new").unwrap();
        let err = txn
            .commit_with(|path, bytes| {
                if path == b {
                    return Err(Error::Config("injected second publication failure".into()));
                }
                publish(path, bytes)
            })
            .unwrap_err();
        assert!(err.to_string().contains("injected"));
        assert_eq!(read_optional(&a).unwrap(), Some(b"old".to_vec()));
        assert_eq!(read_optional(&b).unwrap(), None);
        consistent(&layout, || Ok(())).unwrap();
    }

    #[test]
    fn interrupted_publication_is_rejected_then_recovered() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        let record = Revision::Pending {
            id: uuid::Uuid::new_v4(),
            changes: vec![Change {
                path: path.clone(),
                before: Some(b"old".to_vec()),
                after: b"new".to_vec(),
            }],
        };
        write_revision(&layout, &record).unwrap();
        publish(&path, b"new").unwrap();
        assert!(consistent(&layout, || Ok(())).is_err());
        Transaction::recover(&layout).unwrap();
        assert_eq!(read_optional(&path).unwrap(), Some(b"old".to_vec()));
        Transaction::recover(&layout).unwrap();
        consistent(&layout, || Ok(())).unwrap();
    }

    #[test]
    fn all_read_dependencies_are_checked_before_publication() {
        let (_root, layout) = layout();
        let a = layout.config_file().unwrap();
        let b = layout.workspaces_file().unwrap();
        let mut txn = Transaction::begin(&layout).unwrap();
        txn.read(&a).unwrap();
        txn.read(&b).unwrap();
        txn.write(&a, b"ours").unwrap();
        publish(&b, b"external").unwrap();
        assert!(txn.commit().is_err());
        assert!(!a.exists());
    }

    #[test]
    fn directory_membership_is_a_read_dependency() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        let mut txn = Transaction::begin(&layout).unwrap();
        txn.directory(&layout.config_drop_in_dir().unwrap())
            .unwrap();
        txn.read(&path).unwrap();
        txn.write(&path, b"ours").unwrap();
        publish(
            &layout.config_drop_in_dir().unwrap().join("new.toml"),
            b"external",
        )
        .unwrap();
        assert!(txn.commit().is_err());
        assert!(!path.exists());
    }

    #[test]
    fn recovery_preserves_external_edits_and_keeps_the_journal_pending() {
        let (_root, layout) = layout();
        let path = layout.config_file().unwrap();
        write_revision(
            &layout,
            &Revision::Pending {
                id: uuid::Uuid::new_v4(),
                changes: vec![Change {
                    path: path.clone(),
                    before: None,
                    after: b"ours".to_vec(),
                }],
            },
        )
        .unwrap();
        publish(&path, b"external").unwrap();
        assert!(Transaction::recover(&layout).is_err());
        assert_eq!(read_optional(&path).unwrap(), Some(b"external".to_vec()));
        assert!(pending(revision(&layout).unwrap().as_ref()));
    }
}
