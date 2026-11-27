//! Classify what a directory's `.git` entry makes it.
//!
//! Classification is delegated to `gix::discover::is_git`, which follows
//! `.git` files to their git directory and distinguishes a main worktree,
//! a linked worktree (`<main>/.git/worktrees/<id>`), and a submodule
//! checkout (`<super>/.git/modules/...`).

use std::path::{Path, PathBuf};

use crate::WorkspaceError;

/// What a directory is by virtue of its `.git` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitMarker {
    /// The directory has no `.git` entry.
    Absent,
    /// The main worktree of a repository (`.git` is the git directory).
    Repository,
    /// A linked worktree. `admin_dir` is its private git directory inside
    /// the main repository (`<main>/.git/worktrees/<id>`).
    LinkedWorktree { admin_dir: PathBuf },
    /// A submodule checkout. Its content belongs to the superproject.
    Submodule,
}

impl GitMarker {
    /// Whether the directory is a repository root: a main or linked
    /// worktree. Submodule checkouts are content of their superproject.
    #[must_use]
    pub fn is_repository_root(&self) -> bool {
        matches!(self, Self::Repository | Self::LinkedWorktree { .. })
    }
}

/// Classify `dir` by its `.git` entry.
///
/// A symlinked `.git` is never followed.
///
/// # Errors
///
/// - `WorkspaceError::PathValidation` for a symlinked `.git`, or for a
///   `.git` that resolves to a git directory kind no worktree has (bare
///   repository, worktree or submodule git directory).
/// - `WorkspaceError::GitError` when `.git` exists but is not a valid git
///   directory or gitfile.
/// - `WorkspaceError::Io` when `.git` cannot be inspected.
pub fn git_marker(dir: &Path) -> Result<GitMarker, WorkspaceError> {
    use gix::discover::repository::Kind;

    let dot_git = dir.join(gix::discover::DOT_GIT_DIR);
    match std::fs::symlink_metadata(&dot_git) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(WorkspaceError::PathValidation(format!(
                "{}: symlinked .git is not followed",
                dot_git.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(GitMarker::Absent),
        Err(e) => return Err(WorkspaceError::io_at(&dot_git, e)),
    }
    let kind = gix::discover::is_git(&dot_git)
        .map_err(|e| WorkspaceError::GitError(format!("{}: {e}", dot_git.display())))?;
    match kind {
        Kind::WorkTree {
            linked_git_dir: None,
        } => Ok(GitMarker::Repository),
        Kind::WorkTree {
            linked_git_dir: Some(admin_dir),
        } => Ok(GitMarker::LinkedWorktree { admin_dir }),
        Kind::Submodule { .. } => Ok(GitMarker::Submodule),
        other => Err(WorkspaceError::PathValidation(format!(
            "{}: not a worktree git directory ({other:?})",
            dot_git.display()
        ))),
    }
}

#[cfg(test)]
pub(crate) mod test_repos {
    //! Real git repositories for tests: `gix::discover::is_git` requires
    //! `HEAD`, `objects`, and `refs`, so an empty `.git` directory is not
    //! a repository.

    use std::path::Path;

    /// Initialize a repository with one empty commit on its default branch.
    pub(crate) fn init(path: &Path) -> git2::Repository {
        std::fs::create_dir_all(path).unwrap();
        let repo = git2::Repository::init(path).unwrap();
        {
            let sig = git2::Signature::now("alice", "alice@example.invalid").unwrap();
            let tree_id = repo.index().unwrap().write_tree().unwrap();
            let tree = repo.find_tree(tree_id).unwrap();
            repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
                .unwrap();
        }
        repo
    }

    /// Add a linked worktree of `repo` at `path`.
    pub(crate) fn add_worktree(repo: &git2::Repository, name: &str, path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        repo.worktree(name, path, None).unwrap();
    }

    /// Make `path` (inside `superproject`) a submodule checkout whose git
    /// directory lives in the superproject's `.git/modules/<name>`.
    pub(crate) fn add_submodule_checkout(superproject: &Path, name: &str, path: &Path) {
        let modules = superproject.join(".git").join("modules").join(name);
        git2::Repository::init_bare(&modules).unwrap();
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(
            path.join(".git"),
            format!("gitdir: {}\n", modules.display()),
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_for_plain_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(git_marker(dir.path()).unwrap(), GitMarker::Absent);
    }

    #[test]
    fn repository_for_main_worktree() {
        let dir = tempfile::tempdir().unwrap();
        test_repos::init(dir.path());
        assert_eq!(git_marker(dir.path()).unwrap(), GitMarker::Repository);
    }

    #[test]
    fn linked_worktree_carries_admin_dir() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        let repo = test_repos::init(&main);
        let wt = dir.path().join("wt");
        test_repos::add_worktree(&repo, "wt", &wt);
        match git_marker(&wt).unwrap() {
            GitMarker::LinkedWorktree { admin_dir } => {
                assert!(
                    admin_dir.ends_with(Path::new(".git/worktrees/wt")),
                    "{admin_dir:?}"
                );
            }
            other => panic!("expected linked worktree, got {other:?}"),
        }
    }

    #[test]
    fn submodule_checkout() {
        let dir = tempfile::tempdir().unwrap();
        test_repos::init(dir.path());
        let sub = dir.path().join("Vendor");
        test_repos::add_submodule_checkout(dir.path(), "Vendor", &sub);
        assert_eq!(git_marker(&sub).unwrap(), GitMarker::Submodule);
    }

    #[test]
    fn invalid_git_dir_is_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(matches!(
            git_marker(dir.path()),
            Err(WorkspaceError::GitError(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_git_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        test_repos::init(real.path());
        std::os::unix::fs::symlink(real.path().join(".git"), dir.path().join(".git")).unwrap();
        assert!(matches!(
            git_marker(dir.path()),
            Err(WorkspaceError::PathValidation(_))
        ));
    }
}
