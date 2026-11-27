//! Linked-worktree link files and their rewrite when directories move.
//!
//! A linked worktree is joined to its repository by link files, read by
//! `gix` (`gix::worktree::Proxy::base`, `gix::discover::is_git`) and
//! libgit2 (`git_worktree__read_link`):
//! - `<admin_dir>/gitdir`: the path of the worktree's `.git` file;
//! - `<admin_dir>/commondir`: the main repository's git directory, which
//!   `git worktree add` writes relative (`../..`) and libgit2 writes
//!   absolute;
//! - `<worktree>/.git`: `gitdir: <admin_dir>`.
//!
//! Renaming a directory above either side leaves absolute stored paths
//! naming the old location; both readers resolve a relative stored path
//! against `<admin_dir>`, so it moves with it. Neither gix nor git2
//! provides `git worktree repair`, so the absolute stored paths are
//! rewritten here, through the same rename map that rewrites stored
//! configuration paths.

use std::path::{Path, PathBuf};

use crate::WorkspaceError;

/// A worktree link file whose stored path a rename changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeLinkRewrite {
    /// The link file, at its location after the renames.
    pub file: PathBuf,
    /// The stored path before the renames.
    pub from: PathBuf,
    /// The stored path after the renames.
    pub to: PathBuf,
}

/// The two ends of one linked worktree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WorktreeLink {
    /// The worktree's private git directory (`<main>/.git/worktrees/<id>`).
    admin_dir: PathBuf,
    /// The worktree's `.git` file.
    dot_git: PathBuf,
    /// `<admin_dir>/commondir` when it stores an absolute path (libgit2
    /// writes it absolute, `git worktree add` writes `../..`). A relative
    /// value is invariant under renames above the main repository.
    commondir: Option<PathBuf>,
}

impl WorktreeLink {
    /// The links of every linked worktree of the repository at `repo_dir`.
    ///
    /// # Errors
    ///
    /// `WorkspaceError::GitError` when the repository cannot be opened,
    /// `WorkspaceError::Io` when its `worktrees` directory cannot be read,
    /// and the `from_admin_dir` errors.
    pub(crate) fn of_repository(repo_dir: &Path) -> Result<Vec<Self>, WorkspaceError> {
        let repo = gix::open(repo_dir)
            .map_err(|e| WorkspaceError::GitError(format!("{}: {e}", repo_dir.display())))?;
        repo.worktrees()
            .map_err(|e| {
                WorkspaceError::GitError(format!(
                    "{}: cannot list worktrees: {e}",
                    repo_dir.display()
                ))
            })?
            .iter()
            .map(|proxy| Self::from_admin_dir(proxy.git_dir()))
            .collect()
    }

    /// The link of the linked worktree whose private git directory is
    /// `admin_dir`. A relative stored path is relative to `admin_dir`.
    ///
    /// # Errors
    ///
    /// `WorkspaceError::PathValidation` when `<admin_dir>/gitdir` is
    /// missing, `WorkspaceError::Io` when it cannot be read.
    pub(crate) fn from_admin_dir(admin_dir: &Path) -> Result<Self, WorkspaceError> {
        let gitdir_file = admin_dir.join("gitdir");
        let stored = gix::discover::path::from_plain_file(&gitdir_file).ok_or_else(|| {
            WorkspaceError::PathValidation(format!(
                "linked worktree admin directory has no gitdir file: {}",
                gitdir_file.display()
            ))
        })??;
        let commondir = match gix::discover::path::from_plain_file(&admin_dir.join("commondir")) {
            None => None,
            Some(path) => Some(path?).filter(|p| p.is_absolute()),
        };
        Ok(Self {
            admin_dir: admin_dir.to_path_buf(),
            dot_git: admin_dir.join(stored),
            commondir,
        })
    }
}

/// Write `prefix`, `path`, and a newline to the link file `file`,
/// readable by other git tooling (0644, as git writes it).
fn write_link_file(file: &Path, prefix: &[u8], path: &Path) -> Result<(), WorkspaceError> {
    let mut contents = prefix.to_vec();
    let bytes = gix::path::into_bstr(path).map_err(|e| {
        WorkspaceError::PathValidation(format!("{}: not representable in git: {e}", path.display()))
    })?;
    contents.extend_from_slice(&bytes);
    contents.push(b'\n');
    core_layout::file::write(file, &contents, core_layout::file::Mode::PublicRead)?;
    Ok(())
}

/// Rewrite every link file of each worktree whose stored path `map`
/// changes; `map` takes a pre-rename path to its post-rename path.
///
/// Links are deduplicated, so a worktree reached from its repository and
/// from its own checkout is rewritten once. Without `apply`, only reports.
///
/// # Errors
///
/// `WorkspaceError::Io` when a link file cannot be written; rewrites
/// completed before it are on disk.
pub(crate) fn rewrite_worktree_links(
    links: &[WorktreeLink],
    map: &dyn Fn(&Path) -> PathBuf,
    apply: bool,
) -> Result<Vec<WorktreeLinkRewrite>, WorkspaceError> {
    let mut links = links.to_vec();
    links.sort();
    links.dedup();

    let mut rewrites = Vec::new();
    for link in links {
        let admin_dir = map(&link.admin_dir);
        let dot_git = map(&link.dot_git);
        if dot_git != link.dot_git {
            let file = admin_dir.join("gitdir");
            if apply {
                write_link_file(&file, b"", &dot_git)?;
            }
            rewrites.push(WorktreeLinkRewrite {
                file,
                from: link.dot_git.clone(),
                to: dot_git.clone(),
            });
        }
        if let Some(common) = &link.commondir {
            let mapped = map(common);
            if mapped != *common {
                let file = admin_dir.join("commondir");
                if apply {
                    write_link_file(&file, b"", &mapped)?;
                }
                rewrites.push(WorktreeLinkRewrite {
                    file,
                    from: common.clone(),
                    to: mapped,
                });
            }
        }
        if admin_dir != link.admin_dir {
            if apply {
                write_link_file(&dot_git, b"gitdir: ", &admin_dir)?;
            }
            rewrites.push(WorktreeLinkRewrite {
                file: dot_git,
                from: link.admin_dir,
                to: admin_dir,
            });
        }
    }
    Ok(rewrites)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::marker::test_repos;

    fn prefix_map(from: PathBuf, to: PathBuf) -> impl Fn(&Path) -> PathBuf {
        move |path: &Path| match path.strip_prefix(&from) {
            Ok(rest) if rest.as_os_str().is_empty() => to.clone(),
            Ok(rest) => to.join(rest),
            Err(_) => path.to_path_buf(),
        }
    }

    #[test]
    fn links_survive_renaming_the_shared_parent() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("Org");
        let main = old.join("main");
        let repo = test_repos::init(&main);
        test_repos::add_worktree(&repo, "feature", &old.join("feature"));
        drop(repo);

        let links = WorktreeLink::of_repository(&main).unwrap();
        assert_eq!(links.len(), 1);

        let new = dir.path().join("org");
        std::fs::rename(&old, &new).unwrap();
        let rewrites =
            rewrite_worktree_links(&links, &prefix_map(old.clone(), new.clone()), true).unwrap();
        // gitdir, commondir (absolute, written by libgit2), and `.git`.
        assert_eq!(rewrites.len(), 3, "{rewrites:?}");

        let repo = git2::Repository::open(new.join("main")).unwrap();
        let worktree = repo.find_worktree("feature").unwrap();
        worktree.validate().unwrap();
        git2::Repository::open(new.join("feature")).unwrap();
    }

    #[test]
    fn dry_run_reports_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("Org").join("main");
        let repo = test_repos::init(&main);
        let wt = dir.path().join("Org").join("feature");
        test_repos::add_worktree(&repo, "feature", &wt);
        let before = std::fs::read(wt.join(".git")).unwrap();

        let links = WorktreeLink::of_repository(&main).unwrap();
        let rewrites = rewrite_worktree_links(
            &links,
            &prefix_map(dir.path().join("Org"), dir.path().join("org")),
            false,
        )
        .unwrap();
        assert_eq!(rewrites.len(), 3);
        assert_eq!(std::fs::read(wt.join(".git")).unwrap(), before);
    }

    #[test]
    fn unaffected_links_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        let repo = test_repos::init(&main);
        test_repos::add_worktree(&repo, "feature", &dir.path().join("feature"));
        let links = WorktreeLink::of_repository(&main).unwrap();
        let rewrites = rewrite_worktree_links(
            &links,
            &prefix_map(dir.path().join("Elsewhere"), dir.path().join("elsewhere")),
            true,
        )
        .unwrap();
        assert!(rewrites.is_empty());
    }

    #[test]
    fn duplicate_links_rewrite_once() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("Org").join("main");
        let repo = test_repos::init(&main);
        test_repos::add_worktree(&repo, "feature", &dir.path().join("Org").join("feature"));
        let mut links = WorktreeLink::of_repository(&main).unwrap();
        links.extend(links.clone());
        let rewrites = rewrite_worktree_links(
            &links,
            &prefix_map(dir.path().join("Org"), dir.path().join("org")),
            false,
        )
        .unwrap();
        assert_eq!(rewrites.len(), 3);
    }
}
