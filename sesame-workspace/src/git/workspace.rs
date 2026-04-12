//! git2-based operations for workspace.git lifecycle.
//!
//! These operations use bundled libgit2 because gix does not yet support:
//! - Initializing a repo around an existing populated directory + fetch + checkout
//! - Fast-forward-only pull (fetch + merge analysis + ref update + checkout)

use std::path::Path;

use crate::WorkspaceError;

/// Pull (fast-forward only) using git2.
///
/// Fetches from origin and fast-forwards the current branch. Refuses to
/// proceed if the working tree has uncommitted changes.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the pull fails, is not a
/// fast-forward, or the working tree is dirty.
pub fn pull_ff_only(repo_dir: &Path) -> Result<(), WorkspaceError> {
    let repo =
        git2::Repository::open(repo_dir).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    // Refuse to pull if the working tree has uncommitted changes.
    if repo_has_changes(&repo) {
        return Err(WorkspaceError::GitError(format!(
            "workspace at {} has uncommitted changes; commit or stash before updating",
            repo_dir.display(),
        )));
    }

    let mut remote = repo
        .find_remote("origin")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    remote
        .fetch(&["refs/heads/*:refs/remotes/origin/*"], None, None)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let fetch_head = repo
        .find_reference("FETCH_HEAD")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let fetch_commit = repo
        .reference_to_annotated_commit(&fetch_head)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let (analysis, _) = repo
        .merge_analysis(&[&fetch_commit])
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    if analysis.is_up_to_date() {
        return Ok(());
    }
    if !analysis.is_fast_forward() {
        return Err(WorkspaceError::GitError(
            "pull rejected: not a fast-forward".into(),
        ));
    }

    let mut head_ref = repo
        .head()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    head_ref
        .set_target(fetch_commit.id(), "fast-forward pull")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    Ok(())
}

/// Initialize a git repo around an existing populated directory, fetch from
/// origin, and checkout the default branch.
///
/// When `force` is false, refuses to proceed if the checkout would overwrite
/// existing files. Returns an error listing the conflicting paths so the
/// caller can inform the user.
///
/// When `force` is true, overwrites existing files with the workspace repo's
/// versions. Sibling project repos are preserved because the workspace's
/// `.gitignore` excludes them.
pub(crate) fn init_around_existing(
    url: &str,
    org_dir: &Path,
    force: bool,
) -> Result<(), WorkspaceError> {
    let repo =
        git2::Repository::init(org_dir).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    repo.remote("origin", url)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let mut remote = repo
        .find_remote("origin")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    remote
        .fetch(&["refs/heads/*:refs/remotes/origin/*"], None, None)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let commit = find_remote_head_commit(&repo)?;

    // Before checking out, see which files from the remote would overwrite
    // existing local files. If any conflict and force is not set, refuse.
    if !force {
        let tree = commit
            .tree()
            .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
        let mut conflicts = Vec::new();
        tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
            if let Some(name) = entry.name() {
                let path = if dir.is_empty() {
                    name.to_string()
                } else {
                    format!("{dir}{name}")
                };
                if org_dir.join(&path).exists() {
                    conflicts.push(path);
                }
            }
            git2::TreeWalkResult::Ok
        })
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

        if !conflicts.is_empty() {
            // Clean up the .git we just created — don't leave a broken init.
            let _ = std::fs::remove_dir_all(org_dir.join(".git"));
            return Err(WorkspaceError::GitError(format!(
                "workspace init would overwrite existing files:\n  {}\n\
                 Use --force to overwrite, or remove the conflicting files first.",
                conflicts.join("\n  "),
            )));
        }
    }

    let mut branch = repo
        .branch("main", &commit, true)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    branch
        .set_upstream(Some("origin/main"))
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    repo.set_head("refs/heads/main")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    match repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force())) {
        Ok(()) => {}
        Err(e) => {
            tracing::warn!(
                path = %org_dir.display(),
                error = %e,
                "workspace.git checkout had warnings (expected with sibling repos)"
            );
        }
    }

    Ok(())
}

/// Check if a `.git` directory exists but HEAD is unborn (no commits).
///
/// This indicates a partially failed prior init — the `.git` was created
/// but the fetch or checkout never completed.
pub(crate) fn is_unborn(org_dir: &Path) -> bool {
    let Ok(repo) = git2::Repository::open(org_dir) else {
        return false;
    };
    repo.head().is_err() && repo.is_empty().unwrap_or(true)
}

/// Find the commit at `origin/main` or `origin/master`.
fn find_remote_head_commit(repo: &git2::Repository) -> Result<git2::Commit<'_>, WorkspaceError> {
    for branch in &["refs/remotes/origin/main", "refs/remotes/origin/master"] {
        if let Ok(reference) = repo.find_reference(branch)
            && let Ok(commit) = reference.peel_to_commit()
        {
            return Ok(commit);
        }
    }
    Err(WorkspaceError::GitError(
        "could not find origin/main or origin/master after fetch".into(),
    ))
}

/// Check if a git2 repository has uncommitted changes (staged or unstaged).
fn repo_has_changes(repo: &git2::Repository) -> bool {
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(false)
        .include_ignored(false)
        .include_unmodified(false);
    match repo.statuses(Some(&mut opts)) {
        Ok(statuses) => !statuses.is_empty(),
        Err(_) => false,
    }
}
