//! Local repository inspection — no network, no mutation.

use std::path::Path;

use crate::WorkspaceError;

/// Check if a path is a git repository.
#[must_use]
pub fn is_git_repo(path: &Path) -> bool {
    path.join(".git").exists()
}

/// Get the remote URL for a git repository (origin).
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the repository cannot be opened.
pub fn remote_url(path: &Path) -> Result<Option<String>, WorkspaceError> {
    if !path.join(".git").is_dir() && !path.join(".git").is_file() {
        return Ok(None);
    }

    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let Ok(remote) = repo.find_remote("origin") else {
        return Ok(None);
    };

    Ok(remote
        .url(gix::remote::Direction::Fetch)
        .map(|u| u.to_bstring().to_string()))
}

/// Get the current branch name. Returns `"HEAD"` for detached HEAD.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the repository cannot be opened.
pub fn current_branch(path: &Path) -> Result<String, WorkspaceError> {
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let name = repo
        .head_name()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    match name {
        Some(full_name) => Ok(full_name.shorten().to_string()),
        None => Ok("HEAD".into()),
    }
}

/// Check if the working tree is clean (no uncommitted changes, no untracked files).
///
/// Uses the full status iterator so untracked files count as dirty, matching
/// the behavior of `git status --porcelain`.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the status check fails.
pub fn is_clean(path: &Path) -> Result<bool, WorkspaceError> {
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let has_changes = repo
        .status(gix::progress::Discard)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?
        .into_iter(Vec::new())
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?
        .next()
        .is_some();
    Ok(!has_changes)
}

/// Get the HEAD commit as a short hash string (e.g. "700defa").
/// Returns `None` if HEAD is unborn (no commits yet).
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the repository cannot be opened.
pub fn head_commit_short(path: &Path) -> Result<Option<String>, WorkspaceError> {
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let head = repo
        .head()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    match head.id() {
        Some(id) => {
            let hex = id.to_hex_with_len(7).to_string();
            Ok(Some(hex))
        }
        None => Ok(None),
    }
}

/// Get the remote tracking branch commit as a short hash string.
/// Looks up `refs/remotes/origin/{branch}` where branch defaults to "main".
/// Returns `None` if the tracking ref doesn't exist.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the repository cannot be opened.
pub fn remote_tracking_commit_short(
    path: &Path,
    branch: &str,
) -> Result<Option<String>, WorkspaceError> {
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let refname = format!("refs/remotes/origin/{branch}");
    match repo.find_reference(&refname) {
        Ok(reference) => {
            let id = reference.id().to_hex_with_len(7).to_string();
            Ok(Some(id))
        }
        Err(_) => Ok(None),
    }
}

/// Get the first line of the HEAD commit message.
/// Returns `None` if HEAD is unborn.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the repository cannot be opened.
pub fn head_commit_summary(path: &Path) -> Result<Option<String>, WorkspaceError> {
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let head = repo
        .head()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let Some(id) = head.id() else {
        return Ok(None);
    };
    let object = id
        .object()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let commit = object
        .try_into_commit()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let message = commit.message_raw_sloppy().to_string();
    let first_line = message.lines().next().unwrap_or("").to_string();
    Ok(Some(first_line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_git_repo_false_for_plain_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_git_repo(dir.path()));
    }

    #[test]
    fn is_git_repo_true_for_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(is_git_repo(dir.path()));
    }

    #[test]
    fn remote_url_returns_none_for_non_git() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(remote_url(dir.path()).unwrap(), None);
    }

    #[test]
    fn current_branch_on_fresh_repo() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let branch = current_branch(dir.path()).unwrap();
        assert_eq!(branch, "main");
    }

    #[test]
    fn is_clean_on_fresh_repo() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        assert!(is_clean(dir.path()).unwrap());
    }
}
