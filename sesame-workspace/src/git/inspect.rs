//! Local repository queries — no network, no mutation.
//!
//! Branch, HEAD, summary, and upstream metadata are read through
//! `crate::inspection::inspect`, which opens a repository once for all
//! requested fields; this module holds only the `origin` URL lookup used
//! before a clone or adoption.

use std::path::Path;

use crate::WorkspaceError;

/// Get the remote URL for a git repository (origin).
///
/// Returns `Ok(None)` if the path is not a repository root or if the
/// repository has no origin remote configured.
///
/// # Errors
///
/// Returns the `git_marker` error for an invalid `.git`, and
/// `WorkspaceError::GitError` if the repository cannot be opened or its
/// `origin` cannot be read.
pub fn remote_url(path: &Path) -> Result<Option<String>, WorkspaceError> {
    if !super::git_marker(path)?.is_repository_root() {
        return Ok(None);
    }

    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let remote = match repo.try_find_remote("origin") {
        Some(Ok(remote)) => remote,
        None => return Ok(None),
        Some(Err(e)) => {
            return Err(WorkspaceError::GitError(format!(
                "{}: cannot read remote 'origin': {e}",
                path.display()
            )));
        }
    };

    Ok(remote
        .url(gix::remote::Direction::Fetch)
        .map(|u| u.to_bstring().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_url_returns_none_for_non_git() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(remote_url(dir.path()).unwrap(), None);
    }

    #[test]
    fn remote_url_reads_origin() {
        let dir = tempfile::tempdir().unwrap();
        let repo = crate::git::marker::test_repos::init(dir.path());
        repo.remote("origin", "https://github.com/org/repo")
            .unwrap();
        assert_eq!(
            remote_url(dir.path()).unwrap().as_deref(),
            Some("https://github.com/org/repo")
        );
    }

    #[test]
    fn remote_url_without_origin_is_none() {
        let dir = tempfile::tempdir().unwrap();
        crate::git::marker::test_repos::init(dir.path());
        assert_eq!(remote_url(dir.path()).unwrap(), None);
    }
}
