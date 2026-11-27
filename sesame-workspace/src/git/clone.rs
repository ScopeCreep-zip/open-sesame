//! Repository cloning and workspace.git orchestration.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use core_workspace_types::{RemoteEndpoint, RemoteIdentity};

use crate::{CloneFailureKind, WorkspaceError};

/// What exists at a clone target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneTarget {
    /// Nothing exists at the path; a clone may create it.
    Absent,
    /// A repository whose `origin` is exactly the requested remote
    /// identity exists at the path; it can be adopted.
    SameRepository,
}

/// Inspect a clone target before anything is written.
///
/// Placement is lowercase, so remotes differing only in case share one
/// directory. Only the exact remote identity (host, namespace and
/// repository spelling) is the same repository.
///
/// # Errors
///
/// - `WorkspaceError::PlacementConflict` when a repository with a
///   different `origin` identity occupies the placement.
/// - `WorkspaceError::PathValidation` when the path exists but is not a
///   repository root (inside a workspace repository: workspace content),
///   or is a repository without an `origin` remote.
/// - The `git_marker`, `remote_url`, and `parse_url` errors.
pub fn inspect_clone_target(
    target: &Path,
    requested: &RemoteIdentity,
) -> Result<CloneTarget, WorkspaceError> {
    match std::fs::symlink_metadata(target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CloneTarget::Absent),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    if !super::git_marker(target)?.is_repository_root() {
        return Err(WorkspaceError::PathValidation(format!(
            "{} exists and is not a git repository root; inside a workspace \
             repository it is that repository's content",
            target.display()
        )));
    }
    let Some(remote) = super::remote_url(target)? else {
        return Err(WorkspaceError::PathValidation(format!(
            "{} is a git repository without an 'origin' remote",
            target.display()
        )));
    };
    match crate::convention::parse_url(&remote)? {
        crate::convention::RemoteRef::Repository(existing) if existing == *requested => {
            Ok(CloneTarget::SameRepository)
        }
        _ => Err(WorkspaceError::PlacementConflict {
            path: target.to_path_buf(),
            existing: crate::net::redact_credentials(&remote),
            requested: requested.to_https_url(),
        }),
    }
}

/// Clone a repository to a target directory.
///
/// The target directory must not already exist. Parent directories
/// are created as needed. The endpoint is rendered to a URL string
/// for the gix transport layer.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the target exists or checkout
/// fails, and `WorkspaceError::CloneFailed` if the fetch fails.
pub fn clone_to(
    endpoint: &RemoteEndpoint,
    target: &Path,
    depth: Option<u32>,
) -> Result<PathBuf, WorkspaceError> {
    if target.exists() {
        return Err(WorkspaceError::GitError(format!(
            "target directory already exists: {}",
            target.display()
        )));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    gix_clone(&endpoint.to_url(), target, depth)?;
    Ok(target.to_path_buf())
}

/// Clone or update a workspace.git at an org-level directory.
///
/// Handles these lifecycle states:
/// 1. Org dir absent: fresh clone.
/// 2. Org dir has .git with commits: fast-forward pull.
/// 3. Org dir has .git with unborn HEAD (failed prior init): requires
///    `force` to remove the broken .git and re-initialize.
/// 4. Org dir exists without .git: init-around-existing. Requires
///    `force` if existing files would be overwritten.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the clone, pull, or init
/// fails.
pub fn clone_workspace_git(
    endpoint: &RemoteEndpoint,
    org_dir: &Path,
    force: bool,
) -> Result<PathBuf, WorkspaceError> {
    let url = endpoint.to_url();

    if !org_dir.exists() {
        if let Some(parent) = org_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        gix_clone(&url, org_dir, None)?;
        return Ok(org_dir.to_path_buf());
    }

    if super::git_marker(org_dir)?.is_repository_root() {
        if super::workspace::is_unborn(org_dir)? {
            if !force {
                return Err(WorkspaceError::GitError(format!(
                    "workspace at {} has a broken .git from a failed prior init.\n\
                     Use --force to remove it and re-initialize.",
                    org_dir.display(),
                )));
            }
            tracing::warn!(
                path = %org_dir.display(),
                "removing broken workspace.git (unborn HEAD from failed prior init)"
            );
            std::fs::remove_dir_all(org_dir.join(".git"))?;
        } else {
            tracing::info!(path = %org_dir.display(), "workspace.git already exists, pulling");
            super::workspace::pull_ff_only(org_dir)?;
            return Ok(org_dir.to_path_buf());
        }
    }

    tracing::info!(
        path = %org_dir.display(),
        "initializing workspace.git around existing content"
    );
    super::workspace::init_around_existing(&url, org_dir, force)?;
    Ok(org_dir.to_path_buf())
}

/// Clone via gix with optional shallow depth.
///
/// Transport configuration (`remote::gix_transport_overrides`) goes in as
/// in-memory config overrides: gix-transport's `http::Options` is not
/// publicly constructible.
fn gix_clone(url: &str, target: &Path, depth: Option<u32>) -> Result<(), WorkspaceError> {
    let overrides = super::remote::gix_transport_overrides(url)?;
    let mut prepare = gix::prepare_clone(url, target)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?
        .with_in_memory_config_overrides(overrides);

    if let Some(d) = depth
        && let Some(n) = NonZeroU32::new(d)
    {
        prepare = prepare.with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(n));
    }

    let (mut checkout, _outcome) = prepare
        .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .map_err(|e| WorkspaceError::CloneFailed {
            kind: classify_clone_failure(&e),
            message: format!("{e:#}"),
        })?;

    checkout
        .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    Ok(())
}

/// Classify a fetch failure by walking its source chain for gix's typed
/// transport errors.
///
/// gix's HTTP transport turns a 401 into `io::ErrorKind::PermissionDenied`
/// (`gix_transport::client::http::Http` contract). In gix 0.91 the
/// handshake raises rejected credentials with that `io::Error` as source,
/// so it is found bare or inside `client::Error::Io`. A credential helper
/// that returns nothing is raised as an untyped message without the 401
/// and classifies as `Other`.
pub(crate) fn classify_clone_failure(
    error: &(dyn std::error::Error + 'static),
) -> CloneFailureKind {
    use gix::protocol::transport::client::Error as Transport;

    let denied = |io: &std::io::Error| io.kind() == std::io::ErrorKind::PermissionDenied;
    let mut current = Some(error);
    while let Some(e) = current {
        match e.downcast_ref::<Transport>() {
            Some(Transport::AuthenticationUnsupported | Transport::AuthenticationRefused(_)) => {
                return CloneFailureKind::Authentication;
            }
            Some(Transport::Io(io)) if denied(io) => return CloneFailureKind::Authentication,
            _ => {}
        }
        if e.downcast_ref::<std::io::Error>().is_some_and(denied) {
            return CloneFailureKind::Authentication;
        }
        current = e.source();
    }
    CloneFailureKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An error wrapping another, as gix's fetch errors wrap handshake
    /// and transport errors.
    #[derive(Debug, thiserror::Error)]
    #[error("fetch failed")]
    struct Wrapped(#[source] Box<dyn std::error::Error + Send + Sync>);

    #[test]
    fn rejected_credentials_io_source_is_authentication() {
        // gix 0.91 handshake: `err.and_raise(..)` keeps the 401 io::Error.
        let e = Wrapped(Box::new(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )));
        assert_eq!(classify_clone_failure(&e), CloneFailureKind::Authentication);
    }

    #[test]
    fn authentication_refused_is_authentication() {
        let e = Wrapped(Box::new(
            gix::protocol::transport::client::Error::AuthenticationRefused("clear text"),
        ));
        assert_eq!(classify_clone_failure(&e), CloneFailureKind::Authentication);
    }

    #[test]
    fn http_401_permission_denied_is_authentication() {
        let e = Wrapped(Box::new(gix::protocol::transport::client::Error::Io(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        )));
        assert_eq!(classify_clone_failure(&e), CloneFailureKind::Authentication);
    }

    #[test]
    fn other_transport_failure_is_other() {
        let e = Wrapped(Box::new(gix::protocol::transport::client::Error::Io(
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
        )));
        assert_eq!(classify_clone_failure(&e), CloneFailureKind::Other);
    }

    fn identity(url: &str) -> RemoteIdentity {
        crate::forge::RepoInfo::identity_from_clone_url(url).unwrap()
    }

    fn repo_with_origin(path: &Path, origin: &str) {
        let repo = crate::git::marker::test_repos::init(path);
        repo.remote("origin", origin).unwrap();
    }

    #[test]
    fn absent_target_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("repo");
        assert_eq!(
            inspect_clone_target(&target, &identity("https://github.com/Org/Repo")).unwrap(),
            CloneTarget::Absent
        );
    }

    #[test]
    fn exact_identity_over_another_transport_is_same_repository() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("repo");
        repo_with_origin(&target, "git@github.com:Org/Repo.git");
        assert_eq!(
            inspect_clone_target(&target, &identity("https://github.com/Org/Repo")).unwrap(),
            CloneTarget::SameRepository
        );
    }

    #[test]
    fn case_variant_identity_is_placement_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("repo");
        repo_with_origin(&target, "https://github.com/org/repo");
        let err =
            inspect_clone_target(&target, &identity("https://github.com/Org/Repo")).unwrap_err();
        let WorkspaceError::PlacementConflict {
            existing,
            requested,
            ..
        } = err
        else {
            panic!("expected placement conflict: {err}");
        };
        assert_eq!(existing, "https://github.com/org/repo");
        assert_eq!(requested, "https://github.com/Org/Repo");
    }

    #[test]
    fn non_repository_content_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join(".github");
        std::fs::create_dir_all(target.join("workflows")).unwrap();
        assert!(matches!(
            inspect_clone_target(&target, &identity("https://github.com/org/.github")),
            Err(WorkspaceError::PathValidation(_))
        ));
    }

    #[test]
    fn repository_without_origin_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("repo");
        crate::git::marker::test_repos::init(&target);
        assert!(matches!(
            inspect_clone_target(&target, &identity("https://github.com/org/repo")),
            Err(WorkspaceError::PathValidation(_))
        ));
    }

    #[test]
    fn message_text_does_not_classify() {
        let e = Wrapped(Box::new(std::io::Error::other("auth 401 403")));
        assert_eq!(classify_clone_failure(&e), CloneFailureKind::Other);
    }
}
