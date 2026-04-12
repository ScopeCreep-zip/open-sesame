//! Repository cloning and workspace.git orchestration.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use crate::{CloneTarget, WorkspaceError};

/// Clone a repository to its canonical path.
///
/// For [`CloneTarget::WorkspaceGit`], handles the special case where the org
/// directory may already exist with sibling repos. The `force` parameter
/// controls whether existing files may be overwritten during workspace init.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the clone or checkout fails.
pub fn clone_repo(
    url: &str,
    target: &CloneTarget,
    depth: Option<u32>,
    force: bool,
) -> Result<PathBuf, WorkspaceError> {
    match target {
        CloneTarget::Regular(path) => {
            if path.exists() {
                return Err(WorkspaceError::GitError(format!(
                    "target directory already exists: {}",
                    path.display()
                )));
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            gix_clone(url, path, depth)?;
            Ok(path.clone())
        }
        CloneTarget::WorkspaceGit(org_dir) => {
            clone_workspace_git(url, org_dir, force)?;
            Ok(org_dir.clone())
        }
    }
}

/// Clone via gix with optional shallow depth.
fn gix_clone(url: &str, target: &Path, depth: Option<u32>) -> Result<(), WorkspaceError> {
    let mut prepare =
        gix::prepare_clone(url, target).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    if let Some(d) = depth
        && let Some(n) = NonZeroU32::new(d)
    {
        prepare = prepare.with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(n));
    }

    let (mut checkout, _outcome) = prepare
        .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    checkout
        .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    Ok(())
}

/// Workspace.git clone with lifecycle state handling:
///
/// 1. Org dir doesn't exist → fresh gix clone.
/// 2. Org dir exists with `.git` and commits → pull via git2.
/// 3. Org dir exists with `.git` but unborn HEAD (failed prior init) →
///    requires `force` to remove broken `.git` and re-init.
/// 4. Org dir exists without `.git` → git2 init-around-existing (may require
///    `force` if existing files would be overwritten).
fn clone_workspace_git(url: &str, org_dir: &Path, force: bool) -> Result<(), WorkspaceError> {
    if !org_dir.exists() {
        if let Some(parent) = org_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return gix_clone(url, org_dir, None);
    }

    if org_dir.join(".git").is_dir() {
        if super::workspace::is_unborn(org_dir) {
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
            // Fall through to init_around_existing below.
        } else {
            tracing::info!(path = %org_dir.display(), "workspace.git already exists, pulling");
            return super::workspace::pull_ff_only(org_dir);
        }
    }

    tracing::info!(
        path = %org_dir.display(),
        "initializing workspace.git around existing content"
    );
    super::workspace::init_around_existing(url, org_dir, force)
}
