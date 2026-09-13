//! Repository cloning and workspace.git orchestration.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use core_workspace_types::RemoteEndpoint;

use crate::WorkspaceError;

/// Clone a repository to a target directory.
///
/// The target directory must not already exist. Parent directories
/// are created as needed. The endpoint is rendered to a URL string
/// for the gix transport layer.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the target exists or the
/// clone fails.
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

    if crate::has_git_dir(org_dir) {
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
/// Applies shared proxy policy through in-memory config overrides.
/// This is the public API for injecting transport configuration
/// into `prepare_clone`, since gix-transport's `http::Options` type is
/// not publicly accessible for direct construction.
fn gix_clone(url: &str, target: &Path, depth: Option<u32>) -> Result<(), WorkspaceError> {
    let policy = crate::net::ProxyPolicy::from_env();
    let decision = policy.for_target(url);

    let mut overrides: Vec<String> = Vec::new();
    match &decision {
        crate::net::ProxyDecision::Proxy(endpoint) => {
            tracing::debug!(proxy = %endpoint, "gix clone using proxy");
            overrides.push(format!("http.proxy={}", endpoint.url()));
        }
        crate::net::ProxyDecision::Direct => {
            tracing::debug!("gix clone direct (host in NO_PROXY)");
            // Empty proxy string disables proxy in gix.
            overrides.push("http.proxy=".into());
        }
        crate::net::ProxyDecision::NoEnvironmentProxy => {
            // No override: gix reads http.proxy from gitconfig.
        }
    }

    // Connect timeout and stall detection.
    overrides.push("gitoxide.http.connectTimeout=10000".into());

    let mut prepare =
        gix::prepare_clone(url, target).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    if !overrides.is_empty() {
        prepare = prepare.with_in_memory_config_overrides(overrides);
    }

    if let Some(d) = depth
        && let Some(n) = NonZeroU32::new(d)
    {
        prepare = prepare.with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(n));
    }

    // gix 0.72 may panic inside fetch_then_checkout on connection
    // failure ("refmap always performs handshake"). Suppress the
    // panic hook to prevent stack traces on stderr.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let fetch_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prepare
            .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)
    }));
    std::panic::set_hook(prev_hook);

    let (mut checkout, _outcome) = match fetch_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => return Err(WorkspaceError::GitError(format!("{e}"))),
        Err(panic_payload) => {
            // Clean up the partially-created target directory.
            let _ = std::fs::remove_dir_all(target);
            let msg = panic_payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            return Err(WorkspaceError::GitError(format!(
                "git transport failed (gix panic): {msg}"
            )));
        }
    };

    checkout
        .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    Ok(())
}
