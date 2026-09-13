//! git2-based operations for workspace.git lifecycle.
//!
//! These operations use bundled libgit2 because gix does not yet support:
//! - Initializing a repo around an existing populated directory + fetch + checkout
//! - Fast-forward-only pull (fetch + merge analysis + ref update + checkout)
//!
//! All fetch operations use `proxy_aware_fetch_options()` to honor
//! `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` env vars
//! via git2's `ProxyOptions::auto()` and explicit URL fallback.

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

    if repo_has_changes(&repo) {
        return Err(WorkspaceError::GitError(format!(
            "workspace at {} has uncommitted changes; commit or stash before updating",
            repo_dir.display(),
        )));
    }

    let mut remote = repo
        .find_remote("origin")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let origin_url: Option<String> = remote.url().map(|u| u.to_string());
    // libgit2 does not read proxy env vars from its vendored HTTP transport.
    // ProxyOptions has no no_proxy field, so NO_PROXY is checked before
    // deciding whether to set an explicit proxy URL.
    let mut fetch_opts = proxy_aware_fetch_options(origin_url.as_deref());
    remote
        .fetch(
            &["refs/heads/*:refs/remotes/origin/*"],
            Some(&mut fetch_opts),
            None,
        )
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    // Resolve the current branch's upstream tracking reference
    // instead of using ambiguous FETCH_HEAD.
    let head = repo
        .head()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let local_branch_name = head
        .shorthand()
        .ok_or_else(|| WorkspaceError::GitError("HEAD is detached".into()))?
        .to_string();
    let tracking_ref = format!("refs/remotes/origin/{local_branch_name}");
    let tracking = repo
        .find_reference(&tracking_ref)
        .map_err(|e| WorkspaceError::GitError(format!(
            "no upstream tracking ref {tracking_ref}: {e}"
        )))?;
    let fetch_commit = repo
        .reference_to_annotated_commit(&tracking)
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

    let mut fetch_opts = proxy_aware_fetch_options(Some(url));
    remote
        .fetch(
            &["refs/heads/*:refs/remotes/origin/*"],
            Some(&mut fetch_opts),
            None,
        )
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let (commit, branch_name) = find_remote_default_branch(&repo)?;

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
            // Remove the .git created by init to avoid a broken state.
            let _ = std::fs::remove_dir_all(org_dir.join(".git"));
            return Err(WorkspaceError::GitError(format!(
                "workspace init would overwrite existing files:\n  {}\n\
                 Use --force to overwrite, or remove the conflicting files first.",
                conflicts.join("\n  "),
            )));
        }
    }

    let local_ref = format!("refs/heads/{branch_name}");
    let upstream_ref = format!("origin/{branch_name}");

    let mut branch = repo
        .branch(&branch_name, &commit, true)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    branch
        .set_upstream(Some(&upstream_ref))
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    repo.set_head(&local_ref)
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

/// Construct `FetchOptions` using the shared proxy policy.
///
/// Queries the policy for the target URL's scheme. When the policy
/// returns Direct (NO_PROXY match), leaves proxy options at default
/// (no proxy). When it returns a proxy URL, sets it explicitly.
/// When no environment proxy exists, uses auto() for gitconfig
/// fallback.
fn proxy_aware_fetch_options<'cb>(remote_url: Option<&str>) -> git2::FetchOptions<'cb> {
    let mut fetch_opts = git2::FetchOptions::new();
    let mut proxy_opts = git2::ProxyOptions::new();

    let policy = crate::net::ProxyPolicy::from_env();

    match remote_url.map(|url| policy.for_target(url)) {
        Some(crate::net::ProxyDecision::Proxy(ref endpoint)) => {
            tracing::debug!(proxy = %endpoint, "git2 fetch using proxy");
            proxy_opts.url(endpoint.url());
        }
        Some(crate::net::ProxyDecision::Direct) => {
            tracing::debug!("git2 fetch direct (host in NO_PROXY)");
            // Leave at default: no proxy, not auto().
            // auto() would read gitconfig http.proxy which contradicts
            // the NO_PROXY bypass intent.
        }
        Some(crate::net::ProxyDecision::NoEnvironmentProxy) | None => {
            proxy_opts.auto();
        }
    }

    fetch_opts.proxy_options(proxy_opts);
    fetch_opts
}

/// Find the default branch commit and name from the fetched remote.
///
/// Checks refs/remotes/origin/HEAD first, then enumerates remote
/// tracking branches. No branch names are hardcoded.
fn find_remote_default_branch(
    repo: &git2::Repository,
) -> Result<(git2::Commit<'_>, String), WorkspaceError> {
    // Try symbolic origin/HEAD first.
    if let Ok(head_ref) = repo.find_reference("refs/remotes/origin/HEAD") {
        if let Ok(resolved) = head_ref.resolve() {
            if let Some(name) = resolved.name() {
                let branch_name = name
                    .strip_prefix("refs/remotes/origin/")
                    .unwrap_or(name)
                    .to_string();
                if let Ok(commit) = resolved.peel_to_commit() {
                    return Ok((commit, branch_name));
                }
            }
        }
    }

    // Enumerate remote tracking branches and pick the first one.
    let branches = repo
        .branches(Some(git2::BranchType::Remote))
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    for branch_result in branches {
        let (branch, _) = branch_result
            .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
        let name = match branch.name() {
            Ok(Some(n)) => n.to_string(),
            _ => continue,
        };
        // Skip origin/HEAD itself.
        if name == "origin/HEAD" {
            continue;
        }
        let branch_name = name
            .strip_prefix("origin/")
            .unwrap_or(&name)
            .to_string();
        if let Ok(reference) = branch.into_reference().resolve() {
            if let Ok(commit) = reference.peel_to_commit() {
                return Ok((commit, branch_name));
            }
        }
    }

    Err(WorkspaceError::GitError(
        "no remote tracking branches found after fetch".into(),
    ))
}

/// Check if a git2 repository has uncommitted changes, unstaged
/// changes, or untracked files.
///
/// Matches the semantics of `git status --porcelain` and the gix
/// inspection status check. Includes untracked files so the dirty
/// definition is consistent across git2 and gix consumers.
///
/// Status read failures return true (fail closed) to prevent
/// pull or overwrite operations on an unreadable working tree.
fn repo_has_changes(repo: &git2::Repository) -> bool {
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true)
        .include_ignored(false)
        .include_unmodified(false);
    match repo.statuses(Some(&mut opts)) {
        Ok(statuses) => !statuses.is_empty(),
        Err(_) => true,
    }
}

// Proxy tests are in crate::net::tests. The proxy_aware_fetch_options
// function consumes the shared ProxyPolicy and does not contain
// independently testable logic beyond adapter wiring.
