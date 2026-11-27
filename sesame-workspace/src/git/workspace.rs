//! git2-based operations for workspace.git lifecycle.
//!
//! These operations use bundled libgit2 because gix does not yet support:
//! - Initializing a repo around an existing populated directory + fetch + checkout
//! - Fast-forward-only pull (fetch + merge analysis + ref update + checkout)
//!
//! All fetch operations use `proxy_aware_fetch_options()`, which maps the
//! shared proxy decision (`net::ProxyPolicy`) onto git2's
//! `ProxyOptions`: an explicit proxy URL, no proxy for a `NO_PROXY`
//! match, and `auto()` (gitconfig `http.proxy`) when the environment
//! configures none.

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

    if repo_has_changes(&repo)? {
        return Err(WorkspaceError::GitError(format!(
            "workspace at {} has uncommitted changes; commit or stash before updating",
            repo_dir.display(),
        )));
    }

    let mut remote = repo
        .find_remote("origin")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let origin_url = remote
        .url()
        .map_err(|e| WorkspaceError::GitError(format!("origin URL: {e}")))?
        .to_owned();
    // libgit2 does not read proxy env vars from its vendored HTTP transport.
    // ProxyOptions has no no_proxy field, so NO_PROXY is checked before
    // deciding whether to set an explicit proxy URL.
    let mut fetch_opts = proxy_aware_fetch_options(&origin_url)?;
    remote
        .fetch(
            &["refs/heads/*:refs/remotes/origin/*"],
            Some(&mut fetch_opts),
            None,
        )
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    // A detached HEAD has no branch to fast-forward; its shorthand is
    // "HEAD", which would resolve through refs/remotes/origin/HEAD.
    if repo
        .head_detached()
        .map_err(|e| WorkspaceError::GitError(format!("cannot read HEAD: {e}")))?
    {
        return Err(WorkspaceError::GitError(format!(
            "workspace at {} has a detached HEAD; check out a branch before updating",
            repo_dir.display(),
        )));
    }
    // Resolve the current branch's upstream tracking reference
    // instead of using ambiguous FETCH_HEAD.
    let head = repo
        .head()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let local_branch_name = head
        .shorthand()
        .map_err(|e| WorkspaceError::GitError(format!("current branch name: {e}")))?
        .to_string();
    let tracking_ref = format!("refs/remotes/origin/{local_branch_name}");
    let tracking = repo.find_reference(&tracking_ref).map_err(|e| {
        WorkspaceError::GitError(format!("no upstream tracking ref {tracking_ref}: {e}"))
    })?;
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
///
/// Regardless of `force`, refuses when a tracked path lies inside an
/// existing member repository directory: checking it out would write
/// workspace files into that repository's working tree.
pub(crate) fn init_around_existing(
    url: &str,
    org_dir: &Path,
    force: bool,
) -> Result<(), WorkspaceError> {
    let repo =
        git2::Repository::init(org_dir).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let (commit, branch_name) = match fetch_default_branch(&repo, url) {
        Ok(found) => found,
        Err(e) => return Err(abandon_init(org_dir, e)),
    };

    let tree = commit
        .tree()
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let tracked = tracked_files(&tree)?;

    let overlaps = member_overlaps(org_dir, &tracked)?;
    if !overlaps.is_empty() {
        return Err(abandon_init(
            org_dir,
            WorkspaceError::GitError(format!(
                "workspace repository tracks paths inside existing member repositories:\n  {}\n\
                 Move the member repositories or fix the workspace repository first.",
                overlaps.join("\n  "),
            )),
        ));
    }

    if !force {
        let conflicts: Vec<&String> = tracked
            .iter()
            .filter(|path| org_dir.join(path).exists())
            .collect();
        if !conflicts.is_empty() {
            let listed: Vec<&str> = conflicts.iter().map(|path| path.as_str()).collect();
            return Err(abandon_init(
                org_dir,
                WorkspaceError::GitError(format!(
                    "workspace init would overwrite existing files:\n  {}\n\
                     Use --force to overwrite, or remove the conflicting files first.",
                    listed.join("\n  "),
                )),
            ));
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

    // Sibling member repositories are untracked (the workspace's
    // .gitignore excludes them), so a forced checkout does not touch them;
    // a checkout failure leaves tracked files partially written and is an
    // error.
    repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
        .map_err(|e| {
            WorkspaceError::GitError(format!(
                "workspace.git checkout into {} failed: {e}",
                org_dir.display()
            ))
        })?;

    Ok(())
}

/// Add `origin`, fetch its branches, and resolve the branch the remote
/// advertises as its default (`HEAD`).
fn fetch_default_branch<'repo>(
    repo: &'repo git2::Repository,
    url: &str,
) -> Result<(git2::Commit<'repo>, String), WorkspaceError> {
    let mut remote = repo
        .remote("origin", url)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let mut fetch_opts = proxy_aware_fetch_options(url)?;
    remote
        .fetch(
            &["refs/heads/*:refs/remotes/origin/*"],
            Some(&mut fetch_opts),
            None,
        )
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    // Available after the fetch disconnects (libgit2 keeps the last
    // reference advertisement). The fetch refspec never writes
    // refs/remotes/origin/HEAD, so this is the only default-branch source.
    let default = remote
        .default_branch()
        .map_err(|e| WorkspaceError::GitError(format!("remote {url} advertises no HEAD: {e}")))?;
    let full = default
        .as_str()
        .map_err(|e| WorkspaceError::GitError(format!("remote {url} default branch: {e}")))?;
    let branch_name = full
        .strip_prefix("refs/heads/")
        .ok_or_else(|| {
            WorkspaceError::GitError(format!(
                "remote {url} HEAD points outside refs/heads: {full}"
            ))
        })?
        .to_string();
    let tracking = format!("refs/remotes/origin/{branch_name}");
    let commit = repo
        .find_reference(&tracking)
        .and_then(|r| r.peel_to_commit())
        .map_err(|e| WorkspaceError::GitError(format!("{tracking} after fetch: {e}")))?;
    Ok((commit, branch_name))
}

/// Remove the `.git` that `init_around_existing` created, so a refused
/// or failed init leaves no unborn repository behind, and return `cause`.
/// A removal failure is appended to the error.
fn abandon_init(org_dir: &Path, cause: WorkspaceError) -> WorkspaceError {
    let git_dir = org_dir.join(".git");
    match std::fs::remove_dir_all(&git_dir) {
        Ok(()) => cause,
        Err(e) => WorkspaceError::GitError(format!(
            "{cause}\nadditionally, removing {} failed: {e}",
            git_dir.display()
        )),
    }
}

/// Every non-directory path `tree` tracks, `/`-separated.
///
/// # Errors
///
/// `WorkspaceError::GitError` when a tracked name is not UTF-8 (the walk
/// stops there: an unlisted path would escape the overwrite and
/// member-overlap checks), or the walk fails.
fn tracked_files(tree: &git2::Tree<'_>) -> Result<Vec<String>, WorkspaceError> {
    let mut paths = Vec::new();
    let mut invalid = None;
    let walked = tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(git2::ObjectType::Tree) {
            return git2::TreeWalkResult::Ok;
        }
        match entry.name() {
            Ok(name) => {
                paths.push(format!("{dir}{name}"));
                git2::TreeWalkResult::Ok
            }
            Err(e) => {
                invalid = Some(format!(
                    "tracked path {dir}{} is not UTF-8: {e}",
                    String::from_utf8_lossy(entry.name_bytes())
                ));
                git2::TreeWalkResult::Abort
            }
        }
    });
    if let Some(message) = invalid {
        return Err(WorkspaceError::GitError(message));
    }
    walked.map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    Ok(paths)
}

/// The tracked paths that lie inside an existing repository root below
/// `org_dir`, each with the repository directory it falls in.
fn member_overlaps(org_dir: &Path, tracked: &[String]) -> Result<Vec<String>, WorkspaceError> {
    let mut is_member = std::collections::HashMap::<String, bool>::new();
    let mut overlaps = Vec::new();
    for path in tracked {
        let Some((dirs, _file)) = path.rsplit_once('/') else {
            continue;
        };
        let mut prefix = String::new();
        for component in dirs.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let member = if let Some(&member) = is_member.get(&prefix) {
                member
            } else {
                let member = super::git_marker(&org_dir.join(&prefix))?.is_repository_root();
                is_member.insert(prefix.clone(), member);
                member
            };
            if member {
                overlaps.push(format!("{path} (inside {prefix})"));
                break;
            }
        }
    }
    Ok(overlaps)
}

/// Whether the repository at `org_dir` has an unborn HEAD (no commits).
///
/// This indicates a partially failed prior init — the `.git` was created
/// but the fetch or checkout never completed.
///
/// # Errors
///
/// `WorkspaceError::GitError` when the repository cannot be opened or its
/// HEAD cannot be read for a reason other than being unborn.
pub(crate) fn is_unborn(org_dir: &Path) -> Result<bool, WorkspaceError> {
    let repo = git2::Repository::open(org_dir)
        .map_err(|e| WorkspaceError::GitError(format!("{}: {e}", org_dir.display())))?;
    match repo.head() {
        Ok(_) => Ok(false),
        Err(e) if e.code() == git2::ErrorCode::UnbornBranch => Ok(true),
        Err(e) => Err(WorkspaceError::GitError(format!(
            "{}: cannot read HEAD: {e}",
            org_dir.display()
        ))),
    }
}

/// Construct `FetchOptions` for `remote_url` using the shared proxy policy.
///
/// Queries the policy for the target URL's scheme. When the policy
/// returns Direct (`NO_PROXY` match), leaves proxy options at default
/// (no proxy). When it returns a proxy URL, sets it explicitly.
/// When no environment proxy exists, uses `auto()` for gitconfig
/// fallback.
///
/// # Errors
///
/// The `ProxyPolicy::from_env` errors.
fn proxy_aware_fetch_options<'cb>(
    remote_url: &str,
) -> Result<git2::FetchOptions<'cb>, WorkspaceError> {
    let mut fetch_opts = git2::FetchOptions::new();
    let mut proxy_opts = git2::ProxyOptions::new();

    let policy = crate::net::ProxyPolicy::from_env()?;

    match policy.for_target(remote_url) {
        crate::net::ProxyDecision::Proxy(ref endpoint) => {
            tracing::debug!(proxy = %endpoint, "git2 fetch using proxy");
            proxy_opts.url(endpoint.url());
        }
        crate::net::ProxyDecision::Direct => {
            tracing::debug!("git2 fetch direct (host in NO_PROXY)");
            // Leave at default: no proxy, not auto().
            // auto() would read gitconfig http.proxy which contradicts
            // the NO_PROXY bypass intent.
        }
        crate::net::ProxyDecision::NoEnvironmentProxy => {
            proxy_opts.auto();
        }
    }

    fetch_opts.proxy_options(proxy_opts);
    Ok(fetch_opts)
}

/// Check if a git2 repository has uncommitted changes, unstaged
/// changes, or untracked files.
///
/// Matches the semantics of `git status --porcelain` and the gix
/// inspection status check. Includes untracked files so the dirty
/// definition is consistent across git2 and gix consumers.
///
/// # Errors
///
/// A status read failure is an error, so pull and overwrite operations
/// never run on an unreadable working tree.
fn repo_has_changes(repo: &git2::Repository) -> Result<bool, WorkspaceError> {
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true)
        .include_ignored(false)
        .include_unmodified(false);
    repo.statuses(Some(&mut opts))
        .map(|statuses| !statuses.is_empty())
        .map_err(|e| WorkspaceError::GitError(format!("cannot read working tree status: {e}")))
}

// Proxy tests are in crate::net::tests. The proxy_aware_fetch_options
// function consumes the shared ProxyPolicy and does not contain
// independently testable logic beyond adapter wiring.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::marker::test_repos;

    fn tree_of(files: &[&str]) -> (tempfile::TempDir, git2::Repository, git2::Oid) {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let mut index = repo.index().unwrap();
        for file in files {
            let path = dir.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
            index.add_path(Path::new(file)).unwrap();
        }
        let oid = index.write_tree().unwrap();
        (dir, repo, oid)
    }

    #[test]
    fn tracked_files_lists_files_not_directories() {
        let (_dir, repo, oid) = tree_of(&["README.md", "docs/guide.md"]);
        let tree = repo.find_tree(oid).unwrap();
        assert_eq!(
            tracked_files(&tree).unwrap(),
            vec!["README.md".to_string(), "docs/guide.md".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_tracked_path_is_an_error_not_skipped() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let name = std::ffi::OsStr::from_bytes(b"bad\xff.txt");
        std::fs::write(dir.path().join(name), b"x").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new(name)).unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let err = tracked_files(&tree).unwrap_err();
        assert!(err.to_string().contains("not UTF-8"), "{err}");
    }

    #[test]
    fn pull_on_detached_head_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("origin");
        test_repos::init(&origin);
        let clone_dir = dir.path().join("clone");
        let clone =
            git2::Repository::clone(&format!("file://{}", origin.display()), &clone_dir).unwrap();
        let head = clone.head().unwrap().target().unwrap();
        clone.set_head_detached(head).unwrap();
        let err = pull_ff_only(&clone_dir).unwrap_err();
        assert!(err.to_string().contains("detached HEAD"), "{err}");
    }

    #[test]
    fn member_overlaps_finds_paths_inside_member_repositories() {
        let org = tempfile::tempdir().unwrap();
        test_repos::init(&org.path().join(".github"));
        std::fs::create_dir_all(org.path().join("docs")).unwrap();
        let tracked = vec![
            ".github/workflows/ci.yml".to_string(),
            "docs/guide.md".to_string(),
            "README.md".to_string(),
        ];
        assert_eq!(
            member_overlaps(org.path(), &tracked).unwrap(),
            vec![".github/workflows/ci.yml (inside .github)".to_string()]
        );
    }

    #[test]
    fn is_unborn_distinguishes_unborn_from_committed() {
        let unborn = tempfile::tempdir().unwrap();
        git2::Repository::init(unborn.path()).unwrap();
        assert!(is_unborn(unborn.path()).unwrap());

        let born = tempfile::tempdir().unwrap();
        test_repos::init(born.path());
        assert!(!is_unborn(born.path()).unwrap());
    }

    #[test]
    fn is_unborn_reports_unopenable_repository() {
        let dir = tempfile::tempdir().unwrap();
        assert!(is_unborn(dir.path()).is_err());
    }

    #[test]
    fn default_branch_is_the_advertised_head_not_the_first_branch() {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("origin");
        let repo = test_repos::init(&origin);
        // HEAD is "main"; "aaa" sorts first and must not be picked.
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        repo.branch("aaa", &head, false).unwrap();
        let head_name = repo.head().unwrap().shorthand().unwrap().to_string();

        let clone = git2::Repository::init(dir.path().join("clone")).unwrap();
        let (_, branch) =
            fetch_default_branch(&clone, &format!("file://{}", origin.display())).unwrap();
        assert_eq!(branch, head_name);
        assert_ne!(branch, "aaa");
    }

    #[test]
    fn abandon_init_removes_created_git_dir() {
        let org = tempfile::tempdir().unwrap();
        git2::Repository::init(org.path()).unwrap();
        let err = abandon_init(org.path(), WorkspaceError::GitError("refused".into()));
        assert_eq!(err.to_string(), "git command failed: refused");
        assert!(!org.path().join(".git").exists());
    }
}
