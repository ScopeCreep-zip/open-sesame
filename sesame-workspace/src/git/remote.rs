//! Remote operations: probe remote existence, compare a branch with its
//! remote.
//!
//! A remote on this machine (`file://` or a path) is read in-process:
//! gix reaches the local transport only by running `git upload-pack`
//! (`gix_transport::client::blocking_io::file::connect`), and open-sesame
//! has no git CLI dependency. Every other remote goes through gix's
//! transport with the shared proxy policy and transport-level timeout
//! configuration. No threads are spawned or abandoned. No global state is
//! mutated.

use std::path::{Path, PathBuf};

use crate::{CloneFailureKind, WorkspaceError};

/// Where a remote's repository is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Served {
    /// A repository on this machine, opened in-process.
    Local(PathBuf),
    /// A network transport (`https`, `ssh`, ...), through gix.
    Network,
}

impl Served {
    /// Where the remote at `url` is served from. A relative local path is
    /// taken relative to `base` (the repository the remote belongs to),
    /// not the process's working directory, so the answer does not depend
    /// on where sesame runs.
    ///
    /// # Errors
    ///
    /// `WorkspaceError::GitError` when `url` is not a valid remote URL or a
    /// local path is not valid UTF-8.
    fn of(url: &str, base: Option<&Path>) -> Result<Self, WorkspaceError> {
        let shown = crate::net::redact_credentials(url);
        let parsed = gix::url::parse(url)
            .map_err(|e| WorkspaceError::GitError(format!("invalid remote URL {shown}: {e}")))?;
        if parsed.scheme != gix::url::Scheme::File {
            return Ok(Self::Network);
        }
        let path = gix::path::from_bstring(parsed.path)
            .map_err(|e| WorkspaceError::GitError(format!("remote path {shown}: {e}")))?;
        Ok(Self::Local(match base {
            Some(base) if path.is_relative() => base.join(path),
            _ => path,
        }))
    }
}

/// The in-memory gix configuration for a transfer with `target_url`: the
/// shared proxy decision (`http.proxy`; an empty value disables the
/// proxy, and no override leaves gitconfig's `http.proxy` in effect) and
/// a 10 s connect timeout.
///
/// # Errors
///
/// The `ProxyPolicy::from_env` errors.
pub(crate) fn gix_transport_overrides(target_url: &str) -> Result<Vec<String>, WorkspaceError> {
    let mut overrides = Vec::new();
    match crate::net::ProxyPolicy::from_env()?.for_target(target_url) {
        crate::net::ProxyDecision::Proxy(endpoint) => {
            tracing::debug!(proxy = %endpoint, "gix transfer using proxy");
            overrides.push(format!("http.proxy={}", endpoint.url()));
        }
        crate::net::ProxyDecision::Direct => {
            tracing::debug!("gix transfer direct (host in NO_PROXY)");
            overrides.push("http.proxy=".into());
        }
        crate::net::ProxyDecision::NoEnvironmentProxy => {}
    }
    overrides.push("gitoxide.http.connectTimeout=10000".into());
    Ok(overrides)
}

/// Apply the transfer overrides for `target_url` to an open repository.
fn apply_proxy_config(repo: &mut gix::Repository, target_url: &str) -> Result<(), WorkspaceError> {
    let overrides = gix_transport_overrides(target_url)?;
    let mut snapshot = repo.config_snapshot_mut();
    snapshot
        .append_config(
            overrides.iter().map(String::as_str),
            gix::config::Source::Api,
        )
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    Ok(())
}

/// What a remote answered to a ref listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteProbe {
    /// The remote served its refs.
    Available,
    /// The remote did not serve the repository. gix's HTTP transport
    /// types only a 401 (`kind: Authentication`, which forges such as
    /// GitHub also answer for absent repositories); a 404 and a network
    /// failure are both `kind: Other`, told apart only by `message`.
    Unavailable {
        kind: CloneFailureKind,
        message: String,
    },
}

/// Learn whether the remote at `url` serves a repository: a local remote
/// by opening it, a network remote by listing its refs.
///
/// The network listing uses `prepare_fetch`, which reports handshake
/// failures as errors (`Connection::ref_map` in gix 0.72 panics on them).
/// A relative local path is taken relative to the working directory.
///
/// # Errors
///
/// `WorkspaceError::GitError` when the probe repository cannot be set up
/// or `url` is not a valid remote URL. Remote and transport failures are
/// `Ok(RemoteProbe::Unavailable)`.
pub fn probe_remote(url: &str) -> Result<RemoteProbe, WorkspaceError> {
    let path = match Served::of(url, None)? {
        Served::Local(path) => path,
        Served::Network => return probe_network(url),
    };
    Ok(match gix::open(&path) {
        Ok(_) => RemoteProbe::Available,
        Err(e) => RemoteProbe::Unavailable {
            kind: CloneFailureKind::Other,
            message: format!("{}: {e}", path.display()),
        },
    })
}

/// `probe_remote` for a network remote.
fn probe_network(url: &str) -> Result<RemoteProbe, WorkspaceError> {
    let tmp = tempfile::tempdir()?;
    let mut repo = gix::init_bare(tmp.path())
        .map_err(|e| WorkspaceError::GitError(format!("probe repository init failed: {e}")))?;
    apply_proxy_config(&mut repo, url)?;
    let remote = repo
        .remote_at(url)
        .map_err(|e| WorkspaceError::GitError(format!("invalid remote URL {url}: {e}")))?
        .with_refspecs(
            ["+refs/heads/*:refs/remotes/origin/*"],
            gix::remote::Direction::Fetch,
        )
        .map_err(|e| WorkspaceError::GitError(format!("probe refspec: {e}")))?;

    let unavailable = |e: &(dyn std::error::Error + 'static)| RemoteProbe::Unavailable {
        kind: super::clone::classify_clone_failure(e),
        message: e.to_string(),
    };
    let connection = match remote.connect(gix::remote::Direction::Fetch) {
        Ok(connection) => connection,
        Err(e) => return Ok(unavailable(&e)),
    };
    match connection.prepare_fetch(
        gix::progress::Discard,
        gix::remote::ref_map::Options::default(),
    ) {
        Ok(_) => Ok(RemoteProbe::Available),
        Err(e) => Ok(unavailable(&e)),
    }
}

/// How a repository's current branch compares with the same branch on
/// its `origin`, as the remote advertises it now (not the local tracking
/// ref, which is only as fresh as the last fetch). Commit ids are 7-digit
/// hex abbreviations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamDrift {
    /// HEAD is detached: there is no branch to compare.
    Detached,
    /// The repository has no `origin` remote.
    NoOrigin,
    /// `origin` does not advertise the current branch.
    BranchAbsentOnRemote { branch: String },
    /// The remote branch points at HEAD.
    UpToDate { branch: String },
    /// The remote branch points elsewhere; `local` is `None` when HEAD is
    /// unborn.
    Differs {
        branch: String,
        local: Option<String>,
        remote: String,
    },
}

/// Compare the current branch of the repository at `repo_dir` with its
/// `origin`: a local origin by reading its branch, a network origin by
/// listing its refs. No pack is received and nothing in either
/// repository is written. A relative local origin is taken relative to
/// `repo_dir`.
///
/// # Errors
///
/// `WorkspaceError::GitError` when the repository or its HEAD cannot be
/// read, `origin` has no valid fetch URL, a local origin cannot be read,
/// or a network origin cannot be listed (the message carries the
/// transport cause).
pub fn upstream_drift(repo_dir: &Path) -> Result<UpstreamDrift, WorkspaceError> {
    let git = |what: &str, e: &dyn std::fmt::Display| {
        WorkspaceError::GitError(format!("{}: {what}: {e}", repo_dir.display()))
    };
    let mut repo = gix::open(repo_dir).map_err(|e| git("open", &e))?;
    let Some(branch_ref) = repo.head_name().map_err(|e| git("HEAD", &e))? else {
        return Ok(UpstreamDrift::Detached);
    };
    let branch = branch_ref.shorten().to_string();
    let local = repo
        .head()
        .map_err(|e| git("HEAD", &e))?
        .id()
        .map(|id| id.to_hex_with_len(7).to_string());
    let url = match repo.try_find_remote("origin") {
        None => return Ok(UpstreamDrift::NoOrigin),
        Some(remote) => remote
            .map_err(|e| git("remote origin", &e))?
            .url(gix::remote::Direction::Fetch)
            .ok_or_else(|| git("remote origin", &"no fetch URL"))?
            .to_bstring()
            .to_string(),
    };
    let tip = match Served::of(&url, Some(repo_dir))? {
        Served::Local(origin) => {
            let read = |what: &str, e: &dyn std::fmt::Display| {
                git(&format!("{what} of origin {}", origin.display()), e)
            };
            let origin_repo = gix::open(&origin).map_err(|e| read("open", &e))?;
            match origin_repo
                .try_find_reference(branch_ref.as_ref())
                .map_err(|e| read(&format!("find {branch}"), &e))?
            {
                None => None,
                Some(mut reference) => Some(
                    reference
                        .peel_to_id()
                        .map_err(|e| read(&format!("peel {branch}"), &e))?
                        .to_hex_with_len(7)
                        .to_string(),
                ),
            }
        }
        Served::Network => {
            apply_proxy_config(&mut repo, &url)?;
            let remote = repo
                .find_remote("origin")
                .map_err(|e| git("remote origin", &e))?;
            let shown = crate::net::redact_credentials(&url);
            let prepare = remote
                .connect(gix::remote::Direction::Fetch)
                .map_err(|e| git(&format!("connect {shown}"), &format!("{e:#}")))?
                .prepare_fetch(
                    gix::progress::Discard,
                    gix::remote::ref_map::Options::default(),
                )
                .map_err(|e| git(&format!("list refs of {shown}"), &format!("{e:#}")))?;
            prepare
                .ref_map()
                .remote_refs
                .iter()
                .find_map(|r| {
                    let (name, target, peeled) = r.unpack();
                    (name == branch_ref.as_bstr()).then(|| {
                        peeled
                            .or(target)
                            .map(|id| id.to_hex_with_len(7).to_string())
                    })
                })
                .flatten()
        }
    };
    Ok(match tip {
        None => UpstreamDrift::BranchAbsentOnRemote { branch },
        Some(remote) if local.as_deref() == Some(remote.as_str()) => {
            UpstreamDrift::UpToDate { branch }
        }
        Some(remote) => UpstreamDrift::Differs {
            branch,
            local,
            remote,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clone_of(origin: &std::path::Path, dir: &std::path::Path) -> git2::Repository {
        git2::Repository::clone(&format!("file://{}", origin.display()), dir).unwrap()
    }

    #[test]
    fn drift_up_to_date_after_clone() {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("origin");
        crate::git::marker::test_repos::init(&origin);
        let local = dir.path().join("local");
        clone_of(&origin, &local);
        assert!(matches!(
            upstream_drift(&local).unwrap(),
            UpstreamDrift::UpToDate { .. }
        ));
    }

    #[test]
    fn drift_sees_remote_commit_without_fetching() {
        let dir = tempfile::tempdir().unwrap();
        let origin_path = dir.path().join("origin");
        let origin = crate::git::marker::test_repos::init(&origin_path);
        let local = dir.path().join("local");
        clone_of(&origin_path, &local);
        // The remote advances after the clone; the local tracking ref does
        // not, so only a remote listing can see the drift.
        let sig = git2::Signature::now("alice", "alice@example.invalid").unwrap();
        let parent = origin.head().unwrap().peel_to_commit().unwrap();
        let tree = origin
            .find_tree(origin.index().unwrap().write_tree().unwrap())
            .unwrap();
        let new = origin
            .commit(Some("HEAD"), &sig, &sig, "advance", &tree, &[&parent])
            .unwrap();
        match upstream_drift(&local).unwrap() {
            UpstreamDrift::Differs { remote, local, .. } => {
                assert_eq!(remote, new.to_string()[..7]);
                assert_eq!(local.as_deref(), Some(&parent.id().to_string()[..7]));
            }
            other => panic!("expected Differs, got {other:?}"),
        }
    }

    #[test]
    fn drift_without_origin() {
        let dir = tempfile::tempdir().unwrap();
        crate::git::marker::test_repos::init(dir.path());
        assert_eq!(upstream_drift(dir.path()).unwrap(), UpstreamDrift::NoOrigin);
    }

    #[test]
    fn probe_reports_unreachable_remote_without_panicking() {
        // Connection refused on a closed local port: a transport failure,
        // which gix 0.72's ref_map would panic on.
        let probe = probe_remote("http://127.0.0.1:9/no/such/repo.git").unwrap();
        assert!(
            matches!(
                probe,
                RemoteProbe::Unavailable {
                    kind: CloneFailureKind::Other,
                    ..
                }
            ),
            "{probe:?}"
        );
    }

    #[test]
    fn probe_lists_local_repository() {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("origin");
        crate::git::marker::test_repos::init(&origin);
        let url = format!("file://{}", origin.display());
        assert_eq!(probe_remote(&url).unwrap(), RemoteProbe::Available);
    }

    #[test]
    fn local_remotes_are_told_apart_from_network_remotes() {
        let base = Path::new("/srv/repo");
        for (url, served) in [
            ("https://github.com/org/repo", Served::Network),
            ("ssh://git@github.com/org/repo.git", Served::Network),
            ("git@github.com:org/repo.git", Served::Network),
            ("file:///srv/origin", Served::Local("/srv/origin".into())),
            ("/srv/origin", Served::Local("/srv/origin".into())),
            ("../origin", Served::Local("/srv/repo/../origin".into())),
        ] {
            assert_eq!(Served::of(url, Some(base)).unwrap(), served, "{url}");
        }
    }

    #[test]
    fn drift_reads_a_relative_local_origin_against_the_repository() {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("origin");
        crate::git::marker::test_repos::init(&origin);
        let local = dir.path().join("local");
        clone_of(&origin, &local)
            .remote_set_url("origin", "../origin")
            .unwrap();
        assert!(matches!(
            upstream_drift(&local).unwrap(),
            UpstreamDrift::UpToDate { .. }
        ));
    }

    #[test]
    fn drift_reports_a_branch_the_local_origin_lacks() {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("origin");
        crate::git::marker::test_repos::init(&origin);
        let local = dir.path().join("local");
        let clone = clone_of(&origin, &local);
        let head = clone.head().unwrap().peel_to_commit().unwrap();
        clone.branch("topic", &head, false).unwrap();
        clone.set_head("refs/heads/topic").unwrap();
        assert_eq!(
            upstream_drift(&local).unwrap(),
            UpstreamDrift::BranchAbsentOnRemote {
                branch: "topic".into()
            }
        );
    }

    #[test]
    fn probe_reports_a_local_path_without_a_repository() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("file://{}", dir.path().join("absent").display());
        assert!(matches!(
            probe_remote(&url).unwrap(),
            RemoteProbe::Unavailable {
                kind: CloneFailureKind::Other,
                ..
            }
        ));
    }

    #[test]
    fn probe_rejects_invalid_url() {
        assert!(matches!(
            probe_remote("::not a url::"),
            Err(WorkspaceError::GitError(_))
        ));
    }
}
