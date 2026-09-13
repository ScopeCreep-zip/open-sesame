//! Network operations: probe remote existence, check if behind.
//!
//! All network operations use the shared proxy policy and
//! transport-level timeout configuration. No threads are spawned
//! or abandoned. No global state is mutated.

use std::path::Path;

use crate::WorkspaceError;

/// Apply proxy and timeout config overrides to a gix repository.
fn apply_proxy_config(repo: &mut gix::Repository, target_url: &str) -> Result<(), WorkspaceError> {
    let policy = crate::net::ProxyPolicy::from_env();
    let decision = policy.for_target(target_url);

    let mut overrides: Vec<String> = Vec::new();
    match &decision {
        crate::net::ProxyDecision::Proxy(endpoint) => {
            overrides.push(format!("http.proxy={}", endpoint.url()));
        }
        crate::net::ProxyDecision::Direct => {
            overrides.push("http.proxy=".into());
        }
        crate::net::ProxyDecision::NoEnvironmentProxy => {}
    }
    overrides.push("gitoxide.http.connectTimeout=10000".into());

    if !overrides.is_empty() {
        let mut snapshot = repo.config_snapshot_mut();
        snapshot
            .append_config(
                overrides.iter().map(String::as_str),
                gix::config::Source::Api,
            )
            .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    }

    Ok(())
}

/// Check if a remote git repository exists and is accessible.
///
/// Creates a temporary bare repo with proxy and timeout config,
/// then attempts to list refs. Returns true only if the remote
/// responds within the configured timeout.
#[must_use]
pub fn probe_remote(url: &str) -> bool {
    let Ok(tmp) = tempfile::tempdir() else {
        return false;
    };
    let Ok(mut repo) = gix::init_bare(tmp.path()) else {
        return false;
    };

    if apply_proxy_config(&mut repo, url).is_err() {
        return false;
    }

    let Ok(remote) = repo.remote_at(url) else {
        return false;
    };

    let Ok(connection) = remote.connect(gix::remote::Direction::Fetch) else {
        return false;
    };

    // gix 0.72 may panic inside ref_map on connection failure
    // ("refmap always performs handshake"). catch_unwind converts
    // the panic to a false return, matching probe_remote's contract.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        connection
            .ref_map(
                gix::progress::Discard,
                gix::remote::ref_map::Options::default(),
            )
            .is_ok()
    }))
    .unwrap_or(false)
}

/// Check if a local repository is behind its remote.
///
/// Performs a gix dry-run fetch with proxy and timeout configuration.
/// Returns true if there are ref updates available.
/// Returns false on any error or if already up to date.
#[must_use]
pub fn is_behind_remote(repo_dir: &Path) -> bool {
    behind_inner(repo_dir).unwrap_or(false)
}

fn behind_inner(repo_dir: &Path) -> Result<bool, WorkspaceError> {
    let mut repo = gix::open(repo_dir).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    // Read the origin URL before applying config overrides, since
    // both operations borrow the repo.
    let url = repo
        .find_remote("origin")
        .ok()
        .and_then(|r| {
            r.url(gix::remote::Direction::Fetch)
                .map(|u| u.to_bstring().to_string())
        })
        .unwrap_or_default();

    apply_proxy_config(&mut repo, &url)?;

    // Re-obtain the remote after config modification.
    let remote = repo
        .find_remote("origin")
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let outcome = remote
        .connect(gix::remote::Direction::Fetch)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?
        .prepare_fetch(
            gix::progress::Discard,
            gix::remote::ref_map::Options::default(),
        )
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?
        .with_dry_run(true)
        .receive(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .map_err(|e| WorkspaceError::GitError(format!("{e}")))?;

    let update_refs = match &outcome.status {
        gix::remote::fetch::Status::Change { update_refs, .. }
        | gix::remote::fetch::Status::NoPackReceived { update_refs, .. } => update_refs,
    };
    let has_updates = update_refs.updates.iter().any(|u| {
        !matches!(
            u.mode,
            gix::remote::fetch::refs::update::Mode::NoChangeNeeded
        )
    });
    Ok(has_updates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_false_for_invalid_url() {
        assert!(!probe_remote(
            "https://invalid.example.com/no/such/repo.git"
        ));
    }
}
