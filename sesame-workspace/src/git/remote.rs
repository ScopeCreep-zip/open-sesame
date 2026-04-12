//! Network operations — probe remote existence, check if behind.

use std::path::Path;
use std::time::Duration;

use crate::WorkspaceError;

/// Timeout for network probes and behind-checks. Prevents blocking
/// indefinitely on unreachable servers or slow networks.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

/// Check if a remote git repository exists and is accessible.
///
/// Creates a temporary bare repo and attempts to list refs with a 10-second
/// timeout. Returns `true` only if the remote responds successfully in time.
#[must_use]
pub fn probe_remote(url: &str) -> bool {
    with_timeout(NETWORK_TIMEOUT, {
        let url = url.to_owned();
        move || {
            let prev_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| probe_inner(&url)));
            std::panic::set_hook(prev_hook);
            result.unwrap_or(false)
        }
    })
    .unwrap_or(false)
}

/// Check if a local repository is behind its remote.
///
/// Performs a gix dry-run fetch and returns `true` if there are ref updates
/// available. Returns `false` on any error, timeout, or if already up to date.
#[must_use]
pub fn is_behind_remote(repo_dir: &Path) -> bool {
    let path = repo_dir.to_owned();
    with_timeout(NETWORK_TIMEOUT, move || {
        behind_inner(&path).unwrap_or(false)
    })
    .unwrap_or(false)
}

/// Run a closure on a spawned thread with a timeout. Returns `None` if the
/// thread doesn't complete within `timeout`.
fn with_timeout<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let handle = std::thread::spawn(f);
    let deadline = std::time::Instant::now() + timeout;

    // Poll the thread until it finishes or we time out.
    loop {
        if handle.is_finished() {
            return handle.join().ok();
        }
        if std::time::Instant::now() >= deadline {
            // Thread is still running — abandon it. It will be cleaned up
            // when the process exits or the thread eventually completes.
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn probe_inner(url: &str) -> bool {
    let Ok(tmp) = tempfile::tempdir() else {
        return false;
    };
    let Ok(repo) = gix::init_bare(tmp.path()) else {
        return false;
    };
    let Ok(remote) = repo.remote_at(url) else {
        return false;
    };
    let Ok(connection) = remote.connect(gix::remote::Direction::Fetch) else {
        return false;
    };
    connection
        .ref_map(
            gix::progress::Discard,
            gix::remote::ref_map::Options::default(),
        )
        .is_ok()
}

fn behind_inner(repo_dir: &Path) -> Result<bool, WorkspaceError> {
    let repo = gix::open(repo_dir).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
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

    // In dry-run mode, Status is always NoPackReceived. Check the ref
    // update list for any refs that would change (FastForward, New, Forced).
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
