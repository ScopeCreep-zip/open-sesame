//! Repository inspection: open a repository once and derive requested
//! metadata from a single handle.
//!
//! Discovery finds repositories on the filesystem. Inspection reads
//! Git metadata from them. These are separate operations so callers
//! pay only for the metadata they need.
//!
//! Each field in the inspection result uses `FieldState<T>` to
//! distinguish not-requested, available, legitimately absent, and
//! failed states. Callers never need to guess why a value is missing.

use std::fmt;
use std::path::Path;

use crate::WorkspaceError;

/// The state of a single inspection field.
///
/// Distinguishes why a field has no value so callers can render
/// appropriate output and make correct decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldState<T> {
    /// The field was not requested in the inspection.
    NotRequested,
    /// The field has a value.
    Available(T),
    /// The field was requested but is legitimately absent.
    /// Example: HEAD is unborn (no commits yet).
    Absent,
    /// The field was requested but inspection failed.
    Failed(InspectionFailure),
}

impl<T> FieldState<T> {
    /// Extract the value if available, returning None for all other states.
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Available(v) => Some(v),
            _ => None,
        }
    }

    /// Whether this field has an available value.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }
}

impl<T: fmt::Display> fmt::Display for FieldState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRequested => write!(f, ""),
            Self::Available(v) => write!(f, "{v}"),
            Self::Absent => write!(f, ""),
            Self::Failed(e) => write!(f, "error: {}", e.kind),
        }
    }
}

/// A failure that occurred while inspecting a single field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionFailure {
    pub kind: InspectionFailureKind,
    pub message: String,
}

/// The kind of failure during field inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionFailureKind {
    /// Could not open the repository.
    RepositoryOpen,
    /// Could not read the remote URL.
    RemoteRead,
    /// Could not read the HEAD reference.
    HeadRead,
    /// Could not read working tree status.
    StatusRead,
    /// Could not read the upstream tracking reference.
    UpstreamRead,
    /// Could not traverse the commit graph.
    GraphTraversal,
}

impl fmt::Display for InspectionFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryOpen => write!(f, "repository open"),
            Self::RemoteRead => write!(f, "remote read"),
            Self::HeadRead => write!(f, "head read"),
            Self::StatusRead => write!(f, "status read"),
            Self::UpstreamRead => write!(f, "upstream read"),
            Self::GraphTraversal => write!(f, "graph traversal"),
        }
    }
}

/// Repository working tree status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoStatus {
    Clean,
    Dirty,
}

impl fmt::Display for RepoStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Dirty => write!(f, "dirty"),
        }
    }
}

/// Which metadata fields to collect during inspection.
///
/// Dependency expansion is handled internally: requesting
/// ahead_behind implicitly requests head and upstream.
#[derive(Debug, Clone, Default)]
pub struct InspectionRequest {
    pub remote: bool,
    pub branch: bool,
    pub head: bool,
    pub head_summary: bool,
    pub status: bool,
    pub upstream: bool,
    pub ahead_behind: bool,
}

impl InspectionRequest {
    /// Request all available metadata.
    #[must_use]
    pub fn all() -> Self {
        Self {
            remote: true,
            branch: true,
            head: true,
            head_summary: true,
            status: true,
            upstream: true,
            ahead_behind: true,
        }
    }

    /// Expand implicit dependencies between fields.
    #[must_use]
    pub fn expanded(&self) -> Self {
        let mut r = self.clone();
        if r.ahead_behind {
            r.head = true;
            r.upstream = true;
        }
        if r.upstream {
            r.branch = true;
        }
        r
    }
}

/// The result of inspecting a single repository.
///
/// Every field uses FieldState to distinguish not-requested,
/// available, absent, and failed states.
#[derive(Debug, Clone)]
pub struct InspectionResult {
    pub remote_url: FieldState<String>,
    pub branch: FieldState<String>,
    pub head_short: FieldState<String>,
    pub head_summary: FieldState<String>,
    pub status: FieldState<RepoStatus>,
    pub upstream_short: FieldState<String>,
    pub ahead_behind: FieldState<(usize, usize)>,
}

impl InspectionResult {
    /// All fields set to `Failed("skipped")`. Used when a worker is
    /// cancelled before inspecting this repo. Distinct from `Absent`
    /// (which means the field legitimately has no value) and from
    /// `NotRequested` (which means the caller didn't ask for it).
    #[must_use]
    pub fn skipped() -> Self {
        let failure = InspectionFailure {
            kind: InspectionFailureKind::StatusRead,
            message: "skipped".into(),
        };
        Self {
            remote_url: FieldState::Failed(failure.clone()),
            branch: FieldState::Failed(failure.clone()),
            head_short: FieldState::Failed(failure.clone()),
            head_summary: FieldState::Failed(failure.clone()),
            status: FieldState::Failed(failure.clone()),
            upstream_short: FieldState::Failed(failure.clone()),
            ahead_behind: FieldState::Failed(failure),
        }
    }
}

impl Default for InspectionResult {
    fn default() -> Self {
        Self {
            remote_url: FieldState::NotRequested,
            branch: FieldState::NotRequested,
            head_short: FieldState::NotRequested,
            head_summary: FieldState::NotRequested,
            status: FieldState::NotRequested,
            upstream_short: FieldState::NotRequested,
            ahead_behind: FieldState::NotRequested,
        }
    }
}

/// Inspect a repository at the given path, collecting only the
/// requested metadata fields.
///
/// Opens the repository once via gix and derives all requested
/// fields from that handle. The request is expanded to include
/// implicit dependencies before inspection begins.
///
/// # Errors
///
/// Returns `WorkspaceError::GitError` if the repository cannot be
/// opened. Individual field failures are recorded in `FieldState`
/// rather than aborting the entire inspection.
pub fn inspect(
    path: &Path,
    request: &InspectionRequest,
) -> Result<InspectionResult, WorkspaceError> {
    let request = request.expanded();
    let open_start = std::time::Instant::now();
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let open_ms = open_start.elapsed().as_millis();
    let mut result = InspectionResult::default();

    if request.remote {
        result.remote_url = match repo.find_remote("origin") {
            Ok(remote) => match remote.url(gix::remote::Direction::Fetch) {
                Some(url) => FieldState::Available(url.to_bstring().to_string()),
                None => FieldState::Absent,
            },
            Err(_) => FieldState::Absent,
        };
    }

    if request.branch {
        result.branch = match repo.head_name() {
            Ok(Some(name)) => FieldState::Available(name.shorten().to_string()),
            Ok(None) => FieldState::Absent,
            Err(e) => FieldState::Failed(InspectionFailure {
                kind: InspectionFailureKind::HeadRead,
                message: e.to_string(),
            }),
        };
    }

    if request.head {
        result.head_short = match repo.head() {
            Ok(head) => match head.id() {
                Some(id) => FieldState::Available(id.to_hex_with_len(7).to_string()),
                None => FieldState::Absent,
            },
            Err(e) => FieldState::Failed(InspectionFailure {
                kind: InspectionFailureKind::HeadRead,
                message: e.to_string(),
            }),
        };
    }

    if request.head_summary {
        result.head_summary = match repo.head() {
            Ok(head) => match head.id() {
                Some(id) => match id.object() {
                    Ok(obj) => match obj.try_into_commit() {
                        Ok(commit) => {
                            let msg = commit.message_raw_sloppy().to_string();
                            let first = msg.lines().next().unwrap_or("").to_string();
                            if first.is_empty() {
                                FieldState::Absent
                            } else {
                                FieldState::Available(first)
                            }
                        }
                        Err(e) => FieldState::Failed(InspectionFailure {
                            kind: InspectionFailureKind::HeadRead,
                            message: e.to_string(),
                        }),
                    },
                    Err(e) => FieldState::Failed(InspectionFailure {
                        kind: InspectionFailureKind::HeadRead,
                        message: e.to_string(),
                    }),
                },
                None => FieldState::Absent,
            },
            Err(e) => FieldState::Failed(InspectionFailure {
                kind: InspectionFailureKind::HeadRead,
                message: e.to_string(),
            }),
        };
    }

    if request.status {
        let status_start = std::time::Instant::now();
        result.status = check_status(&repo);
        let status_ms = status_start.elapsed().as_millis();
        if status_ms > 100 {
            tracing::debug!(
                path = %path.display(),
                open_ms,
                status_ms,
                "slow inspection"
            );
        }
    }

    if request.upstream {
        let branch_name = result.branch.value().cloned()
            .unwrap_or_else(|| "main".into());
        let refname = format!("refs/remotes/origin/{branch_name}");
        result.upstream_short = match repo.find_reference(&refname) {
            Ok(reference) => {
                FieldState::Available(reference.id().to_hex_with_len(7).to_string())
            }
            Err(_) => FieldState::Absent,
        };
    }

    // ahead_behind requires both head and upstream commits.
    // This is a placeholder that documents the field exists.
    // Full implementation requires computing the symmetric
    // difference of the two commit graphs.
    if request.ahead_behind {
        // Only compute if both head and upstream are available.
        let head_available = result.head_short.is_available();
        let upstream_available = result.upstream_short.is_available();
        if head_available && upstream_available {
            // TODO: compute actual ahead/behind via graph traversal.
            // For now, report absent rather than fabricating values.
            result.ahead_behind = FieldState::Absent;
        } else {
            result.ahead_behind = FieldState::Absent;
        }
    }

    Ok(result)
}

/// Check repository dirty/clean status using git plumbing.
///
/// Primary path: `git update-index --refresh` + `git diff-index --quiet HEAD`.
/// This is faster than a full working-tree walk for clean repos because:
///   - `update-index --refresh` only re-stats files whose cached stat data
///     (mtime, size) in the index differs from disk.
///   - `diff-index --quiet HEAD` exits on the first difference.
///   - Neither command enumerates untracked files.
///
/// Fallback: `gix::status` if git is not on PATH.
fn check_status(repo: &gix::Repository) -> FieldState<RepoStatus> {
    let work_dir = match repo.workdir() {
        Some(d) => d,
        None => {
            // Bare repo: no working tree to check.
            return FieldState::Available(RepoStatus::Clean);
        }
    };

    // Phase 1: refresh index stat cache (makes diff-index reliable).
    let refresh = std::process::Command::new("git")
        .args(["update-index", "-q", "--refresh"])
        .current_dir(work_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if refresh.is_err() {
        // git not on PATH: fall back to gix.
        return check_status_gix(repo);
    }

    // Check if HEAD exists (unborn branch = no commits = clean).
    // git diff-index HEAD fails on repos with no commits.
    let head_exists = std::process::Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(work_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !head_exists {
        // Unborn branch (no commits). Clean by definition.
        return FieldState::Available(RepoStatus::Clean);
    }

    // Phase 2: diff-index --quiet exits 0 if clean, 1 if dirty.
    let diff = std::process::Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .current_dir(work_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match diff {
        Ok(status) if status.success() => FieldState::Available(RepoStatus::Clean),
        Ok(_) => FieldState::Available(RepoStatus::Dirty),
        Err(_) => check_status_gix(repo),
    }
}

/// gix-based status check. Slower (full tree walk) but no git binary needed.
fn check_status_gix(repo: &gix::Repository) -> FieldState<RepoStatus> {
    let platform = match repo.status(gix::progress::Discard) {
        Ok(p) => p,
        Err(e) => {
            return FieldState::Failed(InspectionFailure {
                kind: InspectionFailureKind::StatusRead,
                message: e.to_string(),
            });
        }
    };
    let mut iter = match platform.into_iter(Vec::new()) {
        Ok(i) => i,
        Err(e) => {
            return FieldState::Failed(InspectionFailure {
                kind: InspectionFailureKind::StatusRead,
                message: e.to_string(),
            });
        }
    };
    if iter.next().is_some() {
        FieldState::Available(RepoStatus::Dirty)
    } else {
        FieldState::Available(RepoStatus::Clean)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_fresh_repo() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let result = inspect(dir.path(), &InspectionRequest::all()).unwrap();
        assert!(matches!(result.remote_url, FieldState::Absent));
        assert_eq!(result.branch.value(), Some(&"main".to_string()));
        assert!(matches!(result.head_short, FieldState::Absent));
        assert_eq!(result.status.value(), Some(&RepoStatus::Clean));
    }

    #[test]
    fn inspect_partial_request() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let request = InspectionRequest {
            branch: true,
            ..Default::default()
        };
        let result = inspect(dir.path(), &request).unwrap();
        assert_eq!(result.branch.value(), Some(&"main".to_string()));
        assert!(matches!(result.remote_url, FieldState::NotRequested));
        assert!(matches!(result.head_short, FieldState::NotRequested));
        assert!(matches!(result.status, FieldState::NotRequested));
    }

    #[test]
    fn inspect_nonexistent_fails() {
        let result = inspect(Path::new("/nonexistent/repo"), &InspectionRequest::all());
        assert!(result.is_err());
    }

    #[test]
    fn repo_status_display() {
        assert_eq!(RepoStatus::Clean.to_string(), "clean");
        assert_eq!(RepoStatus::Dirty.to_string(), "dirty");
    }

    #[test]
    fn field_state_not_requested_display() {
        let fs: FieldState<String> = FieldState::NotRequested;
        assert_eq!(fs.to_string(), "");
    }

    #[test]
    fn field_state_available_display() {
        let fs = FieldState::Available("main".to_string());
        assert_eq!(fs.to_string(), "main");
    }

    #[test]
    fn field_state_failed_display() {
        let fs: FieldState<String> = FieldState::Failed(InspectionFailure {
            kind: InspectionFailureKind::HeadRead,
            message: "corrupt".into(),
        });
        assert!(fs.to_string().contains("head read"));
    }

    #[test]
    fn request_expansion() {
        let req = InspectionRequest {
            ahead_behind: true,
            ..Default::default()
        };
        let expanded = req.expanded();
        assert!(expanded.head);
        assert!(expanded.upstream);
        assert!(expanded.branch);
    }

    #[test]
    fn request_expansion_upstream_requires_branch() {
        let req = InspectionRequest {
            upstream: true,
            ..Default::default()
        };
        let expanded = req.expanded();
        assert!(expanded.branch);
    }
}
