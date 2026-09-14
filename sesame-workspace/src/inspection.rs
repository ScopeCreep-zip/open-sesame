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
//!
//! # Architecture
//!
//! Each metadata field is a struct implementing `FieldInspector`.
//! The [`inspect`] function opens the repository once, then runs
//! each requested inspector in dependency order against the shared
//! handle. Adding a new field requires one struct, one trait impl,
//! and one entry in `INSPECTORS`. The `inspect` function does not
//! change.

use std::fmt;
use std::path::Path;

use crate::WorkspaceError;

// ============================================================================
// FieldState: the per-field result envelope
// ============================================================================

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
            Self::NotRequested | Self::Absent => write!(f, ""),
            Self::Available(v) => write!(f, "{v}"),
            Self::Failed(e) => write!(f, "error: {}", e.kind),
        }
    }
}

// ============================================================================
// Failure types
// ============================================================================

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
    /// Could not compute disk usage.
    DiskUsage,
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
            Self::DiskUsage => write!(f, "disk usage"),
        }
    }
}

// ============================================================================
// RepoStatus
// ============================================================================

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

// ============================================================================
// DiskUsage
// ============================================================================

/// Disk usage breakdown for a repository.
///
/// Computed via parallel filesystem traversal using `dua-core`.
/// All values are in bytes. The walker uses apparent size (logical
/// file length) for cross-platform consistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage {
    /// Total bytes across all files in the repository.
    pub total_bytes: u64,
    /// Bytes consumed by the `.git` directory (object store, refs,
    /// index, hooks, etc.).
    pub git_bytes: u64,
    /// Total number of files (not directories) in the repository.
    pub file_count: u64,
}

// ============================================================================
// InspectionRequest
// ============================================================================

/// Which metadata fields to collect during inspection.
///
/// Dependency expansion is handled internally: requesting
/// `ahead_behind` implicitly requests head and upstream.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct InspectionRequest {
    pub remote: bool,
    pub branch: bool,
    pub head: bool,
    pub head_summary: bool,
    pub status: bool,
    pub upstream: bool,
    pub ahead_behind: bool,
    pub disk_usage: bool,
    pub head_date: bool,
    pub upstream_date: bool,
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
            disk_usage: true,
            head_date: true,
            upstream_date: true,
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
        if r.upstream || r.upstream_date {
            r.branch = true;
        }
        r
    }

    /// Whether the given inspector is requested.
    fn is_requested(&self, id: InspectorId) -> bool {
        match id {
            InspectorId::Remote => self.remote,
            InspectorId::Branch => self.branch,
            InspectorId::Head => self.head,
            InspectorId::HeadSummary => self.head_summary,
            InspectorId::Status => self.status,
            InspectorId::Upstream => self.upstream,
            InspectorId::AheadBehind => self.ahead_behind,
            InspectorId::DiskUsage => self.disk_usage,
            InspectorId::HeadDate => self.head_date,
            InspectorId::UpstreamDate => self.upstream_date,
        }
    }
}

// ============================================================================
// InspectionResult
// ============================================================================

/// The result of inspecting a single repository.
///
/// Every field uses `FieldState` to distinguish not-requested,
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
    pub disk_usage: FieldState<DiskUsage>,
    pub head_date: FieldState<i64>,
    pub upstream_date: FieldState<i64>,
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
            ahead_behind: FieldState::Failed(failure.clone()),
            disk_usage: FieldState::Failed(failure.clone()),
            head_date: FieldState::Failed(failure.clone()),
            upstream_date: FieldState::Failed(failure),
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
            disk_usage: FieldState::NotRequested,
            head_date: FieldState::NotRequested,
            upstream_date: FieldState::NotRequested,
        }
    }
}

// ============================================================================
// FieldInspector trait and registry
// ============================================================================

/// Identity tag for each inspector, used for request dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InspectorId {
    Remote,
    Branch,
    Head,
    HeadSummary,
    Status,
    Upstream,
    AheadBehind,
    DiskUsage,
    HeadDate,
    UpstreamDate,
}

/// A single metadata field inspector.
///
/// Each implementation reads from the shared `gix::Repository` handle
/// and writes to one field of `InspectionResult`. Inspectors may read
/// previously-populated fields in `result` when they have ordering
/// dependencies (e.g. upstream reads the branch name).
trait FieldInspector {
    /// Which inspector this is, for request dispatch.
    fn id(&self) -> InspectorId;

    /// Inspect the repository and write to the result.
    ///
    /// `path` is provided for diagnostic logging only. `result` may
    /// contain values from previously-run inspectors.
    fn inspect(&self, repo: &gix::Repository, path: &Path, result: &mut InspectionResult);
}

/// Inspector registry. Ordered by dependency: inspectors that read
/// from previously-populated result fields come after the fields
/// they depend on.
///
/// Adding a new field:
/// 1. Add a struct implementing `FieldInspector`.
/// 2. Add an `InspectorId` variant.
/// 3. Add a bool to `InspectionRequest` and wire `is_requested`.
/// 4. Add a `FieldState<T>` field to `InspectionResult`.
/// 5. Append to this array in dependency order.
const INSPECTORS: &[&dyn FieldInspector] = &[
    &RemoteInspector,
    &BranchInspector,
    &HeadInspector,
    &HeadSummaryInspector,
    &StatusInspector,
    &UpstreamInspector,     // depends on branch
    &AheadBehindInspector,  // depends on head, upstream
    &HeadDateInspector,     // independent
    &UpstreamDateInspector, // depends on branch
    &DiskUsageInspector,    // independent, runs last (most expensive)
];

// ============================================================================
// Inspector implementations
// ============================================================================

struct RemoteInspector;

impl FieldInspector for RemoteInspector {
    fn id(&self) -> InspectorId {
        InspectorId::Remote
    }

    fn inspect(&self, repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
        result.remote_url = match repo.find_remote("origin") {
            Ok(remote) => match remote.url(gix::remote::Direction::Fetch) {
                Some(url) => FieldState::Available(url.to_bstring().to_string()),
                None => FieldState::Absent,
            },
            Err(_) => FieldState::Absent,
        };
    }
}

struct BranchInspector;

impl FieldInspector for BranchInspector {
    fn id(&self) -> InspectorId {
        InspectorId::Branch
    }

    fn inspect(&self, repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
        result.branch = match repo.head_name() {
            Ok(Some(name)) => FieldState::Available(name.shorten().to_string()),
            Ok(None) => FieldState::Absent,
            Err(e) => FieldState::Failed(InspectionFailure {
                kind: InspectionFailureKind::HeadRead,
                message: e.to_string(),
            }),
        };
    }
}

struct HeadInspector;

impl FieldInspector for HeadInspector {
    fn id(&self) -> InspectorId {
        InspectorId::Head
    }

    fn inspect(&self, repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
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
}

struct HeadSummaryInspector;

impl FieldInspector for HeadSummaryInspector {
    fn id(&self) -> InspectorId {
        InspectorId::HeadSummary
    }

    fn inspect(&self, repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
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
}

struct StatusInspector;

impl FieldInspector for StatusInspector {
    fn id(&self) -> InspectorId {
        InspectorId::Status
    }

    fn inspect(&self, repo: &gix::Repository, path: &Path, result: &mut InspectionResult) {
        result.status = check_status(repo, path);
    }
}

struct UpstreamInspector;

impl FieldInspector for UpstreamInspector {
    fn id(&self) -> InspectorId {
        InspectorId::Upstream
    }

    /// Reads `result.branch` to construct the tracking ref name.
    fn inspect(&self, repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
        let branch_name = result
            .branch
            .value()
            .cloned()
            .unwrap_or_else(|| "main".into());
        let refname = format!("refs/remotes/origin/{branch_name}");
        result.upstream_short = match repo.find_reference(&refname) {
            Ok(reference) => FieldState::Available(reference.id().to_hex_with_len(7).to_string()),
            Err(_) => FieldState::Absent,
        };
    }
}

struct AheadBehindInspector;

impl FieldInspector for AheadBehindInspector {
    fn id(&self) -> InspectorId {
        InspectorId::AheadBehind
    }

    /// Reads `result.head_short` and `result.upstream_short` to
    /// determine whether computation is possible. Full graph
    /// traversal is not yet implemented.
    fn inspect(&self, _repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
        result.ahead_behind = FieldState::Absent;
    }
}

struct HeadDateInspector;

impl FieldInspector for HeadDateInspector {
    fn id(&self) -> InspectorId {
        InspectorId::HeadDate
    }

    /// Extract the committer timestamp from the local HEAD commit.
    fn inspect(&self, repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
        result.head_date = match repo.head() {
            Ok(head) => match head.id() {
                Some(id) => match id.object() {
                    Ok(obj) => match obj.try_into_commit() {
                        Ok(commit) => match commit.time() {
                            Ok(time) => FieldState::Available(time.seconds),
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
}

struct UpstreamDateInspector;

impl FieldInspector for UpstreamDateInspector {
    fn id(&self) -> InspectorId {
        InspectorId::UpstreamDate
    }

    /// Extract the committer timestamp from the upstream tracking
    /// branch HEAD. Reads `result.branch` for the tracking ref name.
    fn inspect(&self, repo: &gix::Repository, _path: &Path, result: &mut InspectionResult) {
        let branch_name = result
            .branch
            .value()
            .cloned()
            .unwrap_or_else(|| "main".into());
        let refname = format!("refs/remotes/origin/{branch_name}");
        result.upstream_date = match repo.find_reference(&refname) {
            Ok(reference) => match reference.id().object() {
                Ok(obj) => match obj.try_into_commit() {
                    Ok(commit) => match commit.time() {
                        Ok(time) => FieldState::Available(time.seconds),
                        Err(e) => FieldState::Failed(InspectionFailure {
                            kind: InspectionFailureKind::UpstreamRead,
                            message: e.to_string(),
                        }),
                    },
                    Err(e) => FieldState::Failed(InspectionFailure {
                        kind: InspectionFailureKind::UpstreamRead,
                        message: e.to_string(),
                    }),
                },
                Err(e) => FieldState::Failed(InspectionFailure {
                    kind: InspectionFailureKind::UpstreamRead,
                    message: e.to_string(),
                }),
            },
            Err(_) => FieldState::Absent,
        };
    }
}

struct DiskUsageInspector;

impl FieldInspector for DiskUsageInspector {
    fn id(&self) -> InspectorId {
        InspectorId::DiskUsage
    }

    /// Compute disk usage via `dua-core` parallel filesystem traversal.
    ///
    /// Uses `threads: 1` because each inspector already runs inside a
    /// pool worker — the cross-repo parallelism is handled by the pool,
    /// intra-repo parallelism would oversubscribe.
    ///
    /// Walks the entire repo directory once. Entries under `.git/` are
    /// summed separately into `git_bytes`. Non-directory entries are
    /// counted in `file_count`.
    fn inspect(&self, _repo: &gix::Repository, path: &Path, result: &mut InspectionResult) {
        let start = std::time::Instant::now();

        let git_dir = path.join(".git");
        let mut total_bytes: u64 = 0;
        let mut git_bytes: u64 = 0;
        let mut file_count: u64 = 0;

        for entry in dua_core::walk(
            path,
            1, // single-threaded: pool provides cross-repo parallelism
            dua_core::Order::Completion,
            dua_core::Options::default(),
            |_| true,
        ) {
            let Ok(entry) = entry else {
                continue;
            };
            if entry.file_type.is_dir() {
                continue;
            }
            let size = entry
                .metadata
                .as_ref()
                .and_then(|m| m.as_ref().ok())
                .map_or(0, dua_core::Metadata::len);
            total_bytes = total_bytes.saturating_add(size);
            file_count += 1;

            if entry.path().starts_with(&git_dir) {
                git_bytes = git_bytes.saturating_add(size);
            }
        }

        let elapsed_ms = start.elapsed().as_millis();
        if elapsed_ms > 500 {
            tracing::debug!(
                path = %path.display(),
                elapsed_ms,
                total_bytes,
                file_count,
                "slow disk usage walk"
            );
        }

        result.disk_usage = FieldState::Available(DiskUsage {
            total_bytes,
            git_bytes,
            file_count,
        });
    }
}

// ============================================================================
// Public entry point
// ============================================================================

/// Inspect a repository at the given path, collecting only the
/// requested metadata fields.
///
/// Opens the repository once via gix, then runs each requested
/// `FieldInspector` in dependency order against the shared handle.
/// The request is expanded to include implicit dependencies before
/// inspection begins.
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
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let mut result = InspectionResult::default();

    for inspector in INSPECTORS {
        if request.is_requested(inspector.id()) {
            inspector.inspect(&repo, path, &mut result);
        }
    }

    Ok(result)
}

// ============================================================================
// Status check implementation (shared by StatusInspector)
// ============================================================================

/// Check repository dirty/clean status using git plumbing.
///
/// Primary path: `git update-index --refresh` + `git diff-index --quiet HEAD`.
/// Faster than a full working-tree walk for clean repos because
/// `update-index` only re-stats changed entries and `diff-index`
/// exits on the first difference.
///
/// Fallback: `gix::status` if git is not on PATH.
///
/// The `path` parameter is for diagnostic tracing only.
fn check_status(repo: &gix::Repository, path: &Path) -> FieldState<RepoStatus> {
    let Some(work_dir) = repo.workdir() else {
        return FieldState::Available(RepoStatus::Clean);
    };

    let start = std::time::Instant::now();

    let refresh = std::process::Command::new("git")
        .args(["update-index", "-q", "--refresh"])
        .current_dir(work_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if refresh.is_err() {
        return check_status_gix(repo);
    }

    let head_exists = std::process::Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(work_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !head_exists {
        return FieldState::Available(RepoStatus::Clean);
    }

    let result = match std::process::Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .current_dir(work_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => FieldState::Available(RepoStatus::Clean),
        Ok(_) => FieldState::Available(RepoStatus::Dirty),
        Err(_) => check_status_gix(repo),
    };

    let elapsed_ms = start.elapsed().as_millis();
    if elapsed_ms > 100 {
        tracing::debug!(
            path = %path.display(),
            elapsed_ms,
            "slow status check"
        );
    }

    result
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

// ============================================================================
// Human-readable byte formatting
// ============================================================================

/// Format a byte count as a human-readable string.
///
/// Uses binary units (KiB, MiB, GiB, TiB) with one decimal place.
/// Values under 1 KiB are shown as whole bytes.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;

    #[allow(clippy::cast_precision_loss)] // display-only; sub-byte precision is irrelevant
    let b = bytes as f64;
    if b >= TIB {
        format!("{:.1} TiB", b / TIB)
    } else if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

// ============================================================================
// Relative time formatting
// ============================================================================

/// Format a unix epoch timestamp as a relative age string.
///
/// Computes the difference between the given timestamp and the
/// current system time. Returns compact human-readable durations:
/// `3m`, `5h`, `2d`, `1w`, `3mo`, `1y`.
///
/// Returns `"future"` for timestamps ahead of now, `"now"` for
/// ages under one minute.
#[must_use]
pub fn format_relative_time(epoch_secs: i64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 3600;
    const DAY: u64 = 86400;
    const WEEK: u64 = 7 * DAY;
    const MONTH: u64 = 30 * DAY;
    const YEAR: u64 = 365 * DAY;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    #[allow(clippy::cast_sign_loss)]
    let epoch = epoch_secs as u64;
    if epoch > now {
        return "future".into();
    }
    let age = now - epoch;

    if age < MINUTE {
        "now".into()
    } else if age < HOUR {
        format!("{}m", age / MINUTE)
    } else if age < DAY {
        format!("{}h", age / HOUR)
    } else if age < WEEK {
        format!("{}d", age / DAY)
    } else if age < MONTH {
        format!("{}w", age / WEEK)
    } else if age < YEAR {
        format!("{}m", age / MONTH)
    } else {
        format!("{}y", age / YEAR)
    }
}

/// Parse a human-readable duration string into seconds.
///
/// Accepts: `Nd` (days), `Nw` (weeks), `Nm` (months, 30d),
/// `Ny` (years, 365d). Returns an error for unrecognized formats.
///
/// # Errors
///
/// Returns an error string if the format is not recognized or
/// the numeric portion cannot be parsed.
pub fn parse_stale_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('y') {
        let n: u64 = n.parse().map_err(|_| format!("invalid number: {n}"))?;
        Ok(n * 365 * 86400)
    } else if let Some(n) = s.strip_suffix('m') {
        let n: u64 = n.parse().map_err(|_| format!("invalid number: {n}"))?;
        Ok(n * 30 * 86400)
    } else if let Some(n) = s.strip_suffix('w') {
        let n: u64 = n.parse().map_err(|_| format!("invalid number: {n}"))?;
        Ok(n * 7 * 86400)
    } else if let Some(n) = s.strip_suffix('d') {
        let n: u64 = n.parse().map_err(|_| format!("invalid number: {n}"))?;
        Ok(n * 86400)
    } else {
        Err(format!(
            "unrecognized duration: {s}\n\
             accepted: Nd (days), Nw (weeks), Nm (months), Ny (years)"
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

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
        // Fresh repo has .git directory structure but no working tree files.
        let du = result.disk_usage.value().expect("disk_usage requested");
        assert!(du.total_bytes > 0, "even empty repo has .git internals");
        assert_eq!(du.git_bytes, du.total_bytes, "no working tree files yet");
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
        assert!(matches!(result.disk_usage, FieldState::NotRequested));
    }

    #[test]
    fn inspect_nonexistent_fails() {
        let result = inspect(Path::new("/nonexistent/repo"), &InspectionRequest::all());
        assert!(result.is_err());
    }

    #[test]
    fn inspect_only_status() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let request = InspectionRequest {
            status: true,
            ..Default::default()
        };
        let result = inspect(dir.path(), &request).unwrap();
        assert_eq!(result.status.value(), Some(&RepoStatus::Clean));
        assert!(matches!(result.branch, FieldState::NotRequested));
        assert!(matches!(result.remote_url, FieldState::NotRequested));
        assert!(matches!(result.disk_usage, FieldState::NotRequested));
    }

    #[test]
    fn inspect_upstream_expands_branch() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let request = InspectionRequest {
            upstream: true,
            ..Default::default()
        };
        let expanded = request.expanded();
        assert!(expanded.branch);
        let result = inspect(dir.path(), &request).unwrap();
        assert!(result.branch.is_available());
        assert!(matches!(result.upstream_short, FieldState::Absent));
    }

    #[test]
    fn inspect_ahead_behind_expands_deps() {
        let request = InspectionRequest {
            ahead_behind: true,
            ..Default::default()
        };
        let expanded = request.expanded();
        assert!(expanded.head);
        assert!(expanded.upstream);
        assert!(expanded.branch);
    }

    #[test]
    fn inspect_disk_usage_only() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        // Create a working tree file.
        std::fs::write(dir.path().join("hello.txt"), "hello world").unwrap();
        let request = InspectionRequest {
            disk_usage: true,
            ..Default::default()
        };
        let result = inspect(dir.path(), &request).unwrap();
        let du = result.disk_usage.value().expect("disk_usage requested");
        assert!(
            du.total_bytes > du.git_bytes,
            "working tree file adds bytes"
        );
        assert!(du.file_count > 0);
        assert!(matches!(result.branch, FieldState::NotRequested));
        assert!(matches!(result.status, FieldState::NotRequested));
    }

    #[test]
    fn inspect_disk_usage_separates_git_from_working_tree() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let payload = vec![0u8; 4096];
        std::fs::write(dir.path().join("data.bin"), &payload).unwrap();
        let request = InspectionRequest {
            disk_usage: true,
            ..Default::default()
        };
        let result = inspect(dir.path(), &request).unwrap();
        let du = result.disk_usage.value().unwrap();
        assert!(
            du.total_bytes >= 4096,
            "total includes working tree file: {}",
            du.total_bytes
        );
        assert!(
            du.total_bytes - du.git_bytes >= 4096,
            "working tree bytes = total - git = {}",
            du.total_bytes - du.git_bytes
        );
    }

    #[test]
    fn inspectors_cover_all_ids() {
        let registered: Vec<InspectorId> = INSPECTORS.iter().map(|i| i.id()).collect();
        assert!(registered.contains(&InspectorId::Remote));
        assert!(registered.contains(&InspectorId::Branch));
        assert!(registered.contains(&InspectorId::Head));
        assert!(registered.contains(&InspectorId::HeadSummary));
        assert!(registered.contains(&InspectorId::Status));
        assert!(registered.contains(&InspectorId::Upstream));
        assert!(registered.contains(&InspectorId::AheadBehind));
        assert!(registered.contains(&InspectorId::DiskUsage));
        let mut deduped = registered.clone();
        deduped.sort_by_key(|id| *id as u8);
        deduped.dedup();
        assert_eq!(registered.len(), deduped.len());
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

    #[test]
    fn inspect_head_date_on_fresh_repo() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let request = InspectionRequest {
            head_date: true,
            ..Default::default()
        };
        let result = inspect(dir.path(), &request).unwrap();
        // Fresh repo has no commits, so head_date is Absent.
        assert!(matches!(result.head_date, FieldState::Absent));
    }

    #[test]
    fn inspect_upstream_date_expands_branch() {
        let request = InspectionRequest {
            upstream_date: true,
            ..Default::default()
        };
        let expanded = request.expanded();
        assert!(expanded.branch);
    }

    #[test]
    fn parse_stale_duration_days() {
        assert_eq!(parse_stale_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_stale_duration("30d").unwrap(), 30 * 86400);
    }

    #[test]
    fn parse_stale_duration_weeks() {
        assert_eq!(parse_stale_duration("2w").unwrap(), 14 * 86400);
    }

    #[test]
    fn parse_stale_duration_months() {
        assert_eq!(parse_stale_duration("3m").unwrap(), 90 * 86400);
    }

    #[test]
    fn parse_stale_duration_years() {
        assert_eq!(parse_stale_duration("1y").unwrap(), 365 * 86400);
    }

    #[test]
    fn parse_stale_duration_rejects_invalid() {
        assert!(parse_stale_duration("abc").is_err());
        assert!(parse_stale_duration("").is_err());
        assert!(parse_stale_duration("7x").is_err());
    }

    #[test]
    fn format_relative_time_recent() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        #[allow(clippy::cast_possible_wrap)]
        let epoch = now as i64;
        assert_eq!(format_relative_time(epoch), "now");
        assert_eq!(format_relative_time(epoch - 30), "now");
        assert_eq!(format_relative_time(epoch - 120), "2m");
        assert_eq!(format_relative_time(epoch - 7200), "2h");
        assert_eq!(format_relative_time(epoch - 172800), "2d");
    }

    #[test]
    fn format_relative_time_future() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        #[allow(clippy::cast_possible_wrap)]
        let future = (now + 3600) as i64;
        assert_eq!(format_relative_time(future), "future");
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GiB");
        assert_eq!(format_bytes(1_099_511_627_776), "1.0 TiB");
        assert_eq!(format_bytes(1_536), "1.5 KiB");
    }
}
