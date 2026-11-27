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
//! A [`Field`] names one piece of metadata; an [`InspectionRequest`] is
//! the set of fields to collect. [`inspect`] opens the repository once,
//! then inspects each requested field in [`Field::ALL`] order — fields
//! that read others' results (the upstream fields read the branch) come
//! after them. Adding a field takes a `Field` variant, an
//! `InspectionResult` field, and its arm in `inspect_field`.

use std::collections::BTreeSet;
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

/// A read's outcome as a field: a value, none (absent), or its failure.
impl<T> From<Result<Option<T>, InspectionFailure>> for FieldState<T> {
    fn from(read: Result<Option<T>, InspectionFailure>) -> Self {
        match read {
            Ok(Some(value)) => Self::Available(value),
            Ok(None) => Self::Absent,
            Err(failure) => Self::Failed(failure),
        }
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

impl InspectionFailure {
    /// A failure of `kind` described by `error`.
    fn new(kind: InspectionFailureKind, error: impl fmt::Display) -> Self {
        Self {
            kind,
            message: error.to_string(),
        }
    }
}

/// The kind of failure during field inspection. A repository that cannot
/// be opened fails the whole inspection instead ([`inspect`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionFailureKind {
    /// Could not read the remote URL.
    RemoteRead,
    /// Could not read the HEAD reference.
    HeadRead,
    /// Could not read working tree status.
    StatusRead,
    /// Could not read the upstream tracking reference.
    UpstreamRead,
    /// Could not compute disk usage.
    DiskUsage,
    /// The worker was cancelled before inspecting the repository.
    Cancelled,
}

impl fmt::Display for InspectionFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteRead => write!(f, "remote read"),
            Self::HeadRead => write!(f, "head read"),
            Self::StatusRead => write!(f, "status read"),
            Self::UpstreamRead => write!(f, "upstream read"),
            Self::DiskUsage => write!(f, "disk usage"),
            Self::Cancelled => write!(f, "cancelled"),
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
// Fields and requests
// ============================================================================

/// One piece of repository metadata inspection can collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
    /// The `origin` fetch URL.
    Remote,
    /// The checked-out branch.
    Branch,
    /// The abbreviated HEAD commit id.
    Head,
    /// The first line of the HEAD commit message.
    HeadSummary,
    /// Whether the working tree has changes.
    Status,
    /// The abbreviated upstream commit id (reads the branch).
    Upstream,
    /// Commits ahead of and behind the upstream (reads the branch).
    AheadBehind,
    /// The HEAD commit's committer time.
    HeadDate,
    /// The upstream commit's committer time (reads the branch).
    UpstreamDate,
    /// Bytes and files on disk; the most expensive, so inspected last.
    DiskUsage,
}

impl Field {
    /// Every field, in inspection order: each after the fields it reads.
    pub const ALL: [Self; 10] = [
        Self::Remote,
        Self::Branch,
        Self::Head,
        Self::HeadSummary,
        Self::Status,
        Self::Upstream,
        Self::AheadBehind,
        Self::HeadDate,
        Self::UpstreamDate,
        Self::DiskUsage,
    ];

    /// The fields this one reads from the result.
    const fn reads(self) -> &'static [Self] {
        match self {
            Self::Upstream | Self::AheadBehind | Self::UpstreamDate => &[Self::Branch],
            _ => &[],
        }
    }
}

/// The set of metadata fields to collect during inspection; the fields a
/// requested field reads are inspected with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InspectionRequest {
    fields: BTreeSet<Field>,
}

impl InspectionRequest {
    /// Request all available metadata.
    #[must_use]
    pub fn all() -> Self {
        Field::ALL.into_iter().collect()
    }

    /// Add `field` to the request.
    pub fn insert(&mut self, field: Field) {
        self.fields.insert(field);
    }

    /// Whether `field` is requested, directly or as a field a requested
    /// one reads.
    #[must_use]
    pub fn contains(&self, field: Field) -> bool {
        self.fields.contains(&field)
            || self
                .fields
                .iter()
                .any(|requested| requested.reads().contains(&field))
    }

    /// Whether nothing is requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl FromIterator<Field> for InspectionRequest {
    fn from_iter<I: IntoIterator<Item = Field>>(fields: I) -> Self {
        Self {
            fields: fields.into_iter().collect(),
        }
    }
}

impl Extend<Field> for InspectionRequest {
    fn extend<I: IntoIterator<Item = Field>>(&mut self, fields: I) {
        self.fields.extend(fields);
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
    pub ahead_behind: FieldState<AheadBehind>,
    pub disk_usage: FieldState<DiskUsage>,
    pub head_date: FieldState<i64>,
    pub upstream_date: FieldState<i64>,
}

/// Commits on HEAD not on its upstream (`ahead`), and on the upstream not
/// on HEAD (`behind`): `git rev-list --count upstream..HEAD` and
/// `HEAD..upstream`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AheadBehind {
    pub ahead: usize,
    pub behind: usize,
}

impl fmt::Display for AheadBehind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "+{} -{}", self.ahead, self.behind)
    }
}

impl InspectionResult {
    /// All fields set to `Failed(Cancelled)`. Used when a worker is
    /// cancelled before inspecting this repo. Distinct from `Absent`
    /// (which means the field legitimately has no value) and from
    /// `NotRequested` (which means the caller didn't ask for it).
    #[must_use]
    pub fn skipped() -> Self {
        let failure =
            InspectionFailure::new(InspectionFailureKind::Cancelled, "inspection cancelled");
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
// Field reads
// ============================================================================

/// Inspect `field` of `repo` (at `path`, for diagnostics) into `result`,
/// which holds the fields inspected before it.
fn inspect_field(field: Field, repo: &gix::Repository, path: &Path, result: &mut InspectionResult) {
    match field {
        Field::Remote => result.remote_url = remote_url(repo).into(),
        Field::Branch => {
            result.branch = repo
                .head_name()
                .map(|name| name.map(|name| name.shorten().to_string()))
                .map_err(|e| InspectionFailure::new(InspectionFailureKind::HeadRead, e))
                .into();
        }
        Field::Head => {
            result.head_short = repo
                .head()
                .map(|head| head.id().map(|id| id.to_hex_with_len(7).to_string()))
                .map_err(|e| InspectionFailure::new(InspectionFailureKind::HeadRead, e))
                .into();
        }
        Field::HeadSummary => {
            result.head_summary = head_commit(repo)
                .map(|commit| {
                    let message = commit?.message_raw_sloppy().to_string();
                    let first = message.lines().next().unwrap_or_default();
                    (!first.is_empty()).then(|| first.to_owned())
                })
                .into();
        }
        Field::Status => result.status = check_status(repo, path),
        Field::Upstream => {
            result.upstream_short = upstream_reference(repo, &result.branch)
                .map(|reference| reference.map(|r| r.id().to_hex_with_len(7).to_string()))
                .into();
        }
        Field::AheadBehind => result.ahead_behind = ahead_behind(repo, &result.branch).into(),
        Field::HeadDate => {
            result.head_date = head_commit(repo)
                .and_then(|commit| {
                    commit
                        .map(|c| commit_time(&c, InspectionFailureKind::HeadRead))
                        .transpose()
                })
                .into();
        }
        Field::UpstreamDate => {
            result.upstream_date = upstream_commit(repo, &result.branch)
                .and_then(|commit| {
                    commit
                        .map(|c| commit_time(&c, InspectionFailureKind::UpstreamRead))
                        .transpose()
                })
                .into();
        }
        Field::DiskUsage => result.disk_usage = disk_usage(repo, path),
    }
}

/// The `origin` fetch URL; `None` without an `origin` remote or URL.
fn remote_url(repo: &gix::Repository) -> Result<Option<String>, InspectionFailure> {
    match repo.try_find_remote("origin") {
        None => Ok(None),
        Some(Err(e)) => Err(InspectionFailure::new(InspectionFailureKind::RemoteRead, e)),
        Some(Ok(remote)) => Ok(remote
            .url(gix::remote::Direction::Fetch)
            .map(|url| url.to_bstring().to_string())),
    }
}

/// The HEAD commit; `None` when HEAD is unborn.
fn head_commit(repo: &gix::Repository) -> Result<Option<gix::Commit<'_>>, InspectionFailure> {
    let failure = |e: &dyn fmt::Display| InspectionFailure::new(InspectionFailureKind::HeadRead, e);
    let head = repo.head().map_err(|e| failure(&e))?;
    let Some(id) = head.id() else {
        return Ok(None);
    };
    let commit = id
        .object()
        .map_err(|e| failure(&e))?
        .try_into_commit()
        .map_err(|e| failure(&e))?;
    Ok(Some(commit))
}

/// The commit of the inspected branch's upstream; `None` without one.
fn upstream_commit<'repo>(
    repo: &'repo gix::Repository,
    branch: &FieldState<String>,
) -> Result<Option<gix::Commit<'repo>>, InspectionFailure> {
    let failure =
        |e: &dyn fmt::Display| InspectionFailure::new(InspectionFailureKind::UpstreamRead, e);
    let Some(reference) = upstream_reference(repo, branch)? else {
        return Ok(None);
    };
    let commit = reference
        .id()
        .object()
        .map_err(|e| failure(&e))?
        .try_into_commit()
        .map_err(|e| failure(&e))?;
    Ok(Some(commit))
}

/// `commit`'s committer time in seconds since the Unix epoch; a failure
/// is of `kind`.
fn commit_time(
    commit: &gix::Commit<'_>,
    kind: InspectionFailureKind,
) -> Result<i64, InspectionFailure> {
    commit
        .time()
        .map(|time| time.seconds)
        .map_err(|e| InspectionFailure::new(kind, e))
}

/// The upstream tracking reference `refs/remotes/origin/<branch>` of the
/// inspected branch. `Ok(None)` when there is no upstream: HEAD is
/// detached (branch `Absent`) or the tracking reference does not exist.
fn upstream_reference<'repo>(
    repo: &'repo gix::Repository,
    branch: &FieldState<String>,
) -> Result<Option<gix::Reference<'repo>>, InspectionFailure> {
    let failure =
        |message: String| InspectionFailure::new(InspectionFailureKind::UpstreamRead, message);
    let name = match branch {
        FieldState::Available(name) => name,
        FieldState::Absent => return Ok(None),
        FieldState::Failed(e) => return Err(failure(format!("branch unknown: {}", e.message))),
        // `InspectionRequest::contains` inspects the branch with every
        // field that reads it.
        FieldState::NotRequested => return Err(failure("branch not inspected".into())),
    };
    let refname = format!("refs/remotes/origin/{name}");
    repo.try_find_reference(refname.as_str())
        .map_err(|e| failure(format!("{refname}: {e}")))
}

/// Ahead/behind counts of HEAD against its upstream; `Ok(None)` when HEAD
/// is unborn or there is no upstream.
fn ahead_behind(
    repo: &gix::Repository,
    branch: &FieldState<String>,
) -> Result<Option<AheadBehind>, InspectionFailure> {
    let Some(mut upstream) = upstream_reference(repo, branch)? else {
        return Ok(None);
    };
    let failure =
        |message: String| InspectionFailure::new(InspectionFailureKind::UpstreamRead, message);
    let head = repo.head().map_err(|e| failure(format!("HEAD: {e}")))?;
    let Some(head_id) = head.id() else {
        return Ok(None); // unborn HEAD
    };
    let upstream_id = upstream
        .peel_to_id()
        .map_err(|e| failure(format!("upstream: {e}")))?
        .detach();
    let head_id = head_id.detach();
    let count = |tip: gix::ObjectId, hidden: gix::ObjectId| -> Result<usize, InspectionFailure> {
        let walk = repo
            .rev_walk([tip])
            .with_hidden([hidden])
            .all()
            .map_err(|e| failure(format!("commit walk: {e}")))?;
        let mut n = 0usize;
        for info in walk {
            info.map_err(|e| failure(format!("commit walk: {e}")))?;
            n += 1;
        }
        Ok(n)
    };
    Ok(Some(AheadBehind {
        ahead: count(head_id, upstream_id)?,
        behind: count(upstream_id, head_id)?,
    }))
}

/// Disk usage via one `dua-core` traversal of `path`.
///
/// Single-threaded (`threads: 1`): each inspection already runs inside a
/// pool worker, which provides the cross-repository parallelism;
/// intra-repository parallelism would oversubscribe.
///
/// Entries under the git directory are summed separately into
/// `git_bytes`; non-directory entries are counted in `file_count`. An
/// entry that cannot be read fails the field rather than being left out
/// of the totals.
fn disk_usage(repo: &gix::Repository, path: &Path) -> FieldState<DiskUsage> {
    let start = std::time::Instant::now();
    // A linked worktree's git directory lives in the main repository,
    // outside `path`; only the `.git` link file is under `path`.
    let git_dir = repo.git_dir();
    let mut usage = DiskUsage {
        total_bytes: 0,
        git_bytes: 0,
        file_count: 0,
    };
    let failed = |message: String| {
        FieldState::Failed(InspectionFailure::new(
            InspectionFailureKind::DiskUsage,
            message,
        ))
    };

    for entry in dua_core::walk(
        path,
        1,
        dua_core::Order::Completion,
        dua_core::Options::default(),
        |_| true,
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            // The error names the failing entry or directory; only a pool
            // failure carries no path.
            Err(e) => {
                return failed(match e.path() {
                    Some(_) => e.to_string(),
                    None => format!("walk {}: {e}", path.display()),
                });
            }
        };
        if entry.file_type.is_dir() {
            continue;
        }
        let size = match entry.metadata.as_ref() {
            Some(Ok(meta)) => meta.len(),
            Some(Err(e)) => return failed(format!("{}: {e}", entry.path().display())),
            None => return failed(format!("{}: no metadata", entry.path().display())),
        };
        usage.total_bytes = usage.total_bytes.saturating_add(size);
        usage.file_count += 1;
        if entry.path().starts_with(git_dir) {
            usage.git_bytes = usage.git_bytes.saturating_add(size);
        }
    }

    let elapsed_ms = start.elapsed().as_millis();
    if elapsed_ms > 500 {
        tracing::debug!(
            path = %path.display(),
            elapsed_ms,
            total_bytes = usage.total_bytes,
            file_count = usage.file_count,
            "slow disk usage walk"
        );
    }
    FieldState::Available(usage)
}

// ============================================================================
// Public entry point
// ============================================================================

/// Inspect a repository at the given path, collecting only the
/// requested metadata fields (with the fields they read).
///
/// Opens the repository once via gix, then inspects each requested field
/// in [`Field::ALL`] order against the shared handle.
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
    let repo = gix::open(path).map_err(|e| WorkspaceError::GitError(format!("{e}")))?;
    let mut result = InspectionResult::default();
    for field in Field::ALL {
        if request.contains(field) {
            inspect_field(field, &repo, path, &mut result);
        }
    }
    Ok(result)
}

// ============================================================================
// Status check
// ============================================================================

/// Repository dirty/clean status from `gix::status`: dirty when any
/// change exists, untracked files included (`git status --porcelain`).
///
/// Read-only: unlike `git update-index --refresh`, the index is not
/// rewritten. A bare repository has no working tree, so status is
/// `Absent`. The `path` parameter is for diagnostic tracing only.
fn check_status(repo: &gix::Repository, path: &Path) -> FieldState<RepoStatus> {
    if repo.workdir().is_none() {
        return FieldState::Absent;
    }
    let start = std::time::Instant::now();
    let result = status_of(repo).map(Some).into();
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

/// Whether any change exists: the first status entry decides.
fn status_of(repo: &gix::Repository) -> Result<RepoStatus, InspectionFailure> {
    let failure =
        |e: &dyn fmt::Display| InspectionFailure::new(InspectionFailureKind::StatusRead, e);
    let mut entries = repo
        .status(gix::progress::Discard)
        .map_err(|e| failure(&e))?
        .into_iter(Vec::new())
        .map_err(|e| failure(&e))?;
    match entries.next() {
        None => Ok(RepoStatus::Clean),
        Some(Ok(_)) => Ok(RepoStatus::Dirty),
        Some(Err(e)) => Err(failure(&e)),
    }
}

// ============================================================================
// Human-readable byte formatting
// ============================================================================

/// Binary units, largest first, with their size in bytes.
const BYTE_UNITS: [(&str, u64); 4] = [
    ("TiB", 1 << 40),
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
];

/// Format a byte count as a human-readable string.
///
/// Uses binary units (KiB, MiB, GiB, TiB) with one decimal place, rounded
/// to the nearest tenth. Values under 1 KiB are shown as whole bytes.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    match BYTE_UNITS.iter().find(|(_, size)| bytes >= *size) {
        Some(&(unit, size)) => {
            let (bytes, size) = (u128::from(bytes), u128::from(size));
            let tenths = (bytes * 10 + size / 2) / size;
            format!("{}.{} {unit}", tenths / 10, tenths % 10)
        }
        None => format!("{bytes} B"),
    }
}

// ============================================================================
// Relative time formatting
// ============================================================================

/// Format a unix epoch timestamp as a relative age string at `now`
/// (seconds since the Unix epoch). Returns compact human-readable
/// durations: `3m`, `5h`, `2d`, `1w`, `3mo`, `1y`.
///
/// Returns `"future"` for timestamps ahead of now, `"now"` for
/// ages under one minute.
#[must_use]
pub fn format_relative_time(epoch_secs: i64, now: u64) -> String {
    // Timestamps before the Unix epoch are older than any representable
    // age; clamp to the epoch rather than wrapping into the future.
    let epoch = u64::try_from(epoch_secs).unwrap_or(0);
    if epoch > now {
        return "future".into();
    }
    let age = now - epoch;

    TIME_UNITS
        .iter()
        .find(|unit| age >= unit.seconds)
        .map_or_else(
            || "now".into(),
            |unit| format!("{}{}", age / unit.seconds, unit.suffix),
        )
}

/// A duration unit shared by relative-time output and `--stale` input.
struct TimeUnit {
    suffix: &'static str,
    seconds: u64,
    name: &'static str,
}

/// Duration units, largest first. Relative times use the first unit the
/// age reaches; parsing matches suffixes in this order, so `mo` is tried
/// before `m`.
const TIME_UNITS: &[TimeUnit] = &[
    TimeUnit {
        suffix: "y",
        seconds: 365 * 86400,
        name: "years (365d)",
    },
    TimeUnit {
        suffix: "mo",
        seconds: 30 * 86400,
        name: "months (30d)",
    },
    TimeUnit {
        suffix: "w",
        seconds: 7 * 86400,
        name: "weeks",
    },
    TimeUnit {
        suffix: "d",
        seconds: 86400,
        name: "days",
    },
    TimeUnit {
        suffix: "h",
        seconds: 3600,
        name: "hours",
    },
    TimeUnit {
        suffix: "m",
        seconds: 60,
        name: "minutes",
    },
];

/// Parse a duration such as `30d` into seconds, using the units of
/// `format_relative_time`: `m` (minutes), `h`, `d`, `w`, `mo` (30d),
/// `y` (365d).
///
/// # Errors
///
/// Returns an error string if the unit is not recognized, the numeric
/// portion cannot be parsed, or the duration overflows `u64` seconds.
pub fn parse_stale_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let accepted = || {
        TIME_UNITS
            .iter()
            .map(|unit| format!("N{} ({})", unit.suffix, unit.name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let Some((count, unit)) = TIME_UNITS
        .iter()
        .find_map(|unit| s.strip_suffix(unit.suffix).map(|count| (count, unit)))
    else {
        return Err(format!(
            "unrecognized duration: {s}\naccepted: {}",
            accepted()
        ));
    };
    let count: u64 = count
        .parse()
        .map_err(|_| format!("invalid number: {count}"))?;
    count
        .checked_mul(unit.seconds)
        .ok_or_else(|| format!("duration too large: {s}"))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn request(fields: &[Field]) -> InspectionRequest {
        fields.iter().copied().collect()
    }

    #[test]
    fn inspect_fresh_repo() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let result = inspect(dir.path(), &InspectionRequest::all()).unwrap();
        assert!(matches!(result.remote_url, FieldState::Absent));
        assert_eq!(result.branch.value(), Some(&"main".to_string()));
        assert!(matches!(result.head_short, FieldState::Absent));
        assert!(matches!(result.head_summary, FieldState::Absent));
        assert!(matches!(result.head_date, FieldState::Absent));
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
        let result = inspect(dir.path(), &request(&[Field::Branch])).unwrap();
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
        let result = inspect(dir.path(), &request(&[Field::Status])).unwrap();
        assert_eq!(result.status.value(), Some(&RepoStatus::Clean));
        assert!(matches!(result.branch, FieldState::NotRequested));
        assert!(matches!(result.remote_url, FieldState::NotRequested));
        assert!(matches!(result.disk_usage, FieldState::NotRequested));
    }

    #[test]
    fn fields_reading_the_branch_inspect_it_too() {
        for field in [Field::Upstream, Field::AheadBehind, Field::UpstreamDate] {
            let req = request(&[field]);
            assert!(req.contains(Field::Branch), "{field:?}");
            assert!(!req.contains(Field::Head));
        }
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        let result = inspect(dir.path(), &request(&[Field::Upstream])).unwrap();
        assert!(result.branch.is_available());
        assert!(matches!(result.upstream_short, FieldState::Absent));
    }

    #[test]
    fn every_field_is_inspected_after_the_fields_it_reads() {
        for (position, field) in Field::ALL.iter().enumerate() {
            for read in field.reads() {
                let read_at = Field::ALL.iter().position(|f| f == read).unwrap();
                assert!(read_at < position, "{field:?} reads {read:?}");
            }
        }
        let distinct: BTreeSet<Field> = Field::ALL.into_iter().collect();
        assert_eq!(distinct.len(), Field::ALL.len());
    }

    /// Commit an empty tree on top of `parent` and point `refname` at it.
    fn commit_on(
        repo: &git2::Repository,
        refname: &str,
        parent: git2::Oid,
        msg: &str,
    ) -> git2::Oid {
        let sig = git2::Signature::now("alice", "alice@example.invalid").unwrap();
        let tree = repo
            .find_tree(repo.index().unwrap().write_tree().unwrap())
            .unwrap();
        let parent = repo.find_commit(parent).unwrap();
        repo.commit(Some(refname), &sig, &sig, msg, &tree, &[&parent])
            .unwrap()
    }

    #[test]
    fn ahead_behind_counts_diverged_history() {
        let dir = tempfile::tempdir().unwrap();
        let repo = crate::git::marker::test_repos::init(dir.path());
        let base = repo.head().unwrap().peel_to_commit().unwrap().id();
        let branch = repo.head().unwrap().shorthand().unwrap().to_string();
        let tracking = format!("refs/remotes/origin/{branch}");
        repo.reference(&tracking, base, true, "test").unwrap();
        // Upstream gains 3 commits; HEAD gains 2 on its own line.
        let mut up = base;
        for i in 0..3 {
            up = commit_on(&repo, &tracking, up, &format!("up {i}"));
        }
        let mut local = base;
        for i in 0..2 {
            local = commit_on(&repo, "HEAD", local, &format!("local {i}"));
        }
        let result = inspect(
            dir.path(),
            &request(&[Field::AheadBehind, Field::HeadSummary, Field::UpstreamDate]),
        )
        .unwrap();
        assert_eq!(
            result.ahead_behind.value(),
            Some(&AheadBehind {
                ahead: 2,
                behind: 3
            })
        );
        assert_eq!(
            result.head_summary.value().map(String::as_str),
            Some("local 1")
        );
        assert!(result.upstream_date.is_available());
    }

    #[test]
    fn ahead_behind_without_upstream_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        crate::git::marker::test_repos::init(dir.path());
        let result = inspect(dir.path(), &request(&[Field::AheadBehind])).unwrap();
        assert!(matches!(result.ahead_behind, FieldState::Absent));
    }

    #[test]
    fn upstream_of_detached_head_is_absent_not_main() {
        let dir = tempfile::tempdir().unwrap();
        let repo = crate::git::marker::test_repos::init(dir.path());
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        // A tracking ref for "main" exists; a detached HEAD must not read it.
        repo.reference("refs/remotes/origin/main", head.id(), true, "test")
            .unwrap();
        repo.set_head_detached(head.id()).unwrap();
        let result = inspect(
            dir.path(),
            &request(&[Field::Upstream, Field::UpstreamDate]),
        )
        .unwrap();
        assert!(matches!(result.branch, FieldState::Absent));
        assert!(matches!(result.upstream_short, FieldState::Absent));
        assert!(matches!(result.upstream_date, FieldState::Absent));
    }

    #[test]
    fn status_does_not_rewrite_the_index() {
        let dir = tempfile::tempdir().unwrap();
        crate::git::marker::test_repos::init(dir.path());
        std::fs::write(dir.path().join("untracked.txt"), "x").unwrap();
        let index = dir.path().join(".git").join("index");
        let before = std::fs::metadata(&index)
            .map(|m| m.modified().unwrap())
            .ok();
        let result = inspect(dir.path(), &request(&[Field::Status])).unwrap();
        assert_eq!(result.status.value(), Some(&RepoStatus::Dirty));
        let after = std::fs::metadata(&index)
            .map(|m| m.modified().unwrap())
            .ok();
        assert_eq!(before, after);
    }

    #[test]
    fn bare_repository_status_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        gix::init_bare(dir.path()).unwrap();
        let result = inspect(dir.path(), &request(&[Field::Status])).unwrap();
        assert!(matches!(result.status, FieldState::Absent));
    }

    #[test]
    fn inspect_disk_usage_only() {
        let dir = tempfile::tempdir().unwrap();
        let _repo = gix::init(dir.path()).unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello world").unwrap();
        let result = inspect(dir.path(), &request(&[Field::DiskUsage])).unwrap();
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
        std::fs::write(dir.path().join("data.bin"), vec![0u8; 4096]).unwrap();
        let result = inspect(dir.path(), &request(&[Field::DiskUsage])).unwrap();
        let du = result.disk_usage.value().unwrap();
        assert!(du.total_bytes >= 4096, "{}", du.total_bytes);
        assert!(du.total_bytes - du.git_bytes >= 4096);
    }

    #[test]
    fn reads_become_field_states() {
        let failure = InspectionFailure::new(InspectionFailureKind::HeadRead, "corrupt");
        assert_eq!(FieldState::from(Ok(Some(1))), FieldState::Available(1));
        assert_eq!(FieldState::<i32>::from(Ok(None)), FieldState::Absent);
        assert_eq!(
            FieldState::<i32>::from(Err(failure.clone())),
            FieldState::Failed(failure)
        );
    }

    #[test]
    fn repo_status_display() {
        assert_eq!(RepoStatus::Clean.to_string(), "clean");
        assert_eq!(RepoStatus::Dirty.to_string(), "dirty");
    }

    #[test]
    fn field_state_display() {
        assert_eq!(FieldState::<String>::NotRequested.to_string(), "");
        assert_eq!(
            FieldState::Available("main".to_string()).to_string(),
            "main"
        );
        let failed: FieldState<String> = FieldState::Failed(InspectionFailure::new(
            InspectionFailureKind::HeadRead,
            "corrupt",
        ));
        assert!(failed.to_string().contains("head read"));
    }

    #[test]
    fn parse_stale_duration_units() {
        assert_eq!(parse_stale_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_stale_duration("2w").unwrap(), 14 * 86400);
        assert_eq!(parse_stale_duration("3mo").unwrap(), 90 * 86400);
        assert_eq!(parse_stale_duration("1y").unwrap(), 365 * 86400);
        // `m` is minutes, as in the relative-time column.
        assert_eq!(parse_stale_duration("3m").unwrap(), 180);
        assert_eq!(parse_stale_duration("2h").unwrap(), 7200);
    }

    #[test]
    fn parse_stale_duration_rejects_overflow_and_garbage() {
        assert!(parse_stale_duration(&format!("{}y", u64::MAX)).is_err());
        assert!(parse_stale_duration("abc").is_err());
        assert!(parse_stale_duration("").is_err());
        assert!(parse_stale_duration("7x").is_err());
    }

    /// A fixed clock for relative-time tests.
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn stale_duration_round_trips_relative_time_output() {
        for secs in [120, 7200, 172_800, 1_209_600, 5_184_000, 63_072_000] {
            let epoch = i64::try_from(NOW - secs).unwrap();
            let shown = format_relative_time(epoch, NOW);
            assert_eq!(parse_stale_duration(&shown).unwrap(), secs, "{shown}");
        }
    }

    #[test]
    fn format_relative_time_recent() {
        let epoch = i64::try_from(NOW).unwrap();
        let at = |e: i64| format_relative_time(e, NOW);
        assert_eq!(at(epoch), "now");
        assert_eq!(at(epoch - 30), "now");
        assert_eq!(at(epoch - 120), "2m");
        assert_eq!(at(epoch - 7200), "2h");
        assert_eq!(at(epoch - 172_800), "2d");
        assert_eq!(at(epoch - 14 * 86_400), "2w");
        assert_eq!(at(epoch - 90 * 86_400), "3mo");
        assert_eq!(at(epoch - 400 * 86_400), "1y");
    }

    #[test]
    fn format_relative_time_pre_epoch_is_old_not_future() {
        assert!(format_relative_time(-1, NOW).ends_with('y'));
    }

    #[test]
    fn format_relative_time_future() {
        let future = i64::try_from(NOW + 3600).unwrap();
        assert_eq!(format_relative_time(future, NOW), "future");
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
        assert_eq!(format_bytes(1_075), "1.0 KiB", "1.0498 rounds down");
        assert_eq!(format_bytes(1_076), "1.1 KiB", "1.0508 rounds up");
        assert_eq!(format_bytes(u64::MAX), "16777216.0 TiB");
    }
}
