//! Column-based output formatting for workspace listings.
//!
//! Columns are static data keyed by [`ColumnId`]: adding one takes a
//! `ColumnId` variant, its `ALL_COLUMNS` entry (with the inspection fields
//! it reads), and its arm in `extract_field`.
//!
//! Discovery provides filesystem facts. Inspection provides Git
//! metadata. This module combines both into field values for display.

use core_workspace_types::{NamespaceDir, RepoDir, WorkspaceKind};

use crate::discover::{DiscoveredWorkspace, DiscoveryIssue};
use crate::inspection::{
    Field, InspectionRequest, InspectionResult, format_bytes, format_relative_time,
};
use crate::layout::Skipped;

/// A workspace list column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnId {
    Name,
    Branch,
    Commit,
    Status,
    Size,
    GitSize,
    Files,
    LastCommit,
    AheadBehind,
    UpstreamDate,
    Profile,
    Server,
    Org,
    Remote,
}

impl ColumnId {
    /// The column's definition.
    #[must_use]
    pub const fn column(self) -> &'static Column {
        &ALL_COLUMNS[self as usize]
    }
}

/// A column definition for workspace list output.
#[derive(Debug, Clone, Copy)]
pub struct Column {
    pub id: ColumnId,
    /// Column identifier used in the --columns flag.
    pub name: &'static str,
    /// Display header for table output.
    pub header: &'static str,
    /// Minimum display width hint for table alignment.
    pub min_width: usize,
    /// The inspection fields the column displays; none for discovery
    /// facts.
    pub fields: &'static [Field],
}

/// All available columns in display order, at their `ColumnId` index.
pub const ALL_COLUMNS: &[Column] = &[
    Column {
        id: ColumnId::Name,
        name: "name",
        header: "NAME",
        min_width: 20,
        fields: &[],
    },
    Column {
        id: ColumnId::Branch,
        name: "branch",
        header: "BRANCH",
        min_width: 14,
        fields: &[Field::Branch],
    },
    Column {
        id: ColumnId::Commit,
        name: "commit",
        header: "COMMIT",
        min_width: 7,
        fields: &[Field::Head],
    },
    Column {
        id: ColumnId::Status,
        name: "status",
        header: "STATUS",
        min_width: 7,
        fields: &[Field::Status],
    },
    Column {
        id: ColumnId::Size,
        name: "size",
        header: "SIZE",
        min_width: 9,
        fields: &[Field::DiskUsage],
    },
    Column {
        id: ColumnId::GitSize,
        name: "git_size",
        header: "GIT",
        min_width: 9,
        fields: &[Field::DiskUsage],
    },
    Column {
        id: ColumnId::Files,
        name: "files",
        header: "FILES",
        min_width: 7,
        fields: &[Field::DiskUsage],
    },
    Column {
        id: ColumnId::LastCommit,
        name: "last_commit",
        header: "LAST",
        min_width: 6,
        fields: &[Field::HeadDate],
    },
    Column {
        id: ColumnId::AheadBehind,
        name: "ahead_behind",
        header: "AHEAD/BEHIND",
        min_width: 8,
        fields: &[Field::AheadBehind],
    },
    Column {
        id: ColumnId::UpstreamDate,
        name: "upstream_date",
        header: "UPSTREAM",
        min_width: 6,
        fields: &[Field::UpstreamDate],
    },
    Column {
        id: ColumnId::Profile,
        name: "profile",
        header: "PROFILE",
        min_width: 8,
        fields: &[],
    },
    Column {
        id: ColumnId::Server,
        name: "server",
        header: "SERVER",
        min_width: 10,
        fields: &[],
    },
    Column {
        id: ColumnId::Org,
        name: "org",
        header: "ORG",
        min_width: 10,
        fields: &[],
    },
    Column {
        id: ColumnId::Remote,
        name: "remote",
        header: "REMOTE",
        min_width: 30,
        fields: &[Field::Remote],
    },
];

/// Default column set for interactive table output.
///
/// Does not include status or disk usage because they require a full
/// working tree walk per repository. Use `--columns` to include them
/// explicitly.
pub const DEFAULT_COLUMNS: &[ColumnId] = &[
    ColumnId::Name,
    ColumnId::Branch,
    ColumnId::Commit,
    ColumnId::Profile,
];

/// The inspection fields `columns` display; empty when they show only
/// discovery facts.
#[must_use]
pub fn inspection_request(columns: &[ColumnId]) -> InspectionRequest {
    columns
        .iter()
        .flat_map(|id| id.column().fields.iter().copied())
        .collect()
}

/// The result of extracting a field value for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// The field has a displayable value.
    Present(String),
    /// The field is legitimately empty (e.g. no profile linked).
    Empty,
    /// The field is legitimately absent (e.g. unborn HEAD, no
    /// upstream tracking ref). Display as `-`.
    Absent,
    /// The field could not be read (inspection failed or data
    /// unavailable). Display as `!`.
    Failed,
}

impl FieldValue {
    /// The display string for table output.
    #[must_use]
    pub fn display(&self) -> &str {
        match self {
            Self::Present(s) => s,
            Self::Empty => "",
            Self::Absent => "-",
            Self::Failed => "!",
        }
    }

    /// The raw string for column width calculation and JSON.
    /// Returns `None` for empty/absent/failed.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Present(s) => Some(s),
            _ => None,
        }
    }
}

/// Extract a field value from a discovered workspace and its
/// inspection result.
///
/// Discovery fields (name, profile, server, org) come from
/// `DiscoveredWorkspace`. Inspection fields (branch, commit,
/// status, remote, size, `git_size`, files, `last_commit`,
/// `upstream_date`) come from `InspectionResult`.
///
/// Returns a `FieldValue` that distinguishes present values
/// from empty, absent, and failed states for appropriate
/// rendering. Relative times are computed at `now` (seconds since the
/// Unix epoch).
#[must_use]
pub fn extract_field(
    ws: &DiscoveredWorkspace,
    inspection: Option<&InspectionResult>,
    column: ColumnId,
    now: u64,
) -> FieldValue {
    use crate::inspection::FieldState;

    /// The one mapping from an inspection field to a display value.
    fn state_field<T>(
        inspection: Option<&InspectionResult>,
        field: impl Fn(&InspectionResult) -> &FieldState<T>,
        render: impl Fn(&T) -> String,
    ) -> FieldValue {
        match inspection.map(field) {
            Some(FieldState::Available(v)) => FieldValue::Present(render(v)),
            Some(FieldState::Failed(_)) => FieldValue::Failed,
            Some(FieldState::Absent | FieldState::NotRequested) | None => FieldValue::Absent,
        }
    }

    match column {
        ColumnId::Name => match ws.coordinate.kind().repository_dir() {
            Some(r) => FieldValue::Present(r.as_str().to_string()),
            None => FieldValue::Absent,
        },
        ColumnId::Branch => state_field(inspection, |i| &i.branch, Clone::clone),
        ColumnId::Commit => state_field(inspection, |i| &i.head_short, Clone::clone),
        ColumnId::Status => state_field(inspection, |i| &i.status, ToString::to_string),
        ColumnId::Size => state_field(
            inspection,
            |i| &i.disk_usage,
            |du| format_bytes(du.total_bytes),
        ),
        ColumnId::GitSize => state_field(
            inspection,
            |i| &i.disk_usage,
            |du| format_bytes(du.git_bytes),
        ),
        ColumnId::Files => state_field(
            inspection,
            |i| &i.disk_usage,
            |du| du.file_count.to_string(),
        ),
        ColumnId::LastCommit => state_field(
            inspection,
            |i| &i.head_date,
            |e| format_relative_time(*e, now),
        ),
        ColumnId::UpstreamDate => state_field(
            inspection,
            |i| &i.upstream_date,
            |e| format_relative_time(*e, now),
        ),
        ColumnId::Profile => match &ws.linked_profile {
            Some(p) => FieldValue::Present(p.clone()),
            None => FieldValue::Empty,
        },
        ColumnId::Server => FieldValue::Present(ws.coordinate.host().to_string()),
        ColumnId::Org => FieldValue::Present(ws.coordinate.namespace().to_string()),
        ColumnId::Remote => state_field(inspection, |i| &i.remote_url, Clone::clone),
        ColumnId::AheadBehind => state_field(inspection, |i| &i.ahead_behind, ToString::to_string),
    }
}

/// Parse a comma-separated column spec into its columns.
///
/// # Errors
///
/// Returns an error listing valid columns if any name is unrecognized,
/// or if the spec is empty.
pub fn parse_columns(spec: &str) -> Result<Vec<ColumnId>, String> {
    let mut result = Vec::new();
    for name in spec.split(',').map(str::trim) {
        if name.is_empty() {
            continue;
        }
        if let Some(col) = ALL_COLUMNS.iter().find(|c| c.name == name) {
            result.push(col.id);
        } else {
            let valid: Vec<&str> = ALL_COLUMNS.iter().map(|c| c.name).collect();
            return Err(format!(
                "unknown column: {name}\nvalid columns: {}",
                valid.join(", ")
            ));
        }
    }
    if result.is_empty() {
        return Err("no columns specified".into());
    }
    Ok(result)
}

/// Stable JSON record for a workspace entry.
///
/// This struct defines the machine-readable output schema. Fields use
/// `Option` to produce JSON `null` for absent values. The schema is
/// independent of table column selection.
///
/// Disk usage fields emit raw bytes as integers for machine
/// consumption. Table output uses `format_bytes` for human display.
///
/// `kind` is `repository` for a member or standalone repository and
/// `workspace` for an org-level workspace repository. Discovery places
/// only those two kinds; an organization has no directory of its own to
/// discover, so `organization` appears only for coordinates built
/// outside discovery.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkspaceRecord {
    pub path: String,
    pub server: String,
    pub namespace: NamespaceDir,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<RepoDir>,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_date_epoch: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_date_epoch: Option<i64>,
    /// Commits on HEAD not on its upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ahead: Option<usize>,
    /// Commits on the upstream not on HEAD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behind: Option<usize>,
}

impl WorkspaceRecord {
    /// Build a record from discovery and optional inspection results.
    #[must_use]
    pub fn from_workspace(ws: &DiscoveredWorkspace, inspection: Option<&InspectionResult>) -> Self {
        let kind = match ws.coordinate.kind() {
            WorkspaceKind::Repository(_) => "repository",
            WorkspaceKind::WorkspaceRepository => "workspace",
            WorkspaceKind::Organization => "organization",
        };
        let du = inspection.and_then(|i| i.disk_usage.value());
        let ab = inspection.and_then(|i| i.ahead_behind.value());
        Self {
            path: ws.path.display().to_string(),
            server: ws.coordinate.host().to_string(),
            namespace: ws.coordinate.namespace().clone(),
            repo: ws.coordinate.kind().repository_dir().cloned(),
            kind,
            profile: ws.linked_profile.clone(),
            remote: inspection.and_then(|i| i.remote_url.value().cloned()),
            branch: inspection.and_then(|i| i.branch.value().cloned()),
            commit: inspection.and_then(|i| i.head_short.value().cloned()),
            status: inspection.and_then(|i| i.status.value().map(ToString::to_string)),
            size_bytes: du.map(|d| d.total_bytes),
            git_size_bytes: du.map(|d| d.git_bytes),
            file_count: du.map(|d| d.file_count),
            head_date_epoch: inspection.and_then(|i| i.head_date.value().copied()),
            upstream_date_epoch: inspection.and_then(|i| i.upstream_date.value().copied()),
            ahead: ab.map(|c| c.ahead),
            behind: ab.map(|c| c.behind),
        }
    }
}

/// Stable JSON record for a layout entry that discovery could not place.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssueRecord {
    pub path: String,
    /// `WorkspaceError::kind` of the cause.
    pub kind: &'static str,
    pub message: String,
    /// Whether `sesame workspace normalize` resolves it.
    pub normalizable: bool,
}

impl IssueRecord {
    #[must_use]
    pub fn from_issue(issue: &DiscoveryIssue) -> Self {
        Self {
            path: issue.path.display().to_string(),
            kind: issue.error.kind(),
            message: issue.error.to_string(),
            normalizable: issue.error.is_normalizable(),
        }
    }
}

/// Stable JSON record for an entry the layout walk did not follow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkippedRecord {
    pub path: String,
    pub reason: String,
}

impl SkippedRecord {
    #[must_use]
    pub fn from_skipped(skipped: &Skipped) -> Self {
        Self {
            path: skipped.path.display().to_string(),
            reason: skipped.reason.clone(),
        }
    }
}

/// The `sesame workspace list --format json` document.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ListDocument {
    pub workspaces: Vec<WorkspaceRecord>,
    pub issues: Vec<IssueRecord>,
    pub skipped: Vec<SkippedRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ColumnId::{
        AheadBehind, Branch, Commit, Files, GitSize, LastCommit, Name, Profile, Remote, Server,
        Size, Status, UpstreamDate,
    };

    #[test]
    fn columns_are_at_their_id_index() {
        for (index, column) in ALL_COLUMNS.iter().enumerate() {
            assert_eq!(column.id as usize, index, "{}", column.name);
            assert_eq!(column.id.column().name, column.name);
        }
    }

    #[test]
    fn parse_columns_valid() {
        let cols = parse_columns("name,branch,commit").unwrap();
        assert_eq!(cols, vec![Name, Branch, Commit]);
    }

    #[test]
    fn parse_columns_with_disk_usage() {
        let cols = parse_columns("name,size,git_size,files").unwrap();
        assert_eq!(cols, vec![Name, Size, GitSize, Files]);
    }

    #[test]
    fn parse_columns_rejects_unknown() {
        assert!(parse_columns("name,bogus").is_err());
    }

    #[test]
    fn parse_columns_rejects_empty() {
        assert!(parse_columns("").is_err());
    }

    #[test]
    fn parse_columns_trims_whitespace() {
        let cols = parse_columns(" name , branch ").unwrap();
        assert_eq!(cols, vec![Name, Branch]);
    }

    #[test]
    fn git_and_disk_columns_need_inspection_and_discovery_columns_do_not() {
        for columns in [
            &[Name, Status][..],
            &[Branch],
            &[Remote],
            &[Size],
            &[GitSize],
            &[Files],
        ] {
            assert!(!inspection_request(columns).is_empty(), "{columns:?}");
        }
        assert!(inspection_request(&[Name, Profile, Server]).is_empty());
    }

    #[test]
    fn default_columns_skip_the_expensive_fields() {
        let request = inspection_request(DEFAULT_COLUMNS);
        assert!(
            !request.contains(Field::Status),
            "status walks the working tree"
        );
        assert!(
            !request.contains(Field::DiskUsage),
            "disk usage walks every file"
        );
    }

    fn coordinate(kind: WorkspaceKind) -> core_workspace_types::WorkspaceCoordinate {
        use core_workspace_types::{GitHost, NamespaceDir, WorkspaceCoordinate};
        WorkspaceCoordinate::new(
            GitHost::new("github.com").unwrap(),
            NamespaceDir::parse(&["org"]).unwrap(),
            kind,
        )
    }

    fn test_workspace() -> DiscoveredWorkspace {
        use core_workspace_types::RepoDir;
        DiscoveredWorkspace {
            path: std::path::PathBuf::from("/workspace/user/github.com/org/repo"),
            coordinate: coordinate(WorkspaceKind::Repository(RepoDir::parse("repo").unwrap())),
            linked_profile: Some("work".into()),
        }
    }

    fn test_inspection() -> InspectionResult {
        use crate::inspection::{DiskUsage, FieldState};
        InspectionResult {
            remote_url: FieldState::Available("https://github.com/org/repo".into()),
            branch: FieldState::Available("main".into()),
            head_short: FieldState::Available("abc1234".into()),
            head_summary: FieldState::NotRequested,
            status: FieldState::Available(crate::inspection::RepoStatus::Clean),
            upstream_short: FieldState::NotRequested,
            ahead_behind: FieldState::Available(crate::inspection::AheadBehind {
                ahead: 2,
                behind: 5,
            }),
            disk_usage: FieldState::Available(DiskUsage {
                total_bytes: 1_073_741_824, // 1 GiB
                git_bytes: 536_870_912,     // 512 MiB
                file_count: 12_345,
            }),
            head_date: FieldState::Available(1_725_321_600), // 2024-09-03
            upstream_date: FieldState::Available(1_725_148_800), // 2024-09-01
        }
    }

    fn p(s: &str) -> FieldValue {
        FieldValue::Present(s.into())
    }

    /// 2024-09-04, one day after `test_inspection`'s head date.
    const NOW: u64 = 1_725_408_000;

    fn field(
        ws: &DiscoveredWorkspace,
        inspection: Option<&InspectionResult>,
        column: ColumnId,
    ) -> FieldValue {
        extract_field(ws, inspection, column, NOW)
    }

    #[test]
    fn failed_inspection_fields_render_failed_not_absent() {
        use crate::inspection::{FieldState, InspectionFailure, InspectionFailureKind};
        fn failure<T>(kind: InspectionFailureKind) -> FieldState<T> {
            FieldState::Failed(InspectionFailure {
                kind,
                message: "x".into(),
            })
        }
        let mut insp = test_inspection();
        insp.disk_usage = failure(InspectionFailureKind::DiskUsage);
        insp.head_date = failure(InspectionFailureKind::HeadRead);
        insp.upstream_date = failure(InspectionFailureKind::UpstreamRead);
        let ws = test_workspace();
        for col in [Size, GitSize, Files, LastCommit, UpstreamDate] {
            assert_eq!(field(&ws, Some(&insp), col), FieldValue::Failed, "{col:?}");
        }
    }

    #[test]
    fn last_commit_is_relative_to_now() {
        let ws = test_workspace();
        assert_eq!(field(&ws, Some(&test_inspection()), LastCommit), p("1d"));
    }

    #[test]
    fn extract_name() {
        let ws = test_workspace();
        assert_eq!(field(&ws, None, Name), p("repo"));
    }

    #[test]
    fn extract_branch_with_inspection() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(field(&ws, Some(&insp), Branch), p("main"));
    }

    #[test]
    fn extract_branch_without_inspection() {
        let ws = test_workspace();
        assert_eq!(field(&ws, None, Branch), FieldValue::Absent);
    }

    #[test]
    fn extract_status() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(field(&ws, Some(&insp), Status), p("clean"));
    }

    #[test]
    fn extract_size() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(field(&ws, Some(&insp), Size), p("1.0 GiB"));
    }

    #[test]
    fn extract_git_size() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(field(&ws, Some(&insp), GitSize), p("512.0 MiB"));
    }

    #[test]
    fn extract_files() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(field(&ws, Some(&insp), Files), p("12345"));
    }

    #[test]
    fn extract_size_without_inspection() {
        let ws = test_workspace();
        assert_eq!(field(&ws, None, Size), FieldValue::Absent);
    }

    #[test]
    fn extract_profile() {
        let ws = test_workspace();
        assert_eq!(field(&ws, None, Profile), p("work"));
    }

    #[test]
    fn extract_profile_not_linked() {
        let mut ws = test_workspace();
        ws.linked_profile = None;
        assert_eq!(field(&ws, None, Profile), FieldValue::Empty);
    }

    #[test]
    fn extract_server() {
        let ws = test_workspace();
        assert_eq!(field(&ws, None, Server), p("github.com"));
    }

    #[test]
    fn extract_remote_with_inspection() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(
            field(&ws, Some(&insp), Remote),
            p("https://github.com/org/repo")
        );
    }

    #[test]
    fn extract_workspace_root_name_is_absent() {
        let ws = DiscoveredWorkspace {
            path: std::path::PathBuf::from("/workspace/user/github.com/org"),
            coordinate: coordinate(WorkspaceKind::WorkspaceRepository),
            linked_profile: None,
        };
        assert_eq!(field(&ws, None, Name), FieldValue::Absent);
        assert_eq!(field(&ws, None, ColumnId::Org), p("org"));
    }

    #[test]
    fn extract_last_commit() {
        let ws = test_workspace();
        let insp = test_inspection();
        let val = field(&ws, Some(&insp), LastCommit);
        // Should be a relative time string, not empty.
        assert!(matches!(val, FieldValue::Present(_)));
    }

    #[test]
    fn extract_upstream_date() {
        let ws = test_workspace();
        let insp = test_inspection();
        let val = field(&ws, Some(&insp), UpstreamDate);
        assert!(matches!(val, FieldValue::Present(_)));
    }

    #[test]
    fn extract_last_commit_without_inspection() {
        let ws = test_workspace();
        assert_eq!(field(&ws, None, LastCommit), FieldValue::Absent);
    }

    #[test]
    fn inspection_requests_hold_exactly_the_columns_fields() {
        let req = inspection_request(&[Name, Branch, Status, Remote]);
        for field in [Field::Branch, Field::Status, Field::Remote] {
            assert!(req.contains(field), "{field:?}");
        }
        assert!(!req.contains(Field::Head));
        assert!(!req.contains(Field::DiskUsage));
        let disk = inspection_request(&[Files]);
        assert!(disk.contains(Field::DiskUsage));
        assert!(!disk.contains(Field::Branch));
        assert!(
            !inspection_request(&[LastCommit]).contains(Field::Head),
            "the age reads the commit date only"
        );
    }

    #[test]
    fn workspace_record_serializes_with_null() {
        let ws = test_workspace();
        let record = WorkspaceRecord::from_workspace(&ws, None);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["server"], "github.com");
        assert_eq!(json["namespace"], "org");
        assert_eq!(json["repo"], "repo");
        assert_eq!(json["kind"], "repository");
        assert_eq!(json["profile"], "work");
        assert!(json.get("branch").is_none());
        assert!(json.get("commit").is_none());
        assert!(json.get("status").is_none());
        assert!(json.get("remote").is_none());
        assert!(json.get("size_bytes").is_none());
        assert!(json.get("git_size_bytes").is_none());
        assert!(json.get("file_count").is_none());
    }

    #[test]
    fn workspace_record_serializes_with_inspection() {
        let ws = test_workspace();
        let insp = test_inspection();
        let record = WorkspaceRecord::from_workspace(&ws, Some(&insp));
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["branch"], "main");
        assert_eq!(json["commit"], "abc1234");
        assert_eq!(json["status"], "clean");
        assert_eq!(json["remote"], "https://github.com/org/repo");
        assert_eq!(json["size_bytes"], 1_073_741_824);
        assert_eq!(json["git_size_bytes"], 536_870_912);
        assert_eq!(json["file_count"], 12_345);
        assert_eq!(json["ahead"], 2);
        assert_eq!(json["behind"], 5);
    }

    #[test]
    fn ahead_behind_column() {
        let ws = test_workspace();
        assert_eq!(
            field(&ws, Some(&test_inspection()), AheadBehind),
            p("+2 -5")
        );
        assert!(inspection_request(&[AheadBehind]).contains(Field::AheadBehind));
    }

    #[test]
    fn workspace_record_kinds() {
        for (kind, expected) in [
            (WorkspaceKind::WorkspaceRepository, "workspace"),
            (WorkspaceKind::Organization, "organization"),
        ] {
            let ws = DiscoveredWorkspace {
                path: std::path::PathBuf::from("/workspace/user/github.com/org"),
                coordinate: coordinate(kind),
                linked_profile: None,
            };
            let json = serde_json::to_value(WorkspaceRecord::from_workspace(&ws, None)).unwrap();
            assert_eq!(json["kind"], expected);
            assert!(json.get("repo").is_none());
            assert!(json.get("profile").is_none());
        }
    }

    #[test]
    fn list_document_shape() {
        let issue = DiscoveryIssue {
            path: std::path::PathBuf::from("/workspace/user/GitHub.com"),
            error: crate::WorkspaceError::CaseConflict {
                requested: "/workspace/user/github.com".into(),
                existing: "/workspace/user/GitHub.com".into(),
            },
        };
        let doc = ListDocument {
            workspaces: vec![WorkspaceRecord::from_workspace(&test_workspace(), None)],
            issues: vec![IssueRecord::from_issue(&issue)],
            skipped: vec![SkippedRecord::from_skipped(&Skipped {
                path: "/workspace/user/link".into(),
                reason: "symlink".into(),
            })],
        };
        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["workspaces"][0]["repo"], "repo");
        assert_eq!(json["issues"][0]["kind"], "case-conflict");
        assert_eq!(json["issues"][0]["normalizable"], true);
        assert_eq!(json["issues"][0]["path"], "/workspace/user/GitHub.com");
        assert_eq!(json["skipped"][0]["reason"], "symlink");
    }
}
