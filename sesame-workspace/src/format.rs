//! Column-based output formatting for workspace listings.
//!
//! Columns are defined as static data. Adding a new column requires
//! adding one entry to `ALL_COLUMNS` and one arm in `extract_field`.
//!
//! Discovery provides filesystem facts. Inspection provides Git
//! metadata. This module combines both into field values for display.

use crate::discover::DiscoveredWorkspace;
use crate::inspection::{InspectionResult, format_bytes, format_relative_time};

/// A named column definition for workspace list output.
#[derive(Debug, Clone, Copy)]
pub struct Column {
    /// Column identifier used in the --columns flag.
    pub name: &'static str,
    /// Display header for table output.
    pub header: &'static str,
    /// Minimum display width hint for table alignment.
    pub min_width: usize,
    /// Whether this column requires repository inspection.
    pub requires_inspection: bool,
}

/// All available columns in display order.
pub const ALL_COLUMNS: &[Column] = &[
    Column {
        name: "name",
        header: "NAME",
        min_width: 20,
        requires_inspection: false,
    },
    Column {
        name: "branch",
        header: "BRANCH",
        min_width: 14,
        requires_inspection: true,
    },
    Column {
        name: "commit",
        header: "COMMIT",
        min_width: 7,
        requires_inspection: true,
    },
    Column {
        name: "status",
        header: "STATUS",
        min_width: 7,
        requires_inspection: true,
    },
    Column {
        name: "size",
        header: "SIZE",
        min_width: 9,
        requires_inspection: true,
    },
    Column {
        name: "git_size",
        header: "GIT",
        min_width: 9,
        requires_inspection: true,
    },
    Column {
        name: "files",
        header: "FILES",
        min_width: 7,
        requires_inspection: true,
    },
    Column {
        name: "last_commit",
        header: "LAST",
        min_width: 6,
        requires_inspection: true,
    },
    Column {
        name: "upstream_date",
        header: "UPSTREAM",
        min_width: 6,
        requires_inspection: true,
    },
    Column {
        name: "profile",
        header: "PROFILE",
        min_width: 8,
        requires_inspection: false,
    },
    Column {
        name: "server",
        header: "SERVER",
        min_width: 10,
        requires_inspection: false,
    },
    Column {
        name: "org",
        header: "ORG",
        min_width: 10,
        requires_inspection: false,
    },
    Column {
        name: "remote",
        header: "REMOTE",
        min_width: 30,
        requires_inspection: true,
    },
];

/// Default column set for interactive table output.
///
/// Does not include status or disk usage because they require a full
/// working tree walk per repository. Use `--columns` to include them
/// explicitly.
pub const DEFAULT_COLUMNS: &[&str] = &["name", "branch", "commit", "profile"];

/// Determine what inspection fields the selected columns need.
#[must_use]
pub fn inspection_request_for_columns(columns: &[&str]) -> crate::inspection::InspectionRequest {
    let mut req = crate::inspection::InspectionRequest::default();
    for col in columns {
        match *col {
            "branch" => req.branch = true,
            "commit" => req.head = true,
            "status" => req.status = true,
            "remote" => req.remote = true,
            "size" | "git_size" | "files" => req.disk_usage = true,
            "last_commit" => {
                req.head_date = true;
                req.head = true;
            }
            "upstream_date" => req.upstream_date = true,
            _ => {}
        }
    }
    req
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
/// rendering.
#[must_use]
pub fn extract_field(
    ws: &DiscoveredWorkspace,
    inspection: Option<&InspectionResult>,
    column: &str,
) -> FieldValue {
    use crate::inspection::FieldState;

    /// Convert a `FieldState<String>` to a `FieldValue`.
    fn string_field(state: &FieldState<String>) -> FieldValue {
        match state {
            FieldState::Available(v) => FieldValue::Present(v.clone()),
            FieldState::Absent | FieldState::NotRequested => FieldValue::Absent,
            FieldState::Failed(_) => FieldValue::Failed,
        }
    }

    match column {
        "name" => match ws.coordinate.kind().repository_name() {
            Some(r) => FieldValue::Present(r.as_str().to_string()),
            None => FieldValue::Absent,
        },
        "branch" => match inspection {
            Some(i) => string_field(&i.branch),
            None => FieldValue::Absent,
        },
        "commit" => match inspection {
            Some(i) => string_field(&i.head_short),
            None => FieldValue::Absent,
        },
        "status" => match inspection.and_then(|i| i.status.value()) {
            Some(s) => FieldValue::Present(s.to_string()),
            None => match inspection {
                Some(i) if matches!(i.status, FieldState::Failed(_)) => FieldValue::Failed,
                _ => FieldValue::Absent,
            },
        },
        "size" => match inspection.and_then(|i| i.disk_usage.value()) {
            Some(du) => FieldValue::Present(format_bytes(du.total_bytes)),
            None => FieldValue::Absent,
        },
        "git_size" => match inspection.and_then(|i| i.disk_usage.value()) {
            Some(du) => FieldValue::Present(format_bytes(du.git_bytes)),
            None => FieldValue::Absent,
        },
        "files" => match inspection.and_then(|i| i.disk_usage.value()) {
            Some(du) => FieldValue::Present(du.file_count.to_string()),
            None => FieldValue::Absent,
        },
        "last_commit" => match inspection.and_then(|i| i.head_date.value().copied()) {
            Some(epoch) => FieldValue::Present(format_relative_time(epoch)),
            None => FieldValue::Absent,
        },
        "upstream_date" => match inspection.and_then(|i| i.upstream_date.value().copied()) {
            Some(epoch) => FieldValue::Present(format_relative_time(epoch)),
            None => FieldValue::Absent,
        },
        "profile" => match &ws.linked_profile {
            Some(p) => FieldValue::Present(p.clone()),
            None => FieldValue::Empty,
        },
        "server" => FieldValue::Present(ws.coordinate.host().to_string()),
        "org" => FieldValue::Present(ws.coordinate.namespace().to_string()),
        "remote" => match inspection {
            Some(i) => string_field(&i.remote_url),
            None => FieldValue::Absent,
        },
        _ => FieldValue::Absent,
    }
}

/// Parse a comma-separated column spec into validated column names.
///
/// # Errors
///
/// Returns an error listing valid columns if any name is unrecognized,
/// or if the spec is empty.
pub fn parse_columns(spec: &str) -> Result<Vec<&'static str>, String> {
    let mut result = Vec::new();
    for name in spec.split(',').map(str::trim) {
        if name.is_empty() {
            continue;
        }
        if let Some(col) = ALL_COLUMNS.iter().find(|c| c.name == name) {
            result.push(col.name);
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
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkspaceRecord {
    pub path: String,
    pub server: String,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
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
}

impl WorkspaceRecord {
    /// Build a record from discovery and optional inspection results.
    #[must_use]
    pub fn from_workspace(ws: &DiscoveredWorkspace, inspection: Option<&InspectionResult>) -> Self {
        let kind_str = if ws.coordinate.kind().is_cloneable() {
            "repository"
        } else {
            "organization"
        };
        let du = inspection.and_then(|i| i.disk_usage.value());
        Self {
            path: ws.path.display().to_string(),
            server: ws.coordinate.host().to_string(),
            namespace: ws.coordinate.namespace().to_string(),
            repo: ws
                .coordinate
                .kind()
                .repository_name()
                .map(|r| r.as_str().to_string()),
            kind: Some(kind_str.into()),
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
        }
    }
}

/// Check if any column in the set requires repository inspection.
#[must_use]
pub fn needs_inspection(columns: &[&str]) -> bool {
    columns.iter().any(|name| {
        ALL_COLUMNS
            .iter()
            .find(|c| c.name == *name)
            .is_some_and(|c| c.requires_inspection)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_columns_valid() {
        let cols = parse_columns("name,branch,commit").unwrap();
        assert_eq!(cols, vec!["name", "branch", "commit"]);
    }

    #[test]
    fn parse_columns_with_disk_usage() {
        let cols = parse_columns("name,size,git_size,files").unwrap();
        assert_eq!(cols, vec!["name", "size", "git_size", "files"]);
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
        assert_eq!(cols, vec!["name", "branch"]);
    }

    #[test]
    fn needs_inspection_detects_git_columns() {
        assert!(needs_inspection(&["name", "status"]));
        assert!(needs_inspection(&["branch"]));
        assert!(needs_inspection(&["remote"]));
        assert!(!needs_inspection(&["name", "profile"]));
    }

    #[test]
    fn needs_inspection_detects_disk_usage_columns() {
        assert!(needs_inspection(&["size"]));
        assert!(needs_inspection(&["git_size"]));
        assert!(needs_inspection(&["files"]));
        assert!(needs_inspection(&["name", "files"]));
    }

    #[test]
    fn default_columns_all_valid() {
        for col in DEFAULT_COLUMNS {
            assert!(
                ALL_COLUMNS.iter().any(|c| c.name == *col),
                "default column {col} not in ALL_COLUMNS"
            );
        }
    }

    #[test]
    fn default_columns_do_not_include_status() {
        assert!(!DEFAULT_COLUMNS.contains(&"status"));
    }

    #[test]
    fn default_columns_do_not_include_disk_usage() {
        assert!(!DEFAULT_COLUMNS.contains(&"size"));
        assert!(!DEFAULT_COLUMNS.contains(&"git_size"));
        assert!(!DEFAULT_COLUMNS.contains(&"files"));
    }

    fn test_workspace() -> DiscoveredWorkspace {
        use core_workspace_types::{
            GitHost, NamespacePath, RepositoryName, WorkspaceCoordinate, WorkspaceKind,
        };
        DiscoveredWorkspace {
            path: std::path::PathBuf::from("/workspace/user/github.com/org/repo"),
            coordinate: WorkspaceCoordinate::new(
                GitHost::new("github.com").unwrap(),
                NamespacePath::new("org").unwrap(),
                WorkspaceKind::Repository(RepositoryName::new("repo").unwrap()),
            ),
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
            ahead_behind: FieldState::NotRequested,
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

    #[test]
    fn extract_name() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "name"), p("repo"));
    }

    #[test]
    fn extract_branch_with_inspection() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(extract_field(&ws, Some(&insp), "branch"), p("main"));
    }

    #[test]
    fn extract_branch_without_inspection() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "branch"), FieldValue::Absent);
    }

    #[test]
    fn extract_status() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(extract_field(&ws, Some(&insp), "status"), p("clean"));
    }

    #[test]
    fn extract_size() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(extract_field(&ws, Some(&insp), "size"), p("1.0 GiB"));
    }

    #[test]
    fn extract_git_size() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(extract_field(&ws, Some(&insp), "git_size"), p("512.0 MiB"));
    }

    #[test]
    fn extract_files() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(extract_field(&ws, Some(&insp), "files"), p("12345"));
    }

    #[test]
    fn extract_size_without_inspection() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "size"), FieldValue::Absent);
    }

    #[test]
    fn extract_profile() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "profile"), p("work"));
    }

    #[test]
    fn extract_profile_not_linked() {
        let mut ws = test_workspace();
        ws.linked_profile = None;
        assert_eq!(extract_field(&ws, None, "profile"), FieldValue::Empty);
    }

    #[test]
    fn extract_server() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "server"), p("github.com"));
    }

    #[test]
    fn extract_remote_with_inspection() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(
            extract_field(&ws, Some(&insp), "remote"),
            p("https://github.com/org/repo")
        );
    }

    #[test]
    fn extract_unknown_column() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "nonexistent"), FieldValue::Absent);
    }

    #[test]
    fn extract_org_name_is_absent() {
        use core_workspace_types::{GitHost, NamespacePath, WorkspaceCoordinate, WorkspaceKind};
        let ws = DiscoveredWorkspace {
            path: std::path::PathBuf::from("/workspace/user/github.com/org"),
            coordinate: WorkspaceCoordinate::new(
                GitHost::new("github.com").unwrap(),
                NamespacePath::new("org").unwrap(),
                WorkspaceKind::Organization,
            ),
            linked_profile: None,
        };
        assert_eq!(extract_field(&ws, None, "name"), FieldValue::Absent);
    }

    #[test]
    fn extract_last_commit() {
        let ws = test_workspace();
        let insp = test_inspection();
        let val = extract_field(&ws, Some(&insp), "last_commit");
        // Should be a relative time string, not empty.
        assert!(matches!(val, FieldValue::Present(_)));
    }

    #[test]
    fn extract_upstream_date() {
        let ws = test_workspace();
        let insp = test_inspection();
        let val = extract_field(&ws, Some(&insp), "upstream_date");
        assert!(matches!(val, FieldValue::Present(_)));
    }

    #[test]
    fn extract_last_commit_without_inspection() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "last_commit"), FieldValue::Absent);
    }

    #[test]
    fn inspection_request_maps_columns() {
        let req = inspection_request_for_columns(&["name", "branch", "status", "remote"]);
        assert!(req.branch);
        assert!(req.status);
        assert!(req.remote);
        assert!(!req.head);
        assert!(!req.disk_usage);
    }

    #[test]
    fn inspection_request_maps_disk_usage_columns() {
        let req = inspection_request_for_columns(&["name", "size", "git_size", "files"]);
        assert!(req.disk_usage);
        assert!(!req.branch);
        assert!(!req.status);
    }

    #[test]
    fn inspection_request_single_disk_column_enables_disk_usage() {
        let req = inspection_request_for_columns(&["files"]);
        assert!(req.disk_usage);
    }

    #[test]
    fn inspection_request_no_git_columns() {
        let req = inspection_request_for_columns(&["name", "profile", "server"]);
        assert!(!req.branch);
        assert!(!req.head);
        assert!(!req.status);
        assert!(!req.remote);
        assert!(!req.disk_usage);
    }

    #[test]
    fn workspace_record_serializes_with_null() {
        let ws = test_workspace();
        let record = WorkspaceRecord::from_workspace(&ws, None);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["server"], "github.com");
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
    }

    #[test]
    fn workspace_record_org_has_null_repo() {
        use core_workspace_types::{GitHost, NamespacePath, WorkspaceCoordinate, WorkspaceKind};
        let ws = DiscoveredWorkspace {
            path: std::path::PathBuf::from("/workspace/user/github.com/org"),
            coordinate: WorkspaceCoordinate::new(
                GitHost::new("github.com").unwrap(),
                NamespacePath::new("org").unwrap(),
                WorkspaceKind::Organization,
            ),
            linked_profile: None,
        };
        let record = WorkspaceRecord::from_workspace(&ws, None);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["kind"], "organization");
        assert!(json.get("repo").is_none());
        assert!(json.get("profile").is_none());
    }
}
