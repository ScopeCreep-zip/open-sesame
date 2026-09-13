//! Column-based output formatting for workspace listings.
//!
//! Columns are defined as static data. Adding a new column requires
//! adding one entry to `ALL_COLUMNS` and one arm in `extract_field`.
//!
//! Discovery provides filesystem facts. Inspection provides Git
//! metadata. This module combines both into field values for display.

use crate::discover::DiscoveredWorkspace;
use crate::inspection::InspectionResult;

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
    Column { name: "name",    header: "NAME",    min_width: 20, requires_inspection: false },
    Column { name: "branch",  header: "BRANCH",  min_width: 14, requires_inspection: true },
    Column { name: "commit",  header: "COMMIT",  min_width: 7,  requires_inspection: true },
    Column { name: "status",  header: "STATUS",  min_width: 7,  requires_inspection: true },
    Column { name: "profile", header: "PROFILE", min_width: 8,  requires_inspection: false },
    Column { name: "server",  header: "SERVER",  min_width: 10, requires_inspection: false },
    Column { name: "org",     header: "ORG",     min_width: 10, requires_inspection: false },
    Column { name: "remote",  header: "REMOTE",  min_width: 30, requires_inspection: true },
];

/// Default column set for interactive table output.
///
/// Does not include status because it requires a full working tree
/// walk per repository. Use `--columns name,branch,commit,status`
/// to include it explicitly.
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
            _ => {}
        }
    }
    req
}

/// Extract a field value from a discovered workspace and its
/// inspection result.
///
/// Discovery fields (name, profile, server, org) come from
/// `DiscoveredWorkspace`. Inspection fields (branch, commit, status,
/// remote) come from `InspectionResult`. Missing inspection data
/// produces `None`.
#[must_use]
pub fn extract_field(
    ws: &DiscoveredWorkspace,
    inspection: Option<&InspectionResult>,
    column: &str,
) -> Option<String> {
    match column {
        "name" => ws.coordinate.kind().repository_name().map(|r| r.as_str().to_string()),
        "branch" => inspection.and_then(|i| i.branch.value().cloned()),
        "commit" => inspection.and_then(|i| i.head_short.value().cloned()),
        "status" => inspection
            .and_then(|i| i.status.value())
            .map(|s| s.to_string()),
        "profile" => ws.linked_profile.clone(),
        "server" => Some(ws.coordinate.host().to_string()),
        "org" => Some(ws.coordinate.namespace().to_string()),
        "remote" => inspection.and_then(|i| i.remote_url.value().cloned()),
        _ => None,
    }
}

/// Parse a comma-separated column spec into validated column names.
///
/// Returns an error listing valid columns if any name is unrecognized.
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
}

impl WorkspaceRecord {
    /// Build a record from discovery and optional inspection results.
    #[must_use]
    pub fn from_workspace(
        ws: &DiscoveredWorkspace,
        inspection: Option<&InspectionResult>,
    ) -> Self {
        let kind_str = if ws.coordinate.kind().is_cloneable() {
            "repository"
        } else {
            "organization"
        };
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
            status: inspection.and_then(|i| i.status.value().map(|s| s.to_string())),
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

    fn test_workspace() -> DiscoveredWorkspace {
        use core_workspace_types::{GitHost, NamespacePath, RepositoryName, WorkspaceCoordinate, WorkspaceKind};
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
        use crate::inspection::FieldState;
        InspectionResult {
            remote_url: FieldState::Available("https://github.com/org/repo".into()),
            branch: FieldState::Available("main".into()),
            head_short: FieldState::Available("abc1234".into()),
            head_summary: FieldState::NotRequested,
            status: FieldState::Available(crate::inspection::RepoStatus::Clean),
            upstream_short: FieldState::NotRequested,
            ahead_behind: FieldState::NotRequested,
        }
    }

    #[test]
    fn extract_name() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "name"), Some("repo".into()));
    }

    #[test]
    fn extract_branch_with_inspection() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(extract_field(&ws, Some(&insp), "branch"), Some("main".into()));
    }

    #[test]
    fn extract_branch_without_inspection() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "branch"), None);
    }

    #[test]
    fn extract_status() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(extract_field(&ws, Some(&insp), "status"), Some("clean".into()));
    }

    #[test]
    fn extract_profile() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "profile"), Some("work".into()));
    }

    #[test]
    fn extract_profile_absent() {
        let mut ws = test_workspace();
        ws.linked_profile = None;
        assert_eq!(extract_field(&ws, None, "profile"), None);
    }

    #[test]
    fn extract_server() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "server"), Some("github.com".into()));
    }

    #[test]
    fn extract_remote_with_inspection() {
        let ws = test_workspace();
        let insp = test_inspection();
        assert_eq!(
            extract_field(&ws, Some(&insp), "remote"),
            Some("https://github.com/org/repo".into())
        );
    }

    #[test]
    fn extract_unknown_column() {
        let ws = test_workspace();
        assert_eq!(extract_field(&ws, None, "nonexistent"), None);
    }

    #[test]
    fn extract_org_name_is_none() {
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
        assert_eq!(extract_field(&ws, None, "name"), None);
    }

    #[test]
    fn inspection_request_maps_columns() {
        let req = inspection_request_for_columns(&["name", "branch", "status", "remote"]);
        assert!(req.branch);
        assert!(req.status);
        assert!(req.remote);
        assert!(!req.head);
    }

    #[test]
    fn inspection_request_no_git_columns() {
        let req = inspection_request_for_columns(&["name", "profile", "server"]);
        assert!(!req.branch);
        assert!(!req.head);
        assert!(!req.status);
        assert!(!req.remote);
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
        // Inspection fields absent without inspection data.
        assert!(json.get("branch").is_none());
        assert!(json.get("commit").is_none());
        assert!(json.get("status").is_none());
        assert!(json.get("remote").is_none());
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
