//! Workspace directory management configuration types.
//!
//! `WorkspaceConfig` is stored in `~/.config/pds/workspaces.toml`.
//! `LocalSesameConfig` is found at `.sesame.toml` in workspace or repo roots.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Workspace directory management configuration.
/// Stored in `~/.config/pds/workspaces.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceConfig {
    /// General workspace settings.
    pub settings: WorkspaceSettings,
    /// Profile links: canonical path -> profile name.
    /// More specific paths override less specific ones (longest prefix wins).
    #[serde(default)]
    pub links: BTreeMap<String, String>,
}

/// Workspace directory settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceSettings {
    /// Root directory for all workspaces.
    pub root: std::path::PathBuf,
    /// Username for workspace path construction.
    pub user: String,
    /// Prefer SSH URLs when cloning.
    pub default_ssh: bool,
    /// Conventional repo name for org-level workspace.git.
    /// When cloning a project repo, sesame probes `{server}/{org}/{workspace_repo}.git`
    /// and auto-clones it to the org directory if it exists.
    pub workspace_repo: String,
    /// Workspace auto-discovery behavior on `sesame workspace clone`:
    ///
    /// - `"auto"` (default): init workspace.git when org dir is new, inform when
    ///   it exists and is behind, never modify an existing directory without a flag.
    /// - `"always"`: always init or update workspace.git without asking.
    /// - `"never"`: skip all workspace.git auto-discovery.
    /// - `"prompt"`: ask interactively before init or update.
    pub workspace_auto: String,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            root: std::env::var("SESAME_WORKSPACE_ROOT").map_or_else(
                |_| std::path::PathBuf::from("/workspace"),
                std::path::PathBuf::from,
            ),
            user: std::env::var("USER").unwrap_or_else(|_| "user".into()),
            default_ssh: true,
            workspace_repo: "workspace".into(),
            workspace_auto: "auto".into(),
        }
    }
}

/// Workspace-level or repo-level sesame configuration.
///
/// Found at `.sesame.toml` in workspace or repo root. Provides per-directory
/// profile defaults, env var injection, and secret prefix configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalSesameConfig {
    /// Default profile for this workspace/repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// Additional environment variables to inject (non-secret).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,

    /// Launch profile tags to apply by default in this context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Env var prefix for secret injection in this context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_prefix: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_config_defaults() {
        let ws = WorkspaceConfig::default();
        assert_eq!(ws.settings.root, std::path::PathBuf::from("/workspace"));
        assert!(ws.settings.default_ssh);
        assert!(ws.links.is_empty());
    }

    #[test]
    fn workspace_config_roundtrips_toml() {
        let mut ws = WorkspaceConfig::default();
        ws.settings.root = std::path::PathBuf::from("/mnt/workspace");
        ws.settings.user = "testuser".into();
        ws.links.insert(
            "/mnt/workspace/testuser/github.com/org".into(),
            "work".into(),
        );
        let toml_str = toml::to_string_pretty(&ws).unwrap();
        let parsed: WorkspaceConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            parsed.settings.root,
            std::path::PathBuf::from("/mnt/workspace")
        );
        assert_eq!(parsed.settings.user, "testuser");
        assert_eq!(
            parsed.links["/mnt/workspace/testuser/github.com/org"],
            "work"
        );
    }
}
