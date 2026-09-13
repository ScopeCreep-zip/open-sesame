//! Workspace directory management configuration types.
//!
//! `WorkspaceConfig` is stored in `~/.config/pds/workspaces.toml`.
//! `LocalSesameConfig` is found at `.sesame.toml` in workspace or repo roots.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use core_workspace_types::{GitHost, GitTransport, RepositoryName, WorkspaceUser};

/// Workspace directory management configuration.
/// Stored in `~/.config/pds/workspaces.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceConfig {
    /// General workspace settings.
    pub settings: WorkspaceSettings,
    /// Profile links: canonical path to profile name.
    /// More specific paths override less specific ones (longest prefix wins).
    #[serde(default)]
    pub links: BTreeMap<String, String>,
}

/// Workspace auto-discovery behavior on clone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceAutoMode {
    /// Init workspace.git when org dir is new, inform when it exists
    /// and is behind, never modify an existing directory without a flag.
    #[default]
    Auto,
    /// Always init or update workspace.git without asking.
    Always,
    /// Skip all workspace.git auto-discovery.
    Never,
}

/// Workspace directory settings.
///
/// All fields use typed values validated at deserialization time.
/// Environment variables are read only in `Default` to establish
/// initial values when no configuration file exists.
/// Workspace directory settings.
///
/// Fields that accept user input are validated types. Deserialization
/// rejects invalid values with actionable error messages. Environment
/// variable precedence is applied by the loader, not by Default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceSettings {
    /// Root directory for all workspaces.
    pub root: std::path::PathBuf,
    /// Username for workspace path construction. Validated as a
    /// single filesystem-safe component.
    pub user: WorkspaceUser,
    /// Preferred transport protocol for shorthand clone URLs.
    /// Explicit URLs with a scheme are never rewritten.
    pub transport: GitTransport,
    /// Conventional repo name for org-level workspace.git. Validated
    /// as a filesystem-safe repository name.
    pub workspace_repo: RepositoryName,
    /// Workspace auto-discovery behavior on clone.
    pub workspace_auto: WorkspaceAutoMode,
    /// Default git server hostname for short-form clone URLs.
    /// Validated as a git server authority.
    pub default_server: GitHost,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            root: std::path::PathBuf::from("/workspace"),
            user: WorkspaceUser::new("user").expect("hardcoded valid name"),
            transport: GitTransport::Https,
            workspace_repo: RepositoryName::new("workspace").expect("hardcoded valid name"),
            workspace_auto: WorkspaceAutoMode::default(),
            default_server: GitHost::new("github.com").expect("hardcoded valid hostname"),
        }
    }
}

/// Partial workspace settings for drop-in fragment merging.
///
/// Every field is `Option`. Only explicitly present fields override
/// the base configuration. This distinguishes "field absent" from
/// "field set to the default value."
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceSettingsOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<WorkspaceUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<GitTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_repo: Option<RepositoryName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_auto: Option<WorkspaceAutoMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_server: Option<GitHost>,
}

/// Drop-in fragment configuration file.
///
/// Uses `WorkspaceSettingsOverride` so only explicitly present fields
/// override the base. Links are always additive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceConfigFragment {
    /// Partial settings that override only explicitly present fields.
    pub settings: WorkspaceSettingsOverride,
    /// Profile links to merge into the base configuration.
    #[serde(default)]
    pub links: BTreeMap<String, String>,
}

impl WorkspaceSettings {
    /// Apply a partial override. Only `Some` fields replace the current value.
    pub fn apply_override(&mut self, partial: &WorkspaceSettingsOverride) {
        if let Some(ref root) = partial.root {
            self.root.clone_from(root);
        }
        if let Some(ref user) = partial.user {
            self.user.clone_from(user);
        }
        if let Some(transport) = partial.transport {
            self.transport = transport;
        }
        if let Some(ref repo) = partial.workspace_repo {
            self.workspace_repo.clone_from(repo);
        }
        if let Some(auto_mode) = partial.workspace_auto {
            self.workspace_auto = auto_mode;
        }
        if let Some(ref server) = partial.default_server {
            self.default_server.clone_from(server);
        }
    }
}

/// Workspace-level or repo-level sesame configuration.
///
/// Found at `.sesame.toml` in workspace or repo root. Provides
/// per-directory profile defaults, env var injection, and secret
/// prefix configuration.
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
        assert_eq!(ws.settings.user.as_str(), "user");
        assert_eq!(ws.settings.transport, GitTransport::Https);
        assert_eq!(ws.settings.workspace_auto, WorkspaceAutoMode::Auto);
        assert_eq!(ws.settings.default_server.to_string(), "github.com");
        assert_eq!(ws.settings.workspace_repo.as_str(), "workspace");
        assert!(ws.links.is_empty());
    }

    #[test]
    fn workspace_config_roundtrips_toml() {
        let mut ws = WorkspaceConfig::default();
        ws.settings.root = std::path::PathBuf::from("/mnt/workspace");
        ws.settings.user = WorkspaceUser::new("testuser").unwrap();
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
        assert_eq!(parsed.settings.user.as_str(), "testuser");
        assert_eq!(
            parsed.links["/mnt/workspace/testuser/github.com/org"],
            "work"
        );
    }

    #[test]
    fn workspace_auto_mode_serde() {
        let toml_str = "workspace_auto = \"never\"\n";
        #[derive(Deserialize)]
        struct T {
            workspace_auto: WorkspaceAutoMode,
        }
        let parsed: T = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.workspace_auto, WorkspaceAutoMode::Never);
    }

    #[test]
    fn transport_serde() {
        let toml_str = "transport = \"https\"\n";
        #[derive(Deserialize)]
        struct T {
            transport: GitTransport,
        }
        let parsed: T = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.transport, GitTransport::Https);
    }

    #[test]
    fn apply_override_partial() {
        let mut settings = WorkspaceSettings::default();
        let partial = WorkspaceSettingsOverride {
            default_server: Some(GitHost::new("gitlab.com").unwrap()),
            transport: Some(GitTransport::Https),
            ..Default::default()
        };
        settings.apply_override(&partial);
        assert_eq!(settings.default_server.to_string(), "gitlab.com");
        assert_eq!(settings.transport, GitTransport::Https);
        assert_eq!(settings.workspace_repo.as_str(), "workspace");
        assert_eq!(settings.workspace_auto, WorkspaceAutoMode::Auto);
    }

    #[test]
    fn apply_override_empty_is_noop() {
        let original = WorkspaceSettings::default();
        let mut settings = original.clone();
        settings.apply_override(&WorkspaceSettingsOverride::default());
        assert_eq!(settings.root, original.root);
        assert_eq!(settings.user, original.user);
        assert_eq!(settings.transport, original.transport);
        assert_eq!(settings.workspace_repo, original.workspace_repo);
        assert_eq!(settings.workspace_auto, original.workspace_auto);
        assert_eq!(settings.default_server, original.default_server);
    }

    #[test]
    fn fragment_deserializes_partial() {
        let toml_str = r#"
            [settings]
            default_server = "git.braincraft.io"

            [links]
            "/workspace/user/git.braincraft.io/org" = "work"
        "#;
        let frag: WorkspaceConfigFragment = toml::from_str(toml_str).unwrap();
        assert_eq!(
            frag.settings.default_server.as_ref().map(|s| s.to_string()),
            Some("git.braincraft.io".to_string())
        );
        assert!(frag.settings.root.is_none());
        assert!(frag.settings.transport.is_none());
        assert_eq!(frag.links.len(), 1);
    }

    #[test]
    fn fragment_empty_settings_all_none() {
        let toml_str = "[links]\n";
        let frag: WorkspaceConfigFragment = toml::from_str(toml_str).unwrap();
        assert!(frag.settings.root.is_none());
        assert!(frag.settings.user.is_none());
        assert!(frag.settings.transport.is_none());
        assert!(frag.settings.workspace_repo.is_none());
        assert!(frag.settings.workspace_auto.is_none());
        assert!(frag.settings.default_server.is_none());
    }

    #[test]
    fn existing_config_without_new_fields_deserializes() {
        // Configs written before transport/default_server existed
        // still deserialize. Unknown fields like default_ssh are
        // ignored by serde default behavior.
        let toml_str = r#"
            [settings]
            root = "/workspace"
            user = "usrbinkat"
            default_ssh = true
            workspace_repo = "workspace"
            workspace_auto = "auto"
        "#;
        let parsed: WorkspaceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.settings.transport, GitTransport::Https);
        assert_eq!(parsed.settings.default_server.to_string(), "github.com");
    }

    #[test]
    fn rejects_invalid_user() {
        let toml_str = r#"
            [settings]
            user = ".."
        "#;
        let result: Result<WorkspaceConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_default_server() {
        let toml_str = r#"
            [settings]
            default_server = "host with spaces"
        "#;
        let result: Result<WorkspaceConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_workspace_repo() {
        let toml_str = r#"
            [settings]
            workspace_repo = "../escape"
        "#;
        let result: Result<WorkspaceConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }
}
