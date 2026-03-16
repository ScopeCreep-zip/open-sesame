//! Workspace configuration helpers.
//!
//! Wraps `core_config::WorkspaceConfig` with profile resolution logic
//! (exact match, then longest prefix match) and multi-layer config precedence.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use core_config::{LocalSesameConfig, WorkspaceConfig};

use crate::WorkspaceError;

/// Resolve the workspace root directory.
///
/// Priority (highest to lowest):
/// 1. `SESAME_WORKSPACE_ROOT` env var
/// 2. `config.settings.root`
/// 3. Default `/workspace`
#[must_use]
pub fn resolve_root(config: &WorkspaceConfig) -> PathBuf {
    if let Ok(env_root) = std::env::var("SESAME_WORKSPACE_ROOT") {
        return PathBuf::from(env_root);
    }
    config.settings.root.clone()
}

/// Resolve the username for workspace path construction.
#[must_use]
pub fn resolve_user(config: &WorkspaceConfig) -> String {
    config.settings.user.clone()
}

/// Resolve the linked profile for a workspace path.
///
/// Resolution order:
/// 1. Exact match in `config.links`
/// 2. Longest prefix match in `config.links`
///
/// Returns `None` if no link matches.
#[must_use]
pub fn resolve_workspace_profile(config: &WorkspaceConfig, path: &Path) -> Option<String> {
    let path_str = path.display().to_string();
    let mut best_match: Option<(&str, &str)> = None;

    for (link_path, profile) in &config.links {
        // Require path boundary match: the link path must be an exact match
        // or followed by '/' to prevent "/org" matching "/organic".
        let is_prefix = path_str == link_path.as_str()
            || path_str.starts_with(&format!("{link_path}/"))
            || link_path.ends_with('/') && path_str.starts_with(link_path.as_str());
        if is_prefix {
            match best_match {
                Some((best_path, _)) if link_path.len() > best_path.len() => {
                    best_match = Some((link_path.as_str(), profile.as_str()));
                }
                None => {
                    best_match = Some((link_path.as_str(), profile.as_str()));
                }
                _ => {}
            }
        }
    }

    best_match.map(|(_, p)| p.to_string())
}

/// Add a workspace-to-profile link.
pub fn add_link(config: &mut WorkspaceConfig, path: &str, profile: &str) {
    config.links.insert(path.to_string(), profile.to_string());
}

/// Remove a workspace-to-profile link.
///
/// Returns `true` if the link existed and was removed.
pub fn remove_link(config: &mut WorkspaceConfig, path: &str) -> bool {
    config.links.remove(path).is_some()
}

/// Load `.sesame.toml` from a directory, returning `None` if absent.
///
/// # Errors
///
/// Returns `WorkspaceError::ConfigError` if the file exists but cannot be parsed.
pub fn load_local_config(dir: &Path) -> Result<Option<LocalSesameConfig>, WorkspaceError> {
    let path = dir.join(".sesame.toml");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)?;
    let config: LocalSesameConfig = toml::from_str(&contents).map_err(|e| {
        WorkspaceError::ConfigError(format!("failed to parse {}: {e}", path.display()))
    })?;
    Ok(Some(config))
}

/// Tracks which configuration layer determined each value.
#[derive(Debug, Clone, Default)]
pub struct ConfigProvenance {
    /// Which layer set the profile value.
    pub profile_source: &'static str,
    /// Which layer set the `secret_prefix` value.
    pub secret_prefix_source: &'static str,
}

/// Resolved configuration for a workspace path, merging all layers.
#[derive(Debug, Clone, Default)]
pub struct EffectiveWorkspaceConfig {
    /// Resolved profile name.
    pub profile: Option<String>,
    /// Merged environment variables (non-secret).
    pub env: BTreeMap<String, String>,
    /// Merged tags.
    pub tags: Vec<String>,
    /// Resolved secret prefix.
    pub secret_prefix: Option<String>,
    /// Which layer determined each value.
    pub provenance: ConfigProvenance,
}

/// Resolve the effective configuration for a path by merging all layers.
///
/// Precedence (highest to lowest):
/// 1. Repo `.sesame.toml` (`{path}/.sesame.toml`)
/// 2. Workspace `.sesame.toml` (`{root}/{user}/{server}/{org}/.sesame.toml`)
/// 3. User config links (`~/.config/pds/workspaces.toml` `[links]` section)
/// 4. System defaults
///
/// # Errors
///
/// Returns `WorkspaceError::ConfigError` if any `.sesame.toml` file is malformed.
pub fn resolve_effective_config(
    user_config: &WorkspaceConfig,
    path: &Path,
    root: &Path,
) -> Result<EffectiveWorkspaceConfig, WorkspaceError> {
    let mut result = EffectiveWorkspaceConfig::default();

    // Layer 1: User config links (lowest priority of file-based layers)
    if let Some(profile) = resolve_workspace_profile(user_config, path) {
        result.profile = Some(profile);
        result.provenance.profile_source = "user config link";
    }

    // Layer 2: Workspace .sesame.toml (org-level dir)
    let conv = crate::convention::parse_path(root, path).ok();
    if let Some(ref conv) = conv {
        let workspace_dir = root
            .join(&user_config.settings.user)
            .join(&conv.server)
            .join(&conv.org);
        if let Some(ws_config) = load_local_config(&workspace_dir)? {
            if let Some(ref p) = ws_config.profile {
                result.profile = Some(p.clone());
                result.provenance.profile_source = "workspace .sesame.toml";
            }
            result.env.extend(ws_config.env);
            result.tags.extend(ws_config.tags);
            if ws_config.secret_prefix.is_some() {
                result.secret_prefix = ws_config.secret_prefix;
                result.provenance.secret_prefix_source = "workspace .sesame.toml";
            }
        }
    }

    // Layer 3: Repo .sesame.toml (highest file-based priority)
    if let Some(repo_config) = load_local_config(path)? {
        if let Some(ref p) = repo_config.profile {
            result.profile = Some(p.clone());
            result.provenance.profile_source = "repo .sesame.toml";
        }
        result.env.extend(repo_config.env);
        result.tags.extend(repo_config.tags);
        if repo_config.secret_prefix.is_some() {
            result.secret_prefix = repo_config.secret_prefix;
            result.provenance.secret_prefix_source = "repo .sesame.toml";
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WorkspaceConfig {
        let mut config = WorkspaceConfig::default();
        config
            .links
            .insert("/workspace/user/github.com/org".into(), "personal".into());
        config
            .links
            .insert("/workspace/user/github.com/org/k9".into(), "work".into());
        config
    }

    #[test]
    fn resolve_profile_exact_match() {
        let config = test_config();
        let profile =
            resolve_workspace_profile(&config, Path::new("/workspace/user/github.com/org/k9"));
        assert_eq!(profile.as_deref(), Some("work"));
    }

    #[test]
    fn resolve_profile_prefix_match() {
        let config = test_config();
        let profile = resolve_workspace_profile(
            &config,
            Path::new("/workspace/user/github.com/org/other-repo"),
        );
        assert_eq!(profile.as_deref(), Some("personal"));
    }

    #[test]
    fn resolve_profile_longest_prefix_wins() {
        let config = test_config();
        let profile =
            resolve_workspace_profile(&config, Path::new("/workspace/user/github.com/org/k9/sub"));
        assert_eq!(profile.as_deref(), Some("work"));
    }

    #[test]
    fn resolve_profile_no_match() {
        let config = test_config();
        let profile = resolve_workspace_profile(&config, Path::new("/home/user/project"));
        assert!(profile.is_none());
    }

    #[test]
    fn add_remove_link() {
        let mut config = WorkspaceConfig::default();
        add_link(&mut config, "/workspace/user/github.com/org/repo", "work");
        assert_eq!(config.links.len(), 1);
        assert!(remove_link(
            &mut config,
            "/workspace/user/github.com/org/repo"
        ));
        assert!(config.links.is_empty());
        assert!(!remove_link(&mut config, "/nonexistent"));
    }

    #[test]
    fn config_toml_roundtrip() {
        let mut config = WorkspaceConfig::default();
        config.settings.root = PathBuf::from("/mnt/workspace");
        config.settings.user = "testuser".into();
        add_link(
            &mut config,
            "/mnt/workspace/testuser/github.com/org",
            "work",
        );

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: WorkspaceConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.settings.root, PathBuf::from("/mnt/workspace"));
        assert_eq!(parsed.settings.user, "testuser");
        assert_eq!(
            parsed.links["/mnt/workspace/testuser/github.com/org"],
            "work"
        );
    }

    #[test]
    fn load_local_config_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_local_config(dir.path()).unwrap().is_none());
    }

    #[test]
    fn load_local_config_present() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
            profile = "work"
            secret_prefix = "MYAPP"
            [env]
            RUST_LOG = "debug"
        "#;
        std::fs::write(dir.path().join(".sesame.toml"), content).unwrap();
        let cfg = load_local_config(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.profile.as_deref(), Some("work"));
        assert_eq!(cfg.secret_prefix.as_deref(), Some("MYAPP"));
        assert_eq!(cfg.env["RUST_LOG"], "debug");
    }

    #[test]
    fn effective_config_repo_overrides_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Set up directory structure: root/user/github.com/org/repo
        let org_dir = root.join("user").join("github.com").join("org");
        let repo_dir = org_dir.join("repo");
        std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

        // Workspace-level config
        std::fs::write(
            org_dir.join(".sesame.toml"),
            "profile = \"workspace-profile\"\n[env]\nSHARED = \"from-workspace\"\nONLY_WS = \"ws\"\n",
        ).unwrap();

        // Repo-level config overrides profile
        std::fs::write(
            repo_dir.join(".sesame.toml"),
            "profile = \"repo-profile\"\n[env]\nSHARED = \"from-repo\"\nONLY_REPO = \"repo\"\n",
        )
        .unwrap();

        let mut user_config = WorkspaceConfig::default();
        user_config.settings.root = root.to_path_buf();
        user_config.settings.user = "user".into();
        user_config
            .links
            .insert(repo_dir.display().to_string(), "user-link-profile".into());

        let eff = resolve_effective_config(&user_config, &repo_dir, root).unwrap();
        // Repo overrides workspace which overrides user link
        assert_eq!(eff.profile.as_deref(), Some("repo-profile"));
        assert_eq!(eff.provenance.profile_source, "repo .sesame.toml");
        // Env merging: repo overrides same keys, workspace-only keys preserved
        assert_eq!(eff.env["SHARED"], "from-repo");
        assert_eq!(eff.env["ONLY_WS"], "ws");
        assert_eq!(eff.env["ONLY_REPO"], "repo");
    }

    #[test]
    fn effective_config_user_link_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo_dir = root
            .join("user")
            .join("github.com")
            .join("org")
            .join("repo");
        std::fs::create_dir_all(repo_dir.join(".git")).unwrap();

        let mut user_config = WorkspaceConfig::default();
        user_config.settings.root = root.to_path_buf();
        user_config.settings.user = "user".into();
        user_config
            .links
            .insert(repo_dir.display().to_string(), "linked-profile".into());

        // No .sesame.toml files exist
        let eff = resolve_effective_config(&user_config, &repo_dir, root).unwrap();
        assert_eq!(eff.profile.as_deref(), Some("linked-profile"));
        assert_eq!(eff.provenance.profile_source, "user config link");
    }
}
