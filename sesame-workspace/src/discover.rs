//! Walk workspace tree to discover git repositories.

use std::path::{Path, PathBuf};

use core_config::WorkspaceConfig;

use crate::WorkspaceError;
use crate::convention;

/// A discovered workspace entry.
#[derive(Debug, Clone)]
pub struct DiscoveredWorkspace {
    /// Filesystem path to the repository root.
    pub path: PathBuf,
    /// Parsed convention components.
    pub convention: convention::WorkspaceConvention,
    /// Remote URL (from `git remote get-url origin`), if available.
    pub remote_url: Option<String>,
    /// Linked profile from workspace config, if any.
    pub linked_profile: Option<String>,
    /// Whether this is a workspace.git (org-level) repo.
    pub is_workspace_git: bool,
}

/// Walk `{root}/{user}/` to discover all git repositories.
///
/// Scans for directories containing `.git` at the expected convention depths.
/// Skips `.git` internals during traversal.
///
/// # Errors
///
/// Returns `WorkspaceError::Io` if the workspace root cannot be read.
pub fn discover_workspaces(
    config: &WorkspaceConfig,
) -> Result<Vec<DiscoveredWorkspace>, WorkspaceError> {
    let root = &config.settings.root;
    let user_dir = root.join(&config.settings.user);

    if !user_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    walk_servers(&user_dir, root, config, &mut results)?;
    results.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(results)
}

fn walk_servers(
    user_dir: &Path,
    root: &Path,
    config: &WorkspaceConfig,
    results: &mut Vec<DiscoveredWorkspace>,
) -> Result<(), WorkspaceError> {
    let entries = match std::fs::read_dir(user_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        // Skip symlinks to avoid symlink loops and TOCTOU traversal attacks.
        if entry.file_type()?.is_symlink() {
            continue;
        }
        let server_path = entry.path();
        if server_path.is_dir() {
            walk_orgs(&server_path, root, config, results)?;
        }
    }
    Ok(())
}

fn walk_orgs(
    server_dir: &Path,
    root: &Path,
    config: &WorkspaceConfig,
    results: &mut Vec<DiscoveredWorkspace>,
) -> Result<(), WorkspaceError> {
    let entries = match std::fs::read_dir(server_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue;
        }
        let org_path = entry.path();
        if !org_path.is_dir() {
            continue;
        }

        let dir_name = entry.file_name();
        if dir_name == ".git" {
            continue;
        }

        // Check if the org dir itself is a workspace.git (has .git)
        if org_path.join(".git").is_dir()
            && let Ok(conv) = convention::parse_path(root, &org_path)
        {
            let remote = crate::git::remote_url(&org_path).ok().flatten();
            let linked = crate::config::resolve_workspace_profile(config, &org_path);
            results.push(DiscoveredWorkspace {
                path: org_path.clone(),
                convention: convention::WorkspaceConvention {
                    is_workspace_git: true,
                    ..conv
                },
                remote_url: remote,
                linked_profile: linked,
                is_workspace_git: true,
            });
        }

        // Walk repos inside the org
        walk_repos(&org_path, root, config, results)?;
    }
    Ok(())
}

fn walk_repos(
    org_dir: &Path,
    root: &Path,
    config: &WorkspaceConfig,
    results: &mut Vec<DiscoveredWorkspace>,
) -> Result<(), WorkspaceError> {
    let entries = match std::fs::read_dir(org_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue;
        }
        let repo_path = entry.path();

        let dir_name = entry.file_name();
        if dir_name == ".git" {
            continue;
        }

        if !repo_path.is_dir() {
            continue;
        }

        // Only include if it has its own .git
        if repo_path.join(".git").is_dir()
            && let Ok(conv) = convention::parse_path(root, &repo_path)
        {
            let remote = crate::git::remote_url(&repo_path).ok().flatten();
            let linked = crate::config::resolve_workspace_profile(config, &repo_path);
            results.push(DiscoveredWorkspace {
                path: repo_path,
                convention: conv,
                remote_url: remote,
                linked_profile: linked,
                is_workspace_git: false,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_git_repos() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = root
            .join("user")
            .join("github.com")
            .join("org")
            .join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let mut config = WorkspaceConfig::default();
        config.settings.root = root.to_path_buf();
        config.settings.user = "user".into();

        let workspaces = discover_workspaces(&config).unwrap();
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].path, repo);
        assert_eq!(workspaces[0].convention.org, "org");
        assert_eq!(workspaces[0].convention.repo.as_deref(), Some("repo"));
    }

    #[test]
    fn skips_non_git_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = root
            .join("user")
            .join("github.com")
            .join("org")
            .join("not-a-repo");
        std::fs::create_dir_all(&repo).unwrap();
        // No .git directory

        let mut config = WorkspaceConfig::default();
        config.settings.root = root.to_path_buf();
        config.settings.user = "user".into();

        let workspaces = discover_workspaces(&config).unwrap();
        assert!(workspaces.is_empty());
    }

    #[test]
    fn discovers_workspace_git() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let org = root.join("user").join("github.com").join("org");
        std::fs::create_dir_all(org.join(".git")).unwrap();

        let mut config = WorkspaceConfig::default();
        config.settings.root = root.to_path_buf();
        config.settings.user = "user".into();

        let workspaces = discover_workspaces(&config).unwrap();
        assert_eq!(workspaces.len(), 1);
        assert!(workspaces[0].is_workspace_git);
    }

    #[test]
    fn empty_workspace_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("user")).unwrap();

        let mut config = WorkspaceConfig::default();
        config.settings.root = root.to_path_buf();
        config.settings.user = "user".into();

        let workspaces = discover_workspaces(&config).unwrap();
        assert!(workspaces.is_empty());
    }
}
