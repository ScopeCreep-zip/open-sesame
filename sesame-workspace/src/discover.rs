//! Walk workspace tree to discover git repositories.
//!
//! Discovery performs filesystem traversal only. It does not open
//! repositories or read Git metadata. Use the inspection module to
//! collect branch, commit, remote, and status information from
//! discovered entries.
//!
//! The walker recurses through namespace directories at any depth
//! below each server directory. A directory containing .git is
//! classified as a git root. If a git root also contains child
//! directories that are themselves git roots, the parent is a
//! workspace root (namespace-level entry with sibling repositories).

use std::path::{Path, PathBuf};

use core_config::WorkspaceConfig;
use core_workspace_types::{
    GitHost, NamespacePath, RepositoryName, WorkspaceCoordinate, WorkspaceKind,
};

use crate::WorkspaceError;
use crate::has_git_dir;

/// A discovered workspace entry containing only filesystem facts.
#[derive(Debug, Clone)]
pub struct DiscoveredWorkspace {
    /// Filesystem path to the repository or workspace root.
    pub path: PathBuf,
    /// Parsed coordinate from the filesystem path.
    pub coordinate: WorkspaceCoordinate,
    /// Linked profile from workspace config link table, if any.
    pub linked_profile: Option<String>,
}

/// Walk `{root}/{user}/` to discover all git repositories.
///
/// Scans server directories, then recursively traverses namespace
/// directories at any depth. Skips symlinks and `.git` internals.
/// Does not open repositories or read Git metadata.
///
/// # Errors
///
/// Returns `WorkspaceError::Io` if the workspace root cannot be read.
pub fn discover_workspaces(
    config: &WorkspaceConfig,
) -> Result<Vec<DiscoveredWorkspace>, WorkspaceError> {
    let root = &config.settings.root;
    let user_dir = root.join(config.settings.user.as_str());

    if !user_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();

    // First level below user: server directories.
    for entry in read_dir_safe(&user_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue;
        }
        let server_path = entry.path();
        if !server_path.is_dir() {
            continue;
        }

        let server_name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let Some(host) = GitHost::from_dir_name(&server_name) else {
            continue;
        };

        // Recurse into namespace directories below this server.
        walk_namespace(&server_path, &host, &[], config, &mut results)?;
    }

    results.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(results)
}

/// Recursively walk namespace directories below a server.
///
/// `ns_segments` accumulates the namespace path components seen so
/// far. At each directory:
///   - If it has .git and child git dirs, it is a workspace root
///     (namespace-level entry). Record it and also scan children.
///   - If it has .git and no child git dirs, it is a regular repo.
///     Record it and stop recursing.
///   - If it has no .git, it is a namespace directory. Recurse.
fn walk_namespace(
    dir: &Path,
    host: &GitHost,
    ns_segments: &[String],
    config: &WorkspaceConfig,
    results: &mut Vec<DiscoveredWorkspace>,
) -> Result<(), WorkspaceError> {
    let entries: Vec<std::fs::DirEntry> = match read_dir_safe(dir) {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(_) => return Ok(()),
    };

    // Collect child directories, skipping symlinks and .git internals.
    let child_dirs: Vec<(std::ffi::OsString, PathBuf)> = entries
        .iter()
        .filter(|e| {
            e.file_type()
                .is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
        })
        .filter(|e| e.file_name() != ".git")
        .map(|e| (e.file_name(), e.path()))
        .collect();

    let this_is_git_root = has_git_dir(dir);

    if this_is_git_root {
        // Check if any children are also git roots.
        let has_child_git = child_dirs.iter().any(|(_, p)| has_git_dir(p));

        if has_child_git {
            // This is a workspace root: a namespace-level directory
            // that contains .git AND has sibling repositories.
            if !ns_segments.is_empty()
                && let Ok(ns) = NamespacePath::from_segments(ns_segments.to_vec())
            {
                let coord = WorkspaceCoordinate::new(host.clone(), ns, WorkspaceKind::Organization);
                let linked = crate::config::resolve_workspace_profile(config, dir);
                results.push(DiscoveredWorkspace {
                    path: dir.to_path_buf(),
                    coordinate: coord,
                    linked_profile: linked,
                });
            }

            // Continue into children to discover sibling repos.
            for (name, child_path) in &child_dirs {
                let Some(name_str) = name.to_str().map(ToString::to_string) else {
                    continue;
                };
                let mut child_ns = ns_segments.to_vec();
                child_ns.push(name_str);

                if has_git_dir(child_path) {
                    // Child is a regular repository inside the workspace.
                    record_repository(child_path, host, ns_segments, &child_ns, config, results);
                } else {
                    // Child namespace directory, recurse deeper.
                    walk_namespace(child_path, host, &child_ns, config, results)?;
                }
            }
        } else {
            // Regular repository with no child git repos.
            // The last namespace segment is the repository name.
            if ns_segments.is_empty() {
                // A git root directly under the server with no namespace
                // is structurally invalid for the convention. Skip it.
                return Ok(());
            }
            record_repository(
                dir,
                host,
                &ns_segments[..ns_segments.len() - 1],
                ns_segments,
                config,
                results,
            );
        }
    } else {
        // Not a git root. Recurse into children as namespace dirs.
        for (name, child_path) in &child_dirs {
            let name_str = match name.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let mut child_ns = ns_segments.to_vec();
            child_ns.push(name_str);
            walk_namespace(child_path, host, &child_ns, config, results)?;
        }
    }

    Ok(())
}

/// Record a repository entry from its path and namespace context.
fn record_repository(
    path: &Path,
    host: &GitHost,
    parent_ns_segments: &[String],
    _full_segments: &[String],
    config: &WorkspaceConfig,
    results: &mut Vec<DiscoveredWorkspace>,
) {
    let Some(repo_name_str) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };

    if parent_ns_segments.is_empty() {
        return;
    }
    let Ok(ns) = NamespacePath::from_segments(parent_ns_segments.to_vec()) else {
        return;
    };

    let Ok(repo) = RepositoryName::new(repo_name_str) else {
        return;
    };

    let coord = WorkspaceCoordinate::new(host.clone(), ns, WorkspaceKind::Repository(repo));
    let linked = crate::config::resolve_workspace_profile(config, path);
    results.push(DiscoveredWorkspace {
        path: path.to_path_buf(),
        coordinate: coord,
        linked_profile: linked,
    });
}

/// Read a directory, returning an error only for non-permission failures.
/// Permission denied is treated as an empty directory.
fn read_dir_safe(path: &Path) -> Result<std::fs::ReadDir, WorkspaceError> {
    match std::fs::read_dir(path) {
        Ok(e) => Ok(e),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(WorkspaceError::Io(e)),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(root: &Path) -> WorkspaceConfig {
        let mut config = WorkspaceConfig::default();
        config.settings.root = root.to_path_buf();
        config.settings.user = core_workspace_types::WorkspaceUser::new("user").unwrap();
        config
    }

    #[test]
    fn discovers_flat_repo() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = root
            .join("user")
            .join("github.com")
            .join("org")
            .join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].path, repo);
        assert_eq!(workspaces[0].coordinate.namespace().root_segment(), "org");
        assert_eq!(
            workspaces[0]
                .coordinate
                .kind()
                .repository_name()
                .map(|r| r.as_str()),
            Some("repo")
        );
        assert!(workspaces[0].coordinate.kind().is_cloneable());
    }

    #[test]
    fn discovers_nested_namespace_repo() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = root
            .join("user")
            .join("gitlab.com")
            .join("group")
            .join("subgroup")
            .join("project");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();
        assert_eq!(workspaces.len(), 1);
        assert_eq!(
            workspaces[0].coordinate.namespace().to_string(),
            "group/subgroup"
        );
        assert_eq!(
            workspaces[0]
                .coordinate
                .kind()
                .repository_name()
                .map(|r| r.as_str()),
            Some("project")
        );
    }

    #[test]
    fn discovers_workspace_root_with_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let org = root.join("user").join("github.com").join("org");
        // Org has .git (workspace root)
        std::fs::create_dir_all(org.join(".git")).unwrap();
        // Sibling repo inside the workspace root
        std::fs::create_dir_all(org.join("repo-a").join(".git")).unwrap();
        std::fs::create_dir_all(org.join("repo-b").join(".git")).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();

        // Should find: workspace root (org), repo-a, repo-b
        assert_eq!(workspaces.len(), 3);

        let ws_root = workspaces.iter().find(|w| w.path == org).unwrap();
        assert!(!ws_root.coordinate.kind().is_cloneable());

        let repo_a = workspaces
            .iter()
            .find(|w| w.path == org.join("repo-a"))
            .unwrap();
        assert_eq!(
            repo_a
                .coordinate
                .kind()
                .repository_name()
                .map(|r| r.as_str()),
            Some("repo-a")
        );

        let repo_b = workspaces
            .iter()
            .find(|w| w.path == org.join("repo-b"))
            .unwrap();
        assert_eq!(
            repo_b
                .coordinate
                .kind()
                .repository_name()
                .map(|r| r.as_str()),
            Some("repo-b")
        );
    }

    #[test]
    fn skips_non_git_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let not_repo = root
            .join("user")
            .join("github.com")
            .join("org")
            .join("not-a-repo");
        std::fs::create_dir_all(&not_repo).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();
        assert!(workspaces.is_empty());
    }

    #[test]
    fn empty_workspace_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("user")).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();
        assert!(workspaces.is_empty());
    }

    #[test]
    fn deeply_nested_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = root
            .join("user")
            .join("gitlab.com")
            .join("a")
            .join("b")
            .join("c")
            .join("d")
            .join("project");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].coordinate.namespace().to_string(), "a/b/c/d");
        assert_eq!(
            workspaces[0]
                .coordinate
                .kind()
                .repository_name()
                .map(|r| r.as_str()),
            Some("project")
        );
    }

    #[test]
    fn ipv6_server_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = root.join("user").join("_ipv6_--1").join("org").join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();
        assert_eq!(workspaces.len(), 1);
        assert!(matches!(workspaces[0].coordinate.host(), GitHost::Ipv6(_)));
    }

    #[test]
    fn discovery_contains_no_git_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = root
            .join("user")
            .join("github.com")
            .join("org")
            .join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let config = test_config(root);
        let workspaces = discover_workspaces(&config).unwrap();
        assert_eq!(workspaces.len(), 1);
        assert!(workspaces[0].linked_profile.is_none());
        assert!(workspaces[0].coordinate.kind().is_cloneable());
    }
}
