//! Workspace coordinate and kind.
//!
//! A workspace coordinate locates an entity within the workspace
//! directory layout. The kind distinguishes repositories from
//! workspace repositories and organizations.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::v1::{GitHost, NamespacePath, RepositoryName, WorkspaceUser};

/// What kind of workspace entity this coordinate identifies.
///
/// Workspace semantics (whether a repository is the org-level
/// workspace repository) are assigned by command context and
/// configuration, not by repository name parsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceKind {
    /// A regular cloneable repository.
    Repository(RepositoryName),
    /// The org-level workspace repository.
    /// Contains the repository name for clone URL construction.
    WorkspaceRepository(RepositoryName),
    /// A forge organization or namespace, not a git remote.
    /// Used for project-wide operations like listing all repositories.
    Organization,
}

impl WorkspaceKind {
    /// The repository name if this is a repository or workspace repository.
    #[must_use]
    pub fn repository_name(&self) -> Option<&RepositoryName> {
        match self {
            Self::Repository(r) | Self::WorkspaceRepository(r) => Some(r),
            Self::Organization => None,
        }
    }

    /// Whether this kind represents a cloneable git remote.
    #[must_use]
    pub fn is_cloneable(&self) -> bool {
        matches!(self, Self::Repository(_) | Self::WorkspaceRepository(_))
    }
}

/// A fully resolved location within the workspace directory layout.
///
/// Combines a host, namespace path, and entity kind into a coordinate
/// that computes filesystem paths. Does not carry transport, port, or
/// user information. Those belong in RemoteEndpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceCoordinate {
    host: GitHost,
    namespace: NamespacePath,
    kind: WorkspaceKind,
}

impl WorkspaceCoordinate {
    /// Construct a workspace coordinate from validated components.
    #[must_use]
    pub fn new(host: GitHost, namespace: NamespacePath, kind: WorkspaceKind) -> Self {
        Self {
            host,
            namespace,
            kind,
        }
    }

    /// The server host.
    #[must_use]
    pub fn host(&self) -> &GitHost {
        &self.host
    }

    /// The namespace path.
    #[must_use]
    pub fn namespace(&self) -> &NamespacePath {
        &self.namespace
    }

    /// The workspace kind.
    #[must_use]
    pub fn kind(&self) -> &WorkspaceKind {
        &self.kind
    }

    /// Compute the canonical filesystem path for this coordinate.
    ///
    /// Layout: `{root}/{user}/{host}/{namespace...}[/{repo}]`
    ///
    /// Organization coordinates resolve to the namespace directory.
    /// Workspace repositories resolve to the namespace directory.
    /// Regular repositories resolve to a subdirectory named after
    /// the repository.
    #[must_use]
    pub fn canonical_path(&self, root: &Path, user: &WorkspaceUser) -> PathBuf {
        let base = root
            .join(user.as_str())
            .join(self.host.as_dir_name())
            .join(self.namespace.as_path());

        match &self.kind {
            WorkspaceKind::Repository(repo) => base.join(repo.as_str()),
            WorkspaceKind::WorkspaceRepository(_) | WorkspaceKind::Organization => base,
        }
    }
}

impl fmt::Display for WorkspaceCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            WorkspaceKind::Repository(r) | WorkspaceKind::WorkspaceRepository(r) => {
                write!(f, "{}/{}/{}", self.host, self.namespace, r)
            }
            WorkspaceKind::Organization => {
                write!(f, "{}/{}", self.host, self.namespace)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> WorkspaceUser {
        WorkspaceUser::new("usrbinkat").unwrap()
    }

    fn github_repo() -> WorkspaceCoordinate {
        WorkspaceCoordinate::new(
            GitHost::new("github.com").unwrap(),
            NamespacePath::new("braincraftio").unwrap(),
            WorkspaceKind::Repository(RepositoryName::new("konductor").unwrap()),
        )
    }

    fn github_workspace() -> WorkspaceCoordinate {
        WorkspaceCoordinate::new(
            GitHost::new("github.com").unwrap(),
            NamespacePath::new("braincraftio").unwrap(),
            WorkspaceKind::WorkspaceRepository(RepositoryName::new("workspace").unwrap()),
        )
    }

    fn github_org() -> WorkspaceCoordinate {
        WorkspaceCoordinate::new(
            GitHost::new("github.com").unwrap(),
            NamespacePath::new("braincraftio").unwrap(),
            WorkspaceKind::Organization,
        )
    }

    #[test]
    fn repository_path() {
        let path = github_repo().canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/usrbinkat/github.com/braincraftio/konductor")
        );
    }

    #[test]
    fn workspace_repository_path() {
        let path = github_workspace().canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/usrbinkat/github.com/braincraftio")
        );
    }

    #[test]
    fn organization_path() {
        let path = github_org().canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/usrbinkat/github.com/braincraftio")
        );
    }

    #[test]
    fn nested_namespace_path() {
        let coord = WorkspaceCoordinate::new(
            GitHost::new("gitlab.com").unwrap(),
            NamespacePath::new("group/subgroup").unwrap(),
            WorkspaceKind::Repository(RepositoryName::new("project").unwrap()),
        );
        let path = coord.canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/usrbinkat/gitlab.com/group/subgroup/project")
        );
    }

    #[test]
    fn port_not_in_path() {
        // Hosts that differ only by port map to the same directory.
        // Port is endpoint metadata, not filesystem provenance.
        let coord = WorkspaceCoordinate::new(
            GitHost::new("git.example.com").unwrap(),
            NamespacePath::new("org").unwrap(),
            WorkspaceKind::Repository(RepositoryName::new("repo").unwrap()),
        );
        let path = coord.canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/usrbinkat/git.example.com/org/repo")
        );
    }

    #[test]
    fn ipv6_path() {
        let coord = WorkspaceCoordinate::new(
            GitHost::new("[2001:db8::25]").unwrap(),
            NamespacePath::new("platform").unwrap(),
            WorkspaceKind::Repository(RepositoryName::new("api").unwrap()),
        );
        let path = coord.canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/usrbinkat/_ipv6_2001-db8--25/platform/api")
        );
    }

    #[test]
    fn display_repository() {
        assert_eq!(
            github_repo().to_string(),
            "github.com/braincraftio/konductor"
        );
    }

    #[test]
    fn display_workspace() {
        assert_eq!(
            github_workspace().to_string(),
            "github.com/braincraftio/workspace"
        );
    }

    #[test]
    fn display_organization() {
        assert_eq!(
            github_org().to_string(),
            "github.com/braincraftio"
        );
    }

    #[test]
    fn repository_is_cloneable() {
        assert!(github_repo().kind().is_cloneable());
    }

    #[test]
    fn workspace_is_cloneable() {
        assert!(github_workspace().kind().is_cloneable());
    }

    #[test]
    fn organization_is_not_cloneable() {
        assert!(!github_org().kind().is_cloneable());
    }

    #[test]
    fn repository_name_accessor() {
        assert_eq!(
            github_repo().kind().repository_name().map(|r| r.as_str()),
            Some("konductor")
        );
    }

    #[test]
    fn organization_has_no_repository_name() {
        assert!(github_org().kind().repository_name().is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let coord = github_repo();
        let json = serde_json::to_string(&coord).unwrap();
        let parsed: WorkspaceCoordinate = serde_json::from_str(&json).unwrap();
        assert_eq!(coord, parsed);
    }
}
