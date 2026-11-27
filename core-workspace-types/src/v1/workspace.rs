//! Workspace coordinate and kind.
//!
//! A workspace coordinate locates an entity within the workspace
//! directory layout. It is a pure placement: every component is a
//! lowercase placement type, and it carries no remote spelling. Remote
//! identity lives in `RemoteIdentity`/`RemoteEndpoint`; the
//! `from_remote_*` constructors are the only mapping from remote to
//! placement, and no mapping exists in the other direction.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::v1::{GitHost, NamespaceDir, NamespacePath, RemoteIdentity, RepoDir, WorkspaceUser};

/// What kind of workspace entity this coordinate identifies.
///
/// Workspace semantics (whether a repository is the org-level
/// workspace repository) are assigned by command context and
/// configuration, not by repository name parsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceKind {
    /// A regular repository, placed in its own directory.
    Repository(RepoDir),
    /// The org-level workspace repository, placed at the namespace
    /// directory itself.
    WorkspaceRepository,
    /// A forge organization or namespace, not a git remote.
    Organization,
}

impl WorkspaceKind {
    /// The repository directory if this is a regular repository.
    #[must_use]
    pub fn repository_dir(&self) -> Option<&RepoDir> {
        match self {
            Self::Repository(r) => Some(r),
            Self::WorkspaceRepository | Self::Organization => None,
        }
    }

    /// Whether this kind represents a cloneable git remote.
    #[must_use]
    pub fn is_cloneable(&self) -> bool {
        matches!(self, Self::Repository(_) | Self::WorkspaceRepository)
    }
}

/// A fully resolved location within the workspace directory layout.
///
/// Combines a host, namespace directory, and entity kind into a
/// coordinate that computes filesystem paths. Does not carry remote
/// spelling, transport, port, or user information. Those belong in
/// `RemoteEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceCoordinate {
    host: GitHost,
    namespace: NamespaceDir,
    kind: WorkspaceKind,
}

impl WorkspaceCoordinate {
    /// Construct from placement components (directory names parsed from disk).
    #[must_use]
    pub fn new(host: GitHost, namespace: NamespaceDir, kind: WorkspaceKind) -> Self {
        Self {
            host,
            namespace,
            kind,
        }
    }

    /// Placement of a regular repository.
    #[must_use]
    pub fn from_remote_repository(identity: &RemoteIdentity) -> Self {
        Self::new(
            identity.host().clone(),
            NamespaceDir::from_remote(identity.namespace()),
            WorkspaceKind::Repository(RepoDir::from_remote(identity.repository())),
        )
    }

    /// Placement of the org-level workspace repository for a namespace.
    #[must_use]
    pub fn from_remote_workspace_repository(host: &GitHost, namespace: &NamespacePath) -> Self {
        Self::new(
            host.clone(),
            NamespaceDir::from_remote(namespace),
            WorkspaceKind::WorkspaceRepository,
        )
    }

    /// Placement of a forge organization.
    #[must_use]
    pub fn from_remote_organization(host: &GitHost, namespace: &NamespacePath) -> Self {
        Self::new(
            host.clone(),
            NamespaceDir::from_remote(namespace),
            WorkspaceKind::Organization,
        )
    }

    /// The server host.
    #[must_use]
    pub fn host(&self) -> &GitHost {
        &self.host
    }

    /// The namespace directory.
    #[must_use]
    pub fn namespace(&self) -> &NamespaceDir {
        &self.namespace
    }

    /// The workspace kind.
    #[must_use]
    pub fn kind(&self) -> &WorkspaceKind {
        &self.kind
    }

    /// The path components below the user directory, in order:
    /// host directory, namespace segments, then the repository
    /// directory for regular repositories.
    #[must_use]
    pub fn components(&self) -> Vec<String> {
        let mut parts = Vec::with_capacity(self.namespace.segments().len() + 2);
        parts.push(self.host.as_dir_name());
        parts.extend(self.namespace.segments().iter().cloned());
        if let WorkspaceKind::Repository(repo) = &self.kind {
            parts.push(repo.as_str().to_string());
        }
        parts
    }

    /// Compute the canonical filesystem path for this coordinate.
    ///
    /// Layout: `{root}/{user}/{host}/{namespace...}[/{repo}]`
    ///
    /// Organization and workspace-repository coordinates resolve to the
    /// namespace directory. Regular repositories resolve to a
    /// subdirectory named after the repository.
    #[must_use]
    pub fn canonical_path(&self, root: &Path, user: &WorkspaceUser) -> PathBuf {
        let mut path = root.join(user.as_str());
        path.extend(self.components());
        path
    }
}

impl fmt::Display for WorkspaceCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            WorkspaceKind::Repository(r) => write!(f, "{}/{}/{}", self.host, self.namespace, r),
            WorkspaceKind::WorkspaceRepository | WorkspaceKind::Organization => {
                write!(f, "{}/{}", self.host, self.namespace)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::RepositoryName;

    fn test_user() -> WorkspaceUser {
        WorkspaceUser::new("alice").unwrap()
    }

    fn identity(host: &str, ns: &str, repo: &str) -> RemoteIdentity {
        RemoteIdentity::new(
            GitHost::new(host).unwrap(),
            NamespacePath::new(ns).unwrap(),
            RepositoryName::new(repo).unwrap(),
        )
    }

    fn github_repo() -> WorkspaceCoordinate {
        WorkspaceCoordinate::from_remote_repository(&identity(
            "github.com",
            "braincraftio",
            "konductor",
        ))
    }

    fn github_org() -> WorkspaceCoordinate {
        WorkspaceCoordinate::from_remote_organization(
            &GitHost::new("github.com").unwrap(),
            &NamespacePath::new("braincraftio").unwrap(),
        )
    }

    #[test]
    fn repository_path() {
        let path = github_repo().canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/alice/github.com/braincraftio/konductor")
        );
    }

    #[test]
    fn workspace_repository_path_is_namespace_dir() {
        let coord = WorkspaceCoordinate::from_remote_workspace_repository(
            &GitHost::new("github.com").unwrap(),
            &NamespacePath::new("braincraftio").unwrap(),
        );
        assert_eq!(
            coord.canonical_path(Path::new("/workspace"), &test_user()),
            PathBuf::from("/workspace/alice/github.com/braincraftio")
        );
    }

    #[test]
    fn organization_path() {
        let path = github_org().canonical_path(Path::new("/workspace"), &test_user());
        assert_eq!(
            path,
            PathBuf::from("/workspace/alice/github.com/braincraftio")
        );
    }

    #[test]
    fn remote_spellings_share_one_placement() {
        let a = WorkspaceCoordinate::from_remote_repository(&identity(
            "GitHub.com",
            "NixOS",
            "NixPkgs",
        ));
        let b = WorkspaceCoordinate::from_remote_repository(&identity(
            "github.com",
            "nixos",
            "nixpkgs",
        ));
        assert_eq!(a, b);
        assert_eq!(
            a.canonical_path(Path::new("/workspace"), &test_user()),
            PathBuf::from("/workspace/alice/github.com/nixos/nixpkgs")
        );
    }

    #[test]
    fn leading_dot_repository_path() {
        let coord = WorkspaceCoordinate::from_remote_repository(&identity(
            "github.com",
            "SesameOS",
            ".github",
        ));
        assert_eq!(
            coord.canonical_path(Path::new("/workspace"), &test_user()),
            PathBuf::from("/workspace/alice/github.com/sesameos/.github")
        );
    }

    #[test]
    fn nested_namespace_path() {
        let coord = WorkspaceCoordinate::from_remote_repository(&identity(
            "gitlab.com",
            "group/subgroup",
            "project",
        ));
        assert_eq!(
            coord.canonical_path(Path::new("/workspace"), &test_user()),
            PathBuf::from("/workspace/alice/gitlab.com/group/subgroup/project")
        );
    }

    #[test]
    fn port_not_in_path() {
        let coord = WorkspaceCoordinate::from_remote_repository(&identity(
            "git.example.com",
            "org",
            "repo",
        ));
        assert_eq!(
            coord.canonical_path(Path::new("/workspace"), &test_user()),
            PathBuf::from("/workspace/alice/git.example.com/org/repo")
        );
    }

    #[test]
    fn ipv6_path() {
        let coord = WorkspaceCoordinate::from_remote_repository(&identity(
            "[2001:db8::25]",
            "platform",
            "api",
        ));
        assert_eq!(
            coord.canonical_path(Path::new("/workspace"), &test_user()),
            PathBuf::from("/workspace/alice/_ipv6_2001-db8--25/platform/api")
        );
    }

    #[test]
    fn components_order() {
        assert_eq!(
            github_repo().components(),
            vec!["github.com", "braincraftio", "konductor"]
        );
        assert_eq!(
            github_org().components(),
            vec!["github.com", "braincraftio"]
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
    fn display_organization() {
        assert_eq!(github_org().to_string(), "github.com/braincraftio");
    }

    #[test]
    fn cloneability() {
        assert!(github_repo().kind().is_cloneable());
        assert!(WorkspaceKind::WorkspaceRepository.is_cloneable());
        assert!(!github_org().kind().is_cloneable());
    }

    #[test]
    fn repository_dir_accessor() {
        assert_eq!(
            github_repo().kind().repository_dir().map(RepoDir::as_str),
            Some("konductor")
        );
        assert!(github_org().kind().repository_dir().is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let coord = github_repo();
        let json = serde_json::to_string(&coord).unwrap();
        let parsed: WorkspaceCoordinate = serde_json::from_str(&json).unwrap();
        assert_eq!(coord, parsed);
    }
}
