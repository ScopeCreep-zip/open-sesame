//! Semantic remote identity.
//!
//! Two remotes identify the same repository when they share the same
//! host, namespace, and repository name. Transport, port, username,
//! and URL rendering do not affect identity. Port is an endpoint
//! concern, not a provenance concern.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::v1::{GitHost, NamespacePath, RepositoryName};

/// The identity of a git remote repository.
///
/// Equality compares host (case-insensitive for FQDNs, canonical for
/// IPs), namespace, and repository name. Two `RemoteIdentity` values
/// representing the same repository via HTTPS and SSH are equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RemoteIdentity {
    host: GitHost,
    namespace: NamespacePath,
    repository: RepositoryName,
}

impl RemoteIdentity {
    /// Construct a remote identity from validated components.
    #[must_use]
    pub fn new(host: GitHost, namespace: NamespacePath, repository: RepositoryName) -> Self {
        Self {
            host,
            namespace,
            repository,
        }
    }

    /// The server host.
    #[must_use]
    pub fn host(&self) -> &GitHost {
        &self.host
    }

    /// The namespace path between server and repository.
    #[must_use]
    pub fn namespace(&self) -> &NamespacePath {
        &self.namespace
    }

    /// The repository name.
    #[must_use]
    pub fn repository(&self) -> &RepositoryName {
        &self.repository
    }

    /// Render as an HTTPS clone URL on the default port.
    ///
    /// For URLs with nonstandard ports, use `RemoteEndpoint` rendering.
    #[must_use]
    pub fn to_https_url(&self) -> String {
        let host_str = match &self.host {
            GitHost::Ipv6(addr) => format!("[{addr}]"),
            other => other.as_str(),
        };
        format!("https://{host_str}/{}/{}", self.namespace, self.repository)
    }

    /// Render as an SCP-style SSH clone URL on the default port.
    ///
    /// For URLs with nonstandard ports, use `RemoteEndpoint` rendering
    /// which produces ssh:// syntax.
    #[must_use]
    pub fn to_ssh_url(&self) -> String {
        let host_str = match &self.host {
            GitHost::Ipv6(addr) => format!("[{addr}]"),
            other => other.as_str(),
        };
        format!("git@{host_str}:{}/{}.git", self.namespace, self.repository)
    }
}

impl fmt::Display for RemoteIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.host, self.namespace, self.repository)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github_remote() -> RemoteIdentity {
        RemoteIdentity::new(
            GitHost::new("github.com").unwrap(),
            NamespacePath::new("braincraftio").unwrap(),
            RepositoryName::new("konductor").unwrap(),
        )
    }

    #[test]
    fn https_url() {
        assert_eq!(
            github_remote().to_https_url(),
            "https://github.com/braincraftio/konductor"
        );
    }

    #[test]
    fn ssh_url() {
        assert_eq!(
            github_remote().to_ssh_url(),
            "git@github.com:braincraftio/konductor.git"
        );
    }

    #[test]
    fn display() {
        assert_eq!(
            github_remote().to_string(),
            "github.com/braincraftio/konductor"
        );
    }

    #[test]
    fn equality_ignores_case() {
        let a = RemoteIdentity::new(
            GitHost::new("GitHub.COM").unwrap(),
            NamespacePath::new("org").unwrap(),
            RepositoryName::new("repo.git").unwrap(),
        );
        let b = RemoteIdentity::new(
            GitHost::new("github.com").unwrap(),
            NamespacePath::new("org").unwrap(),
            RepositoryName::new("repo").unwrap(),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn nested_namespace_https() {
        let r = RemoteIdentity::new(
            GitHost::new("gitlab.com").unwrap(),
            NamespacePath::new("group/subgroup").unwrap(),
            RepositoryName::new("project").unwrap(),
        );
        assert_eq!(
            r.to_https_url(),
            "https://gitlab.com/group/subgroup/project"
        );
    }

    #[test]
    fn nested_namespace_ssh() {
        let r = RemoteIdentity::new(
            GitHost::new("gitlab.com").unwrap(),
            NamespacePath::new("group/subgroup").unwrap(),
            RepositoryName::new("project").unwrap(),
        );
        assert_eq!(r.to_ssh_url(), "git@gitlab.com:group/subgroup/project.git");
    }

    #[test]
    fn ipv6_https() {
        let r = RemoteIdentity::new(
            GitHost::new("[2001:db8::25]").unwrap(),
            NamespacePath::new("org").unwrap(),
            RepositoryName::new("repo").unwrap(),
        );
        assert_eq!(r.to_https_url(), "https://[2001:db8::25]/org/repo");
    }

    #[test]
    fn ipv6_ssh() {
        let r = RemoteIdentity::new(
            GitHost::new("[::1]").unwrap(),
            NamespacePath::new("org").unwrap(),
            RepositoryName::new("repo").unwrap(),
        );
        assert_eq!(r.to_ssh_url(), "git@[::1]:org/repo.git");
    }

    #[test]
    fn ipv4_https() {
        let r = RemoteIdentity::new(
            GitHost::new("192.0.2.40").unwrap(),
            NamespacePath::new("eng").unwrap(),
            RepositoryName::new("compiler").unwrap(),
        );
        assert_eq!(r.to_https_url(), "https://192.0.2.40/eng/compiler");
    }

    #[test]
    fn serde_roundtrip() {
        let original = github_remote();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: RemoteIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }
}
