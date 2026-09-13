//! Remote endpoint: connection details for reaching a git repository.
//!
//! A `RemoteEndpoint` combines a `RemoteIdentity` (host + namespace + repo)
//! with transport-specific connection metadata: protocol, port, and
//! SSH username. The identity determines workspace placement. The
//! endpoint determines how to connect.

use std::fmt;

use crate::v1::{GitHost, GitTransport, RemoteIdentity};

/// Connection details for a git remote repository.
///
/// Contains the identity (for workspace placement and comparison)
/// plus transport metadata (for network operations). The rendered
/// URL is computed from the components, not stored as a string.
#[derive(Debug, Clone)]
pub struct RemoteEndpoint {
    identity: RemoteIdentity,
    transport: GitTransport,
    port: Option<u16>,
    user: Option<String>,
}

impl RemoteEndpoint {
    /// Construct an endpoint from identity and transport details.
    #[must_use]
    pub fn new(
        identity: RemoteIdentity,
        transport: GitTransport,
        port: Option<u16>,
        user: Option<String>,
    ) -> Self {
        Self {
            identity,
            transport,
            port,
            user,
        }
    }

    /// Construct an HTTPS endpoint with default port and no user.
    #[must_use]
    pub fn https(identity: RemoteIdentity) -> Self {
        Self {
            identity,
            transport: GitTransport::Https,
            port: None,
            user: None,
        }
    }

    /// Construct an SSH endpoint with default port and "git" user.
    #[must_use]
    pub fn ssh(identity: RemoteIdentity) -> Self {
        Self {
            identity,
            transport: GitTransport::Ssh,
            port: None,
            user: Some("git".into()),
        }
    }

    /// The repository identity for workspace placement and comparison.
    #[must_use]
    pub fn identity(&self) -> &RemoteIdentity {
        &self.identity
    }

    /// The transport protocol.
    #[must_use]
    pub fn transport(&self) -> GitTransport {
        self.transport
    }

    /// The port, if nonstandard.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The SSH username, if applicable.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Render as a clone URL string.
    ///
    /// The rendered URL is suitable for passing to gix or git2 clone
    /// operations. HTTPS URLs include the port when nonstandard.
    /// SSH URLs use ssh:// syntax when a port is specified, and
    /// SCP-style syntax otherwise.
    #[must_use]
    pub fn to_url(&self) -> String {
        let host = &self.identity.host();
        let ns = self.identity.namespace();
        let repo = self.identity.repository();

        let host_str = match host {
            GitHost::Ipv6(addr) => format!("[{addr}]"),
            other => other.as_str(),
        };

        match self.transport {
            GitTransport::Https => match self.port {
                Some(p) => format!("https://{host_str}:{p}/{ns}/{repo}"),
                None => format!("https://{host_str}/{ns}/{repo}"),
            },
            GitTransport::Ssh => {
                let user = self.user.as_deref().unwrap_or("git");
                match self.port {
                    Some(p) => format!("ssh://{user}@{host_str}:{p}/{ns}/{repo}"),
                    None => format!("{user}@{host_str}:{ns}/{repo}.git"),
                }
            }
        }
    }
}

impl fmt::Display for RemoteEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{NamespacePath, RepositoryName};

    fn github_identity() -> RemoteIdentity {
        RemoteIdentity::new(
            GitHost::new("github.com").unwrap(),
            NamespacePath::new("braincraftio").unwrap(),
            RepositoryName::new("konductor").unwrap(),
        )
    }

    #[test]
    fn https_default_port() {
        let ep = RemoteEndpoint::https(github_identity());
        assert_eq!(ep.to_url(), "https://github.com/braincraftio/konductor");
    }

    #[test]
    fn https_custom_port() {
        let ep = RemoteEndpoint::new(
            github_identity(),
            GitTransport::Https,
            Some(8443),
            None,
        );
        assert_eq!(
            ep.to_url(),
            "https://github.com:8443/braincraftio/konductor"
        );
    }

    #[test]
    fn ssh_default_port() {
        let ep = RemoteEndpoint::ssh(github_identity());
        assert_eq!(
            ep.to_url(),
            "git@github.com:braincraftio/konductor.git"
        );
    }

    #[test]
    fn ssh_custom_port() {
        let ep = RemoteEndpoint::new(
            github_identity(),
            GitTransport::Ssh,
            Some(2222),
            Some("git".into()),
        );
        assert_eq!(
            ep.to_url(),
            "ssh://git@github.com:2222/braincraftio/konductor"
        );
    }

    #[test]
    fn ssh_custom_user() {
        let ep = RemoteEndpoint::new(
            github_identity(),
            GitTransport::Ssh,
            None,
            Some("deploy".into()),
        );
        assert_eq!(
            ep.to_url(),
            "deploy@github.com:braincraftio/konductor.git"
        );
    }

    #[test]
    fn ipv6_https() {
        let id = RemoteIdentity::new(
            GitHost::new("[2001:db8::25]").unwrap(),
            NamespacePath::new("org").unwrap(),
            RepositoryName::new("repo").unwrap(),
        );
        let ep = RemoteEndpoint::new(id, GitTransport::Https, Some(8443), None);
        assert_eq!(ep.to_url(), "https://[2001:db8::25]:8443/org/repo");
    }

    #[test]
    fn ipv6_ssh_with_port() {
        let id = RemoteIdentity::new(
            GitHost::new("[::1]").unwrap(),
            NamespacePath::new("org").unwrap(),
            RepositoryName::new("repo").unwrap(),
        );
        let ep = RemoteEndpoint::new(id, GitTransport::Ssh, Some(2222), Some("git".into()));
        assert_eq!(ep.to_url(), "ssh://git@[::1]:2222/org/repo");
    }

    #[test]
    fn nested_namespace_https() {
        let id = RemoteIdentity::new(
            GitHost::new("gitlab.com").unwrap(),
            NamespacePath::new("group/subgroup").unwrap(),
            RepositoryName::new("project").unwrap(),
        );
        let ep = RemoteEndpoint::https(id);
        assert_eq!(
            ep.to_url(),
            "https://gitlab.com/group/subgroup/project"
        );
    }

    #[test]
    fn nested_namespace_ssh() {
        let id = RemoteIdentity::new(
            GitHost::new("gitlab.com").unwrap(),
            NamespacePath::new("group/subgroup").unwrap(),
            RepositoryName::new("project").unwrap(),
        );
        let ep = RemoteEndpoint::ssh(id);
        assert_eq!(
            ep.to_url(),
            "git@gitlab.com:group/subgroup/project.git"
        );
    }

    #[test]
    fn identity_preserved() {
        let id = github_identity();
        let ep = RemoteEndpoint::https(id.clone());
        assert_eq!(ep.identity(), &id);
    }

    #[test]
    fn same_identity_different_transport() {
        let id = github_identity();
        let https = RemoteEndpoint::https(id.clone());
        let ssh = RemoteEndpoint::ssh(id.clone());
        assert_eq!(https.identity(), ssh.identity());
        assert_ne!(https.to_url(), ssh.to_url());
    }

    #[test]
    fn same_identity_different_port() {
        let id = github_identity();
        let a = RemoteEndpoint::new(id.clone(), GitTransport::Https, Some(8443), None);
        let b = RemoteEndpoint::new(id.clone(), GitTransport::Https, Some(9443), None);
        assert_eq!(a.identity(), b.identity());
        assert_ne!(a.to_url(), b.to_url());
    }
}
