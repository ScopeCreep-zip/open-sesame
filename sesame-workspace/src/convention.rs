//! URL parsing, shorthand resolution, and clone input construction.
//!
//! Remote and placement are separate vocabularies:
//! - URL parsing produces remote identifiers in the spelling the user
//!   or forge supplied (`RemoteRef`, `RemoteTarget`). Explicit URLs are
//!   never rewritten.
//! - Placement (`WorkspaceCoordinate`) is derived from remote identity
//!   through `WorkspaceCoordinate::from_remote_*`, never the reverse.
//! - Filesystem paths parse strictly into placement (`parse_path`); a
//!   non-canonical directory name is an error, not a normalization.

use std::path::Path;

use core_workspace_types::{
    GitHost, GitTransport, NamespaceDir, NamespacePath, RemoteEndpoint, RemoteIdentity, RepoDir,
    RepositoryName, ValidationError, WorkspaceCoordinate,
};

use crate::WorkspaceError;
use crate::net::redact_credentials;

/// A parsed remote: either a repository or a forge organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteRef {
    /// A cloneable repository.
    Repository(RemoteIdentity),
    /// A forge organization or user namespace (no repository).
    Organization {
        host: GitHost,
        namespace: NamespacePath,
    },
}

impl RemoteRef {
    /// The workspace placement of this remote.
    #[must_use]
    pub fn coordinate(&self) -> WorkspaceCoordinate {
        match self {
            Self::Repository(identity) => WorkspaceCoordinate::from_remote_repository(identity),
            Self::Organization { host, namespace } => {
                WorkspaceCoordinate::from_remote_organization(host, namespace)
            }
        }
    }
}

/// The network target of a clone request.
#[derive(Debug, Clone)]
pub enum RemoteTarget {
    /// A repository reachable at this endpoint.
    Repository(RemoteEndpoint),
    /// A forge organization; repositories are enumerated through the
    /// forge API.
    Organization {
        host: GitHost,
        namespace: NamespacePath,
    },
}

/// The result of parsing a clone input from raw user input.
#[derive(Debug, Clone)]
pub struct CloneInput {
    /// The network target in remote spelling.
    pub target: RemoteTarget,
    /// The workspace placement.
    pub coordinate: WorkspaceCoordinate,
    /// The resolved URL string for user-facing display.
    pub display_url: String,
}

/// Parse raw user input into a fully typed clone input.
///
/// Performs shorthand resolution, URL parsing, transport selection,
/// and workspace repository classification in one step. A repository
/// whose placement equals the placement of `workspace_repo` is the
/// org-level workspace repository, placed at the namespace directory.
///
/// # Errors
///
/// Returns `WorkspaceError::InvalidUrl` or `WorkspaceError::PathValidation`
/// for unparseable or invalid input.
pub fn parse_clone_input(
    input: &str,
    default_server: &str,
    transport: GitTransport,
    workspace_repo: &RepositoryName,
) -> Result<CloneInput, WorkspaceError> {
    let resolved = resolve_url(input, default_server, transport == GitTransport::Ssh)?;
    let components = parse_components(&resolved)?;
    let transport = components.transport;
    let port = components.port;
    let user = components.user.clone();

    let (target, coordinate) = match remote_from_components(components)? {
        RemoteRef::Organization { host, namespace } => {
            let coordinate = WorkspaceCoordinate::from_remote_organization(&host, &namespace);
            (RemoteTarget::Organization { host, namespace }, coordinate)
        }
        RemoteRef::Repository(identity) => {
            let coordinate = if RepoDir::from_remote(identity.repository())
                == RepoDir::from_remote(workspace_repo)
            {
                WorkspaceCoordinate::from_remote_workspace_repository(
                    identity.host(),
                    identity.namespace(),
                )
            } else {
                WorkspaceCoordinate::from_remote_repository(&identity)
            };
            let endpoint = match transport {
                GitTransport::Https => {
                    RemoteEndpoint::new(identity, GitTransport::Https, port, None)
                }
                GitTransport::Ssh => RemoteEndpoint::new(identity, GitTransport::Ssh, port, user),
            };
            (RemoteTarget::Repository(endpoint), coordinate)
        }
    };

    Ok(CloneInput {
        target,
        coordinate,
        display_url: resolved,
    })
}

/// Parse a git remote URL into a remote reference in remote spelling.
///
/// Lower-level function for parsing URLs from existing remotes
/// (adoption comparison) and forge API responses. Does not perform
/// shorthand resolution or workspace classification.
///
/// # Errors
///
/// Returns `WorkspaceError::InvalidUrl` or `WorkspaceError::PathValidation`
/// for unparseable or invalid URLs.
pub fn parse_url(url: &str) -> Result<RemoteRef, WorkspaceError> {
    remote_from_components(parse_components(url)?)
}

/// Build typed remote identifiers from parsed URL components.
fn remote_from_components(components: ParsedComponents) -> Result<RemoteRef, WorkspaceError> {
    let host = GitHost::new(&components.host)
        .map_err(|e| WorkspaceError::PathValidation(format!("server: {e}")))?;

    if components.org_only {
        let namespace = NamespacePath::from_segments(components.segments)
            .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;
        return Ok(RemoteRef::Organization { host, namespace });
    }

    let mut segments = components.segments;
    let Some(repo_str) = segments.pop() else {
        return Err(WorkspaceError::InvalidUrl(
            "URL must have at least namespace/repo".into(),
        ));
    };
    if segments.is_empty() {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL must have at least namespace/repo, got only: {repo_str}"
        )));
    }
    let namespace = NamespacePath::from_segments(segments)
        .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;
    let repo = RepositoryName::new(&repo_str)
        .map_err(|e| WorkspaceError::PathValidation(format!("repository: {e}")))?;

    Ok(RemoteRef::Repository(RemoteIdentity::new(
        host, namespace, repo,
    )))
}

/// Placement components parsed strictly from a workspace filesystem path.
///
/// Does not determine `WorkspaceKind`. The caller assigns kind from
/// command context, configuration, and filesystem inspection.
#[derive(Debug, Clone)]
pub struct ParsedPath {
    pub host: GitHost,
    pub namespace: NamespaceDir,
    /// The terminal path component, if the path extends beyond the
    /// namespace level: the repository directory for repository paths,
    /// or None for namespace-level paths.
    pub terminal: Option<RepoDir>,
}

/// Parse a filesystem path under `{root}/{user}` into placement components.
///
/// The path must follow the layout `{root}/{user}/{server}/{ns...}[/{repo}]`.
/// Symlinks are canonicalized to prevent escape from the workspace root.
/// Every directory name must already be canonical.
///
/// # Errors
///
/// - `WorkspaceError::NotInWorkspace` if the path is outside the root or
///   too shallow.
/// - `WorkspaceError::NonCanonical` if a directory name in the layout is
///   not lowercase.
/// - `WorkspaceError::PathValidation` for non-UTF-8 components, an
///   undecodable server directory, or canonicalization failure.
pub fn parse_path(root: &Path, path: &Path) -> Result<ParsedPath, WorkspaceError> {
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        WorkspaceError::PathValidation(format!("cannot canonicalize {}: {e}", path.display()))
    })?;
    let canonical_root = std::fs::canonicalize(root).map_err(|e| {
        WorkspaceError::PathValidation(format!("cannot canonicalize root {}: {e}", root.display()))
    })?;

    let rel = canonical
        .strip_prefix(&canonical_root)
        .map_err(|_| WorkspaceError::NotInWorkspace(path.to_path_buf()))?;

    let components: Vec<&str> = rel
        .components()
        .map(|c| match c {
            std::path::Component::Normal(s) => s.to_str().ok_or_else(|| {
                WorkspaceError::PathValidation(format!(
                    "non-UTF-8 path component in {}",
                    path.display()
                ))
            }),
            _ => Err(WorkspaceError::PathValidation(format!(
                "unexpected path component type in {}",
                path.display()
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Minimum: [user, server, namespace_segment]
    if components.len() < 3 {
        return Err(WorkspaceError::NotInWorkspace(path.to_path_buf()));
    }

    let placement = |source: ValidationError| WorkspaceError::placement(&canonical, source);

    let host = GitHost::from_dir_name(components[1]).map_err(placement)?;

    // Exactly [user, server, ns]: namespace-level path, no terminal.
    if components.len() == 3 {
        let namespace = NamespaceDir::parse(&components[2..]).map_err(placement)?;
        return Ok(ParsedPath {
            host,
            namespace,
            terminal: None,
        });
    }

    // [user, server, ns..., terminal]: last component is terminal,
    // everything between server and terminal is namespace.
    let ns_end = components.len() - 1;
    let namespace = NamespaceDir::parse(&components[2..ns_end]).map_err(placement)?;
    let terminal = RepoDir::parse(components[ns_end]).map_err(placement)?;

    Ok(ParsedPath {
        host,
        namespace,
        terminal: Some(terminal),
    })
}

/// Whether `path`'s parent directory is a repository root, which places
/// `path` inside that repository's working tree (the org-level
/// workspace.git for a member repository).
///
/// # Errors
///
/// Returns the `git_marker` error when the parent's `.git` is invalid.
pub fn is_inside_workspace_git(path: &Path) -> Result<bool, WorkspaceError> {
    match path.parent() {
        Some(parent) => Ok(crate::git::git_marker(parent)?.is_repository_root()),
        None => Ok(false),
    }
}

// ============================================================================
// Internal: shorthand resolution
// ============================================================================

/// Resolve shorthand input into a full URL string.
///
/// This is an internal step used by `parse_clone_input`. The resolved
/// URL is immediately parsed into typed components; the string does
/// not escape to the orchestration layer.
fn resolve_url(input: &str, default_server: &str, use_ssh: bool) -> Result<String, WorkspaceError> {
    let input = input.trim().trim_end_matches('/');

    if input.is_empty() {
        return Err(WorkspaceError::InvalidUrl("empty URL".into()));
    }

    if input.starts_with("https://") || input.starts_with("http://") || input.starts_with("ssh://")
    {
        return Ok(input.to_string());
    }

    if input.contains('@') && input.contains(':') {
        return Ok(input.to_string());
    }

    if input.contains('\0') {
        return Err(WorkspaceError::InvalidUrl("URL contains null bytes".into()));
    }

    let segments: Vec<&str> = input.split('/').collect();
    let input = redact_credentials(input);

    match segments.len() {
        3 => {
            if segments[0].contains('.') {
                if use_ssh {
                    Ok(format!(
                        "git@{}:{}/{}.git",
                        segments[0], segments[1], segments[2]
                    ))
                } else {
                    Ok(format!("https://{}", segments.join("/")))
                }
            } else {
                Err(WorkspaceError::InvalidUrl(format!(
                    "three-segment input requires a hostname with a dot in \
                     the first segment: {input}\n\
                     accepted: https://server/ns/repo, server/ns/repo, ns/repo"
                )))
            }
        }
        2 => {
            let path = segments.join("/");
            if segments[0].contains('.') {
                Ok(format!("https://{path}"))
            } else if use_ssh {
                Ok(format!("git@{default_server}:{path}.git"))
            } else {
                Ok(format!("https://{default_server}/{path}"))
            }
        }
        1 => Err(WorkspaceError::InvalidUrl(format!(
            "single-segment input is ambiguous: {input}\n\
             accepted: https://server/ns/repo, server/ns/repo, ns/repo"
        ))),
        _ => Err(WorkspaceError::InvalidUrl(format!(
            "unrecognized URL format: {input}\n\
             accepted: https://server/ns/repo, server/ns/repo, ns/repo"
        ))),
    }
}

// ============================================================================
// Internal: URL component parsing
// ============================================================================

/// Parsed URL components before typed construction.
struct ParsedComponents {
    host: String,
    segments: Vec<String>,
    org_only: bool,
    transport: GitTransport,
    port: Option<u16>,
    user: Option<String>,
}

/// Parse any supported URL form into components.
fn parse_components(url: &str) -> Result<ParsedComponents, WorkspaceError> {
    let url = url.trim();

    if url.contains('\0') {
        return Err(WorkspaceError::InvalidUrl("URL contains null bytes".into()));
    }

    if url.starts_with("http://") {
        tracing::warn!(
            url = redact_credentials(url),
            "HTTP URL detected. Credentials will be transmitted in cleartext."
        );
    }

    if let Some(without_scheme) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        parse_https(url, without_scheme)
    } else if url.starts_with("ssh://") {
        parse_ssh_scheme(url)
    } else if url.contains('@') && url.contains(':') {
        parse_scp(url)
    } else {
        Err(WorkspaceError::InvalidUrl(format!(
            "unrecognized URL format: {}\n\
             expected https://, http://, ssh://, or git@host:ns/repo",
            redact_credentials(url)
        )))
    }
}

/// Parse an HTTP(S) URL; `without_scheme` is `url` after its
/// `https://` or `http://` prefix.
fn parse_https(url: &str, without_scheme: &str) -> Result<ParsedComponents, WorkspaceError> {
    if without_scheme.contains('?') || without_scheme.contains('#') {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL contains query string or fragment: {}",
            redact_credentials(url)
        )));
    }

    let clean = without_scheme.trim_end_matches('/');
    let (authority, path) = match clean.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (clean, None),
    };

    // Credentials in the URL would be stored as the remote and printed
    // by every tool that shows it; git credential helpers supply them.
    if authority.contains('@') {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL contains credentials; use a git credential helper instead: {}",
            redact_credentials(url)
        )));
    }

    let (host, port) = split_host_port(authority)?;
    let Some(path) = path else {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL must have at least server/namespace: {}",
            redact_credentials(url)
        )));
    };
    let segments: Vec<String> = path.split('/').map(ToString::to_string).collect();
    Ok(ParsedComponents {
        host,
        org_only: segments.len() == 1,
        segments,
        transport: GitTransport::Https,
        port,
        user: None,
    })
}

/// Parse SCP-style SSH URL: [user@]host:path
fn parse_scp(url: &str) -> Result<ParsedComponents, WorkspaceError> {
    let shown = redact_credentials(url);
    if url.contains('?') || url.contains('#') {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL contains query string or fragment: {shown}"
        )));
    }

    let at_pos = url
        .find('@')
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("SSH URL missing '@': {shown}")))?;

    let user = url[..at_pos].to_string();
    let after_at = &url[at_pos + 1..];

    let colon_pos = after_at
        .find(':')
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("SSH URL missing ':': {shown}")))?;

    let host = after_at[..colon_pos].to_string();
    let path = &after_at[colon_pos + 1..];

    let segments: Vec<String> = path
        .trim_end_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();

    if segments.len() < 2 {
        return Err(WorkspaceError::InvalidUrl(format!(
            "SSH URL must have namespace/repo after ':': {shown}"
        )));
    }

    Ok(ParsedComponents {
        host,
        segments,
        org_only: false,
        transport: GitTransport::Ssh,
        port: None,
        user: Some(user),
    })
}

/// Parse ssh:// scheme URL: ssh://[user@]host[:port]/path
fn parse_ssh_scheme(url: &str) -> Result<ParsedComponents, WorkspaceError> {
    let shown = redact_credentials(url);
    if url.contains('?') || url.contains('#') {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL contains query string or fragment: {shown}"
        )));
    }

    let without_scheme = url
        .strip_prefix("ssh://")
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("not ssh://: {shown}")))?;

    let (user_opt, after_user) = match without_scheme.find('@') {
        Some(at_pos) => (
            Some(without_scheme[..at_pos].to_string()),
            &without_scheme[at_pos + 1..],
        ),
        None => (None, without_scheme),
    };
    let Some(slash) = after_user.find('/') else {
        return Err(WorkspaceError::InvalidUrl(format!(
            "ssh:// URL must have a path: {shown}"
        )));
    };
    let (host, port) = split_host_port(&after_user[..slash])?;
    let path_str = &after_user[slash + 1..];

    let segments: Vec<String> = path_str
        .trim_end_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();

    if segments.len() < 2 {
        return Err(WorkspaceError::InvalidUrl(format!(
            "ssh:// URL must have namespace/repo path: {shown}"
        )));
    }

    Ok(ParsedComponents {
        host,
        segments,
        org_only: false,
        transport: GitTransport::Ssh,
        port,
        user: user_opt,
    })
}

/// Parse a port suffix strictly.
fn parse_port(value: &str) -> Result<u16, WorkspaceError> {
    value.parse::<u16>().map_err(|_| {
        WorkspaceError::InvalidUrl(
            ValidationError::InvalidPort {
                value: value.to_string(),
            }
            .to_string(),
        )
    })
}

/// Split "host:port" or "host" into (host, Option<port>).
///
/// Bracketed IPv6 (`[::1]`, `[::1]:2222`) takes an optional `:port`
/// after the bracket; anything else after the bracket is an error. A
/// bare host with exactly one colon has a port suffix, which must parse.
/// A bare host with several colons is an unbracketed IPv6 address and is
/// returned whole for `GitHost` validation.
fn split_host_port(input: &str) -> Result<(String, Option<u16>), WorkspaceError> {
    if input.starts_with('[') {
        let Some(close) = input.find(']') else {
            return Ok((input.to_string(), None));
        };
        let host = input[..=close].to_string();
        let rest = &input[close + 1..];
        if rest.is_empty() {
            return Ok((host, None));
        }
        let Some(port) = rest.strip_prefix(':') else {
            return Err(WorkspaceError::InvalidUrl(format!(
                "unexpected characters after IPv6 address: {input}"
            )));
        };
        return Ok((host, Some(parse_port(port)?)));
    }

    // Exactly one colon: `host:port`. None, or several (unbracketed IPv6):
    // the whole input is the host.
    match input.split_once(':') {
        Some((host, port)) if !port.contains(':') => {
            Ok((host.to_string(), Some(parse_port(port)?)))
        }
        _ => Ok((input.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_workspace_types::{WorkspaceKind, WorkspaceUser};
    use std::path::PathBuf;

    fn repo_identity(url: &str) -> RemoteIdentity {
        match parse_url(url).unwrap() {
            RemoteRef::Repository(identity) => identity,
            RemoteRef::Organization { .. } => panic!("expected repository: {url}"),
        }
    }

    fn user() -> WorkspaceUser {
        WorkspaceUser::new("alice").unwrap()
    }

    fn ws_repo() -> RepositoryName {
        RepositoryName::new("workspace").unwrap()
    }

    fn endpoint(input: &CloneInput) -> &RemoteEndpoint {
        match &input.target {
            RemoteTarget::Repository(endpoint) => endpoint,
            RemoteTarget::Organization { .. } => panic!("expected repository target"),
        }
    }

    // parse_url

    #[test]
    fn parse_https_repo() {
        let id = repo_identity("https://github.com/scopecreep-zip/open-sesame");
        assert_eq!(id.host().to_string(), "github.com");
        assert_eq!(id.namespace().root_segment(), "scopecreep-zip");
        assert_eq!(id.repository().as_str(), "open-sesame");
    }

    #[test]
    fn parse_preserves_remote_spelling() {
        let id = repo_identity("https://github.com/NixOS/NixPkgs");
        assert_eq!(id.namespace().to_string(), "NixOS");
        assert_eq!(id.repository().as_str(), "NixPkgs");
    }

    #[test]
    fn parse_https_git_suffix_stripped() {
        assert_eq!(
            repo_identity("https://github.com/org/repo.git")
                .repository()
                .as_str(),
            "repo"
        );
    }

    #[test]
    fn parse_https_leading_dot_repo() {
        let id = repo_identity("https://github.com/sesameos/.github.git");
        assert_eq!(id.namespace().root_segment(), "sesameos");
        assert_eq!(id.repository().as_str(), ".github");
    }

    #[test]
    fn parse_https_rejects_git_dir_repo_name() {
        assert!(parse_url("https://github.com/sesameos/.git.git").is_err());
        assert!(parse_url("https://github.com/sesameos/.GIT").is_err());
    }

    #[test]
    fn parse_https_org_only() {
        let parsed = parse_url("https://github.com/ScopeCreep-zip").unwrap();
        assert!(matches!(&parsed, RemoteRef::Organization { namespace, .. }
            if namespace.to_string() == "ScopeCreep-zip"));
        assert!(!parsed.coordinate().kind().is_cloneable());
    }

    #[test]
    fn parse_https_org_trailing_slash() {
        assert!(matches!(
            parse_url("https://github.com/ScopeCreep-zip/").unwrap(),
            RemoteRef::Organization { .. }
        ));
    }

    #[test]
    fn parse_scp_url() {
        let id = repo_identity("git@github.com:braincraftio/k9.git");
        assert_eq!(id.host().to_string(), "github.com");
        assert_eq!(id.repository().as_str(), "k9");
    }

    #[test]
    fn parse_ssh_scheme_url() {
        let id = repo_identity("ssh://git@github.com/org/repo.git");
        assert_eq!(id.host().to_string(), "github.com");
        assert_eq!(id.repository().as_str(), "repo");
    }

    #[test]
    fn parse_ssh_scheme_with_port() {
        let id = repo_identity("ssh://git@git.example.com:2222/org/repo.git");
        assert_eq!(id.host().to_string(), "git.example.com");
    }

    #[test]
    fn parse_ssh_scheme_without_user() {
        let id = repo_identity("ssh://git.example.com/org/repo.git");
        assert_eq!(id.host().to_string(), "git.example.com");
    }

    #[test]
    fn rejects_invalid_port() {
        for url in [
            "ssh://git@git.example.com:99999/org/repo",
            "https://git.example.com:abc/org/repo",
            "ssh://git@[::1]:x/org/repo",
            "ssh://git@[::1]junk/org/repo",
        ] {
            assert!(
                matches!(parse_url(url), Err(WorkspaceError::InvalidUrl(_))),
                "{url}"
            );
        }
    }

    #[test]
    fn https_credentials_are_rejected_and_redacted() {
        let err = parse_url("https://alice:s3cret@github.com/org/repo").unwrap_err();
        assert!(matches!(err, WorkspaceError::InvalidUrl(_)));
        let message = err.to_string();
        assert!(!message.contains("s3cret"), "{message}");
        assert!(
            message.contains("https://***@github.com/org/repo"),
            "{message}"
        );
    }

    #[test]
    fn url_errors_never_print_userinfo() {
        for url in [
            "https://alice:s3cret@github.com/org/repo?x=1",
            "ssh://alice:s3cret@git.example.com/org/repo?x=1",
            "ssh://alice:s3cret@git.example.com",
            "alice:s3cret@github.com:repo",
        ] {
            let message = parse_url(url).unwrap_err().to_string();
            assert!(!message.contains("s3cret"), "{url}: {message}");
        }
    }

    #[test]
    fn parse_ipv6_with_port() {
        let id = repo_identity("ssh://git@[::1]:2222/org/repo");
        assert!(matches!(id.host(), GitHost::Ipv6(_)));
    }

    #[test]
    fn parse_nested_namespace() {
        let id = repo_identity("https://gitlab.com/group/subgroup/project");
        assert_eq!(id.namespace().to_string(), "group/subgroup");
        assert_eq!(id.repository().as_str(), "project");
    }

    #[test]
    fn parse_deeply_nested() {
        assert_eq!(
            repo_identity("https://gitlab.com/a/b/c/d/repo")
                .namespace()
                .to_string(),
            "a/b/c/d"
        );
    }

    #[test]
    fn parse_scp_nested() {
        assert_eq!(
            repo_identity("git@gitlab.com:group/subgroup/project.git")
                .namespace()
                .to_string(),
            "group/subgroup"
        );
    }

    #[test]
    fn parse_ssh_scheme_nested() {
        assert_eq!(
            repo_identity("ssh://git@gitlab.com/group/subgroup/project.git")
                .namespace()
                .to_string(),
            "group/subgroup"
        );
    }

    #[test]
    fn server_normalized_lowercase() {
        assert_eq!(
            repo_identity("https://GITHUB.COM/org/repo")
                .host()
                .to_string(),
            "github.com"
        );
    }

    #[test]
    fn rejects_query_string() {
        assert!(parse_url("https://github.com/org/repo?ref=main").is_err());
    }

    #[test]
    fn rejects_fragment() {
        assert!(parse_url("https://github.com/org/repo#readme").is_err());
    }

    #[test]
    fn rejects_null_bytes() {
        assert!(parse_url("https://github.com/org/repo\0evil").is_err());
    }

    #[test]
    fn rejects_unrecognized_scheme() {
        assert!(parse_url("ftp://github.com/org/repo").is_err());
    }

    #[test]
    fn rejects_server_only() {
        assert!(parse_url("https://github.com").is_err());
    }

    #[test]
    fn rejects_non_ascii_names() {
        assert!(parse_url("https://github.com/örg/repo").is_err());
        assert!(parse_url("https://github.com/org/rëpo").is_err());
    }

    // Placement derived from remote

    #[test]
    fn mixed_case_inputs_resolve_to_one_lowercase_path() {
        let expected = PathBuf::from("/workspace/alice/github.com/nixos/nixpkgs");
        for url in [
            "https://github.com/NixOS/nixpkgs",
            "https://github.com/nixos/nixpkgs",
            "https://GitHub.com/NIXOS/NixPkgs.git",
            "git@github.com:NixOS/NixPkgs.git",
            "ssh://git@github.com/NixOS/nixpkgs",
        ] {
            assert_eq!(
                parse_url(url)
                    .unwrap()
                    .coordinate()
                    .canonical_path(Path::new("/workspace"), &user()),
                expected,
                "{url}"
            );
        }
    }

    #[test]
    fn canonical_path_repository() {
        assert_eq!(
            parse_url("https://github.com/scopecreep-zip/open-sesame")
                .unwrap()
                .coordinate()
                .canonical_path(Path::new("/workspace"), &user()),
            PathBuf::from("/workspace/alice/github.com/scopecreep-zip/open-sesame")
        );
    }

    #[test]
    fn canonical_path_organization() {
        assert_eq!(
            parse_url("https://github.com/ScopeCreep-zip")
                .unwrap()
                .coordinate()
                .canonical_path(Path::new("/workspace"), &user()),
            PathBuf::from("/workspace/alice/github.com/scopecreep-zip")
        );
    }

    // parse_clone_input

    #[test]
    fn clone_input_https_shorthand() {
        let input = parse_clone_input(
            "braincraftio/konductor",
            "github.com",
            GitTransport::Https,
            &ws_repo(),
        )
        .unwrap();
        assert_eq!(endpoint(&input).transport(), GitTransport::Https);
        assert_eq!(input.coordinate.host().to_string(), "github.com");
        assert_eq!(
            input
                .coordinate
                .kind()
                .repository_dir()
                .map(RepoDir::as_str),
            Some("konductor")
        );
    }

    #[test]
    fn clone_input_ssh_shorthand() {
        let input = parse_clone_input(
            "braincraftio/konductor",
            "github.com",
            GitTransport::Ssh,
            &ws_repo(),
        )
        .unwrap();
        assert_eq!(endpoint(&input).transport(), GitTransport::Ssh);
        assert!(endpoint(&input).to_url().contains("git@"));
    }

    #[test]
    fn clone_input_endpoint_preserves_remote_spelling() {
        let input = parse_clone_input(
            "NixOS/NixPkgs",
            "github.com",
            GitTransport::Https,
            &ws_repo(),
        )
        .unwrap();
        assert_eq!(
            endpoint(&input).to_url(),
            "https://github.com/NixOS/NixPkgs"
        );
        assert_eq!(
            input
                .coordinate
                .canonical_path(Path::new("/workspace"), &user()),
            PathBuf::from("/workspace/alice/github.com/nixos/nixpkgs")
        );
    }

    #[test]
    fn clone_input_explicit_ssh_url_is_not_rewritten() {
        let input = parse_clone_input(
            "ssh://git@git.example.com:2222/Team/Repo.git",
            "github.com",
            GitTransport::Https,
            &ws_repo(),
        )
        .unwrap();
        let ep = endpoint(&input);
        assert_eq!(ep.transport(), GitTransport::Ssh);
        assert_eq!(ep.port(), Some(2222));
        assert_eq!(ep.to_url(), "ssh://git@git.example.com:2222/Team/Repo");
    }

    #[test]
    fn clone_input_leading_dot_shorthand() {
        let input = parse_clone_input(
            "sesameos/.github",
            "github.com",
            GitTransport::Https,
            &ws_repo(),
        )
        .unwrap();
        assert_eq!(
            endpoint(&input).to_url(),
            "https://github.com/sesameos/.github"
        );
        assert_eq!(
            input
                .coordinate
                .canonical_path(Path::new("/workspace"), &user()),
            PathBuf::from("/workspace/alice/github.com/sesameos/.github")
        );
    }

    #[test]
    fn clone_input_workspace_classification() {
        for url in [
            "https://github.com/braincraftio/workspace.git",
            "https://github.com/braincraftio/Workspace.git",
        ] {
            let input =
                parse_clone_input(url, "github.com", GitTransport::Https, &ws_repo()).unwrap();
            assert_eq!(
                input.coordinate.kind(),
                &WorkspaceKind::WorkspaceRepository,
                "{url}"
            );
            assert!(
                endpoint(&input).to_url().ends_with(
                    url.trim_start_matches("https://github.com/braincraftio/")
                        .trim_end_matches(".git")
                )
            );
        }
    }

    #[test]
    fn clone_input_regular_repo_not_reclassified() {
        let input = parse_clone_input(
            "https://github.com/braincraftio/konductor",
            "github.com",
            GitTransport::Https,
            &ws_repo(),
        )
        .unwrap();
        assert!(matches!(
            input.coordinate.kind(),
            WorkspaceKind::Repository(_)
        ));
    }

    #[test]
    fn clone_input_org_only() {
        let input = parse_clone_input(
            "https://github.com/ScopeCreep-zip",
            "github.com",
            GitTransport::Https,
            &ws_repo(),
        )
        .unwrap();
        assert!(
            matches!(&input.target, RemoteTarget::Organization { namespace, .. }
            if namespace.to_string() == "ScopeCreep-zip")
        );
        assert_eq!(input.coordinate.kind(), &WorkspaceKind::Organization);
        assert_eq!(input.coordinate.namespace().to_string(), "scopecreep-zip");
    }

    #[test]
    fn clone_input_display_url_matches_resolved() {
        let input = parse_clone_input(
            "braincraftio/konductor",
            "github.com",
            GitTransport::Https,
            &ws_repo(),
        )
        .unwrap();
        assert_eq!(
            input.display_url,
            "https://github.com/braincraftio/konductor"
        );
    }

    // parse_path

    fn layout_dir(root: &Path, parts: &[&str]) -> PathBuf {
        let mut path = root.to_path_buf();
        path.extend(parts);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn parse_path_leading_dot_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let repo = layout_dir(dir.path(), &["user", "github.com", "sesameos", ".github"]);
        let parsed = parse_path(dir.path(), &repo).unwrap();
        assert_eq!(parsed.namespace.to_string(), "sesameos");
        assert_eq!(
            parsed.terminal.as_ref().map(RepoDir::as_str),
            Some(".github")
        );
    }

    #[test]
    fn parse_path_namespace_level() {
        let dir = tempfile::tempdir().unwrap();
        let org = layout_dir(dir.path(), &["user", "github.com", "org"]);
        let parsed = parse_path(dir.path(), &org).unwrap();
        assert_eq!(parsed.namespace.to_string(), "org");
        assert!(parsed.terminal.is_none());
    }

    #[test]
    fn parse_path_rejects_non_canonical_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let repo = layout_dir(dir.path(), &["user", "github.com", "NixOS", "nixpkgs"]);
        assert!(matches!(
            parse_path(dir.path(), &repo),
            Err(WorkspaceError::NonCanonical { .. })
        ));
    }

    #[test]
    fn parse_path_rejects_non_canonical_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = layout_dir(dir.path(), &["user", "github.com", "nixos", "NixPkgs"]);
        assert!(matches!(
            parse_path(dir.path(), &repo),
            Err(WorkspaceError::NonCanonical { .. })
        ));
    }

    #[test]
    fn parse_path_rejects_non_canonical_server() {
        let dir = tempfile::tempdir().unwrap();
        let repo = layout_dir(dir.path(), &["user", "GitHub.com", "nixos", "nixpkgs"]);
        assert!(matches!(
            parse_path(dir.path(), &repo),
            Err(WorkspaceError::NonCanonical { .. })
        ));
    }

    #[test]
    fn parse_path_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        assert!(matches!(
            parse_path(root.path(), other.path()),
            Err(WorkspaceError::NotInWorkspace(_))
        ));
    }

    // is_inside_workspace_git

    #[test]
    fn inside_workspace_git_true() {
        let dir = tempfile::tempdir().unwrap();
        let org = dir.path().join("org");
        crate::git::marker::test_repos::init(&org);
        let repo = org.join("my-repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(is_inside_workspace_git(&repo).unwrap());
    }

    #[test]
    fn inside_workspace_git_false() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("standalone");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(!is_inside_workspace_git(&repo).unwrap());
    }
}
