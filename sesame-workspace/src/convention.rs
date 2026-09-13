//! URL parsing, shorthand resolution, and clone input construction.
//!
//! The primary entry point is `parse_clone_input` which accepts raw
//! user input and configuration, and produces a `CloneInput` containing
//! both a `RemoteEndpoint` (for network operations) and a
//! `WorkspaceCoordinate` (for filesystem placement). No intermediate
//! URL string passes through the orchestration layer.
//!
//! `parse_url` remains available for parsing existing remote URLs
//! (adoption comparison, forge API results) where transport and
//! workspace reclassification are not needed.

use std::path::Path;

use core_workspace_types::{
    GitHost, GitTransport, NamespacePath, RemoteEndpoint, RemoteIdentity, RepositoryName,
    WorkspaceCoordinate, WorkspaceKind,
};

use crate::WorkspaceError;

/// The result of parsing a clone input from raw user input.
///
/// Contains everything needed for clone operations: the endpoint
/// for network access, the coordinate for filesystem placement,
/// and the original resolved URL for display.
#[derive(Debug, Clone)]
pub struct CloneInput {
    /// The remote endpoint for clone/fetch operations.
    pub endpoint: RemoteEndpoint,
    /// The workspace coordinate for filesystem placement.
    pub coordinate: WorkspaceCoordinate,
    /// The resolved URL string for user-facing display.
    pub display_url: String,
}

/// Parse raw user input into a fully typed clone input.
///
/// Performs shorthand resolution, URL parsing, transport selection,
/// and workspace repository reclassification in one step.
///
/// When the parsed repository name matches `workspace_repo`, the
/// coordinate's kind is set to `WorkspaceRepository` so clone
/// operations use workspace.git lifecycle handling.
///
/// # Errors
///
/// Returns `WorkspaceError::InvalidUrl` for unparseable input.
///
/// # Panics
///
/// Panics if the hardcoded placeholder repository name `"_placeholder"`
/// fails validation, which cannot occur with the current value.
pub fn parse_clone_input(
    input: &str,
    default_server: &str,
    transport: GitTransport,
    workspace_repo: &RepositoryName,
) -> Result<CloneInput, WorkspaceError> {
    let resolved = resolve_url(input, default_server, transport == GitTransport::Ssh)?;
    let components = parse_components(&resolved)?;

    let host = GitHost::new(&components.host)
        .map_err(|e| WorkspaceError::PathValidation(format!("server: {e}")))?;

    if components.org_only {
        let ns_path = components.segments.join("/");
        let namespace = NamespacePath::new(&ns_path)
            .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;
        let coord =
            WorkspaceCoordinate::new(host.clone(), namespace.clone(), WorkspaceKind::Organization);
        // Org-only endpoints always use HTTPS for forge API access.
        let identity = RemoteIdentity::new(
            host,
            namespace,
            RepositoryName::new("_placeholder").expect("valid"),
        );
        let endpoint = RemoteEndpoint::https(identity);
        return Ok(CloneInput {
            endpoint,
            coordinate: coord,
            display_url: resolved,
        });
    }

    if components.segments.len() < 2 {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL must have at least namespace/repo: {resolved}"
        )));
    }

    let ns_segments = &components.segments[..components.segments.len() - 1];
    let repo_str = &components.segments[components.segments.len() - 1];

    let ns_path = ns_segments.join("/");
    let namespace = NamespacePath::new(&ns_path)
        .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;
    let repo = RepositoryName::new(repo_str)
        .map_err(|e| WorkspaceError::PathValidation(format!("repository: {e}")))?;

    // Reclassify as workspace repository when the name matches config.
    let kind = if repo.as_str() == workspace_repo.as_str() {
        WorkspaceKind::WorkspaceRepository(repo.clone())
    } else {
        WorkspaceKind::Repository(repo.clone())
    };

    let coord = WorkspaceCoordinate::new(host.clone(), namespace.clone(), kind);

    let identity = RemoteIdentity::new(host, namespace, repo);
    let endpoint = match components.transport {
        GitTransport::Https => {
            RemoteEndpoint::new(identity, GitTransport::Https, components.port, None)
        }
        GitTransport::Ssh => RemoteEndpoint::new(
            identity,
            GitTransport::Ssh,
            components.port,
            components.user,
        ),
    };

    Ok(CloneInput {
        endpoint,
        coordinate: coord,
        display_url: resolved,
    })
}

/// Parse a git remote URL into a `WorkspaceCoordinate`.
///
/// Lower-level function for parsing URLs from existing remotes
/// (adoption comparison) and forge API responses. Does not perform
/// shorthand resolution or workspace reclassification.
///
/// # Errors
///
/// Returns `WorkspaceError::InvalidUrl` for unparseable URLs.
pub fn parse_url(url: &str) -> Result<WorkspaceCoordinate, WorkspaceError> {
    let components = parse_components(url)?;

    let host = GitHost::new(&components.host)
        .map_err(|e| WorkspaceError::PathValidation(format!("server: {e}")))?;

    if components.org_only {
        let ns_path = components.segments.join("/");
        let namespace = NamespacePath::new(&ns_path)
            .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;
        return Ok(WorkspaceCoordinate::new(
            host,
            namespace,
            WorkspaceKind::Organization,
        ));
    }

    if components.segments.len() < 2 {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL must have at least namespace/repo: {url}"
        )));
    }

    let ns_segments = &components.segments[..components.segments.len() - 1];
    let repo_str = &components.segments[components.segments.len() - 1];

    let ns_path = ns_segments.join("/");
    let namespace = NamespacePath::new(&ns_path)
        .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;
    let repo = RepositoryName::new(repo_str)
        .map_err(|e| WorkspaceError::PathValidation(format!("repository: {e}")))?;

    Ok(WorkspaceCoordinate::new(
        host,
        namespace,
        WorkspaceKind::Repository(repo),
    ))
}

/// Structural components extracted from a workspace filesystem path.
///
/// Does not determine `WorkspaceKind`. The caller assigns kind from
/// command context, configuration, and filesystem inspection.
#[derive(Debug, Clone)]
pub struct ParsedPath {
    pub host: GitHost,
    pub namespace: NamespacePath,
    /// The terminal path component, if the path extends beyond the
    /// namespace level. This is the repository directory name for
    /// repository paths, or None for namespace-level paths.
    pub terminal: Option<RepositoryName>,
}

/// Parse a filesystem path into structural components.
///
/// The path must follow the layout `{root}/{user}/{server}/{ns...}[/{repo}]`.
/// Symlinks are canonicalized to prevent escape from the workspace root.
/// Non-UTF-8 path components produce an explicit error.
///
/// Does not classify the path as a repository, workspace root, or
/// organization. The caller determines kind from context.
///
/// # Errors
///
/// Returns an error if the path is outside the workspace root, too
/// shallow, contains non-UTF-8 components, or fails canonicalization.
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

    let host = GitHost::from_dir_name(components[1]).ok_or_else(|| {
        WorkspaceError::PathValidation(format!("cannot decode server directory: {}", components[1]))
    })?;

    // Exactly [user, server, ns]: namespace-level path, no terminal.
    if components.len() == 3 {
        let namespace = NamespacePath::new(components[2])
            .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;
        return Ok(ParsedPath {
            host,
            namespace,
            terminal: None,
        });
    }

    // [user, server, ns..., terminal]: last component is terminal,
    // everything between server and terminal is namespace.
    let ns_end = components.len() - 1;
    let ns_segments: Vec<String> = components[2..ns_end]
        .iter()
        .map(ToString::to_string)
        .collect();

    let namespace = NamespacePath::from_segments(ns_segments)
        .map_err(|e| WorkspaceError::PathValidation(format!("namespace: {e}")))?;

    let terminal = RepositoryName::new(components[ns_end])
        .map_err(|e| WorkspaceError::PathValidation(format!("terminal component: {e}")))?;

    Ok(ParsedPath {
        host,
        namespace,
        terminal: Some(terminal),
    })
}

/// Check if a path is inside a workspace.git working tree.
#[must_use]
pub fn is_inside_workspace_git(path: &Path) -> bool {
    if let Some(parent) = path.parent() {
        crate::has_git_dir(parent) && parent != path
    } else {
        false
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

    match segments.len() {
        3 => {
            if segments[0].contains('.') {
                if use_ssh {
                    Ok(format!(
                        "git@{}:{}/{}.git",
                        segments[0], segments[1], segments[2]
                    ))
                } else {
                    Ok(format!("https://{input}"))
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
            if segments[0].contains('.') {
                Ok(format!("https://{input}"))
            } else if use_ssh {
                Ok(format!("git@{default_server}:{input}.git"))
            } else {
                Ok(format!("https://{default_server}/{input}"))
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
            url = url,
            "HTTP URL detected. Credentials will be transmitted in cleartext."
        );
    }

    if url.starts_with("https://") || url.starts_with("http://") {
        parse_https(url)
    } else if url.starts_with("ssh://") {
        parse_ssh_scheme(url)
    } else if url.contains('@') && url.contains(':') {
        parse_scp(url)
    } else {
        Err(WorkspaceError::InvalidUrl(format!(
            "unrecognized URL format: {url}\n\
             expected https://, http://, ssh://, or git@host:ns/repo"
        )))
    }
}

/// Parse HTTP(S) URL.
fn parse_https(url: &str) -> Result<ParsedComponents, WorkspaceError> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    if without_scheme.contains('?') || without_scheme.contains('#') {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL contains query string or fragment: {url}"
        )));
    }

    let clean = without_scheme.trim_end_matches('/');
    let parts: Vec<&str> = clean.split('/').collect();

    // Extract port from host:port if present.
    let (host, port) = split_host_port(parts.first().copied().unwrap_or(""));

    match parts.len() {
        0 | 1 => Err(WorkspaceError::InvalidUrl(format!(
            "URL must have at least server/namespace: {url}"
        ))),
        2 => Ok(ParsedComponents {
            host,
            segments: vec![parts[1].to_string()],
            org_only: true,
            transport: GitTransport::Https,
            port,
            user: None,
        }),
        _ => Ok(ParsedComponents {
            host,
            segments: parts[1..].iter().map(ToString::to_string).collect(),
            org_only: false,
            transport: GitTransport::Https,
            port,
            user: None,
        }),
    }
}

/// Parse SCP-style SSH URL: [user@]host:path
fn parse_scp(url: &str) -> Result<ParsedComponents, WorkspaceError> {
    if url.contains('?') || url.contains('#') {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL contains query string or fragment: {url}"
        )));
    }

    let at_pos = url
        .find('@')
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("SSH URL missing '@': {url}")))?;

    let user = url[..at_pos].to_string();
    let after_at = &url[at_pos + 1..];

    let colon_pos = after_at
        .find(':')
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("SSH URL missing ':': {url}")))?;

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
            "SSH URL must have namespace/repo after ':': {url}"
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
    if url.contains('?') || url.contains('#') {
        return Err(WorkspaceError::InvalidUrl(format!(
            "URL contains query string or fragment: {url}"
        )));
    }

    let without_scheme = url
        .strip_prefix("ssh://")
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("not ssh://: {url}")))?;

    let (user_opt, hostport, path_str) = if let Some(at_pos) = without_scheme.find('@') {
        let user = without_scheme[..at_pos].to_string();
        let after_at = &without_scheme[at_pos + 1..];
        match after_at.find('/') {
            Some(slash) => (Some(user), &after_at[..slash], &after_at[slash + 1..]),
            None => {
                return Err(WorkspaceError::InvalidUrl(format!(
                    "ssh:// URL must have a path: {url}"
                )));
            }
        }
    } else {
        match without_scheme.find('/') {
            Some(slash) => (
                None::<String>,
                &without_scheme[..slash],
                &without_scheme[slash + 1..],
            ),
            None => {
                return Err(WorkspaceError::InvalidUrl(format!(
                    "ssh:// URL must have a path: {url}"
                )));
            }
        }
    };
    let (host, port) = split_host_port(hostport);

    let segments: Vec<String> = path_str
        .trim_end_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();

    if segments.len() < 2 {
        return Err(WorkspaceError::InvalidUrl(format!(
            "ssh:// URL must have namespace/repo path: {url}"
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

/// Split "host:port" or "host" into (host, Option<port>).
/// Handles bracketed IPv6 addresses.
fn split_host_port(input: &str) -> (String, Option<u16>) {
    if input.starts_with('[') {
        // Bracketed IPv6: [::1]:port or [::1]
        if let Some(close) = input.find(']') {
            let host = input[..=close].to_string();
            let rest = &input[close + 1..];
            let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
        return (input.to_string(), None);
    }

    // For non-bracketed: if there is exactly one colon and the part
    // after it parses as a port number, split. Otherwise treat the
    // whole string as hostname (bare IPv6 without brackets has
    // multiple colons and will not have a parseable port suffix).
    if let Some(colon) = input.rfind(':') {
        let maybe_port = &input[colon + 1..];
        if let Ok(port) = maybe_port.parse::<u16>() {
            let host = input[..colon].to_string();
            return (host, Some(port));
        }
    }

    (input.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // parse_url tests

    #[test]
    fn parse_https_repo() {
        let coord = parse_url("https://github.com/scopecreep-zip/open-sesame").unwrap();
        assert_eq!(coord.host().to_string(), "github.com");
        assert_eq!(coord.namespace().root_segment(), "scopecreep-zip");
        assert_eq!(
            coord.kind().repository_name().map(|r| r.as_str()),
            Some("open-sesame")
        );
    }

    #[test]
    fn parse_https_git_suffix_stripped() {
        let coord = parse_url("https://github.com/org/repo.git").unwrap();
        assert_eq!(
            coord.kind().repository_name().map(|r| r.as_str()),
            Some("repo")
        );
    }

    #[test]
    fn parse_https_org_only() {
        let coord = parse_url("https://github.com/ScopeCreep-zip").unwrap();
        assert!(!coord.kind().is_cloneable());
    }

    #[test]
    fn parse_https_org_trailing_slash() {
        let coord = parse_url("https://github.com/ScopeCreep-zip/").unwrap();
        assert!(!coord.kind().is_cloneable());
    }

    #[test]
    fn parse_scp_url() {
        let coord = parse_url("git@github.com:braincraftio/k9.git").unwrap();
        assert_eq!(coord.host().to_string(), "github.com");
        assert_eq!(
            coord.kind().repository_name().map(|r| r.as_str()),
            Some("k9")
        );
    }

    #[test]
    fn parse_ssh_scheme_url() {
        let coord = parse_url("ssh://git@github.com/org/repo.git").unwrap();
        assert_eq!(coord.host().to_string(), "github.com");
        assert_eq!(
            coord.kind().repository_name().map(|r| r.as_str()),
            Some("repo")
        );
    }

    #[test]
    fn parse_ssh_scheme_with_port() {
        let coord = parse_url("ssh://git@git.example.com:2222/org/repo.git").unwrap();
        assert_eq!(coord.host().to_string(), "git.example.com");
    }

    #[test]
    fn parse_nested_namespace() {
        let coord = parse_url("https://gitlab.com/group/subgroup/project").unwrap();
        assert_eq!(coord.namespace().to_string(), "group/subgroup");
        assert_eq!(
            coord.kind().repository_name().map(|r| r.as_str()),
            Some("project")
        );
    }

    #[test]
    fn parse_deeply_nested() {
        let coord = parse_url("https://gitlab.com/a/b/c/d/repo").unwrap();
        assert_eq!(coord.namespace().to_string(), "a/b/c/d");
    }

    #[test]
    fn parse_scp_nested() {
        let coord = parse_url("git@gitlab.com:group/subgroup/project.git").unwrap();
        assert_eq!(coord.namespace().to_string(), "group/subgroup");
    }

    #[test]
    fn parse_ssh_scheme_nested() {
        let coord = parse_url("ssh://git@gitlab.com/group/subgroup/project.git").unwrap();
        assert_eq!(coord.namespace().to_string(), "group/subgroup");
    }

    #[test]
    fn server_normalized_lowercase() {
        let coord = parse_url("https://GITHUB.COM/org/repo").unwrap();
        assert_eq!(coord.host().to_string(), "github.com");
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

    // parse_clone_input tests

    #[test]
    fn clone_input_https_shorthand() {
        let ws_repo = RepositoryName::new("workspace").unwrap();
        let input = parse_clone_input(
            "braincraftio/konductor",
            "github.com",
            GitTransport::Https,
            &ws_repo,
        )
        .unwrap();
        assert_eq!(input.endpoint.transport(), GitTransport::Https);
        assert_eq!(input.coordinate.host().to_string(), "github.com");
        assert_eq!(
            input
                .coordinate
                .kind()
                .repository_name()
                .map(|r| r.as_str()),
            Some("konductor")
        );
        assert!(input.coordinate.kind().is_cloneable());
    }

    #[test]
    fn clone_input_ssh_shorthand() {
        let ws_repo = RepositoryName::new("workspace").unwrap();
        let input = parse_clone_input(
            "braincraftio/konductor",
            "github.com",
            GitTransport::Ssh,
            &ws_repo,
        )
        .unwrap();
        assert_eq!(input.endpoint.transport(), GitTransport::Ssh);
        assert!(input.endpoint.to_url().contains("git@"));
    }

    #[test]
    fn clone_input_workspace_reclassification() {
        let ws_repo = RepositoryName::new("workspace").unwrap();
        let input = parse_clone_input(
            "https://github.com/braincraftio/workspace.git",
            "github.com",
            GitTransport::Https,
            &ws_repo,
        )
        .unwrap();
        assert!(matches!(
            input.coordinate.kind(),
            WorkspaceKind::WorkspaceRepository(_)
        ));
    }

    #[test]
    fn clone_input_regular_repo_not_reclassified() {
        let ws_repo = RepositoryName::new("workspace").unwrap();
        let input = parse_clone_input(
            "https://github.com/braincraftio/konductor",
            "github.com",
            GitTransport::Https,
            &ws_repo,
        )
        .unwrap();
        assert!(matches!(
            input.coordinate.kind(),
            WorkspaceKind::Repository(_)
        ));
    }

    #[test]
    fn clone_input_org_only() {
        let ws_repo = RepositoryName::new("workspace").unwrap();
        let input = parse_clone_input(
            "https://github.com/ScopeCreep-zip",
            "github.com",
            GitTransport::Https,
            &ws_repo,
        )
        .unwrap();
        assert!(!input.coordinate.kind().is_cloneable());
    }

    #[test]
    fn clone_input_explicit_ssh_url() {
        let ws_repo = RepositoryName::new("workspace").unwrap();
        let input = parse_clone_input(
            "ssh://git@git.example.com:2222/org/repo.git",
            "github.com",
            GitTransport::Https,
            &ws_repo,
        )
        .unwrap();
        assert_eq!(input.endpoint.transport(), GitTransport::Ssh);
        assert_eq!(input.endpoint.port(), Some(2222));
    }

    #[test]
    fn clone_input_display_url_matches_resolved() {
        let ws_repo = RepositoryName::new("workspace").unwrap();
        let input = parse_clone_input(
            "braincraftio/konductor",
            "github.com",
            GitTransport::Https,
            &ws_repo,
        )
        .unwrap();
        assert_eq!(
            input.display_url,
            "https://github.com/braincraftio/konductor"
        );
    }

    // parse_path tests

    #[test]
    fn canonical_path_repository() {
        let coord = parse_url("https://github.com/scopecreep-zip/open-sesame").unwrap();
        let user = core_workspace_types::WorkspaceUser::new("usrbinkat").unwrap();
        assert_eq!(
            coord.canonical_path(Path::new("/workspace"), &user),
            PathBuf::from("/workspace/usrbinkat/github.com/scopecreep-zip/open-sesame")
        );
    }

    #[test]
    fn canonical_path_organization() {
        let coord = parse_url("https://github.com/ScopeCreep-zip").unwrap();
        let user = core_workspace_types::WorkspaceUser::new("usrbinkat").unwrap();
        assert_eq!(
            coord.canonical_path(Path::new("/workspace"), &user),
            PathBuf::from("/workspace/usrbinkat/github.com/ScopeCreep-zip")
        );
    }

    // is_inside_workspace_git

    #[test]
    fn inside_workspace_git_true() {
        let dir = tempfile::tempdir().unwrap();
        let org = dir.path().join("org");
        std::fs::create_dir_all(org.join(".git")).unwrap();
        let repo = org.join("my-repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(is_inside_workspace_git(&repo));
    }

    #[test]
    fn inside_workspace_git_false() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("standalone");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(!is_inside_workspace_git(&repo));
    }
}
