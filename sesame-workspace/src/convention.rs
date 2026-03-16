//! URL parsing, path computation, and workspace.git detection.
//!
//! Converts git remote URLs into deterministic local paths following the
//! workspace convention: `{ROOT}/{USER}/{SERVER}/{ORG}/{REPO}`.

use std::path::{Path, PathBuf};

use crate::WorkspaceError;

/// Parsed components of a git remote URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConvention {
    /// Git server hostname (e.g., "github.com").
    pub server: String,
    /// Organization or user on the server (e.g., "scopecreep-zip").
    pub org: String,
    /// Repository name, or `None` for workspace.git (org-level clone).
    pub repo: Option<String>,
    /// True if the original URL pointed to a `workspace.git` repository.
    pub is_workspace_git: bool,
}

/// Where to clone a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloneTarget {
    /// Normal repo: `{root}/{user}/{server}/{org}/{repo}`
    Regular(PathBuf),
    /// workspace.git: `{root}/{user}/{server}/{org}/`
    WorkspaceGit(PathBuf),
}

impl CloneTarget {
    /// The filesystem path this target refers to.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Regular(p) | Self::WorkspaceGit(p) => p,
        }
    }
}

/// Parse a git remote URL into workspace convention components.
///
/// Accepts HTTPS (`https://github.com/org/repo`) and SSH (`git@github.com:org/repo.git`).
///
/// # Errors
///
/// Returns `WorkspaceError::InvalidUrl` if the URL cannot be parsed or contains
/// path traversal sequences, null bytes, or empty components.
pub fn parse_url(url: &str) -> Result<WorkspaceConvention, WorkspaceError> {
    let url = url.trim();

    // Reject null bytes anywhere in the input.
    if url.contains('\0') {
        return Err(WorkspaceError::InvalidUrl("URL contains null bytes".into()));
    }

    // Warn on insecure HTTP URLs — credentials transmitted in cleartext.
    if url.starts_with("http://") {
        tracing::warn!(
            url = url,
            "HTTP git URL detected -- credentials will be transmitted in cleartext. Use HTTPS or SSH."
        );
    }

    let (server, org, raw_repo) = if url.starts_with("https://") || url.starts_with("http://") {
        parse_https(url)?
    } else if url.contains('@') && url.contains(':') {
        parse_ssh(url)?
    } else {
        return Err(WorkspaceError::InvalidUrl(format!(
            "unrecognized URL format: {url} (expected https:// or git@host:org/repo)"
        )));
    };

    // Normalize server to lowercase.
    let server = server.to_lowercase();

    // Strip .git suffix from repo name.
    let repo = raw_repo
        .strip_suffix(".git")
        .unwrap_or(&raw_repo)
        .to_string();

    // Validate components: no empty, no traversal, no slashes, no null bytes.
    for (label, val) in [("server", &server), ("org", &org), ("repo", &repo)] {
        validate_component(label, val)?;
    }

    let is_workspace_git = repo == "workspace";

    Ok(WorkspaceConvention {
        server,
        org,
        repo: if is_workspace_git { None } else { Some(repo) },
        is_workspace_git,
    })
}

/// Compute the canonical local path for a parsed URL.
///
/// For workspace.git repos, returns [`CloneTarget::WorkspaceGit`] pointing at the
/// org-level directory. For regular repos, returns [`CloneTarget::Regular`].
#[must_use]
pub fn canonical_path(root: &Path, user: &str, conv: &WorkspaceConvention) -> CloneTarget {
    let base = root.join(user).join(&conv.server).join(&conv.org);
    if conv.is_workspace_git {
        CloneTarget::WorkspaceGit(base)
    } else {
        CloneTarget::Regular(base.join(conv.repo.as_deref().unwrap_or("repo")))
    }
}

/// Convenience: parse a URL and compute the canonical path in one step.
///
/// # Errors
///
/// Returns `WorkspaceError::InvalidUrl` if URL parsing fails.
pub fn canonical_path_from_url(
    root: &Path,
    user: &str,
    url: &str,
) -> Result<CloneTarget, WorkspaceError> {
    let conv = parse_url(url)?;
    Ok(canonical_path(root, user, &conv))
}

/// Parse a filesystem path back into convention components.
///
/// The path must be of the form `{root}/{user}/{server}/{org}[/{repo}]`.
///
/// # Errors
///
/// Returns an error if the path is not inside the workspace root or does not
/// match the expected depth.
pub fn parse_path(root: &Path, path: &Path) -> Result<WorkspaceConvention, WorkspaceError> {
    // Canonicalize to resolve symlinks before checking containment.
    // Prevents symlink escape attacks where a path inside the workspace
    // root is a symlink pointing outside it.
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());

    let rel = canonical
        .strip_prefix(&canonical_root)
        .map_err(|_| WorkspaceError::NotInWorkspace(path.to_path_buf()))?;

    let components: Vec<&str> = rel
        .components()
        .filter_map(|c| {
            if let std::path::Component::Normal(s) = c {
                s.to_str()
            } else {
                None
            }
        })
        .collect();

    // Expected: [user, server, org] or [user, server, org, repo]
    if components.len() < 3 {
        return Err(WorkspaceError::NotInWorkspace(path.to_path_buf()));
    }

    let server = components[1].to_string();
    let org = components[2].to_string();

    // Determine if this is a workspace.git or a regular repo.
    let is_workspace_git = path.join(".git").is_dir() && components.len() == 3;

    let repo = if components.len() >= 4 {
        Some(components[3].to_string())
    } else {
        None
    };

    Ok(WorkspaceConvention {
        server,
        org,
        repo,
        is_workspace_git,
    })
}

/// Check if a path is inside a workspace.git working tree.
///
/// Walks up from `path` looking for a `.git` directory at the parent (org) level,
/// where the parent is not `path` itself (i.e., `path` is a sibling repo inside
/// a workspace.git).
#[must_use]
pub fn is_inside_workspace_git(path: &Path) -> bool {
    if let Some(parent) = path.parent() {
        // The parent has a .git dir and is not the same as path.
        parent.join(".git").is_dir() && parent != path
    } else {
        false
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

fn parse_https(url: &str) -> Result<(String, String, String), WorkspaceError> {
    // https://github.com/org/repo[.git]
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    let parts: Vec<&str> = without_scheme.splitn(4, '/').collect();
    if parts.len() < 3 {
        return Err(WorkspaceError::InvalidUrl(format!(
            "HTTPS URL must have at least server/org/repo: {url}"
        )));
    }

    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

fn parse_ssh(url: &str) -> Result<(String, String, String), WorkspaceError> {
    // git@github.com:org/repo.git
    let at_pos = url
        .find('@')
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("SSH URL missing '@': {url}")))?;
    let after_at = &url[at_pos + 1..];

    let colon_pos = after_at
        .find(':')
        .ok_or_else(|| WorkspaceError::InvalidUrl(format!("SSH URL missing ':': {url}")))?;

    let server = &after_at[..colon_pos];
    let path = &after_at[colon_pos + 1..];

    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() < 2 {
        return Err(WorkspaceError::InvalidUrl(format!(
            "SSH URL must have org/repo after ':': {url}"
        )));
    }

    Ok((
        server.to_string(),
        parts[0].to_string(),
        parts[1].to_string(),
    ))
}

fn validate_component(label: &str, value: &str) -> Result<(), WorkspaceError> {
    if value.is_empty() {
        return Err(WorkspaceError::InvalidUrl(format!(
            "{label} component is empty"
        )));
    }
    // Reject leading dots to prevent collisions with .git, .ssh, .config etc.
    if value.starts_with('.') {
        return Err(WorkspaceError::PathValidation(format!(
            "{label} starts with '.': {value}"
        )));
    }
    if value.contains("..") {
        return Err(WorkspaceError::PathValidation(format!(
            "{label} contains path traversal '..': {value}"
        )));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(WorkspaceError::PathValidation(format!(
            "{label} contains path separator: {value}"
        )));
    }
    if value.contains('\0') {
        return Err(WorkspaceError::PathValidation(format!(
            "{label} contains null byte"
        )));
    }
    // Filesystem component length limit (ext4, btrfs, etc.)
    if value.len() > 255 {
        return Err(WorkspaceError::PathValidation(format!(
            "{label} exceeds 255 bytes: {}",
            value.len()
        )));
    }
    // Reject leading/trailing whitespace — creates filesystem ambiguity.
    if value != value.trim() {
        return Err(WorkspaceError::PathValidation(format!(
            "{label} has leading/trailing whitespace: '{value}'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_url() {
        let conv = parse_url("https://github.com/scopecreep-zip/open-sesame").unwrap();
        assert_eq!(conv.server, "github.com");
        assert_eq!(conv.org, "scopecreep-zip");
        assert_eq!(conv.repo.as_deref(), Some("open-sesame"));
        assert!(!conv.is_workspace_git);
    }

    #[test]
    fn parse_https_url_with_git_suffix() {
        let conv = parse_url("https://github.com/scopecreep-zip/open-sesame.git").unwrap();
        assert_eq!(conv.repo.as_deref(), Some("open-sesame"));
    }

    #[test]
    fn parse_ssh_url() {
        let conv = parse_url("git@github.com:braincraftio/k9.git").unwrap();
        assert_eq!(conv.server, "github.com");
        assert_eq!(conv.org, "braincraftio");
        assert_eq!(conv.repo.as_deref(), Some("k9"));
        assert!(!conv.is_workspace_git);
    }

    #[test]
    fn parse_ssh_self_hosted() {
        let conv = parse_url("git@git.braincraft.io:braincraft/k9.git").unwrap();
        assert_eq!(conv.server, "git.braincraft.io");
        assert_eq!(conv.org, "braincraft");
        assert_eq!(conv.repo.as_deref(), Some("k9"));
    }

    #[test]
    fn parse_workspace_git_url() {
        let conv = parse_url("https://github.com/braincraftio/workspace.git").unwrap();
        assert_eq!(conv.server, "github.com");
        assert_eq!(conv.org, "braincraftio");
        assert!(conv.repo.is_none());
        assert!(conv.is_workspace_git);
    }

    #[test]
    fn parse_workspace_git_no_suffix() {
        let conv = parse_url("https://github.com/braincraftio/workspace").unwrap();
        assert!(conv.is_workspace_git);
        assert!(conv.repo.is_none());
    }

    #[test]
    fn parse_url_normalizes_server() {
        let conv = parse_url("https://GITHUB.COM/org/repo").unwrap();
        assert_eq!(conv.server, "github.com");
    }

    #[test]
    fn parse_url_rejects_path_traversal() {
        assert!(parse_url("https://github.com/../etc/passwd").is_err());
    }

    #[test]
    fn parse_url_rejects_null_bytes() {
        assert!(parse_url("https://github.com/org/repo\0evil").is_err());
    }

    #[test]
    fn parse_url_rejects_empty_org() {
        assert!(parse_url("https://github.com//repo").is_err());
    }

    #[test]
    fn parse_url_rejects_unrecognized_format() {
        assert!(parse_url("ftp://github.com/org/repo").is_err());
    }

    #[test]
    fn canonical_path_regular() {
        let conv = parse_url("https://github.com/scopecreep-zip/open-sesame").unwrap();
        let target = canonical_path(Path::new("/workspace"), "usrbinkat", &conv);
        assert_eq!(
            target,
            CloneTarget::Regular(PathBuf::from(
                "/workspace/usrbinkat/github.com/scopecreep-zip/open-sesame"
            ))
        );
    }

    #[test]
    fn canonical_path_workspace_git() {
        let conv = parse_url("https://github.com/braincraftio/workspace.git").unwrap();
        let target = canonical_path(Path::new("/workspace"), "usrbinkat", &conv);
        assert_eq!(
            target,
            CloneTarget::WorkspaceGit(PathBuf::from(
                "/workspace/usrbinkat/github.com/braincraftio"
            ))
        );
    }

    #[test]
    fn parse_path_roundtrip() {
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/usrbinkat/github.com/scopecreep-zip/open-sesame");
        let conv = parse_path(root, path).unwrap();
        assert_eq!(conv.server, "github.com");
        assert_eq!(conv.org, "scopecreep-zip");
        assert_eq!(conv.repo.as_deref(), Some("open-sesame"));
    }

    #[test]
    fn parse_path_rejects_outside_root() {
        let root = Path::new("/workspace");
        let path = Path::new("/home/user/project");
        assert!(parse_path(root, path).is_err());
    }

    #[test]
    fn parse_path_rejects_too_shallow() {
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/usrbinkat");
        assert!(parse_path(root, path).is_err());
    }

    #[test]
    fn is_inside_workspace_git_true() {
        let dir = tempfile::tempdir().unwrap();
        let org = dir.path().join("org");
        std::fs::create_dir_all(org.join(".git")).unwrap();
        let repo = org.join("my-repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(is_inside_workspace_git(&repo));
    }

    #[test]
    fn is_inside_workspace_git_false() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("standalone");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(!is_inside_workspace_git(&repo));
    }

    #[test]
    fn validate_component_rejects_leading_dot() {
        assert!(parse_url("https://github.com/.hidden/repo").is_err());
    }

    #[test]
    fn validate_component_rejects_long_name() {
        let long = "a".repeat(256);
        let url = format!("https://github.com/org/{long}");
        assert!(parse_url(&url).is_err());
    }

    #[test]
    fn validate_component_rejects_whitespace() {
        assert!(parse_url("https://github.com/org/ repo").is_err());
    }

    #[test]
    fn parse_url_accepts_valid_255_byte_name() {
        let name = "a".repeat(255);
        let url = format!("https://github.com/org/{name}");
        assert!(parse_url(&url).is_ok());
    }
}
