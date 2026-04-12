//! Forge API abstraction for querying repository metadata from git hosting providers.
//!
//! Each provider (GitHub, GitLab, Forgejo) implements the [`Forge`] trait.
//! Provider detection is based on the server hostname.

mod github;

use crate::WorkspaceError;

/// Metadata for a single repository returned by a forge API.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RepoInfo {
    /// Repository name (e.g. "open-sesame").
    pub name: String,
    /// HTTPS clone URL.
    pub clone_url: String,
    /// Web URL for the repository.
    pub html_url: String,
    /// Default branch name (e.g. "main").
    pub default_branch: String,
    /// Whether this repository is a fork.
    #[serde(default)]
    pub fork: bool,
    /// Whether this repository is archived.
    #[serde(default)]
    pub archived: bool,
    /// Repository description, if any.
    pub description: Option<String>,
}

/// Options controlling which repos to list.
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    /// Include forked repositories.
    pub include_forks: bool,
    /// Include archived repositories.
    pub include_archived: bool,
}

/// A forge backend that can list repositories for an organization or user.
pub trait Forge {
    /// List repositories in the given organization/user namespace.
    ///
    /// # Errors
    ///
    /// Returns `WorkspaceError::GitError` if the API request fails.
    fn list_org_repos(
        &self,
        org: &str,
        opts: &ListOptions,
    ) -> Result<Vec<RepoInfo>, WorkspaceError>;
}

/// Detect the appropriate forge implementation from a server hostname.
///
/// Returns `None` for unsupported forges.
#[must_use]
pub fn forge_for_server(server: &str) -> Option<Box<dyn Forge>> {
    match server {
        "github.com" => Some(Box::new(github::GitHub::new())),
        // Future: "gitlab.com" => Some(Box::new(gitlab::GitLab::new())),
        // Future: detect Forgejo/Gitea via API probe
        _ => None,
    }
}
