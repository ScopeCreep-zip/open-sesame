//! Forge API abstraction for querying repository metadata from git hosting providers.
//!
//! Each provider (GitHub, GitLab, Forgejo) implements the [`Forge`] trait.
//! Provider detection is based on the server hostname.

mod github;

use core_workspace_types::RemoteIdentity;

use crate::WorkspaceError;
use crate::convention::{RemoteRef, parse_url};

/// Metadata for a single repository returned by a forge API.
///
/// Built from the provider's response once, when the listing is
/// mapped; the clone URL is parsed into its identity there.
#[derive(Debug, Clone)]
pub struct RepoInfo {
    /// The repository's remote identity, in the forge's spelling,
    /// parsed from the forge's HTTPS clone URL.
    pub identity: RemoteIdentity,
    /// Web URL for the repository.
    pub html_url: String,
    /// Default branch name (e.g. "main").
    pub default_branch: String,
    /// Whether this repository is a fork.
    pub fork: bool,
    /// Whether this repository is archived.
    pub archived: bool,
    /// Repository description, if any.
    pub description: Option<String>,
}

impl RepoInfo {
    /// Parse a forge clone URL that must name a repository.
    ///
    /// # Errors
    ///
    /// The `parse_url` errors, and `WorkspaceError::InvalidUrl` when the
    /// URL names an organization rather than a repository.
    pub fn identity_from_clone_url(clone_url: &str) -> Result<RemoteIdentity, WorkspaceError> {
        match parse_url(clone_url)? {
            RemoteRef::Repository(identity) => Ok(identity),
            RemoteRef::Organization { .. } => Err(WorkspaceError::InvalidUrl(format!(
                "forge clone URL names no repository: {}",
                crate::net::redact_credentials(clone_url)
            ))),
        }
    }
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
    /// Returns `WorkspaceError::GitError` if the API request fails, and
    /// `WorkspaceError::InvalidUrl` or `WorkspaceError::PathValidation`
    /// if a listed clone URL cannot be parsed into a repository identity.
    fn list_org_repos(
        &self,
        org: &str,
        opts: &ListOptions,
    ) -> Result<Vec<RepoInfo>, WorkspaceError>;
}

/// Detect the appropriate forge implementation from a server hostname.
///
/// Returns `Ok(None)` for unsupported forges.
///
/// # Errors
///
/// The forge client construction errors (`github::GitHub::new`).
pub fn forge_for_server(server: &str) -> Result<Option<Box<dyn Forge>>, WorkspaceError> {
    Ok(match server {
        "github.com" => Some(Box::new(github::GitHub::new()?)),
        _ => None,
    })
}
