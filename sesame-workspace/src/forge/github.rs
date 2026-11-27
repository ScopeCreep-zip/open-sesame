//! GitHub forge implementation using ureq for REST API calls.

use super::{Forge, ListOptions, RepoInfo};
use crate::WorkspaceError;

/// GitHub REST API client.
pub struct GitHub {
    agent: ureq::Agent,
    token: Option<String>,
}

impl GitHub {
    /// A client honoring the shared proxy policy and `GITHUB_TOKEN`.
    ///
    /// # Errors
    ///
    /// The `ProxyPolicy::from_env` errors; `WorkspaceError::ConfigError`
    /// when the selected proxy URL is invalid (connecting directly instead
    /// would bypass it); the `env::first_set` errors for `GITHUB_TOKEN`.
    pub fn new() -> Result<Self, WorkspaceError> {
        let policy = crate::net::ProxyPolicy::from_env()?;
        let decision = policy.for_target("https://api.github.com");

        let mut builder =
            ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30)));

        // The agent's proxy is always set explicitly: ureq's default
        // (`Config::default()`) re-reads the proxy variables with its own
        // precedence, a second resolution beside `ProxyPolicy`.
        let proxy = match &decision {
            crate::net::ProxyDecision::Proxy(endpoint) => {
                tracing::debug!(proxy = %endpoint, "forge API using proxy");
                Some(ureq::Proxy::new(endpoint.url()).map_err(|e| {
                    WorkspaceError::ConfigError(format!("invalid proxy {endpoint}: {e}"))
                })?)
            }
            crate::net::ProxyDecision::Direct => {
                tracing::debug!("forge API direct (host in NO_PROXY)");
                None
            }
            crate::net::ProxyDecision::NoEnvironmentProxy => {
                tracing::debug!("forge API direct (no proxy configured)");
                None
            }
        };
        builder = builder.proxy(proxy);

        let agent = builder.build().into();
        // Optional auth: higher rate limits (5000/hr vs 60/hr
        // unauthenticated) and access to private repositories.
        let token = crate::env::first_set(&["GITHUB_TOKEN"])?;
        Ok(Self { agent, token })
    }

    /// Fetch one page of a repository listing.
    ///
    /// Non-success statuses are `ureq::Error::StatusCode` (ureq's default
    /// `http_status_as_error`), so the caller can tell 404 apart.
    fn fetch_page(&self, url: &str) -> Result<Page, FetchError> {
        let mut req = self
            .agent
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "open-sesame");

        if let Some(ref token) = self.token {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }

        let mut response = req.call().map_err(FetchError::Http)?;
        self.check_rate_limit(&response);

        // Check for Link header with rel="next" before consuming body.
        let has_next = response
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|link| link.contains("rel=\"next\""));

        let repos: Vec<ApiRepo> = response
            .body_mut()
            .read_json()
            .map_err(|e| FetchError::Decode(e.to_string()))?;
        Ok(Page { repos, has_next })
    }

    /// Check rate limit headers and warn if running low; without a token,
    /// name the variable that raises the limit.
    fn check_rate_limit(&self, response: &ureq::http::Response<ureq::Body>) {
        let remaining = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        if let Some(remaining) = remaining
            && remaining <= 5
        {
            eprintln!(
                "  Warning: GitHub API rate limit nearly exhausted ({remaining} requests remaining)."
            );
            if self.token.is_none() {
                eprintln!("  Set GITHUB_TOKEN for 5000 req/hr instead of 60 req/hr.");
            }
        }
    }
}

/// A repository as the GitHub REST API returns it.
#[derive(Debug, serde::Deserialize)]
struct ApiRepo {
    clone_url: String,
    html_url: String,
    default_branch: String,
    #[serde(default)]
    fork: bool,
    #[serde(default)]
    archived: bool,
    description: Option<String>,
}

impl TryFrom<ApiRepo> for RepoInfo {
    type Error = WorkspaceError;

    fn try_from(repo: ApiRepo) -> Result<Self, Self::Error> {
        Ok(Self {
            identity: RepoInfo::identity_from_clone_url(&repo.clone_url)?,
            html_url: repo.html_url,
            default_branch: repo.default_branch,
            fork: repo.fork,
            archived: repo.archived,
            description: repo.description,
        })
    }
}

/// One page of a listing.
struct Page {
    repos: Vec<ApiRepo>,
    has_next: bool,
}

/// Why a page could not be fetched.
#[derive(Debug)]
enum FetchError {
    /// The request failed or returned a non-success status.
    Http(ureq::Error),
    /// The response body was not a repository list.
    Decode(String),
}

impl FetchError {
    fn into_workspace_error(self, url: &str) -> WorkspaceError {
        match self {
            Self::Http(e) => {
                WorkspaceError::GitError(format!("GitHub API request failed: {url}: {e}"))
            }
            Self::Decode(e) => {
                WorkspaceError::GitError(format!("failed to parse GitHub API response: {url}: {e}"))
            }
        }
    }
}

/// GitHub listing endpoint: organizations and users list repositories
/// under different paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Org,
    User,
}

impl Endpoint {
    fn url(self, owner: &str, page: u32) -> String {
        let kind = match self {
            Self::Org => "orgs",
            Self::User => "users",
        };
        format!("https://api.github.com/{kind}/{owner}/repos?per_page=100&type=public&page={page}")
    }
}

/// List every repository of `owner`, following pagination.
///
/// `owner` is tried as an organization first. Only a 404 on the first
/// organization page means "not an organization" and switches to the
/// user endpoint; every other failure (rate limit, authentication,
/// server error, transport) is returned.
fn list_all(
    owner: &str,
    opts: &ListOptions,
    mut fetch: impl FnMut(&str) -> Result<Page, FetchError>,
) -> Result<Vec<RepoInfo>, WorkspaceError> {
    let mut endpoint = Endpoint::Org;
    let mut page = 1u32;
    let mut all = Vec::new();
    loop {
        let url = endpoint.url(owner, page);
        let result = match fetch(&url) {
            Err(FetchError::Http(ureq::Error::StatusCode(404)))
                if endpoint == Endpoint::Org && page == 1 =>
            {
                endpoint = Endpoint::User;
                let user_url = endpoint.url(owner, page);
                fetch(&user_url).map_err(|e| e.into_workspace_error(&user_url))
            }
            other => other.map_err(|e| e.into_workspace_error(&url)),
        };
        let listing = result?;
        if listing.repos.is_empty() {
            break;
        }
        for repo in listing.repos {
            if (!opts.include_forks && repo.fork) || (!opts.include_archived && repo.archived) {
                continue;
            }
            all.push(RepoInfo::try_from(repo)?);
        }
        if !listing.has_next {
            break;
        }
        page += 1;
    }
    Ok(all)
}

impl Forge for GitHub {
    fn list_org_repos(
        &self,
        org: &str,
        opts: &ListOptions,
    ) -> Result<Vec<RepoInfo>, WorkspaceError> {
        list_all(org, opts, |url| self.fetch_page(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_repo(url: &str) -> ApiRepo {
        ApiRepo {
            clone_url: url.into(),
            html_url: url.into(),
            default_branch: "main".into(),
            fork: false,
            archived: false,
            description: None,
        }
    }

    /// A final page holding `repos`.
    fn page(repos: Vec<ApiRepo>) -> Page {
        Page {
            repos,
            has_next: false,
        }
    }

    #[test]
    fn org_404_falls_back_to_user_endpoint() {
        let mut requested = Vec::new();
        let repos = list_all("alice", &ListOptions::default(), |url| {
            requested.push(url.to_string());
            if url.contains("/orgs/") {
                Err(FetchError::Http(ureq::Error::StatusCode(404)))
            } else {
                Ok(page(vec![api_repo(
                    "https://github.com/alice/dotfiles.git",
                )]))
            }
        })
        .unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(requested.len(), 2);
        assert!(requested[1].contains("/users/alice/"));
    }

    #[test]
    fn rate_limit_on_org_is_not_retried_as_user() {
        for status in [403, 429, 500] {
            let mut requested = Vec::new();
            let result = list_all("org", &ListOptions::default(), |url| {
                requested.push(url.to_string());
                Err(FetchError::Http(ureq::Error::StatusCode(status)))
            });
            assert!(result.is_err(), "{status}");
            assert_eq!(requested.len(), 1, "{status}: {requested:?}");
        }
    }

    #[test]
    fn listing_maps_typed_identity_in_forge_spelling() {
        let repos = list_all("SesameOS", &ListOptions::default(), |_| {
            Ok(page(vec![api_repo(
                "https://github.com/SesameOS/.github.git",
            )]))
        })
        .unwrap();
        assert_eq!(repos[0].identity.namespace().to_string(), "SesameOS");
        assert_eq!(repos[0].identity.repository().as_str(), ".github");
    }

    #[test]
    fn listing_rejects_clone_url_without_repository() {
        let result = list_all("org", &ListOptions::default(), |_| {
            Ok(page(vec![api_repo("https://github.com/SesameOS")]))
        });
        assert!(matches!(result, Err(WorkspaceError::InvalidUrl(_))));
    }

    #[test]
    fn filters_forks_and_archived() {
        let mut fork = api_repo("https://github.com/org/fork.git");
        fork.fork = true;
        let mut archived = api_repo("https://github.com/org/old.git");
        archived.archived = true;
        let mut pages = vec![vec![
            api_repo("https://github.com/org/keep.git"),
            fork,
            archived,
        ]];
        let repos = list_all("org", &ListOptions::default(), |_| {
            Ok(page(pages.remove(0)))
        })
        .unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].identity.repository().as_str(), "keep");
    }
}
