//! GitHub forge implementation using ureq for REST API calls.

use super::{Forge, ListOptions, RepoInfo};
use crate::WorkspaceError;

/// GitHub REST API client.
pub struct GitHub {
    agent: ureq::Agent,
    token: Option<String>,
}

impl GitHub {
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        // Optional auth: GITHUB_TOKEN env var for higher rate limits (5000/hr
        // vs 60/hr unauthenticated) and access to private repos.
        let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
        Self { agent, token }
    }

    fn get(&self, url: &str) -> Result<ureq::http::Response<ureq::Body>, WorkspaceError> {
        let mut req = self
            .agent
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "open-sesame");

        if let Some(ref token) = self.token {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }

        req.call()
            .map_err(|e| WorkspaceError::GitError(format!("GitHub API request failed: {e}")))
    }

    /// Check rate limit headers and warn if running low.
    fn check_rate_limit(response: &ureq::http::Response<ureq::Body>) {
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
            if std::env::var("GITHUB_TOKEN")
                .ok()
                .filter(|t| !t.is_empty())
                .is_none()
            {
                eprintln!("  Set GITHUB_TOKEN for 5000 req/hr instead of 60 req/hr.");
            }
        }
    }
}

/// GitHub API endpoint type — org or user. Remembered after first successful
/// request so pagination uses the correct endpoint.
enum Endpoint {
    Org,
    User,
}

impl Forge for GitHub {
    fn list_org_repos(
        &self,
        org: &str,
        opts: &ListOptions,
    ) -> Result<Vec<RepoInfo>, WorkspaceError> {
        let mut all_repos = Vec::new();
        let mut page = 1u32;
        let mut endpoint: Option<Endpoint> = None;

        loop {
            let url = match endpoint {
                Some(Endpoint::User) => format!(
                    "https://api.github.com/users/{org}/repos?per_page=100&type=public&page={page}"
                ),
                _ => format!(
                    "https://api.github.com/orgs/{org}/repos?per_page=100&type=public&page={page}"
                ),
            };

            let mut response = match self.get(&url) {
                Ok(r) => {
                    if endpoint.is_none() {
                        endpoint = Some(Endpoint::Org);
                    }
                    r
                }
                Err(_) if endpoint.is_none() => {
                    // First request to /orgs/ failed — try /users/ endpoint.
                    let user_url = format!(
                        "https://api.github.com/users/{org}/repos?per_page=100&type=public&page={page}"
                    );
                    endpoint = Some(Endpoint::User);
                    self.get(&user_url)?
                }
                Err(e) => return Err(e),
            };

            Self::check_rate_limit(&response);

            // Check for Link header with rel="next" before consuming body.
            let has_next = response
                .headers()
                .get("link")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|link| link.contains("rel=\"next\""));

            let repos: Vec<RepoInfo> = response.body_mut().read_json().map_err(|e| {
                WorkspaceError::GitError(format!("failed to parse GitHub API response: {e}"))
            })?;

            if repos.is_empty() {
                break;
            }

            for repo in repos {
                if !opts.include_forks && repo.fork {
                    continue;
                }
                if !opts.include_archived && repo.archived {
                    continue;
                }
                all_repos.push(repo);
            }

            if !has_next {
                break;
            }
            page += 1;
        }

        Ok(all_repos)
    }
}
