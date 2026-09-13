//! Centralized proxy policy resolution.
//!
//! Reads proxy and NO_PROXY environment variables once, then provides
//! target-aware proxy decisions for different transport adapters.
//! Proxy credentials are redacted in Display and Debug output.

use std::fmt;

/// A resolved proxy policy from environment variables.
///
/// Constructed once from environment state, then queried per target
/// URL to determine the appropriate proxy behavior.
#[derive(Clone)]
pub struct ProxyPolicy {
    /// Proxy for HTTPS targets (from HTTPS_PROXY or https_proxy).
    https: Option<ProxyEndpoint>,
    /// Proxy for HTTP targets (from HTTP_PROXY or http_proxy).
    http: Option<ProxyEndpoint>,
    /// Fallback proxy for any scheme (from ALL_PROXY or all_proxy).
    all: Option<ProxyEndpoint>,
    /// NO_PROXY rules parsed from environment.
    no_proxy: NoProxyRules,
}

/// A proxy endpoint with credentials redacted from Display/Debug.
#[derive(Clone)]
pub struct ProxyEndpoint {
    url: String,
}

impl ProxyEndpoint {
    /// The raw URL for transport configuration.
    /// Callers that pass this to a transport must handle credential
    /// security at the transport level.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl fmt::Display for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", redact_credentials(&self.url))
    }
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyEndpoint")
            .field("url", &redact_credentials(&self.url))
            .finish()
    }
}

/// The decision for a specific target URL.
///
/// The Proxy variant contains a ProxyEndpoint whose Display/Debug
/// implementations redact credentials. Raw URL access is through
/// ProxyEndpoint::url() for adapter configuration only.
#[derive(Debug, Clone)]
pub enum ProxyDecision {
    /// Connect directly without a proxy.
    Direct,
    /// Use this proxy endpoint.
    Proxy(ProxyEndpoint),
    /// No environment proxy found. Transport should fall back to
    /// its own configuration (e.g. git config http.proxy).
    NoEnvironmentProxy,
}

/// Parsed NO_PROXY rules.
#[derive(Clone, Default)]
struct NoProxyRules {
    entries: Vec<NoProxyEntry>,
}

#[derive(Clone)]
enum NoProxyEntry {
    MatchAll,
    ExactHost(String),
    DomainSuffix(String),
}

impl ProxyPolicy {
    /// Read proxy policy from the current environment.
    ///
    /// Reads HTTPS_PROXY, https_proxy, HTTP_PROXY, http_proxy,
    /// ALL_PROXY, all_proxy, NO_PROXY, and no_proxy.
    #[must_use]
    pub fn from_env() -> Self {
        let https = read_env_pair("HTTPS_PROXY", "https_proxy").map(|url| ProxyEndpoint { url });
        let http = read_env_pair("HTTP_PROXY", "http_proxy").map(|url| ProxyEndpoint { url });
        let all = read_env_pair("ALL_PROXY", "all_proxy").map(|url| ProxyEndpoint { url });
        let no_proxy = read_env_pair("NO_PROXY", "no_proxy")
            .map(|val| NoProxyRules::parse(&val))
            .unwrap_or_default();

        Self {
            https,
            http,
            all,
            no_proxy,
        }
    }

    /// Determine the proxy decision for a target URL.
    ///
    /// Selects the proxy based on the target scheme:
    ///   HTTPS targets check HTTPS_PROXY, then ALL_PROXY.
    ///   HTTP targets check HTTP_PROXY, then ALL_PROXY.
    ///   Other schemes (SSH, file) return NoEnvironmentProxy.
    ///
    /// If a proxy is found but the target host matches NO_PROXY,
    /// returns Direct.
    #[must_use]
    pub fn for_target(&self, target_url: &str) -> ProxyDecision {
        let scheme = if target_url.starts_with("https://") {
            Scheme::Https
        } else if target_url.starts_with("http://") {
            Scheme::Http
        } else {
            return ProxyDecision::NoEnvironmentProxy;
        };

        let proxy = match scheme {
            Scheme::Https => self.https.as_ref().or(self.all.as_ref()),
            Scheme::Http => self.http.as_ref().or(self.all.as_ref()),
        };

        let Some(endpoint) = proxy else {
            return ProxyDecision::NoEnvironmentProxy;
        };

        if let Some(host) = extract_host(target_url) {
            if self.no_proxy.matches(host) {
                return ProxyDecision::Direct;
            }
        }

        ProxyDecision::Proxy(endpoint.clone())
    }

    /// The HTTPS proxy endpoint, if configured.
    #[must_use]
    pub fn https_proxy(&self) -> Option<&ProxyEndpoint> {
        self.https.as_ref()
    }

    /// The HTTP proxy endpoint, if configured.
    #[must_use]
    pub fn http_proxy(&self) -> Option<&ProxyEndpoint> {
        self.http.as_ref()
    }

    /// The ALL_PROXY fallback endpoint, if configured.
    #[must_use]
    pub fn all_proxy(&self) -> Option<&ProxyEndpoint> {
        self.all.as_ref()
    }

    /// Whether any proxy is configured from environment.
    #[must_use]
    pub fn has_proxy(&self) -> bool {
        self.https.is_some() || self.http.is_some() || self.all.is_some()
    }

    /// The first active proxy endpoint for diagnostic display.
    #[must_use]
    pub fn active_proxy(&self) -> Option<&ProxyEndpoint> {
        self.https.as_ref().or(self.http.as_ref()).or(self.all.as_ref())
    }

    /// The raw NO_PROXY value, if set.
    #[must_use]
    pub fn no_proxy_entry_count(&self) -> usize {
        self.no_proxy.entries.len()
    }

    /// Whether different proxy variables are set to different values.
    #[must_use]
    pub fn has_conflicting_values(&self) -> bool {
        let mut seen: Vec<&str> = Vec::new();
        if let Some(ref p) = self.https {
            seen.push(&p.url);
        }
        if let Some(ref p) = self.http {
            seen.push(&p.url);
        }
        if let Some(ref p) = self.all {
            seen.push(&p.url);
        }
        if seen.len() <= 1 {
            return false;
        }
        seen.windows(2).any(|w| w[0] != w[1])
    }
}

enum Scheme {
    Https,
    Http,
}

impl NoProxyRules {
    fn parse(input: &str) -> Self {
        let entries = input
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|entry| match entry {
                "*" => NoProxyEntry::MatchAll,
                e if e.starts_with("*.") => {
                    NoProxyEntry::DomainSuffix(e[1..].to_ascii_lowercase())
                }
                e if e.starts_with('.') => {
                    NoProxyEntry::DomainSuffix(e.to_ascii_lowercase())
                }
                e => NoProxyEntry::ExactHost(e.to_ascii_lowercase()),
            })
            .collect();
        Self { entries }
    }

    fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_ascii_lowercase();
        self.entries.iter().any(|entry| match entry {
            NoProxyEntry::MatchAll => true,
            NoProxyEntry::ExactHost(h) => *h == host_lower,
            NoProxyEntry::DomainSuffix(suffix) => host_lower.ends_with(suffix.as_str()),
        })
    }
}

/// Read from an uppercase/lowercase env var pair. Uppercase takes
/// precedence.
fn read_env_pair(upper: &str, lower: &str) -> Option<String> {
    std::env::var(upper)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var(lower).ok().filter(|v| !v.is_empty()))
}

/// Redact credentials from a proxy URL for safe display.
///
/// Replaces the user:password portion between scheme:// and @host
/// with ***. Handles schemeless URLs by checking for @ presence.
fn redact_credentials(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            let prefix = &url[..scheme_end + 3];
            let suffix = &url[at_pos..];
            return format!("{prefix}***{suffix}");
        }
        // Schemeless URL with credentials: user:pass@host
        let suffix = &url[at_pos..];
        return format!("***{suffix}");
    }
    url.to_string()
}

/// Extract the host portion from a URL for NO_PROXY matching.
fn extract_host(url: &str) -> Option<&str> {
    if let Some(rest) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) {
        let host_part = rest.split('/').next()?;
        // Strip user@ prefix if present.
        let host = host_part.rsplit('@').next().unwrap_or(host_part);
        // Strip :port suffix.
        if host.starts_with('[') {
            // IPv6 bracketed: [::1]:port
            host.find(']').map(|end| &host[..end + 1])
        } else {
            Some(host.split(':').next().unwrap_or(host))
        }
    } else if let Some(at_pos) = url.find('@') {
        // SCP-style SSH: git@host:path
        let after_at = &url[at_pos + 1..];
        Some(after_at.split(':').next().unwrap_or(after_at))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_https_credentials() {
        assert_eq!(
            redact_credentials("http://user:pass@proxy:8080"),
            "http://***@proxy:8080"
        );
    }

    #[test]
    fn redact_schemeless_credentials() {
        assert_eq!(redact_credentials("user:pass@proxy:8080"), "***@proxy:8080");
    }

    #[test]
    fn redact_no_credentials() {
        assert_eq!(redact_credentials("http://proxy:8080"), "http://proxy:8080");
    }

    #[test]
    fn extract_host_https() {
        assert_eq!(extract_host("https://github.com/org/repo"), Some("github.com"));
    }

    #[test]
    fn extract_host_https_with_port() {
        assert_eq!(extract_host("https://git.example.com:8443/org"), Some("git.example.com"));
    }

    #[test]
    fn extract_host_https_with_user() {
        assert_eq!(extract_host("https://user@github.com/org"), Some("github.com"));
    }

    #[test]
    fn extract_host_ssh() {
        assert_eq!(extract_host("git@github.com:org/repo"), Some("github.com"));
    }

    #[test]
    fn extract_host_ipv6() {
        assert_eq!(extract_host("https://[::1]:8080/path"), Some("[::1]"));
    }

    #[test]
    fn no_proxy_exact() {
        let rules = NoProxyRules::parse("github.com");
        assert!(rules.matches("github.com"));
        assert!(!rules.matches("gitlab.com"));
    }

    #[test]
    fn no_proxy_domain_suffix() {
        let rules = NoProxyRules::parse(".example.com");
        assert!(rules.matches("api.example.com"));
        assert!(!rules.matches("example.com"));
    }

    #[test]
    fn no_proxy_wildcard_suffix() {
        let rules = NoProxyRules::parse("*.internal.corp");
        assert!(rules.matches("git.internal.corp"));
        assert!(!rules.matches("internal.corp"));
    }

    #[test]
    fn no_proxy_match_all() {
        let rules = NoProxyRules::parse("*");
        assert!(rules.matches("anything.example.com"));
    }

    #[test]
    fn no_proxy_multiple() {
        let rules = NoProxyRules::parse("localhost,127.0.0.1,*.internal.com");
        assert!(rules.matches("localhost"));
        assert!(rules.matches("127.0.0.1"));
        assert!(rules.matches("git.internal.com"));
        assert!(!rules.matches("github.com"));
    }

    #[test]
    fn no_proxy_case_insensitive() {
        let rules = NoProxyRules::parse("GITHUB.COM");
        assert!(rules.matches("github.com"));
        assert!(rules.matches("GitHub.COM"));
    }

    #[test]
    fn policy_https_target_uses_https_proxy() {
        let policy = ProxyPolicy {
            https: Some(ProxyEndpoint { url: "http://https-proxy:8080".into() }),
            http: Some(ProxyEndpoint { url: "http://http-proxy:8080".into() }),
            all: None,
            no_proxy: NoProxyRules::default(),
        };
        match policy.for_target("https://github.com/org/repo") {
            ProxyDecision::Proxy(ep) => assert_eq!(ep.url(), "http://https-proxy:8080"),
            other => panic!("expected Proxy, got {other:?}"),
        }
    }

    #[test]
    fn policy_http_target_uses_http_proxy() {
        let policy = ProxyPolicy {
            https: Some(ProxyEndpoint { url: "http://https-proxy:8080".into() }),
            http: Some(ProxyEndpoint { url: "http://http-proxy:8080".into() }),
            all: None,
            no_proxy: NoProxyRules::default(),
        };
        match policy.for_target("http://example.com/org/repo") {
            ProxyDecision::Proxy(ep) => assert_eq!(ep.url(), "http://http-proxy:8080"),
            other => panic!("expected Proxy, got {other:?}"),
        }
    }

    #[test]
    fn policy_falls_back_to_all() {
        let policy = ProxyPolicy {
            https: None,
            http: None,
            all: Some(ProxyEndpoint { url: "http://all-proxy:8080".into() }),
            no_proxy: NoProxyRules::default(),
        };
        match policy.for_target("https://github.com/org") {
            ProxyDecision::Proxy(ep) => assert_eq!(ep.url(), "http://all-proxy:8080"),
            other => panic!("expected Proxy, got {other:?}"),
        }
    }

    #[test]
    fn policy_no_proxy_bypasses() {
        let policy = ProxyPolicy {
            https: Some(ProxyEndpoint { url: "http://proxy:8080".into() }),
            http: None,
            all: None,
            no_proxy: NoProxyRules::parse("github.com"),
        };
        assert!(matches!(
            policy.for_target("https://github.com/org/repo"),
            ProxyDecision::Direct
        ));
    }

    #[test]
    fn policy_ssh_returns_no_env_proxy() {
        let policy = ProxyPolicy {
            https: Some(ProxyEndpoint { url: "http://proxy:8080".into() }),
            http: None,
            all: None,
            no_proxy: NoProxyRules::default(),
        };
        assert!(matches!(
            policy.for_target("git@github.com:org/repo.git"),
            ProxyDecision::NoEnvironmentProxy
        ));
    }

    #[test]
    fn policy_no_proxy_configured() {
        let policy = ProxyPolicy {
            https: None,
            http: None,
            all: None,
            no_proxy: NoProxyRules::default(),
        };
        assert!(matches!(
            policy.for_target("https://github.com/org"),
            ProxyDecision::NoEnvironmentProxy
        ));
    }

    #[test]
    fn proxy_endpoint_display_redacts() {
        let ep = ProxyEndpoint {
            url: "http://user:secret@proxy:8080".into(),
        };
        assert_eq!(ep.to_string(), "http://***@proxy:8080");
        assert!(!format!("{ep:?}").contains("secret"));
    }

    #[test]
    fn conflicting_values_detected() {
        let policy = ProxyPolicy {
            https: Some(ProxyEndpoint { url: "http://a:8080".into() }),
            http: Some(ProxyEndpoint { url: "http://b:8080".into() }),
            all: None,
            no_proxy: NoProxyRules::default(),
        };
        assert!(policy.has_conflicting_values());
    }

    #[test]
    fn same_values_not_conflicting() {
        let policy = ProxyPolicy {
            https: Some(ProxyEndpoint { url: "http://proxy:8080".into() }),
            http: Some(ProxyEndpoint { url: "http://proxy:8080".into() }),
            all: None,
            no_proxy: NoProxyRules::default(),
        };
        assert!(!policy.has_conflicting_values());
    }
}
