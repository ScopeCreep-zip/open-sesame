//! Network checks: proxy configuration and git transport readiness.

use super::{Check, Status};

pub fn checks() -> Vec<Check> {
    let mut results = Vec::new();
    let policy = sesame_workspace::net::ProxyPolicy::from_env();

    // Active proxy endpoint.
    results.push(if let Some(endpoint) = policy.active_proxy() {
        Check {
            id: "network.proxy".into(),
            category: "network",
            status: Status::Pass,
            value: endpoint.to_string(),
            description: "HTTP proxy detected from environment".into(),
        }
    } else {
        Check {
            id: "network.proxy".into(),
            category: "network",
            status: Status::Pass,
            value: "direct (no environment proxy)".into(),
            description: "Git config http.proxy may still supply a proxy".into(),
        }
    });

    // NO_PROXY check.
    let np_count = policy.no_proxy_entry_count();
    if policy.has_proxy() && np_count == 0 {
        results.push(Check {
            id: "network.no_proxy".into(),
            category: "network",
            status: Status::Warn,
            value: "not set".into(),
            description: "NO_PROXY not set while proxy is active".into(),
        });
    } else if np_count > 0 {
        results.push(Check {
            id: "network.no_proxy".into(),
            category: "network",
            status: Status::Pass,
            value: format!("{np_count} entries"),
            description: String::new(),
        });
    }

    // Conflicting proxy values across scheme-specific variables.
    if policy.has_conflicting_values() {
        results.push(Check {
            id: "network.proxy_conflict".into(),
            category: "network",
            status: Status::Pass,
            value: "scheme-specific proxies configured".into(),
            description: "HTTP and HTTPS use different proxy endpoints".into(),
        });
    }

    // Transport summary.
    results.push(Check {
        id: "network.git_transport".into(),
        category: "network",
        status: Status::Pass,
        value: "curl-sys (gix), libgit2 (git2), ureq/rustls (forge API)".into(),
        description: "Proxy env vars resolved by shared policy".into(),
    });

    results
}
