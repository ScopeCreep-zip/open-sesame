//! Network checks: the environment proxy policy every git and forge
//! transport resolves through.

use sesame_workspace::net::ProxyPolicy;

use super::{Check, Status};

const CATEGORY: &str = "network";

pub fn checks() -> Vec<Check> {
    match ProxyPolicy::from_env() {
        Ok(policy) => policy_checks(&policy),
        Err(e) => vec![Check::new(
            "network.proxy",
            CATEGORY,
            Status::Fail,
            e.to_string(),
            "the proxy environment cannot be read",
        )],
    }
}

fn policy_checks(policy: &ProxyPolicy) -> Vec<Check> {
    let mut results = vec![match policy.active_proxy() {
        Some(endpoint) => Check::new(
            "network.proxy",
            CATEGORY,
            Status::Pass,
            endpoint.to_string(),
            "HTTP proxy from the environment",
        ),
        None => Check::new(
            "network.proxy",
            CATEGORY,
            Status::Pass,
            "direct (no environment proxy)",
            "git configuration http.proxy may still supply a proxy",
        ),
    }];

    let no_proxy = policy.no_proxy_entry_count();
    if policy.has_proxy() && no_proxy == 0 {
        results.push(Check::new(
            "network.no_proxy",
            CATEGORY,
            Status::Warn,
            "not set",
            "NO_PROXY is not set while a proxy is active; local hosts go through the proxy",
        ));
    } else if no_proxy > 0 {
        results.push(Check::new(
            "network.no_proxy",
            CATEGORY,
            Status::Pass,
            format!("{no_proxy} entries"),
            "",
        ));
    }

    if policy.has_conflicting_values() {
        results.push(Check::new(
            "network.proxy_schemes",
            CATEGORY,
            Status::Pass,
            "scheme-specific proxies configured",
            "HTTP and HTTPS targets use different proxy endpoints",
        ));
    }
    results
}
