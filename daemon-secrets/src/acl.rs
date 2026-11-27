//! Per-secret access control.
//!
//! Pure functions over `core_config::Config` — no I/O, no state.

use core_types::{Daemon, DaemonId, TrustProfileName};

/// What a secret request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Request<'a> {
    /// One secret by key (get, set, delete).
    Key(&'a str),
    /// The profile's key names.
    List,
}

/// Whether the daemon `daemon_name` may make `request` within `profile`.
///
/// Policy from config `[profiles.<name>.secrets.access]`:
/// - Profile not in config AND any profile has ACL policy: DENIED (fail-closed).
/// - Profile not in config AND no profile has ACL policy: ALLOWED (no policy anywhere).
/// - Profile in config, empty access map: ALLOWED (no policy for this profile).
/// - Unregistered client (no `verified_sender_name`) when policy exists: DENIED.
/// - Daemon name absent from the map: ALLOWED (explicit opt-in).
/// - Daemon name present: a key is ALLOWED when it is listed; the list is
///   ALLOWED when the daemon may read at least one key. An empty list is
///   no access at all.
pub(crate) fn check_access(
    config: &core_config::Config,
    profile: &TrustProfileName,
    daemon_name: Option<&str>,
    request: Request<'_>,
) -> bool {
    let Some(profile_config) = config.profiles.get(profile.as_ref()) else {
        let any_acl_active = config
            .profiles
            .values()
            .any(|p| !p.secrets.access.is_empty());
        if any_acl_active {
            tracing::warn!(
                audit = "access-denied",
                ?request,
                profile = %profile,
                "profile not found in config — denied because ACL policy is active on other profiles"
            );
        }
        return !any_acl_active;
    };

    if profile_config.secrets.access.is_empty() {
        return true;
    }

    let Some(daemon_name) = daemon_name else {
        tracing::warn!(
            audit = "access-denied",
            ?request,
            profile = %profile,
            "unregistered client (no verified_sender_name) denied by ACL policy"
        );
        return false;
    };

    let Some(allowed_keys) = profile_config.secrets.access.get(daemon_name) else {
        return true;
    };

    match request {
        Request::Key(key) => allowed_keys.iter().any(|k| k == key),
        Request::List => !allowed_keys.is_empty(),
    }
}

/// Check if a requester is expected to issue secret operations.
///
/// Uses `verified_sender_name` stamped by the bus server from the Noise IK
/// registry — NOT self-declared capabilities. Expected requesters:
/// daemon-secrets (self), daemon-launcher (env injection), or `None`
/// (CLI relay via daemon-profile with Open clearance).
pub(crate) fn check_secret_requester(requester: DaemonId, verified_name: Option<&str>) {
    if let Some(name) = verified_name
        && !matches!(
            Daemon::from_name(name),
            Some(Daemon::Secrets | Daemon::Launcher)
        )
    {
        tracing::warn!(
            audit = "anomaly",
            anomaly_type = "unexpected-secret-requester",
            requester = %requester,
            verified_name = name,
            "daemon not expected to request secrets (verified identity)"
        );
    }
}

/// Emit a structured audit log entry for every secret operation.
pub(crate) fn audit_secret_access(
    event_type: &str,
    requester: DaemonId,
    profile: &str,
    key: Option<&str>,
    outcome: &str,
) {
    tracing::info!(
        audit = "secret-access",
        event_type,
        requester = %requester,
        profile,
        key = key.unwrap_or("-"),
        outcome,
        "secret access audit"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::profile as profile_name;
    use core_config::{Config, ProfileConfig, SecretsConfig};
    use std::collections::BTreeMap;

    /// A Config whose profile `work` has the access map `access`, each
    /// entry a daemon and its allowed keys.
    fn work_with_acl(access: &[(&str, &[&str])]) -> Config {
        let access: BTreeMap<String, Vec<String>> = access
            .iter()
            .map(|(daemon, keys)| {
                (
                    (*daemon).to_owned(),
                    keys.iter().map(|k| (*k).to_owned()).collect(),
                )
            })
            .collect();
        let profile = ProfileConfig {
            name: profile_name("work"),
            secrets: SecretsConfig {
                access,
                ..Default::default()
            },
            ..Default::default()
        };
        Config {
            profiles: BTreeMap::from([("work".to_owned(), profile)]),
            ..Default::default()
        }
    }

    fn allowed(config: &Config, profile: &str, daemon: Option<&str>, request: Request<'_>) -> bool {
        check_access(config, &profile_name(profile), daemon, request)
    }

    const LAUNCHER: Option<&str> = Some("daemon-launcher");

    // SECURITY INVARIANT: With no ACL policy anywhere, every request on any
    // profile (even one absent from config) is allowed.
    #[test]
    fn no_policy_anywhere_allows_every_request() {
        let config = work_with_acl(&[]);
        for request in [Request::Key("key"), Request::List] {
            assert!(allowed(&config, "nonexistent", LAUNCHER, request));
            assert!(allowed(&config, "work", LAUNCHER, request));
        }
    }

    // SECURITY INVARIANT: With an ACL policy on any profile, a profile absent
    // from config is denied (fail-closed): a request cannot bypass the ACL
    // by naming a profile that does not exist.
    #[test]
    fn a_missing_profile_is_denied_when_any_policy_exists() {
        let config = work_with_acl(&[("daemon-wm", &["x"])]);
        for request in [Request::Key("key"), Request::List] {
            assert!(!allowed(&config, "unknown", LAUNCHER, request));
        }
    }

    // SECURITY INVARIANT: Unregistered clients (no verified sender name)
    // cannot be identity-verified and are denied when a policy exists.
    #[test]
    fn unregistered_clients_are_denied_under_a_policy() {
        let config = work_with_acl(&[("daemon-wm", &["x"])]);
        for request in [Request::Key("key"), Request::List] {
            assert!(!allowed(&config, "work", None, request));
        }
    }

    // SECURITY INVARIANT: A daemon absent from the access map is
    // unrestricted (explicit opt-in).
    #[test]
    fn a_daemon_absent_from_the_map_is_unrestricted() {
        let config = work_with_acl(&[("other-daemon", &["key"])]);
        for request in [Request::Key("key"), Request::List] {
            assert!(allowed(&config, "work", LAUNCHER, request));
        }
    }

    // SECURITY INVARIANT: A listed daemon reads exactly its allowed keys,
    // and may list them when it has at least one.
    #[test]
    fn a_listed_daemon_reads_exactly_its_keys() {
        let config = work_with_acl(&[("daemon-launcher", &["api-key"])]);
        assert!(allowed(&config, "work", LAUNCHER, Request::Key("api-key")));
        assert!(!allowed(&config, "work", LAUNCHER, Request::Key("db-pass")));
        assert!(allowed(&config, "work", LAUNCHER, Request::List));
    }

    // SECURITY INVARIANT: An empty allowed list is no access at all: no
    // key, and not even the key names.
    #[test]
    fn an_empty_list_denies_keys_and_listing() {
        let config = work_with_acl(&[("daemon-launcher", &[])]);
        for request in [Request::Key("any-key"), Request::List] {
            assert!(!allowed(&config, "work", LAUNCHER, request));
        }
    }
}
