//! Per-secret access control.
//!
//! Pure functions over `core_config::Config` — no I/O, no state.
//! Extracted from `main.rs` for testability.

use core_types::{DaemonId, TrustProfileName};

/// Check if a daemon is allowed to access a specific secret key within a profile.
///
/// Policy from config `[profiles.<name>.secrets.access]`:
/// - Profile not in config AND any profile has ACL policy: DENIED (fail-closed).
/// - Profile not in config AND no profile has ACL policy: ALLOWED (no policy anywhere).
/// - Profile in config, empty access map: ALLOWED (no policy for this profile).
/// - Daemon name present with empty list: DENIED (no access).
/// - Daemon name present with key in list: ALLOWED.
/// - Daemon name present but key not in list: DENIED.
/// - Daemon name absent from map: ALLOWED (backward compatible default).
/// - Unregistered client when ACL policy exists: DENIED.
pub(crate) fn check_secret_access(
    config: &core_config::Config,
    profile: &TrustProfileName,
    daemon_name: Option<&str>,
    key: &str,
) -> bool {
    let Some(profile_config) = config.profiles.get(profile.as_ref()) else {
        // Profile not in config. Check if ACL enforcement is active anywhere.
        let any_acl_active = config
            .profiles
            .values()
            .any(|p| !p.secrets.access.is_empty());
        if any_acl_active {
            tracing::warn!(
                audit = "access-denied",
                key,
                profile = %profile,
                "profile not found in config — denied because ACL policy is active on other profiles"
            );
            return false;
        }
        // No ACL policy configured anywhere — allow (pre-ACL behavior).
        return true;
    };

    if profile_config.secrets.access.is_empty() {
        return true; // No access policy configured.
    }

    let Some(daemon_name) = daemon_name else {
        tracing::warn!(
            audit = "access-denied",
            key,
            profile = %profile,
            "unregistered client (no verified_sender_name) denied by ACL policy"
        );
        return false;
    };

    let Some(allowed_keys) = profile_config.secrets.access.get(daemon_name) else {
        return true; // Daemon not in policy = unrestricted.
    };

    // Daemon is in policy. Check if the key is allowed.
    allowed_keys.iter().any(|k| k == key)
}

/// Check if a daemon is allowed to list secret keys within a profile.
///
/// Policy from config `[profiles.<name>.secrets.access]`:
/// - Profile not in config AND any profile has ACL policy: DENIED (fail-closed).
/// - Profile not in config AND no profile has ACL policy: ALLOWED (no policy anywhere).
/// - Profile in config, empty access map: ALLOWED (no policy for this profile).
/// - Daemon name absent from map: ALLOWED (backward compatible default).
/// - Daemon name present with non-empty list: ALLOWED (has at least some access).
/// - Daemon name present with empty list: DENIED (explicit no-access).
/// - Unregistered client (no verified_sender_name) when policy exists: DENIED.
pub(crate) fn check_secret_list_access(
    config: &core_config::Config,
    profile: &TrustProfileName,
    daemon_name: Option<&str>,
) -> bool {
    let Some(profile_config) = config.profiles.get(profile.as_ref()) else {
        let any_acl_active = config
            .profiles
            .values()
            .any(|p| !p.secrets.access.is_empty());
        if any_acl_active {
            tracing::warn!(
                audit = "access-denied",
                profile = %profile,
                "profile not found — secret list denied because ACL policy is active"
            );
            return false;
        }
        return true;
    };

    if profile_config.secrets.access.is_empty() {
        return true; // No access policy configured.
    }

    let Some(daemon_name) = daemon_name else {
        tracing::warn!(
            audit = "access-denied",
            profile = %profile,
            "unregistered client (no verified_sender_name) denied secret list by ACL policy"
        );
        return false;
    };

    let Some(allowed_keys) = profile_config.secrets.access.get(daemon_name) else {
        return true; // Daemon not in policy = unrestricted.
    };

    // Daemon is in policy. Allow list only if it has access to at least one key.
    if allowed_keys.is_empty() {
        tracing::warn!(
            audit = "access-denied",
            daemon_name,
            profile = %profile,
            "daemon has empty ACL (explicit deny-all), secret list denied"
        );
        return false;
    }

    true
}

/// Check if a requester is expected to issue secret operations.
///
/// Uses `verified_sender_name` stamped by the bus server from the Noise IK
/// registry — NOT self-declared capabilities. Expected requesters:
/// "daemon-secrets" (self), "daemon-launcher" (env injection), or `None`
/// (CLI relay via daemon-profile with Open clearance).
pub(crate) fn check_secret_requester(requester: DaemonId, verified_name: Option<&str>) {
    if let Some(name) = verified_name {
        match name {
            "daemon-secrets" | "daemon-launcher" => {} // Expected requesters.
            other => {
                tracing::warn!(
                    audit = "anomaly",
                    anomaly_type = "unexpected-secret-requester",
                    requester = %requester,
                    verified_name = other,
                    "daemon not expected to request secrets (verified identity)"
                );
            }
        }
    }
    // None = unregistered client (CLI relay via daemon-profile). Not anomalous.
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
    use core_config::{Config, ProfileConfig, SecretsConfig};
    use std::collections::BTreeMap;

    fn profile_name(s: &str) -> TrustProfileName {
        TrustProfileName::try_from(s).unwrap()
    }

    /// Build a Config with one profile that has the given ACL access map.
    fn config_with_acl(profile: &str, access: BTreeMap<String, Vec<String>>) -> Config {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            profile.to_string(),
            ProfileConfig {
                name: profile_name(profile),
                secrets: SecretsConfig {
                    access,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        Config {
            profiles,
            ..Default::default()
        }
    }

    // ========================================================================
    // check_secret_access — 8 branches
    // ========================================================================

    // SECURITY INVARIANT: When no ACL policy exists anywhere in config,
    // access to any profile (even nonexistent) must be allowed for backward
    // compatibility with pre-ACL deployments.
    #[test]
    fn acl_001_profile_missing_no_acl_anywhere_allows() {
        let config = config_with_acl("work", BTreeMap::new());
        assert!(check_secret_access(
            &config,
            &profile_name("nonexistent"),
            Some("daemon-launcher"),
            "key"
        ));
    }

    // SECURITY INVARIANT: When ACL policy is active on ANY profile, access to
    // a nonexistent profile must be DENIED (fail-closed). An attacker must not
    // bypass ACL by requesting a profile that doesn't exist in config.
    #[test]
    fn acl_002_profile_missing_acl_elsewhere_denies() {
        let mut access = BTreeMap::new();
        access.insert("daemon-wm".into(), vec!["x".into()]);
        let config = config_with_acl("work", access);
        assert!(!check_secret_access(
            &config,
            &profile_name("unknown"),
            Some("daemon-launcher"),
            "key"
        ));
    }

    // SECURITY INVARIANT: A profile that exists but has no access map entries
    // means "no ACL policy for this profile" — all access is allowed.
    #[test]
    fn acl_003_profile_exists_empty_access_allows() {
        let config = config_with_acl("work", BTreeMap::new());
        assert!(check_secret_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher"),
            "key"
        ));
    }

    // SECURITY INVARIANT: Unregistered clients (no verified_sender_name from
    // Noise IK registry) must be denied when ACL policy exists. They cannot
    // be identity-verified.
    #[test]
    fn acl_004_unregistered_client_with_acl_denies() {
        let mut access = BTreeMap::new();
        access.insert("daemon-wm".into(), vec!["x".into()]);
        let config = config_with_acl("work", access);
        assert!(!check_secret_access(
            &config,
            &profile_name("work"),
            None,
            "key"
        ));
    }

    // SECURITY INVARIANT: A daemon not mentioned in the access map has
    // unrestricted access (backward compatible default — explicit opt-in).
    #[test]
    fn acl_005_daemon_absent_from_map_allows() {
        let mut access = BTreeMap::new();
        access.insert("other-daemon".into(), vec!["key".into()]);
        let config = config_with_acl("work", access);
        assert!(check_secret_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher"),
            "key"
        ));
    }

    // SECURITY INVARIANT: A daemon listed in the access map with the requested
    // key in its allowed list must be granted access.
    #[test]
    fn acl_006_daemon_present_key_allowed() {
        let mut access = BTreeMap::new();
        access.insert("daemon-launcher".into(), vec!["api-key".into()]);
        let config = config_with_acl("work", access);
        assert!(check_secret_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher"),
            "api-key"
        ));
    }

    // SECURITY INVARIANT: A daemon listed in the access map requesting a key
    // NOT in its allowed list must be denied. Allowlists are strict.
    #[test]
    fn acl_007_daemon_present_key_denied() {
        let mut access = BTreeMap::new();
        access.insert("daemon-launcher".into(), vec!["api-key".into()]);
        let config = config_with_acl("work", access);
        assert!(!check_secret_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher"),
            "db-pass"
        ));
    }

    // SECURITY INVARIANT: A daemon listed with an empty allowed list is
    // explicitly denied all access. Empty list means "no access", not
    // "unrestricted access".
    #[test]
    fn acl_008_daemon_present_empty_list_denies() {
        let mut access = BTreeMap::new();
        access.insert("daemon-launcher".into(), vec![]);
        let config = config_with_acl("work", access);
        assert!(!check_secret_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher"),
            "any-key"
        ));
    }

    // ========================================================================
    // check_secret_list_access — 7 branches
    // ========================================================================

    #[test]
    fn acl_009_list_profile_missing_no_acl_allows() {
        let config = config_with_acl("work", BTreeMap::new());
        assert!(check_secret_list_access(
            &config,
            &profile_name("nonexistent"),
            Some("daemon-launcher")
        ));
    }

    // SECURITY INVARIANT: Fail-closed for list access on nonexistent profiles
    // when ACL is active elsewhere (same fail-closed semantics as check_secret_access).
    #[test]
    fn acl_010_list_profile_missing_acl_elsewhere_denies() {
        let mut access = BTreeMap::new();
        access.insert("daemon-wm".into(), vec!["x".into()]);
        let config = config_with_acl("work", access);
        assert!(!check_secret_list_access(
            &config,
            &profile_name("unknown"),
            Some("daemon-launcher")
        ));
    }

    #[test]
    fn acl_011_list_profile_exists_empty_access_allows() {
        let config = config_with_acl("work", BTreeMap::new());
        assert!(check_secret_list_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher")
        ));
    }

    #[test]
    fn acl_012_list_unregistered_client_denies() {
        let mut access = BTreeMap::new();
        access.insert("daemon-wm".into(), vec!["x".into()]);
        let config = config_with_acl("work", access);
        assert!(!check_secret_list_access(
            &config,
            &profile_name("work"),
            None
        ));
    }

    #[test]
    fn acl_013_list_daemon_absent_allows() {
        let mut access = BTreeMap::new();
        access.insert("other-daemon".into(), vec!["key".into()]);
        let config = config_with_acl("work", access);
        assert!(check_secret_list_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher")
        ));
    }

    #[test]
    fn acl_014_list_daemon_present_nonempty_allows() {
        let mut access = BTreeMap::new();
        access.insert("daemon-launcher".into(), vec!["api-key".into()]);
        let config = config_with_acl("work", access);
        assert!(check_secret_list_access(
            &config,
            &profile_name("work"),
            Some("daemon-launcher")
        ));
    }

    // SECURITY INVARIANT: Daemon with empty ACL list is explicitly denied all
    // access including listing — "no keys allowed" means "cannot even see what
    // keys exist".
    #[test]
    fn acl_015_list_daemon_present_empty_denies() {
        let mut access = BTreeMap::new();
        access.insert("daemon-wm".into(), vec![]);
        let config = config_with_acl("work", access);
        assert!(!check_secret_list_access(
            &config,
            &profile_name("work"),
            Some("daemon-wm")
        ));
    }
}
