use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Shared constants — single source of truth for cross-crate values
// ============================================================================

/// Level-0 namespace seed for deterministic profile-ID derivation.
///
/// Used as the root UUID v5 namespace from which installation namespaces,
/// org namespaces, and ultimately `ProfileId` values are derived.
/// **Never use directly for `ProfileId` derivation** — derive an `install_ns` first.
pub const PROFILE_NAMESPACE: Uuid = Uuid::from_bytes([
    0x4c, 0x45, 0xa6, 0x4f, 0xab, 0xcd, 0x59, 0x77, 0xbc, 0x73, 0x99, 0xd4, 0xc9, 0x3d, 0x66, 0x8b,
]);

// ============================================================================
// Namespace derivation functions
// ============================================================================

/// Derive the installation-scoped namespace from an installation UUID.
///
/// First derivation step: `UUID_v5(PROFILE_NAMESPACE, id.as_bytes())`.
/// The result is installation-unique because `id` is a random UUID v4.
/// All further namespace derivations (profile, vault, audit, network)
/// are sub-namespaces of this value.
#[must_use]
pub fn installation_namespace(installation_id: &Uuid) -> Uuid {
    Uuid::new_v5(&PROFILE_NAMESPACE, installation_id.as_bytes())
}

/// Derive a sub-namespace from an installation namespace.
///
/// Produces domain-specific namespaces: `"profiles"`, `"vault"`, `"audit"`, `"network"`.
#[must_use]
pub fn sub_namespace(install_ns: &Uuid, domain: &str) -> Uuid {
    Uuid::new_v5(install_ns, domain.as_bytes())
}

/// Derive a [`ProfileId`](crate::ids::ProfileId) from an installation namespace and profile name.
///
/// The format `"profile:{name}"` matches the existing derivation in
/// `daemon-profile/src/main.rs` and `open-sesame/src/init.rs`.
#[must_use]
pub fn derive_profile_id(install_ns: &Uuid, profile_name: &str) -> crate::ids::ProfileId {
    crate::ids::ProfileId::from_uuid(Uuid::new_v5(
        install_ns,
        format!("profile:{profile_name}").as_bytes(),
    ))
}

/// Canonical name for the default profile created during `sesame init`.
///
/// All crates that need to reference the default profile should use this constant
/// rather than hardcoding `"default"` to prevent silent divergence.
pub const DEFAULT_PROFILE_NAME: &str = "default";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_namespace_deterministic() {
        let id = uuid::uuid!("550e8400-e29b-41d4-a716-446655440000");
        let ns1 = installation_namespace(&id);
        let ns2 = installation_namespace(&id);
        assert_eq!(ns1, ns2);
    }

    #[test]
    fn different_installations_different_namespaces() {
        let id1 = uuid::uuid!("550e8400-e29b-41d4-a716-446655440000");
        let id2 = uuid::uuid!("660f9511-f3ac-52e5-b827-557766551111");
        assert_ne!(installation_namespace(&id1), installation_namespace(&id2));
    }

    #[test]
    fn derive_profile_id_regression() {
        let id = uuid::uuid!("550e8400-e29b-41d4-a716-446655440000");
        let ns = installation_namespace(&id);
        let pid = derive_profile_id(&ns, "default");
        // Derivation must match: UUID_v5(ns, "profile:default")
        let expected = Uuid::new_v5(&ns, b"profile:default");
        assert_eq!(*pid.as_uuid(), expected);
    }

    #[test]
    fn sub_namespace_deterministic_and_distinct() {
        let ns = uuid::uuid!("550e8400-e29b-41d4-a716-446655440000");
        let profiles = sub_namespace(&ns, "profiles");
        let vault = sub_namespace(&ns, "vault");
        let network = sub_namespace(&ns, "network");
        assert_ne!(profiles, vault);
        assert_ne!(profiles, network);
        assert_ne!(vault, network);
        assert_eq!(profiles, sub_namespace(&ns, "profiles"));
    }

    #[test]
    fn same_profile_name_different_installations_different_ids() {
        let id1 = uuid::uuid!("550e8400-e29b-41d4-a716-446655440000");
        let id2 = uuid::uuid!("660f9511-f3ac-52e5-b827-557766551111");
        let ns1 = installation_namespace(&id1);
        let ns2 = installation_namespace(&id2);
        let pid1 = derive_profile_id(&ns1, "work");
        let pid2 = derive_profile_id(&ns2, "work");
        assert_ne!(pid1, pid2);
    }
}

// ============================================================================
// Timestamp
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    /// Monotonic counter for ordering within a single daemon lifecycle.
    /// Nanoseconds since daemon start.
    pub monotonic_ns: u64,
    /// Wall clock for cross-daemon and cross-restart ordering.
    /// Milliseconds since Unix epoch.
    pub wall_ms: u64,
}

impl Timestamp {
    #[must_use]
    pub fn now(epoch: Instant) -> Self {
        let mono = epoch.elapsed();
        let wall = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self {
            #[allow(clippy::cast_possible_truncation)] // Uptime > 584 years before truncation
            monotonic_ns: mono.as_nanos() as u64,
            #[allow(clippy::cast_possible_truncation)] // Wall clock > 584M years before truncation
            wall_ms: wall.as_millis() as u64,
        }
    }
}
