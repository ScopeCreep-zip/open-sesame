//! Clearance registry: maps daemon names to verified identities and security levels,
//! with O(1) pubkey lookups via a reverse index.
//!
//! Built by `daemon-profile` at startup from per-daemon keypairs. After Noise IK
//! handshake, the server extracts the client's X25519 static public key via
//! `TransportState::get_remote_static()` and resolves it here.
//!
//! Keys not in the registry receive `SecurityLevel::SecretsOnly` (ephemeral CLI clients).
//!
//! ## Data Model
//!
//! `identities: HashMap<String, DaemonIdentity>` is the source of truth, keyed by
//! daemon name. One entry per daemon. `find_by_name` is O(1) and deterministic.
//!
//! `pubkey_index: HashMap<[u8; 32], String>` is a derived reverse index for O(1)
//! pubkey resolution during Noise handshake. Both `current_pubkey` and `pending_pubkey`
//! (when present during key rotation) have entries in this index.
//!
//! ## Consistency Invariant
//!
//! For every `(pubkey, name)` in `pubkey_index`:
//!   `identities[name].current_pubkey == pubkey || identities[name].pending_pubkey == Some(pubkey)`
//!
//! Enforced by all mutation methods. Validated by `debug_assert_consistent()` in debug builds.

use core_types::SecurityLevel;
use std::collections::HashMap;

/// A daemon's verified identity, clearance, and key state.
///
/// Does NOT derive `Serialize` — internal registry state that must never
/// cross a process boundary or appear in logs, API responses, or error messages.
#[derive(Debug, Clone)]
pub struct DaemonIdentity {
    /// Current active X25519 static public key.
    pub current_pubkey: [u8; 32],
    /// Pending rotation pubkey. Set by phase 1, cleared by phase 2 finalization.
    /// Both current and pending are valid for identity resolution during
    /// the grace period.
    pub pending_pubkey: Option<[u8; 32]>,
    /// Security clearance level for this daemon.
    pub security_level: SecurityLevel,
    /// Monotonic generation counter. Incremented on every finalized rotation
    /// or crash-revocation. Used by two-phase rotation to detect concurrent
    /// revocations and avoid double-rotation.
    pub generation: u64,
}

/// Maps daemon names to identities with O(1) pubkey lookups via reverse index.
#[derive(Debug, Clone, Default)]
pub struct ClearanceRegistry {
    /// Source of truth: daemon name → identity.
    identities: HashMap<String, DaemonIdentity>,
    /// Derived cache: pubkey → daemon name. Maintained by mutation methods.
    pubkey_index: HashMap<[u8; 32], String>,
}

impl ClearanceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            pubkey_index: HashMap::new(),
        }
    }

    /// Register a daemon with its initial pubkey and clearance level.
    /// Generation starts at 0. Overwrites any existing registration for this name.
    pub fn register(&mut self, name: String, pubkey: [u8; 32], level: SecurityLevel) {
        // Remove any existing pubkeys for this daemon from the reverse index.
        if let Some(existing) = self.identities.get(&name) {
            self.pubkey_index.remove(&existing.current_pubkey);
            if let Some(pending) = existing.pending_pubkey {
                self.pubkey_index.remove(&pending);
            }
        }

        let identity = DaemonIdentity {
            current_pubkey: pubkey,
            pending_pubkey: None,
            security_level: level,
            generation: 0,
        };
        self.identities.insert(name.clone(), identity);
        self.pubkey_index.insert(pubkey, name);
        self.debug_assert_consistent();
    }

    /// Register with an explicit generation (used after revoke-then-reregister).
    pub fn register_with_generation(
        &mut self,
        name: String,
        pubkey: [u8; 32],
        level: SecurityLevel,
        generation: u64,
    ) {
        // Remove any existing pubkeys for this daemon from the reverse index.
        if let Some(existing) = self.identities.get(&name) {
            self.pubkey_index.remove(&existing.current_pubkey);
            if let Some(pending) = existing.pending_pubkey {
                self.pubkey_index.remove(&pending);
            }
        }

        let identity = DaemonIdentity {
            current_pubkey: pubkey,
            pending_pubkey: None,
            security_level: level,
            generation,
        };
        self.identities.insert(name.clone(), identity);
        self.pubkey_index.insert(pubkey, name);
        self.debug_assert_consistent();
    }

    /// Look up a daemon identity by pubkey. O(1) via reverse index.
    /// Returns `None` for unregistered keys (ephemeral CLI clients).
    #[must_use]
    pub fn lookup(&self, pubkey: &[u8; 32]) -> Option<&DaemonIdentity> {
        let name = self.pubkey_index.get(pubkey)?;
        self.identities.get(name)
    }

    /// Look up the daemon name for a pubkey. O(1) via reverse index.
    #[must_use]
    pub fn lookup_name(&self, pubkey: &[u8; 32]) -> Option<&str> {
        self.pubkey_index.get(pubkey).map(String::as_str)
    }

    /// Find a daemon identity by name. O(1). Always deterministic.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&DaemonIdentity> {
        self.identities.get(name)
    }

    /// Register a pending rotation pubkey for an existing daemon.
    ///
    /// Both old (current) and new (pending) pubkeys are valid for identity
    /// resolution during the grace period. The pending key gets the same
    /// `security_level` and `generation` as the current identity — `register_pending`
    /// does NOT accept these as parameters to prevent accidental clearance changes.
    ///
    /// If a pending key already exists (double rotation without finalize),
    /// the old pending key is removed from the index and replaced.
    ///
    /// Returns `true` if the daemon was found and the pending key was registered.
    /// Returns `false` if no daemon with that name exists.
    pub fn register_pending(&mut self, daemon_name: &str, new_pubkey: [u8; 32]) -> bool {
        let Some(identity) = self.identities.get_mut(daemon_name) else {
            return false;
        };

        // Remove any existing pending key from the reverse index.
        if let Some(old_pending) = identity.pending_pubkey {
            self.pubkey_index.remove(&old_pending);
        }

        identity.pending_pubkey = Some(new_pubkey);
        self.pubkey_index.insert(new_pubkey, daemon_name.to_owned());
        self.debug_assert_consistent();
        true
    }

    /// Finalize rotation: promote pending to current, remove old from index,
    /// increment generation.
    ///
    /// Returns `true` if the daemon was found and had a pending key to finalize.
    /// Returns `false` if the daemon doesn't exist or has no pending key.
    pub fn finalize_rotation(&mut self, daemon_name: &str) -> bool {
        let Some(identity) = self.identities.get_mut(daemon_name) else {
            return false;
        };

        let Some(new_pubkey) = identity.pending_pubkey.take() else {
            return false;
        };

        // Remove old current pubkey from reverse index.
        self.pubkey_index.remove(&identity.current_pubkey);

        // Promote pending to current.
        identity.current_pubkey = new_pubkey;
        identity.generation += 1;
        // new_pubkey is already in the reverse index from register_pending().

        self.debug_assert_consistent();
        true
    }

    /// Revoke a daemon entirely: remove identity and all pubkey index entries.
    ///
    /// Handles the dual-key case atomically: removes both current and pending
    /// pubkeys from the reverse index in one operation.
    ///
    /// Returns the removed identity (for generation continuity) or `None`.
    pub fn revoke_by_name(&mut self, daemon_name: &str) -> Option<DaemonIdentity> {
        let identity = self.identities.remove(daemon_name)?;

        // Remove all pubkeys for this daemon from the reverse index.
        self.pubkey_index.remove(&identity.current_pubkey);
        if let Some(pending) = identity.pending_pubkey {
            self.pubkey_index.remove(&pending);
        }

        self.debug_assert_consistent();
        Some(identity)
    }

    /// Snapshot all daemon generations. Used by rotation phase 1 baseline.
    #[must_use]
    pub fn snapshot_generations(&self) -> HashMap<String, u64> {
        self.identities
            .iter()
            .map(|(name, id)| (name.clone(), id.generation))
            .collect()
    }

    /// Validate internal consistency between primary map and reverse index.
    ///
    /// Every pubkey in the reverse index must point to an existing identity
    /// whose `current_pubkey` or `pending_pubkey` matches. Every pubkey in every
    /// identity must have a reverse index entry.
    ///
    /// Only runs in debug builds. Panics on inconsistency.
    fn debug_assert_consistent(&self) {
        #[cfg(debug_assertions)]
        {
            // Forward check: every reverse index entry points to a valid identity+pubkey.
            for (pubkey, name) in &self.pubkey_index {
                let identity = self
                    .identities
                    .get(name)
                    .unwrap_or_else(|| panic!("pubkey_index points to nonexistent daemon: {name}"));
                let matches_current = identity.current_pubkey == *pubkey;
                let matches_pending = identity.pending_pubkey.as_ref() == Some(pubkey);
                assert!(
                    matches_current || matches_pending,
                    "pubkey_index entry for {name} matches neither current nor pending pubkey"
                );
            }

            // Reverse check: every pubkey in every identity has a reverse index entry.
            for (name, identity) in &self.identities {
                assert_eq!(
                    self.pubkey_index.get(&identity.current_pubkey),
                    Some(name),
                    "current_pubkey for {name} missing from pubkey_index"
                );
                if let Some(pending) = &identity.pending_pubkey {
                    assert_eq!(
                        self.pubkey_index.get(pending),
                        Some(name),
                        "pending_pubkey for {name} missing from pubkey_index"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::SecurityLevel;

    #[test]
    fn register_and_lookup() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xAA; 32];
        reg.register("daemon-secrets".into(), key, SecurityLevel::SecretsOnly);
        let identity = reg.lookup(&key).unwrap();
        assert_eq!(identity.current_pubkey, key);
        assert_eq!(identity.security_level, SecurityLevel::SecretsOnly);
        assert_eq!(identity.generation, 0);
        assert!(identity.pending_pubkey.is_none());
    }

    #[test]
    fn lookup_name() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xAA; 32];
        reg.register("daemon-wm".into(), key, SecurityLevel::Internal);
        assert_eq!(reg.lookup_name(&key), Some("daemon-wm"));
        assert_eq!(reg.lookup_name(&[0xBB; 32]), None);
    }

    #[test]
    fn lookup_miss() {
        let reg = ClearanceRegistry::new();
        assert!(reg.lookup(&[0xBB; 32]).is_none());
    }

    #[test]
    fn find_by_name_deterministic() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xAA; 32];
        reg.register("daemon-wm".into(), key, SecurityLevel::Internal);
        let identity = reg.find_by_name("daemon-wm").unwrap();
        assert_eq!(identity.current_pubkey, key);
        assert!(reg.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn register_overwrites_existing() {
        let mut reg = ClearanceRegistry::new();
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        reg.register("daemon-wm".into(), key_a, SecurityLevel::Internal);
        reg.register("daemon-wm".into(), key_b, SecurityLevel::SecretsOnly);

        // Old key should not resolve.
        assert!(reg.lookup(&key_a).is_none());
        // New key should resolve.
        let identity = reg.lookup(&key_b).unwrap();
        assert_eq!(identity.security_level, SecurityLevel::SecretsOnly);
    }

    #[test]
    fn register_pending_allows_dual_key_lookup() {
        let mut reg = ClearanceRegistry::new();
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];
        reg.register("daemon-wm".into(), old_key, SecurityLevel::Internal);

        assert!(reg.register_pending("daemon-wm", new_key));

        // Both keys resolve to the same daemon.
        let id_old = reg.lookup(&old_key).unwrap();
        let id_new = reg.lookup(&new_key).unwrap();
        assert_eq!(id_old.current_pubkey, old_key);
        assert_eq!(id_new.current_pubkey, old_key);
        assert_eq!(id_old.pending_pubkey, Some(new_key));
        assert_eq!(id_new.pending_pubkey, Some(new_key));
        assert_eq!(id_old.security_level, SecurityLevel::Internal);
        assert_eq!(id_new.security_level, SecurityLevel::Internal);
    }

    #[test]
    fn register_pending_returns_false_for_unknown_daemon() {
        let mut reg = ClearanceRegistry::new();
        assert!(!reg.register_pending("nonexistent", [0xFF; 32]));
    }

    #[test]
    fn register_pending_clones_security_level() {
        let mut reg = ClearanceRegistry::new();
        reg.register(
            "daemon-secrets".into(),
            [0xAA; 32],
            SecurityLevel::SecretsOnly,
        );
        reg.register_pending("daemon-secrets", [0xBB; 32]);

        // Lookup via new key should show SecretsOnly (cloned from existing).
        let identity = reg.lookup(&[0xBB; 32]).unwrap();
        assert_eq!(identity.security_level, SecurityLevel::SecretsOnly);
    }

    #[test]
    fn register_pending_replaces_existing_pending() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.register_pending("daemon-wm", [0xCC; 32]);

        // Old pending key should not resolve.
        assert!(reg.lookup(&[0xBB; 32]).is_none());
        // New pending key should resolve.
        assert!(reg.lookup(&[0xCC; 32]).is_some());
        // Current key still resolves.
        assert!(reg.lookup(&[0xAA; 32]).is_some());
    }

    #[test]
    fn finalize_rotation_promotes_pending() {
        let mut reg = ClearanceRegistry::new();
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];
        reg.register("daemon-wm".into(), old_key, SecurityLevel::Internal);
        reg.register_pending("daemon-wm", new_key);

        assert!(reg.finalize_rotation("daemon-wm"));

        let identity = reg.find_by_name("daemon-wm").unwrap();
        assert_eq!(identity.current_pubkey, new_key);
        assert!(identity.pending_pubkey.is_none());
    }

    #[test]
    fn finalize_rotation_removes_old_from_index() {
        let mut reg = ClearanceRegistry::new();
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];
        reg.register("daemon-wm".into(), old_key, SecurityLevel::Internal);
        reg.register_pending("daemon-wm", new_key);

        reg.finalize_rotation("daemon-wm");

        // Old key no longer resolves.
        assert!(reg.lookup(&old_key).is_none());
        // New key still resolves.
        assert!(reg.lookup(&new_key).is_some());
    }

    #[test]
    fn finalize_rotation_increments_generation() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm");

        assert_eq!(reg.find_by_name("daemon-wm").unwrap().generation, 1);
    }

    #[test]
    fn finalize_rotation_returns_false_without_pending() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);

        // No pending key registered.
        assert!(!reg.finalize_rotation("daemon-wm"));
        // Identity unchanged.
        assert_eq!(reg.find_by_name("daemon-wm").unwrap().generation, 0);
    }

    #[test]
    fn finalize_rotation_returns_false_for_unknown() {
        let mut reg = ClearanceRegistry::new();
        assert!(!reg.finalize_rotation("nonexistent"));
    }

    #[test]
    fn revoke_by_name_removes_both_keys() {
        let mut reg = ClearanceRegistry::new();
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];
        reg.register("daemon-wm".into(), old_key, SecurityLevel::Internal);
        reg.register_pending("daemon-wm", new_key);

        let revoked = reg.revoke_by_name("daemon-wm").unwrap();
        assert_eq!(revoked.generation, 0);

        // Both keys removed from reverse index.
        assert!(reg.lookup(&old_key).is_none());
        assert!(reg.lookup(&new_key).is_none());
        // Name removed from primary map.
        assert!(reg.find_by_name("daemon-wm").is_none());
    }

    #[test]
    fn revoke_by_name_returns_none_for_unknown() {
        let mut reg = ClearanceRegistry::new();
        assert!(reg.revoke_by_name("nonexistent").is_none());
    }

    #[test]
    fn revoke_by_name_returns_identity_with_generation() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 1
        reg.register_pending("daemon-wm", [0xCC; 32]);
        // gen still 1 (pending not finalized yet)

        let revoked = reg.revoke_by_name("daemon-wm").unwrap();
        assert_eq!(revoked.generation, 1);
    }

    #[test]
    fn register_with_generation_preserves_counter() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xDD; 32];
        reg.register_with_generation("daemon-wm".into(), key, SecurityLevel::Internal, 5);
        assert_eq!(reg.lookup(&key).unwrap().generation, 5);
    }

    #[test]
    fn snapshot_generations_captures_all_daemons() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register(
            "daemon-secrets".into(),
            [0xBB; 32],
            SecurityLevel::SecretsOnly,
        );

        // Finalize one rotation for daemon-wm.
        reg.register_pending("daemon-wm", [0xCC; 32]);
        reg.finalize_rotation("daemon-wm");

        let snap = reg.snapshot_generations();
        assert_eq!(snap["daemon-wm"], 1);
        assert_eq!(snap["daemon-secrets"], 0);
    }

    // SECURITY INVARIANT: double finalization must be safe (returns false, no state change).
    #[test]
    fn double_finalize_is_safe() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register_pending("daemon-wm", [0xBB; 32]);

        assert!(reg.finalize_rotation("daemon-wm"));
        assert!(!reg.finalize_rotation("daemon-wm"));
        assert_eq!(reg.find_by_name("daemon-wm").unwrap().generation, 1);
    }

    // SECURITY INVARIANT: two full rotation cycles must produce generation 2.
    #[test]
    fn double_rotation_increments_generation_twice() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);

        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 1

        reg.register_pending("daemon-wm", [0xCC; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 2

        let identity = reg.find_by_name("daemon-wm").unwrap();
        assert_eq!(identity.generation, 2);
        assert_eq!(identity.current_pubkey, [0xCC; 32]);
        assert!(reg.lookup(&[0xAA; 32]).is_none());
        assert!(reg.lookup(&[0xBB; 32]).is_none());
        assert!(reg.lookup(&[0xCC; 32]).is_some());
    }

    // SECURITY INVARIANT: crash-restart path must preserve generation continuity.
    // revoke_by_name returns the identity with current generation; re-register with gen+1.
    #[test]
    fn revoke_then_reregister_preserves_generation_continuity() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 1

        let revoked = reg.revoke_by_name("daemon-wm").unwrap();
        assert_eq!(revoked.generation, 1);

        reg.register_with_generation(
            "daemon-wm".into(),
            [0xCC; 32],
            SecurityLevel::Internal,
            revoked.generation + 1,
        );
        assert_eq!(reg.find_by_name("daemon-wm").unwrap().generation, 2);
    }

    // SECURITY INVARIANT: revoke during pending must clean both keys.
    #[test]
    fn revoke_during_pending_cleans_both() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register_pending("daemon-wm", [0xBB; 32]);

        reg.revoke_by_name("daemon-wm");

        assert!(reg.lookup(&[0xAA; 32]).is_none());
        assert!(reg.lookup(&[0xBB; 32]).is_none());
        assert!(reg.find_by_name("daemon-wm").is_none());
    }

    // SECURITY INVARIANT: any key NOT in the registry must return None on lookup.
    // The server assigns SecretsOnly clearance to None — elevated clearance must
    // never be granted to unregistered keys.
    #[test]
    fn unregistered_keys_always_return_none() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register(
            "daemon-secrets".into(),
            [0xBB; 32],
            SecurityLevel::SecretsOnly,
        );

        for byte in [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xCC, 0xDD, 0xEE, 0xFF,
        ] {
            assert!(
                reg.lookup(&[byte; 32]).is_none(),
                "key [{byte:#04X}; 32] should not be in registry"
            );
        }
    }

    // SECURITY INVARIANT: find_by_name must return the correct identity after rotation.
    #[test]
    fn find_by_name_tracks_through_rotation() {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal);
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm");

        let identity = reg.find_by_name("daemon-wm").unwrap();
        assert_eq!(identity.current_pubkey, [0xBB; 32]);
        assert_eq!(identity.generation, 1);
    }
}
