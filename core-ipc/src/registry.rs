//! Clearance registry: maps daemon names to their registrations (keys,
//! security level, rotation generation), with O(1) pubkey lookups via a
//! reverse index.
//!
//! Built by `daemon-profile` at startup from per-daemon keypairs. After the
//! Noise IK handshake, the server takes the client's X25519 static public
//! key from the transport and resolves it here.
//!
//! Keys not in the registry receive `SecurityLevel::SecretsOnly` (ephemeral CLI clients).
//!
//! ## Data Model
//!
//! `registrations: HashMap<String, Registration>` is the source of truth,
//! keyed by daemon name. One entry per daemon. `find_by_name` is O(1) and
//! deterministic.
//!
//! `pubkey_index: HashMap<[u8; 32], String>` is a derived reverse index for O(1)
//! pubkey resolution during Noise handshake. Both `current_pubkey` and `pending_pubkey`
//! (when present during key rotation) have entries in this index.
//!
//! ## Consistency Invariant
//!
//! For every `(pubkey, name)` in `pubkey_index`:
//!   `registrations[name].current_pubkey == pubkey || registrations[name].pending_pubkey == Some(pubkey)`
//!
//! Enforced by all mutation methods. Validated by `debug_assert_consistent()` in debug builds.

use core_types::SecurityLevel;
use std::collections::HashMap;

/// A daemon's registration: its keys, clearance, and rotation generation.
///
/// Does NOT derive `Serialize` — internal registry state that must never
/// cross a process boundary or appear in logs, API responses, or error messages.
#[derive(Debug, Clone)]
pub struct Registration {
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

/// Maps daemon names to registrations with O(1) pubkey lookups via a
/// reverse index.
#[derive(Debug, Clone, Default)]
pub struct ClearanceRegistry {
    /// Source of truth: daemon name → registration.
    registrations: HashMap<String, Registration>,
    /// Derived cache: pubkey → daemon name. Maintained by mutation methods.
    pubkey_index: HashMap<[u8; 32], String>,
}

impl ClearanceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `name` with `pubkey` at `level` under `generation`: 0 when
    /// daemon-profile first issues the key, the next generation when it
    /// reissues one after revoking the daemon. Replaces any existing
    /// registration of `name`, current and pending keys alike.
    pub fn register(
        &mut self,
        name: String,
        pubkey: [u8; 32],
        level: SecurityLevel,
        generation: u64,
    ) {
        if let Some(existing) = self.registrations.get(&name) {
            self.pubkey_index.remove(&existing.current_pubkey);
            if let Some(pending) = existing.pending_pubkey {
                self.pubkey_index.remove(&pending);
            }
        }
        let registration = Registration {
            current_pubkey: pubkey,
            pending_pubkey: None,
            security_level: level,
            generation,
        };
        self.registrations.insert(name.clone(), registration);
        self.pubkey_index.insert(pubkey, name);
        self.debug_assert_consistent();
    }

    /// Look up a daemon's registration by pubkey. O(1) via reverse index.
    /// Returns `None` for unregistered keys (ephemeral CLI clients).
    #[must_use]
    pub fn lookup(&self, pubkey: &[u8; 32]) -> Option<&Registration> {
        let name = self.pubkey_index.get(pubkey)?;
        self.registrations.get(name)
    }

    /// Look up the daemon name for a pubkey. O(1) via reverse index.
    #[must_use]
    pub fn lookup_name(&self, pubkey: &[u8; 32]) -> Option<&str> {
        self.pubkey_index.get(pubkey).map(String::as_str)
    }

    /// Find a daemon's registration by name. O(1). Always deterministic.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&Registration> {
        self.registrations.get(name)
    }

    /// Register a pending rotation pubkey for an existing daemon.
    ///
    /// Both old (current) and new (pending) pubkeys are valid for identity
    /// resolution during the grace period. The pending key gets the same
    /// `security_level` and `generation` as the current registration —
    /// `register_pending` does NOT accept these as parameters to prevent
    /// accidental clearance changes.
    ///
    /// If a pending key already exists (double rotation without finalize),
    /// the old pending key is removed from the index and replaced.
    ///
    /// Returns `true` if the daemon was found and the pending key was registered.
    /// Returns `false` if no daemon with that name exists.
    pub fn register_pending(&mut self, daemon_name: &str, new_pubkey: [u8; 32]) -> bool {
        let Some(registration) = self.registrations.get_mut(daemon_name) else {
            return false;
        };
        if let Some(old_pending) = registration.pending_pubkey {
            self.pubkey_index.remove(&old_pending);
        }
        registration.pending_pubkey = Some(new_pubkey);
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
        let Some(registration) = self.registrations.get_mut(daemon_name) else {
            return false;
        };
        let Some(new_pubkey) = registration.pending_pubkey.take() else {
            return false;
        };
        self.pubkey_index.remove(&registration.current_pubkey);
        registration.current_pubkey = new_pubkey;
        registration.generation += 1;
        // new_pubkey is already in the reverse index from register_pending().
        self.debug_assert_consistent();
        true
    }

    /// Revoke a daemon entirely: remove its registration and every pubkey
    /// index entry (current and pending alike, in one operation).
    ///
    /// Returns the removed registration (for generation continuity) or `None`.
    pub fn revoke_by_name(&mut self, daemon_name: &str) -> Option<Registration> {
        let registration = self.registrations.remove(daemon_name)?;
        self.pubkey_index.remove(&registration.current_pubkey);
        if let Some(pending) = registration.pending_pubkey {
            self.pubkey_index.remove(&pending);
        }
        self.debug_assert_consistent();
        Some(registration)
    }

    /// Every daemon's generation, taken by rotation phase 1 so phase 2 can
    /// skip a daemon revoked (re-registered under a new generation) during
    /// the grace period.
    #[must_use]
    pub fn snapshot_generations(&self) -> HashMap<String, u64> {
        self.registrations
            .iter()
            .map(|(name, registration)| (name.clone(), registration.generation))
            .collect()
    }

    /// Validate internal consistency between primary map and reverse index.
    ///
    /// Every pubkey in the reverse index must point to an existing
    /// registration whose `current_pubkey` or `pending_pubkey` matches.
    /// Every pubkey of every registration must have a reverse index entry.
    ///
    /// Only runs in debug builds. Panics on inconsistency.
    fn debug_assert_consistent(&self) {
        #[cfg(debug_assertions)]
        {
            for (pubkey, name) in &self.pubkey_index {
                let registration = self
                    .registrations
                    .get(name)
                    .unwrap_or_else(|| panic!("pubkey_index points to nonexistent daemon: {name}"));
                let matches_current = registration.current_pubkey == *pubkey;
                let matches_pending = registration.pending_pubkey.as_ref() == Some(pubkey);
                assert!(
                    matches_current || matches_pending,
                    "pubkey_index entry for {name} matches neither current nor pending pubkey"
                );
            }
            for (name, registration) in &self.registrations {
                assert_eq!(
                    self.pubkey_index.get(&registration.current_pubkey),
                    Some(name),
                    "current_pubkey for {name} missing from pubkey_index"
                );
                if let Some(pending) = &registration.pending_pubkey {
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

    /// A registry holding `daemon-wm` at Internal under `[0xAA; 32]`,
    /// generation 0.
    fn with_wm() -> ClearanceRegistry {
        let mut reg = ClearanceRegistry::new();
        reg.register("daemon-wm".into(), [0xAA; 32], SecurityLevel::Internal, 0);
        reg
    }

    #[test]
    fn register_and_lookup() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xAA; 32];
        reg.register("daemon-secrets".into(), key, SecurityLevel::SecretsOnly, 0);
        let registration = reg.lookup(&key).unwrap();
        assert_eq!(registration.current_pubkey, key);
        assert_eq!(registration.security_level, SecurityLevel::SecretsOnly);
        assert_eq!(registration.generation, 0);
        assert!(registration.pending_pubkey.is_none());
    }

    #[test]
    fn register_records_the_given_generation() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xDD; 32];
        reg.register("daemon-wm".into(), key, SecurityLevel::Internal, 5);
        assert_eq!(reg.lookup(&key).unwrap().generation, 5);
    }

    #[test]
    fn lookup_name() {
        let reg = with_wm();
        assert_eq!(reg.lookup_name(&[0xAA; 32]), Some("daemon-wm"));
        assert_eq!(reg.lookup_name(&[0xBB; 32]), None);
    }

    #[test]
    fn lookup_miss() {
        let reg = ClearanceRegistry::new();
        assert!(reg.lookup(&[0xBB; 32]).is_none());
    }

    #[test]
    fn find_by_name_deterministic() {
        let reg = with_wm();
        assert_eq!(
            reg.find_by_name("daemon-wm").unwrap().current_pubkey,
            [0xAA; 32]
        );
        assert!(reg.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn register_overwrites_existing() {
        let mut reg = with_wm();
        let key_b = [0xBB; 32];
        reg.register("daemon-wm".into(), key_b, SecurityLevel::SecretsOnly, 0);
        assert!(reg.lookup(&[0xAA; 32]).is_none());
        assert_eq!(
            reg.lookup(&key_b).unwrap().security_level,
            SecurityLevel::SecretsOnly
        );
    }

    #[test]
    fn register_pending_allows_dual_key_lookup() {
        let mut reg = with_wm();
        let (old_key, new_key) = ([0xAA; 32], [0xBB; 32]);
        assert!(reg.register_pending("daemon-wm", new_key));
        // Both keys resolve to the same daemon.
        for key in [old_key, new_key] {
            let registration = reg.lookup(&key).unwrap();
            assert_eq!(registration.current_pubkey, old_key);
            assert_eq!(registration.pending_pubkey, Some(new_key));
            assert_eq!(registration.security_level, SecurityLevel::Internal);
        }
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
            0,
        );
        reg.register_pending("daemon-secrets", [0xBB; 32]);
        assert_eq!(
            reg.lookup(&[0xBB; 32]).unwrap().security_level,
            SecurityLevel::SecretsOnly
        );
    }

    #[test]
    fn register_pending_replaces_existing_pending() {
        let mut reg = with_wm();
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.register_pending("daemon-wm", [0xCC; 32]);
        assert!(reg.lookup(&[0xBB; 32]).is_none());
        assert!(reg.lookup(&[0xCC; 32]).is_some());
        assert!(reg.lookup(&[0xAA; 32]).is_some());
    }

    #[test]
    fn finalize_rotation_promotes_pending_and_drops_the_old_key() {
        let mut reg = with_wm();
        reg.register_pending("daemon-wm", [0xBB; 32]);
        assert!(reg.finalize_rotation("daemon-wm"));
        let registration = reg.find_by_name("daemon-wm").unwrap();
        assert_eq!(registration.current_pubkey, [0xBB; 32]);
        assert!(registration.pending_pubkey.is_none());
        assert_eq!(registration.generation, 1);
        assert!(reg.lookup(&[0xAA; 32]).is_none());
        assert!(reg.lookup(&[0xBB; 32]).is_some());
    }

    #[test]
    fn finalize_rotation_returns_false_without_pending() {
        let mut reg = with_wm();
        assert!(!reg.finalize_rotation("daemon-wm"));
        assert_eq!(reg.find_by_name("daemon-wm").unwrap().generation, 0);
    }

    #[test]
    fn finalize_rotation_returns_false_for_unknown() {
        let mut reg = ClearanceRegistry::new();
        assert!(!reg.finalize_rotation("nonexistent"));
    }

    // SECURITY INVARIANT: revoke during pending must clean both keys.
    #[test]
    fn revoke_by_name_removes_both_keys() {
        let mut reg = with_wm();
        reg.register_pending("daemon-wm", [0xBB; 32]);
        let revoked = reg.revoke_by_name("daemon-wm").unwrap();
        assert_eq!(revoked.generation, 0);
        assert!(reg.lookup(&[0xAA; 32]).is_none());
        assert!(reg.lookup(&[0xBB; 32]).is_none());
        assert!(reg.find_by_name("daemon-wm").is_none());
    }

    #[test]
    fn revoke_by_name_returns_none_for_unknown() {
        let mut reg = ClearanceRegistry::new();
        assert!(reg.revoke_by_name("nonexistent").is_none());
    }

    #[test]
    fn revoke_by_name_returns_the_registration_with_its_generation() {
        let mut reg = with_wm();
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 1
        reg.register_pending("daemon-wm", [0xCC; 32]); // gen still 1
        assert_eq!(reg.revoke_by_name("daemon-wm").unwrap().generation, 1);
    }

    #[test]
    fn snapshot_generations_captures_all_daemons() {
        let mut reg = with_wm();
        reg.register(
            "daemon-secrets".into(),
            [0xBB; 32],
            SecurityLevel::SecretsOnly,
            0,
        );
        reg.register_pending("daemon-wm", [0xCC; 32]);
        reg.finalize_rotation("daemon-wm");
        let snap = reg.snapshot_generations();
        assert_eq!(snap["daemon-wm"], 1);
        assert_eq!(snap["daemon-secrets"], 0);
    }

    // SECURITY INVARIANT: double finalization must be safe (returns false, no state change).
    #[test]
    fn double_finalize_is_safe() {
        let mut reg = with_wm();
        reg.register_pending("daemon-wm", [0xBB; 32]);
        assert!(reg.finalize_rotation("daemon-wm"));
        assert!(!reg.finalize_rotation("daemon-wm"));
        assert_eq!(reg.find_by_name("daemon-wm").unwrap().generation, 1);
    }

    // SECURITY INVARIANT: two full rotation cycles must produce generation 2.
    #[test]
    fn double_rotation_increments_generation_twice() {
        let mut reg = with_wm();
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 1
        reg.register_pending("daemon-wm", [0xCC; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 2
        let registration = reg.find_by_name("daemon-wm").unwrap();
        assert_eq!(registration.generation, 2);
        assert_eq!(registration.current_pubkey, [0xCC; 32]);
        assert!(reg.lookup(&[0xAA; 32]).is_none());
        assert!(reg.lookup(&[0xBB; 32]).is_none());
        assert!(reg.lookup(&[0xCC; 32]).is_some());
    }

    // SECURITY INVARIANT: crash-restart path must preserve generation continuity.
    // revoke_by_name returns the registration with its generation; re-register with gen+1.
    #[test]
    fn revoke_then_reregister_preserves_generation_continuity() {
        let mut reg = with_wm();
        reg.register_pending("daemon-wm", [0xBB; 32]);
        reg.finalize_rotation("daemon-wm"); // gen = 1
        let revoked = reg.revoke_by_name("daemon-wm").unwrap();
        assert_eq!(revoked.generation, 1);
        reg.register(
            "daemon-wm".into(),
            [0xCC; 32],
            SecurityLevel::Internal,
            revoked.generation + 1,
        );
        assert_eq!(reg.find_by_name("daemon-wm").unwrap().generation, 2);
    }

    // SECURITY INVARIANT: any key NOT in the registry must return None on lookup.
    // The server assigns SecretsOnly clearance to None — elevated clearance must
    // never be granted to unregistered keys.
    #[test]
    fn unregistered_keys_always_return_none() {
        let mut reg = with_wm();
        reg.register(
            "daemon-secrets".into(),
            [0xBB; 32],
            SecurityLevel::SecretsOnly,
            0,
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
}
