//! Clearance registry: maps daemon public keys to verified identities and security levels.
//!
//! The registry is built by `daemon-profile` at startup from the per-daemon keypairs
//! it generates. After Noise IK handshake, the server extracts the client's static
//! public key via `TransportState::get_remote_static()` and looks it up here.
//!
//! Keys not in the registry receive `SecurityLevel::Open` (ephemeral CLI clients).

use core_types::SecurityLevel;
use std::collections::HashMap;

/// A daemon's verified identity and security clearance.
#[derive(Debug, Clone)]
pub struct DaemonClearance {
    pub name: String,
    pub security_level: SecurityLevel,
    /// Monotonic generation counter. Incremented on every key change (rotation
    /// or crash-revocation). Used by two-phase rotation to detect concurrent
    /// revocations and avoid double-rotation.
    pub generation: u64,
}

/// Maps X25519 static public keys to daemon identities and clearance levels.
///
/// Populated once at `daemon-profile` startup; mutable via `RwLock` for
/// rotation and revocation at runtime.
#[derive(Debug, Clone, Default)]
pub struct ClearanceRegistry {
    entries: HashMap<[u8; 32], DaemonClearance>,
}

impl ClearanceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register a daemon's public key with its name and clearance level.
    /// Initial generation is 0.
    pub fn register(&mut self, pubkey: [u8; 32], name: String, level: SecurityLevel) {
        self.entries.insert(
            pubkey,
            DaemonClearance {
                name,
                security_level: level,
                generation: 0,
            },
        );
    }

    /// Look up a daemon by its public key. Returns `None` for unregistered keys.
    #[must_use]
    pub fn lookup(&self, pubkey: &[u8; 32]) -> Option<&DaemonClearance> {
        self.entries.get(pubkey)
    }

    /// Update a daemon's public key in the registry (key rotation).
    ///
    /// Removes the old entry and inserts the new one with the same name/level
    /// and an incremented generation counter.
    /// Returns `true` if the old key was found and replaced.
    pub fn rotate_key(&mut self, old_pubkey: &[u8; 32], new_pubkey: [u8; 32]) -> bool {
        if let Some(mut entry) = self.entries.remove(old_pubkey) {
            entry.generation += 1;
            self.entries.insert(new_pubkey, entry);
            true
        } else {
            false
        }
    }

    /// Revoke a daemon's public key (remove from registry).
    /// Returns the removed entry (including generation) so callers can
    /// re-register with the incremented generation.
    pub fn revoke(&mut self, pubkey: &[u8; 32]) -> Option<DaemonClearance> {
        self.entries.remove(pubkey)
    }

    /// Register with an explicit generation (used after revoke-then-re-register).
    pub fn register_with_generation(
        &mut self,
        pubkey: [u8; 32],
        name: String,
        level: SecurityLevel,
        generation: u64,
    ) {
        self.entries.insert(
            pubkey,
            DaemonClearance {
                name,
                security_level: level,
                generation,
            },
        );
    }

    /// Find a daemon entry by name (linear scan, acceptable for <10 daemons).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<(&[u8; 32], &DaemonClearance)> {
        self.entries.iter().find(|(_, v)| v.name == name)
    }

    /// Snapshot all daemon generations. Used by rotation phase 1 to record
    /// the baseline before the grace period starts.
    #[must_use]
    pub fn snapshot_generations(&self) -> HashMap<String, u64> {
        self.entries
            .values()
            .map(|e| (e.name.clone(), e.generation))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::SecurityLevel;

    #[test]
    fn registry_lookup_hit() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xAA; 32];
        reg.register(key, "daemon-secrets".into(), SecurityLevel::SecretsOnly);
        let entry = reg.lookup(&key).unwrap();
        assert_eq!(entry.name, "daemon-secrets");
        assert_eq!(entry.security_level, SecurityLevel::SecretsOnly);
        assert_eq!(entry.generation, 0);
    }

    #[test]
    fn registry_lookup_miss() {
        let reg = ClearanceRegistry::new();
        assert!(reg.lookup(&[0xBB; 32]).is_none());
    }

    #[test]
    fn registry_overwrite() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xCC; 32];
        reg.register(key, "daemon-wm".into(), SecurityLevel::Internal);
        reg.register(key, "daemon-secrets".into(), SecurityLevel::SecretsOnly);
        let entry = reg.lookup(&key).unwrap();
        assert_eq!(entry.name, "daemon-secrets");
        assert_eq!(entry.security_level, SecurityLevel::SecretsOnly);
    }

    #[test]
    fn rotate_key_increments_generation() {
        let mut reg = ClearanceRegistry::new();
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];
        reg.register(old_key, "daemon-wm".into(), SecurityLevel::Internal);

        assert!(reg.rotate_key(&old_key, new_key));
        let entry = reg.lookup(&new_key).unwrap();
        assert_eq!(entry.generation, 1);
        assert!(reg.lookup(&old_key).is_none());
    }

    #[test]
    fn revoke_returns_entry_with_generation() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xAA; 32];
        reg.register(key, "daemon-wm".into(), SecurityLevel::Internal);

        // Rotate once to get generation 1.
        let new_key = [0xBB; 32];
        reg.rotate_key(&key, new_key);

        // Revoke returns the entry with generation 1.
        let entry = reg.revoke(&new_key).unwrap();
        assert_eq!(entry.generation, 1);
        assert!(reg.lookup(&new_key).is_none());
    }

    #[test]
    fn snapshot_generations_captures_all_daemons() {
        let mut reg = ClearanceRegistry::new();
        reg.register([0xAA; 32], "daemon-wm".into(), SecurityLevel::Internal);
        reg.register(
            [0xBB; 32],
            "daemon-secrets".into(),
            SecurityLevel::SecretsOnly,
        );

        // Rotate daemon-wm once.
        reg.rotate_key(&[0xAA; 32], [0xCC; 32]);

        let snap = reg.snapshot_generations();
        assert_eq!(snap["daemon-wm"], 1);
        assert_eq!(snap["daemon-secrets"], 0);
    }

    #[test]
    fn register_with_generation_preserves_counter() {
        let mut reg = ClearanceRegistry::new();
        let key = [0xDD; 32];
        reg.register_with_generation(key, "daemon-wm".into(), SecurityLevel::Internal, 5);
        assert_eq!(reg.lookup(&key).unwrap().generation, 5);
    }

    // SECURITY INVARIANT: Rotating a key that does not exist in the registry
    // must return false and leave the registry unchanged — never silently succeed.
    #[test]
    fn rotate_missing_key_returns_false() {
        let mut reg = ClearanceRegistry::new();
        assert!(!reg.rotate_key(&[0xFF; 32], [0xAA; 32]));
        assert!(reg.lookup(&[0xFF; 32]).is_none());
        assert!(reg.lookup(&[0xAA; 32]).is_none());
    }

    // SECURITY INVARIANT: Each rotation must increment the generation counter
    // exactly once. Two rotations must produce generation 2, not 1 or 0.
    #[test]
    fn double_rotation_increments_generation_twice() {
        let mut reg = ClearanceRegistry::new();
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let key_c = [0xCC; 32];
        reg.register(key_a, "daemon-wm".into(), SecurityLevel::Internal);

        assert!(reg.rotate_key(&key_a, key_b));
        assert!(reg.rotate_key(&key_b, key_c));

        let entry = reg.lookup(&key_c).unwrap();
        assert_eq!(entry.generation, 2);
        assert!(reg.lookup(&key_a).is_none());
        assert!(reg.lookup(&key_b).is_none());
    }

    // SECURITY INVARIANT: Crash-restart path must preserve generation continuity.
    // revoke returns the entry with current generation; re-register with gen+1
    // ensures phase 2 detects the revocation via generation mismatch.
    #[test]
    fn revoke_then_reregister_preserves_generation_continuity() {
        let mut reg = ClearanceRegistry::new();
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let key_c = [0xCC; 32];

        reg.register(key_a, "daemon-wm".into(), SecurityLevel::Internal);
        reg.rotate_key(&key_a, key_b); // gen = 1

        let revoked = reg.revoke(&key_b).unwrap();
        assert_eq!(revoked.generation, 1);

        reg.register_with_generation(
            key_c,
            "daemon-wm".into(),
            SecurityLevel::Internal,
            revoked.generation + 1,
        );
        assert_eq!(reg.lookup(&key_c).unwrap().generation, 2);
    }

    // SECURITY INVARIANT: Any key NOT in the registry must return None on lookup.
    // The server assigns Open clearance to None — elevated clearance must never
    // be granted to unregistered keys.
    #[test]
    fn unregistered_keys_always_return_none() {
        let mut reg = ClearanceRegistry::new();
        reg.register([0xAA; 32], "daemon-wm".into(), SecurityLevel::Internal);
        reg.register(
            [0xBB; 32],
            "daemon-secrets".into(),
            SecurityLevel::SecretsOnly,
        );

        // Spot-check several unregistered keys.
        for byte in [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xCC, 0xDD, 0xEE, 0xFF,
        ] {
            assert!(
                reg.lookup(&[byte; 32]).is_none(),
                "key [{byte:#04X}; 32] should not be in registry"
            );
        }
    }

    // SECURITY INVARIANT: Revoking a key that doesn't exist must return None,
    // not panic or return a stale entry.
    #[test]
    fn revoke_missing_key_returns_none() {
        let mut reg = ClearanceRegistry::new();
        assert!(reg.revoke(&[0xFF; 32]).is_none());
    }

    // SECURITY INVARIANT: find_by_name must return the correct key even after
    // rotation changes the underlying pubkey.
    #[test]
    fn find_by_name_tracks_through_rotation() {
        let mut reg = ClearanceRegistry::new();
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        reg.register(key_a, "daemon-wm".into(), SecurityLevel::Internal);

        reg.rotate_key(&key_a, key_b);
        let (found_key, entry) = reg.find_by_name("daemon-wm").unwrap();
        assert_eq!(*found_key, key_b);
        assert_eq!(entry.generation, 1);
    }
}
