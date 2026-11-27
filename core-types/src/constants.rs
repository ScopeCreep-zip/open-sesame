use std::time::{Instant, SystemTime};

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

/// Canonical name for the default profile created during `sesame init`.
///
/// All crates that need to reference the default profile should use this constant
/// rather than hardcoding `"default"` to prevent silent divergence.
pub const DEFAULT_PROFILE_NAME: &str = "default";

// ============================================================================
// Timestamp
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    /// Monotonic counter for ordering within a single daemon lifecycle.
    /// Nanoseconds since daemon start.
    pub monotonic_ns: u64,
    /// Wall clock for cross-daemon and cross-restart ordering.
    /// Milliseconds since Unix epoch; `None` when the system clock reads
    /// before the epoch.
    pub wall_ms: Option<u64>,
}

impl Timestamp {
    /// The time now: elapsed since `epoch` (daemon start) and the system
    /// wall clock.
    #[must_use]
    pub fn now(epoch: Instant) -> Self {
        Self::at(epoch, SystemTime::now())
    }

    /// The time elapsed since `epoch`, with the wall clock reading `wall`.
    fn at(epoch: Instant, wall: SystemTime) -> Self {
        // Saturating: u64 nanoseconds of uptime last 584 years, u64
        // milliseconds of wall clock 584 million.
        Self {
            monotonic_ns: u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX),
            wall_ms: wall
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_wall_clock_before_the_epoch_is_absent_not_zero() {
        let epoch = Instant::now();
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(Timestamp::at(epoch, before).wall_ms, None);
        let after = SystemTime::UNIX_EPOCH + Duration::from_millis(5);
        assert_eq!(Timestamp::at(epoch, after).wall_ms, Some(5));
    }
}
