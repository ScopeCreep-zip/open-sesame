//! Foca SWIM runtime integration.
//!
//! Uses `foca::AccumulatingRuntime` to buffer send/schedule/notify events,
//! then drains them into `daemon-network`'s transport layer.
//!
//! The pattern:
//! 1. Interact with `Foca` (`handle_data`, `handle_timer`, `announce`)
//! 2. Drain `runtime.to_send()` → send via `daemon-network`'s UDP socket
//! 3. Drain `runtime.to_schedule()` → schedule via tokio timers
//! 4. Drain `runtime.to_notify()` → emit `MemberUp`/`MemberDown` events

// Re-export AccumulatingRuntime — no custom impl needed.
// foca provides a complete runtime that accumulates events for async drain.
pub use foca::AccumulatingRuntime;

use crate::gossip::swim::PeerId;

/// Type alias for the foca instance with our identity, codec, and RNG.
///
/// Uses `rand::rngs::SmallRng` for SWIM's random member selection —
/// not cryptographic, just needs uniform distribution for probe targets.
pub type SwimInstance =
    foca::Foca<PeerId, foca::PostcardCodec, rand::rngs::SmallRng, foca::NoCustomBroadcast>;

/// Create a new SWIM instance with the given identity and config.
#[must_use]
pub fn new_swim(identity: PeerId, config: foca::Config) -> SwimInstance {
    use rand::SeedableRng;
    let rng = rand::rngs::SmallRng::from_os_rng();
    foca::Foca::new(identity, config, rng, foca::PostcardCodec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::swim::{PeerId, default_swim_config};
    use std::net::SocketAddr;

    #[test]
    fn create_swim_instance() {
        let id = PeerId {
            addr: "10.0.0.1:48627".parse::<SocketAddr>().unwrap(),
            generation: 0,
            key_prefix: "aabb".into(),
        };
        let config = default_swim_config();
        let swim = new_swim(id, config);
        assert_eq!(swim.num_members(), 0);
    }

    #[test]
    fn accumulating_runtime_starts_empty() {
        let mut runtime = AccumulatingRuntime::<PeerId>::new();
        assert!(runtime.to_send().is_none());
        assert!(runtime.to_schedule().is_none());
        assert!(runtime.to_notify().is_none());
        assert_eq!(runtime.backlog(), 0);
    }
}
