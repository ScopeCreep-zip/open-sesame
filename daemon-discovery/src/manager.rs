//! Discovery manager composing all backends into a unified dial queue.
//!
//! Orchestrates bootstrap seed loading, mDNS, BEP-44, DNS SRV, and
//! gossip — feeding discovered peers into the `DialQueue` that
//! `daemon-network` consumes.

use crate::queue::{DialEntry, DialQueue, DiscoverySource};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Events emitted by the discovery manager to `daemon-network`.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A new peer address discovered — should be added to the dial queue.
    PeerDiscovered {
        addr: SocketAddr,
        source: DiscoverySource,
        advisory_pubkey_hex: Option<String>,
    },
    /// A peer address is no longer valid (goodbye announcement, TTL expiry).
    PeerRemoved {
        addr: SocketAddr,
        source: DiscoverySource,
    },
}

/// The discovery manager. Owns the dial queue and coordinates backends.
pub struct DiscoveryManager {
    /// Shared dial queue that `daemon-network` reads from.
    pub queue: Arc<DialQueue>,
    /// Channel for discovery events.
    event_tx: tokio::sync::mpsc::Sender<DiscoveryEvent>,
    /// Count of mDNS peers discovered (atomic for lock-free reads).
    mdns_peer_count: std::sync::atomic::AtomicU32,
}

impl DiscoveryManager {
    /// Create a new discovery manager with a bounded dial queue.
    #[must_use]
    pub fn new(
        max_queue_entries: usize,
        event_tx: tokio::sync::mpsc::Sender<DiscoveryEvent>,
    ) -> Self {
        Self {
            queue: Arc::new(DialQueue::new(max_queue_entries)),
            event_tx,
            mdns_peer_count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Add a discovered peer to the dial queue and emit an event.
    pub fn add_peer(
        &self,
        addr: SocketAddr,
        source: DiscoverySource,
        pubkey_hex: Option<String>,
    ) {
        let entry = DialEntry {
            addr,
            source,
            advisory_pubkey_hex: pubkey_hex.clone(),
            next_dial_at: Instant::now(),
            consecutive_failures: 0,
        };

        if self.queue.push(entry) {
            if source == DiscoverySource::Mdns {
                self.mdns_peer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let _ = self.event_tx.try_send(DiscoveryEvent::PeerDiscovered {
                addr,
                source,
                advisory_pubkey_hex: pubkey_hex,
            });
        }
    }

    /// Load bootstrap seeds into the dial queue.
    pub fn load_bootstrap(&self, targets: &[crate::bootstrap::DialTarget]) {
        for target in targets {
            self.add_peer(
                target.addr,
                DiscoverySource::Bootstrap,
                target.public_key_hex.clone(),
            );
        }
        tracing::info!(
            count = targets.len(),
            queue_depth = self.queue.len(),
            "bootstrap seeds loaded into dial queue"
        );
    }

    /// Current dial queue depth.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }

    /// Number of mDNS peers discovered.
    #[must_use]
    pub fn mdns_peer_count(&self) -> u32 {
        self.mdns_peer_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::fmt::Debug for DiscoveryManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryManager")
            .field("queue_depth", &self.queue_depth())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_peer_emits_event() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let mgr = DiscoveryManager::new(100, tx);

        let addr: SocketAddr = "10.0.0.1:48627".parse().unwrap();
        mgr.add_peer(addr, DiscoverySource::Mdns, Some("aabb".into()));

        let event = rx.try_recv().unwrap();
        match event {
            DiscoveryEvent::PeerDiscovered {
                addr: a,
                source,
                advisory_pubkey_hex,
            } => {
                assert_eq!(a, addr);
                assert_eq!(source, DiscoverySource::Mdns);
                assert_eq!(advisory_pubkey_hex, Some("aabb".into()));
            }
            _ => panic!("wrong event type"),
        }

        assert_eq!(mgr.queue_depth(), 1);
    }

    #[tokio::test]
    async fn load_bootstrap_populates_queue() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mgr = DiscoveryManager::new(100, tx);

        let targets = vec![
            crate::bootstrap::DialTarget {
                addr: "10.0.0.1:48627".parse().unwrap(),
                public_key_hex: Some("aa".into()),
                signing_pubkey_hex: None,
                display_name: Some("peer1".into()),
                dial_on_start: true,
            },
            crate::bootstrap::DialTarget {
                addr: "10.0.0.2:48627".parse().unwrap(),
                public_key_hex: None,
                signing_pubkey_hex: None,
                display_name: None,
                dial_on_start: false,
            },
        ];

        mgr.load_bootstrap(&targets);
        assert_eq!(mgr.queue_depth(), 2);
    }
}
