//! Dial queue with back-off, deduplication, and priority.
//!
//! All discovery backends feed `DialEntry` values into this queue.
//! `daemon-network` consumes entries and initiates TCP handshakes.

use dashmap::DashSet;
use std::collections::BinaryHeap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Source of a dial target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiscoverySource {
    /// Pre-configured seed list.
    Bootstrap = 3,
    /// DNS SRV record.
    DnsSrv = 2,
    /// BEP-44 Mainline DHT.
    Bep44 = 1,
    /// mDNS local link.
    Mdns = 0,
}

/// A dial target in the queue.
#[derive(Debug, Clone)]
pub struct DialEntry {
    /// Target address.
    pub addr: SocketAddr,
    /// Discovery source (higher = higher priority).
    pub source: DiscoverySource,
    /// Advisory public key (for TOFU pre-population).
    pub advisory_pubkey_hex: Option<String>,
    /// When to next attempt dialing.
    pub next_dial_at: Instant,
    /// Consecutive failures (for exponential back-off).
    pub consecutive_failures: u32,
}

impl DialEntry {
    /// Compute back-off duration based on consecutive failures.
    #[must_use]
    pub fn backoff(&self) -> Duration {
        match self.consecutive_failures {
            0 => Duration::from_secs(0),
            1 => Duration::from_secs(30),
            2 => Duration::from_secs(60),
            3 => Duration::from_secs(120),
            4 => Duration::from_secs(300),
            _ => Duration::from_secs(900), // 15 min cap
        }
    }
}

// Priority: higher source priority first, then earliest next_dial_at.
impl PartialEq for DialEntry {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl Eq for DialEntry {}

impl PartialOrd for DialEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DialEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source
            .cmp(&other.source)
            .then(other.next_dial_at.cmp(&self.next_dial_at))
    }
}

/// Bounded, deduplicating dial queue.
pub struct DialQueue {
    heap: Mutex<BinaryHeap<DialEntry>>,
    dedup: DashSet<SocketAddr>,
    max_entries: usize,
}

impl DialQueue {
    /// Create a new dial queue with the given capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::with_capacity(max_entries)),
            dedup: DashSet::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Push a dial entry. Returns `false` if the queue is full or the address is a duplicate.
    pub fn push(&self, entry: DialEntry) -> bool {
        if self.dedup.contains(&entry.addr) {
            return false;
        }
        let mut heap = self.heap.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if heap.len() >= self.max_entries {
            return false;
        }
        self.dedup.insert(entry.addr);
        heap.push(entry);
        true
    }

    /// Pop the highest-priority entry that is ready to dial (`next_dial_at` <= now).
    ///
    /// # Panics
    ///
    /// Cannot panic — `heap.pop()` is only called after `heap.peek()` confirms non-empty.
    #[must_use]
    pub fn pop_ready(&self) -> Option<DialEntry> {
        let mut heap = self.heap.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = heap.peek()
            && entry.next_dial_at <= Instant::now()
        {
            let entry = heap.pop().unwrap();
            self.dedup.remove(&entry.addr);
            return Some(entry);
        }
        None
    }

    /// Re-enqueue a failed dial with incremented back-off.
    pub fn requeue_failed(&self, mut entry: DialEntry) {
        self.dedup.remove(&entry.addr);
        entry.consecutive_failures += 1;
        entry.next_dial_at = Instant::now() + entry.backoff();
        self.push(entry);
    }

    /// Current queue depth.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Remove a pending dial entry by address.
    ///
    /// Called on `PeerRemoved` to cancel pending dial attempts for a departed
    /// peer. Returns `true` if an entry was found and removed.
    pub fn remove(&self, addr: &SocketAddr) -> bool {
        if self.dedup.remove(addr).is_none() {
            return false;
        }
        let mut heap = self.heap.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = heap.len();
        let entries: Vec<DialEntry> = heap.drain().filter(|e| e.addr != *addr).collect();
        *heap = BinaryHeap::from(entries);
        heap.len() < before
    }

    /// Snapshot all addresses currently in the queue.
    ///
    /// Used to seed SWIM gossip with known peers at startup.
    #[must_use]
    pub fn snapshot_addrs(&self) -> Vec<SocketAddr> {
        let heap = self.heap.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        heap.iter().map(|e| e.addr).collect()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for DialQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialQueue")
            .field("len", &self.len())
            .field("max", &self.max_entries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(addr: &str, source: DiscoverySource) -> DialEntry {
        DialEntry {
            addr: addr.parse().unwrap(),
            source,
            advisory_pubkey_hex: None,
            next_dial_at: Instant::now(),
            consecutive_failures: 0,
        }
    }

    #[test]
    fn push_and_pop() {
        let q = DialQueue::new(10);
        assert!(q.push(entry("10.0.0.1:48627", DiscoverySource::Mdns)));
        assert_eq!(q.len(), 1);
        let e = q.pop_ready().unwrap();
        assert_eq!(e.addr.to_string(), "10.0.0.1:48627");
        assert!(q.is_empty());
    }

    #[test]
    fn dedup_rejects_duplicate() {
        let q = DialQueue::new(10);
        assert!(q.push(entry("10.0.0.1:48627", DiscoverySource::Mdns)));
        assert!(!q.push(entry("10.0.0.1:48627", DiscoverySource::Bootstrap)));
    }

    #[test]
    fn priority_bootstrap_over_mdns() {
        let q = DialQueue::new(10);
        q.push(entry("10.0.0.1:48627", DiscoverySource::Mdns));
        q.push(entry("10.0.0.2:48627", DiscoverySource::Bootstrap));
        let first = q.pop_ready().unwrap();
        assert_eq!(first.addr.to_string(), "10.0.0.2:48627");
    }

    #[test]
    fn full_queue_rejects() {
        let q = DialQueue::new(2);
        assert!(q.push(entry("10.0.0.1:1", DiscoverySource::Mdns)));
        assert!(q.push(entry("10.0.0.2:2", DiscoverySource::Mdns)));
        assert!(!q.push(entry("10.0.0.3:3", DiscoverySource::Mdns)));
    }

    #[test]
    fn requeue_increments_failures() {
        let q = DialQueue::new(10);
        let e = entry("10.0.0.1:48627", DiscoverySource::Mdns);
        q.push(e.clone());
        let popped = q.pop_ready().unwrap();
        assert_eq!(popped.consecutive_failures, 0);
        q.requeue_failed(popped);
        // Won't be ready immediately due to back-off.
        assert!(q.pop_ready().is_none());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn remove_by_address() {
        let q = DialQueue::new(10);
        q.push(entry("10.0.0.1:48627", DiscoverySource::Mdns));
        q.push(entry("10.0.0.2:48627", DiscoverySource::Bootstrap));
        assert_eq!(q.len(), 2);
        assert!(q.remove(&"10.0.0.1:48627".parse().unwrap()));
        assert_eq!(q.len(), 1);
        // Removed address can be re-added (dedup cleared).
        assert!(q.push(entry("10.0.0.1:48627", DiscoverySource::Mdns)));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let q = DialQueue::new(10);
        assert!(!q.remove(&"10.0.0.1:48627".parse().unwrap()));
    }

    #[test]
    fn backoff_schedule() {
        let mut e = entry("10.0.0.1:48627", DiscoverySource::Mdns);
        assert_eq!(e.backoff(), Duration::from_secs(0));
        e.consecutive_failures = 1;
        assert_eq!(e.backoff(), Duration::from_secs(30));
        e.consecutive_failures = 5;
        assert_eq!(e.backoff(), Duration::from_secs(900));
    }
}
