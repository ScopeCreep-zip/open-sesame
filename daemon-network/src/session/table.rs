//! Concurrent peer session table with composite-score eviction.
//!
//! Primary index: `SessionId → PeerState` (`DashMap`).
//! Secondary index: `SocketAddr → SessionId` (`DashMap`) for fast frame dispatch.
//! Address index updated atomically on session creation, path change, and eviction.

use crate::session::state::PeerState;
use crate::transport::frame::SessionId;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

/// Bounded concurrent session table.
pub struct PeerTable {
    /// Primary: session ID → peer state.
    sessions: DashMap<[u8; 12], PeerState>,
    /// Secondary: socket address → session ID (for UDP frame dispatch).
    addr_index: DashMap<SocketAddr, SessionId>,
    /// Maximum concurrent sessions.
    max_sessions: u32,
    /// Current session count (atomic for lock-free reads).
    count: AtomicU32,
}

impl PeerTable {
    /// Create a new peer table with the given capacity limit.
    #[must_use]
    pub fn new(max_sessions: u32) -> Self {
        Self {
            sessions: DashMap::with_capacity(max_sessions as usize),
            addr_index: DashMap::with_capacity(max_sessions as usize),
            max_sessions,
            count: AtomicU32::new(0),
        }
    }

    /// Insert a new session. Returns `false` if the table is full after eviction attempts.
    pub fn insert(&self, state: PeerState) -> bool {
        if self.count.load(Ordering::Relaxed) >= self.max_sessions {
            // Try eviction before rejecting.
            if !self.evict_one() {
                return false;
            }
        }

        let sid = state.session_id;
        let addr = state.remote_addr;
        self.sessions.insert(sid.0, state);
        self.addr_index.insert(addr, sid);
        self.count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Look up a session by session ID.
    #[must_use]
    pub fn get(&self, sid: &SessionId) -> Option<dashmap::mapref::one::Ref<'_, [u8; 12], PeerState>> {
        self.sessions.get(&sid.0)
    }

    /// Look up a mutable session by session ID.
    #[must_use]
    pub fn get_mut(&self, sid: &SessionId) -> Option<dashmap::mapref::one::RefMut<'_, [u8; 12], PeerState>> {
        self.sessions.get_mut(&sid.0)
    }

    /// Look up session ID by socket address (for incoming UDP frames).
    #[must_use]
    pub fn lookup_addr(&self, addr: &SocketAddr) -> Option<SessionId> {
        self.addr_index.get(addr).map(|r| *r.value())
    }

    /// Update address index on path migration.
    pub fn update_addr(&self, sid: &SessionId, old_addr: &SocketAddr, new_addr: SocketAddr) {
        self.addr_index.remove(old_addr);
        self.addr_index.insert(new_addr, *sid);
        if let Some(mut peer) = self.sessions.get_mut(&sid.0) {
            peer.remote_addr = new_addr;
        }
    }

    /// Remove a session by session ID.
    pub fn remove(&self, sid: &SessionId) {
        if let Some((_, state)) = self.sessions.remove(&sid.0) {
            self.addr_index.remove(&state.remote_addr);
            self.count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Current number of active sessions.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Collect all session IDs (snapshot).
    #[must_use]
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions
            .iter()
            .map(|r| SessionId(*r.key()))
            .collect()
    }

    /// Find sessions idle longer than `secs`.
    #[must_use]
    pub fn idle_sessions(&self, secs: u64) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter(|r| r.value().idle_secs() > secs)
            .map(|r| SessionId(*r.key()))
            .collect()
    }

    /// Find sessions that need rekeying (sequence exhaustion or age).
    #[must_use]
    pub fn sessions_needing_rekey(&self, max_age_secs: u64) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter(|r| r.value().needs_rekey() || r.value().age_secs() > max_age_secs)
            .map(|r| SessionId(*r.key()))
            .collect()
    }

    /// Evict the session with the lowest composite score.
    ///
    /// Returns `true` if a session was evicted.
    fn evict_one(&self) -> bool {
        let mut worst_sid: Option<[u8; 12]> = None;
        let mut worst_score = f64::MAX;

        for entry in &self.sessions {
            let score = entry.value().eviction_score();
            if score < worst_score {
                worst_score = score;
                worst_sid = Some(*entry.key());
            }
        }

        if let Some(sid) = worst_sid {
            self.remove(&SessionId(sid));
            tracing::info!(
                session = %SessionId(sid),
                score = worst_score,
                "evicted session (table full)"
            );
            true
        } else {
            false
        }
    }
}

impl std::fmt::Debug for PeerTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerTable")
            .field("sessions", &self.len())
            .field("max", &self.max_sessions)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // We can't easily construct a NoiseTransport in tests without a full
    // handshake, so we test the table logic that doesn't depend on it.

    #[test]
    fn new_table_is_empty() {
        let table = PeerTable::new(256);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn session_ids_empty() {
        let table = PeerTable::new(10);
        assert!(table.session_ids().is_empty());
    }

    #[test]
    fn idle_sessions_empty_table() {
        let table = PeerTable::new(10);
        assert!(table.idle_sessions(0).is_empty());
    }

    #[test]
    fn lookup_missing_addr() {
        let table = PeerTable::new(10);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert!(table.lookup_addr(&addr).is_none());
    }

    #[test]
    fn get_missing_session() {
        let table = PeerTable::new(10);
        let sid = SessionId::random();
        assert!(table.get(&sid).is_none());
    }
}
