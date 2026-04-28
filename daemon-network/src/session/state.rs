//! Per-peer session state with composite trust scoring.

use crate::noise::state::NoiseTransport;
use crate::session::replay::ReplayWindow;
use crate::transport::frame::WireSessionId;
use core_types::TofuTrustLevel;
use std::net::SocketAddr;
use std::time::Instant;

/// Per-peer session state.
///
/// All mutable fields use plain types (not Atomic) because `DashMap` provides
/// exclusive access via `RefMut` on `get_mut()`. Atomics would add overhead
/// without benefit when the caller already holds an exclusive lock.
pub struct PeerState {
    /// Wire session identifier (12-byte random).
    pub session_id: WireSessionId,
    /// Remote peer's Noise static public key (32 bytes).
    pub remote_static_key: [u8; 32],
    /// Current remote address (updated on path migration).
    pub remote_addr: SocketAddr,
    /// Noise transport state (encrypt/decrypt).
    pub transport: NoiseTransport,
    /// Per-direction replay window.
    pub replay_window: ReplayWindow,
    /// TOFU trust level for this peer.
    pub tofu_trust_level: TofuTrustLevel,
    /// When this session was created.
    pub created_at: Instant,
    /// Last time we received any valid frame.
    pub last_recv_at: Instant,
    /// Last time we sent any frame.
    pub last_send_at: Instant,
    /// Last time we received productive data (not keepalive).
    pub last_productive_data_at: Instant,
    /// AEAD decryption failures (potential active attack indicator).
    pub aead_failure_count: u32,
    /// Handshake failures from this peer's address.
    pub handshake_failure_count: u32,
    /// Monotonic send sequence number.
    pub send_seq: u32,
    /// Bytes sent to this peer.
    pub bytes_sent: u64,
    /// Bytes received from this peer.
    pub bytes_received: u64,
}

impl PeerState {
    /// Create a new peer session state after completed handshake.
    #[must_use]
    pub fn new(
        session_id: WireSessionId,
        remote_static_key: [u8; 32],
        remote_addr: SocketAddr,
        transport: NoiseTransport,
        tofu_trust_level: TofuTrustLevel,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            remote_static_key,
            remote_addr,
            transport,
            replay_window: ReplayWindow::new(),
            tofu_trust_level,
            created_at: now,
            last_recv_at: now,
            last_send_at: now,
            last_productive_data_at: now,
            aead_failure_count: 0,
            handshake_failure_count: 0,
            send_seq: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Advance and return the next send sequence number.
    pub fn next_send_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq += 1;
        seq
    }

    /// Record received bytes.
    pub fn record_recv(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.last_recv_at = Instant::now();
    }

    /// Record received productive data (not keepalive).
    pub fn record_productive_recv(&mut self, bytes: u64) {
        self.record_recv(bytes);
        self.last_productive_data_at = Instant::now();
    }

    /// Record sent bytes.
    pub fn record_send(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.last_send_at = Instant::now();
    }

    /// Increment AEAD failure count.
    pub fn record_aead_failure(&mut self) {
        self.aead_failure_count += 1;
    }

    /// Compute composite eviction score.
    ///
    /// Lower score = higher eviction priority.
    /// Failures weight heavily negative. Idle time moderate negative.
    /// Productive data positive.
    #[must_use]
    pub fn eviction_score(&self) -> f64 {
        let aead_fails = f64::from(self.aead_failure_count);
        let hs_fails = f64::from(self.handshake_failure_count);
        let idle_secs = self.last_recv_at.elapsed().as_secs_f64();
        #[allow(clippy::cast_precision_loss)]
        let productive_bytes = self.bytes_received as f64;

        -10.0 * aead_fails - 5.0 * hs_fails - idle_secs + 0.001 * productive_bytes
    }

    /// Seconds since session creation.
    #[must_use]
    pub fn age_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }

    /// Seconds since last received frame.
    #[must_use]
    pub fn idle_secs(&self) -> u64 {
        self.last_recv_at.elapsed().as_secs()
    }

    /// Whether the send sequence is approaching exhaustion (needs rekey).
    #[must_use]
    pub fn needs_rekey(&self) -> bool {
        self.send_seq >= u32::MAX - 1024
            || self.replay_window.top() >= u32::MAX - 1024
    }

    /// Whether this transport was created by the initiator (dialer) side.
    #[must_use]
    pub fn is_initiator(&self) -> bool {
        self.transport.is_initiator()
    }

    /// Remote static key as hex string.
    #[must_use]
    pub fn remote_key_hex(&self) -> String {
        hex::encode(self.remote_static_key)
    }
}

impl std::fmt::Debug for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerState")
            .field("session_id", &self.session_id)
            .field("remote_addr", &self.remote_addr)
            .field("remote_key", &format_args!("{}…", &self.remote_key_hex()[..16]))
            .field("initiator", &self.is_initiator())
            .field("tofu_trust_level", &self.tofu_trust_level)
            .field("age_secs", &self.age_secs())
            .field("idle_secs", &self.idle_secs())
            .field("aead_failures", &self.aead_failure_count)
            .field("send_seq", &self.send_seq)
            .field("recv_top", &self.replay_window.top())
            .finish_non_exhaustive()
    }
}
