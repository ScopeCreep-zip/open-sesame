//! Daemon state and identity types.
//!
//! `DaemonState` holds all shared subsystems that dispatch functions operate on.
//! Extracted from `main.rs` so that integration tests can construct a
//! `DaemonState` directly without running the full daemon lifecycle.

use crate::audit::AuditLog;
use crate::flood::cookie::CookieChallenger;
use crate::flood::pow::PowChallenger;
use crate::metrics::Metrics;
use crate::ratelimit::bucket::TokenBucket;
use crate::session::table::PeerTable;
use crate::transport::tcp::TcpInbound;
use std::sync::Arc;

/// Installation identity loaded from `installation.toml` at startup.
pub struct InstallationIdentity {
    /// Installation UUID as string.
    pub id: String,
    /// X25519 network transport public key (32 bytes).
    pub network_pubkey: [u8; 32],
    /// Ed25519 signing public key (32 bytes), if available.
    pub signing_pubkey: Option<[u8; 32]>,
}

/// Shared daemon state passed to all dispatch and lifecycle functions.
///
/// Every field is either `Arc`-wrapped (for sharing across spawned tasks)
/// or a plain value (for single-owner state like the discovery receiver).
pub struct DaemonState {
    /// Dual-stack UDP socket for transport frames.
    pub udp_socket: Arc<tokio::net::UdpSocket>,
    /// Concurrent peer session table.
    pub peer_table: Arc<PeerTable>,
    /// TOFU identity store (`SQLite`, mutex-protected).
    pub tofu_store: Arc<std::sync::Mutex<crate::tofu::store::TofuStore>>,
    /// Stateless BLAKE3 cookie challenger.
    pub cookie: Arc<std::sync::Mutex<CookieChallenger>>,
    /// Equi-X `PoW` second-tier `DoS` gate.
    pub pow: Arc<std::sync::Mutex<PowChallenger>>,
    /// Global handshake rate limiter.
    pub global_hs_limiter: Arc<TokenBucket>,
    /// Prometheus-style metrics.
    pub metrics: Arc<Metrics>,
    /// BLAKE3-chained audit log.
    pub audit: Arc<AuditLog>,
    /// Noise static keypair for network identity.
    pub local_keypair: Arc<snow::Keypair>,
    /// IPC bus client for inter-daemon communication.
    pub bus_client: Arc<tokio::sync::Mutex<core_ipc::BusClient>>,
    /// Discovery manager (owns the dial queue, coordinates backends).
    pub discovery: Arc<daemon_discovery::manager::DiscoveryManager>,
    /// Receiver for discovery events (`PeerDiscovered`, `PeerRemoved`).
    /// Consumed by the main event loop for immediate dial and session teardown.
    pub discovery_rx: tokio::sync::mpsc::Receiver<daemon_discovery::manager::DiscoveryEvent>,
    /// Listen port for the transport socket.
    pub listen_port: u16,
    /// Seconds after which an idle session is closed.
    pub idle_timeout_secs: u64,
    /// Seconds after which a session is flagged for rekey.
    pub rekey_interval_secs: u64,
    /// Whether BEP-44 DHT publishing is enabled.
    pub bep44_enabled: bool,
    /// DNS SRV domains for enterprise discovery (hot-reloadable).
    pub dns_srv_domains: Arc<std::sync::RwLock<Vec<String>>>,
    /// This installation's identity (ID, keys).
    pub identity: InstallationIdentity,
    /// Ed25519 signing seed (32 bytes, zeroized on drop).
    pub signing_seed: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// Channel sender for TCP inbound events (post-handshake frame loop).
    pub tcp_tx: tokio::sync::mpsc::Sender<TcpInbound>,
    /// If true, reject first-contact TOFU pins from unknown peers.
    /// Only `Bootstrap` and `Endorsed` peers (pre-configured or coordinator-
    /// signed) are accepted. Prevents auto-pinning on untrusted networks.
    pub require_known_peers: bool,
    /// HMAC-BLAKE3 key for SWIM gossip authentication (from bootstrap.json
    /// `gossip_secret`). When `None`, SWIM gossip is disabled entirely —
    /// unauthenticated gossip is not permitted.
    pub gossip_hmac_key: Option<[u8; 32]>,
    /// Per-peer replication watermark cache. Key: peer installation ID.
    /// Value: HLC watermark JSON from the last `VaultReplicationPullResponse`.
    /// Used to avoid re-fetching the entire log on each pull cycle.
    pub replication_watermarks: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// Per-installation rate limiter for received replication entries (E-02).
    /// Keyed on installation ID (not session ID) to prevent bypass via
    /// multiple sessions from the same identity.
    pub replication_rate_limiter:
        std::sync::Mutex<std::collections::HashMap<String, governor::DefaultDirectRateLimiter>>,
    /// Channel for forwarding received replication data from sync UDP/TCP
    /// handlers to the async event loop for IPC publishing. The sync handlers
    /// can't call `bus_client.publish().await` directly.
    pub replication_inbound_tx: tokio::sync::mpsc::Sender<(String, String)>, // (installation_id, envelope_json)
}
