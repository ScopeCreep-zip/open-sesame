//! Network transport and discovery configuration schema.

use serde::{Deserialize, Serialize};

/// Top-level network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub transport: TransportConfig,
    pub session: SessionConfig,
    pub tofu: TofuConfig,
    pub ratelimit: RateLimitConfig,
    pub flood: FloodConfig,
    pub discovery: DiscoveryConfig,
}

/// Transport layer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    pub listen_port: u16,
    pub listen_addr: String,
    pub tcp_enabled: bool,
    pub max_tcp_frame_size: u32,
    pub max_tcp_connections_per_address: u32,
    /// UDP port for SWIM gossip (separate from Noise transport).
    pub gossip_port: u16,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            listen_port: 48627,
            listen_addr: "::".into(),
            tcp_enabled: true,
            max_tcp_frame_size: 65535,
            max_tcp_connections_per_address: 4,
            gossip_port: 48628,
        }
    }
}

/// Session management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    pub max_concurrent_sessions: u32,
    pub idle_timeout_secs: u32,
    pub keepalive_reply_timeout_secs: u32,
    pub handshake_timeout_secs: u32,
    pub aead_failure_close_threshold: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: 256,
            idle_timeout_secs: 300,
            keepalive_reply_timeout_secs: 10,
            handshake_timeout_secs: 10,
            aead_failure_close_threshold: 5,
        }
    }
}

/// TOFU identity store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct TofuConfig {
    /// Empty string = default `$STATE_DIR/pds/network-tofu.db`.
    pub database_path: String,
    pub require_known_peers: bool,
}

/// Per-peer and global rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub data_rate_per_sec: u32,
    pub data_burst: u32,
    pub control_rate_per_sec: u32,
    pub control_burst: u32,
    pub handshake_rate_per_sec: u32,
    pub handshake_burst: u32,
    pub global_data_rate_per_sec: u32,
    pub global_data_burst: u32,
    pub global_handshake_rate_per_sec: u32,
    pub global_handshake_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            data_rate_per_sec: 256,
            data_burst: 512,
            control_rate_per_sec: 32,
            control_burst: 64,
            handshake_rate_per_sec: 4,
            handshake_burst: 8,
            global_data_rate_per_sec: 8192,
            global_data_burst: 16384,
            global_handshake_rate_per_sec: 128,
            global_handshake_burst: 256,
        }
    }
}

/// Anti-flooding and `DoS` resistance configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FloodConfig {
    pub cookie_challenge_threshold: f64,
    pub cookie_epoch_secs: u32,
    /// Fraction of global handshake capacity at which Equi-X `PoW` activates.
    /// 0.0 = always active, 1.0 = never active. Default 0.8 (80% saturation).
    pub pow_challenge_threshold: f64,
}

impl Default for FloodConfig {
    fn default() -> Self {
        Self {
            cookie_challenge_threshold: 0.5,
            cookie_epoch_secs: 120,
            pow_challenge_threshold: 0.8,
        }
    }
}

/// Discovery subsystem configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct DiscoveryConfig {
    pub bootstrap_json_path: String,
    pub mdns: MdnsConfig,
    pub dns_srv: DnsSrvConfig,
    pub bep44: Bep44Config,
}

/// BEP-44 Mainline DHT discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Bep44Config {
    pub enabled: bool,
    pub publish_interval_secs: u32,
}

impl Default for Bep44Config {
    fn default() -> Self {
        Self {
            enabled: false,
            publish_interval_secs: 3600,
        }
    }
}

/// mDNS (RFC 6762/6763) discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MdnsConfig {
    pub enabled: bool,
    pub interface: String,
    pub srv_ttl: u32,
    pub ptr_ttl: u32,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: String::new(),
            srv_ttl: 120,
            ptr_ttl: 4500,
        }
    }
}

/// DNS SRV discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSrvConfig {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub resolver: String,
    pub min_refresh_secs: u32,
    pub max_refresh_secs: u32,
}

impl Default for DnsSrvConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            resolver: String::new(),
            min_refresh_secs: 60,
            max_refresh_secs: 3600,
        }
    }
}
