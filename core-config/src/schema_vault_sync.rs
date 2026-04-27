//! Vault replication, delegation, and coordinator configuration schema.

use serde::{Deserialize, Serialize};

/// Top-level vault sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultSyncConfig {
    pub log_db_path: String,
    pub compaction_threshold: u32,
    pub max_clock_skew_secs: u32,
    pub sync_interval_secs: u32,
    pub reachability_timeout_secs: u32,
    pub sync_profiles: Vec<SyncProfileConfig>,
    pub relay: RelayConfig,
    pub delegation: DelegationConfig,
    pub coordinator: CoordinatorConfig,
    pub trust_coordinators: Vec<TrustedCoordinatorConfig>,
}

impl Default for VaultSyncConfig {
    fn default() -> Self {
        Self {
            log_db_path: String::new(),
            compaction_threshold: 10_000,
            max_clock_skew_secs: 300,
            sync_interval_secs: 300,
            reachability_timeout_secs: 30,
            sync_profiles: Vec::new(),
            relay: RelayConfig::default(),
            delegation: DelegationConfig::default(),
            coordinator: CoordinatorConfig::default(),
            trust_coordinators: Vec::new(),
        }
    }
}

/// Per-profile replication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProfileConfig {
    pub profile_name: String,
    pub direction: String,
    pub peers: Vec<String>,
    #[serde(default = "default_true")]
    pub replicate_revocations: bool,
    #[serde(default)]
    pub replicate_delegations: bool,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u32,
}

fn default_true() -> bool {
    true
}

fn default_sync_interval() -> u32 {
    300
}

/// Relay store-and-forward configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    pub enabled: bool,
    pub max_bytes_per_destination: u64,
    pub retention_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes_per_destination: 10_485_760,
            retention_secs: 604_800,
        }
    }
}

/// Delegation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DelegationConfig {
    pub pop_cache_db_path: String,
    pub default_offline_posture: String,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self {
            pop_cache_db_path: String::new(),
            default_offline_posture: "deny-when-offline".into(),
        }
    }
}

/// Coordinator role configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct CoordinatorConfig {
    pub role_enabled: bool,
}

/// A trusted coordinator entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCoordinatorConfig {
    pub installation_id: String,
    pub coordinator_pubkey: String,
    pub display_name: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default)]
    pub crossorg_org_name: Option<String>,
}

fn default_scope() -> String {
    "intraorg".into()
}
