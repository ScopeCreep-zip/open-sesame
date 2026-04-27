//! Configuration loading for daemon-network.

use core_config::NetworkConfig;
use std::path::PathBuf;

/// Load the network configuration from `$CONFIG_DIR/pds/network.toml`.
///
/// Returns default config if the file does not exist.
pub fn load_network_config() -> NetworkConfig {
    let path = network_config_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        toml::from_str(&contents).unwrap_or_else(|e| {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to parse network.toml, using defaults"
            );
            NetworkConfig::default()
        })
    } else {
        tracing::info!(
            path = %path.display(),
            "network.toml not found, using defaults"
        );
        NetworkConfig::default()
    }
}

/// Resolve the network config file path.
fn network_config_path() -> PathBuf {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pds");
    config_dir.join("network.toml")
}

/// Resolve the TOFU database path from config or default.
pub fn tofu_db_path(config: &NetworkConfig) -> PathBuf {
    if config.tofu.database_path.is_empty() {
        let state_dir = dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("pds");
        state_dir.join("network-tofu.db")
    } else {
        PathBuf::from(&config.tofu.database_path)
    }
}

/// Resolve the audit log path from config or default.
pub fn audit_log_path() -> PathBuf {
    let state_dir = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pds");
    state_dir.join("network-audit.jsonl")
}
