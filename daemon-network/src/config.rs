//! Configuration helpers for daemon-network.
//!
//! Network configuration lives in the `[network]` section of `config.toml`,
//! loaded via `core_config::load_config()` like every other daemon. This
//! module provides path resolution helpers for daemon-network-specific
//! filesystem locations (TOFU store, audit log).

use core_config::NetworkConfig;
use std::path::PathBuf;

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
