//! Shared test helpers for daemon-network integration tests.

#![allow(dead_code)] // Not all helpers are used by every test binary.

pub mod test_daemon;

use daemon_network::noise::state;

/// Generate a Noise XX keypair for testing.
pub fn generate_keypair() -> snow::Keypair {
    snow::Builder::new(state::NOISE_XX.parse().unwrap())
        .generate_keypair()
        .unwrap()
}

/// Create a temporary TOFU store.
pub fn temp_tofu(dir: &std::path::Path, name: &str) -> daemon_network::tofu::store::TofuStore {
    daemon_network::tofu::store::TofuStore::open(&dir.join(format!("{name}-tofu.db")), name)
        .unwrap()
}
