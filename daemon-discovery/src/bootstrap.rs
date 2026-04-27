//! `bootstrap.json` seed list loader.
//!
//! Loads a static list of known peers from `$CONFIG_DIR/pds/bootstrap.json`.
//! Each entry carries a peer's address, public key, trust level, and
//! optional `did:peer-2` identifier. The loader validates the format and
//! returns a list of dial targets for `daemon-network`.
//!
//! Hot-reloadable via `sesame network discovery reload` (M2).

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// A bootstrap seed list file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapFile {
    /// Schema version (must be 2).
    pub version: u32,
    /// This installation's identity (optional, for display only).
    #[serde(default)]
    pub this_installation: Option<BootstrapIdentity>,
    /// DNS seed domains for SRV discovery (M2).
    #[serde(default)]
    pub dns_seeds: Vec<DnsSeed>,
    /// Static peer entries.
    #[serde(default)]
    pub peers: Vec<BootstrapPeer>,
}

/// This installation's identity block (informational).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapIdentity {
    pub installation_id: String,
    pub display_name: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub organisation: Option<String>,
}

/// A DNS seed domain for SRV discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSeed {
    pub domain: String,
    #[serde(default)]
    pub comment: Option<String>,
}

/// A bootstrap peer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapPeer {
    /// Human-readable name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Installation UUID (advisory, for TOFU cross-reference).
    #[serde(default)]
    pub installation_id: Option<String>,
    /// X25519 public key as hex string. Mutually exclusive with `did`.
    #[serde(default)]
    pub public_key_hex: Option<String>,
    /// `did:peer-2` identifier carrying both transport and signing keys.
    /// Mutually exclusive with `public_key_hex`.
    #[serde(default)]
    pub did: Option<String>,
    /// Network addresses to dial (`host:port`).
    pub addresses: Vec<String>,
    /// Preferred transport: `"udp"` or `"tcp"`.
    #[serde(default = "default_transport")]
    pub preferred_transport: String,
    /// Trust level: `"bootstrap"` (default), `"tofu"`, `"endorsed"`.
    #[serde(default = "default_trust")]
    pub trust_level: String,
    /// Whether to dial this peer on daemon-network startup.
    #[serde(default)]
    pub dial_on_start: bool,
    /// Back-off seconds between dial retries.
    #[serde(default = "default_backoff")]
    pub dial_back_off_secs: u32,
}

fn default_transport() -> String {
    "udp".into()
}

fn default_trust() -> String {
    "bootstrap".into()
}

fn default_backoff() -> u32 {
    30
}

/// A parsed dial target ready for `daemon-network`.
#[derive(Debug, Clone)]
pub struct DialTarget {
    /// Resolved socket address.
    pub addr: SocketAddr,
    /// Public key hex (if available).
    pub public_key_hex: Option<String>,
    /// Display name.
    pub display_name: Option<String>,
    /// Whether to dial on startup.
    pub dial_on_start: bool,
}

/// Load and parse `bootstrap.json` from the given path.
///
/// Returns an empty list if the file does not exist (not an error).
///
/// # Errors
///
/// Returns an error if the file exists but contains invalid JSON.
pub fn load_bootstrap(path: &Path) -> Result<Vec<DialTarget>, BootstrapError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = std::fs::read_to_string(path).map_err(BootstrapError::Io)?;
    let file: BootstrapFile =
        serde_json::from_str(&contents).map_err(BootstrapError::Parse)?;

    if file.version != 2 {
        return Err(BootstrapError::UnsupportedVersion(file.version));
    }

    let mut targets = Vec::new();
    for peer in &file.peers {
        for addr_str in &peer.addresses {
            let addr: SocketAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(addr = %addr_str, error = %e, "skipping invalid bootstrap address");
                    continue;
                }
            };
            targets.push(DialTarget {
                addr,
                public_key_hex: peer.public_key_hex.clone(),
                display_name: peer.display_name.clone(),
                dial_on_start: peer.dial_on_start,
            });
        }
    }

    tracing::info!(
        path = %path.display(),
        peers = file.peers.len(),
        targets = targets.len(),
        "bootstrap.json loaded"
    );

    Ok(targets)
}

/// Errors from bootstrap.json loading.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// File I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parse error.
    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),
    /// Unsupported schema version.
    #[error("unsupported bootstrap.json version: {0} (expected 2)")]
    UnsupportedVersion(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_bootstrap() {
        let json = r#"{
            "version": 2,
            "peers": [
                {
                    "display_name": "test-peer",
                    "public_key_hex": "aabbccdd",
                    "addresses": ["10.0.0.1:48627", "10.0.0.2:48627"],
                    "dial_on_start": true
                }
            ]
        }"#;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, json).unwrap();

        let targets = load_bootstrap(&path).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].addr.to_string(), "10.0.0.1:48627");
        assert_eq!(targets[0].public_key_hex.as_deref(), Some("aabbccdd"));
        assert!(targets[0].dial_on_start);
    }

    #[test]
    fn missing_file_returns_empty() {
        let targets = load_bootstrap(Path::new("/nonexistent/bootstrap.json")).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn wrong_version_errors() {
        let json = r#"{"version": 1, "peers": []}"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, json).unwrap();

        let result = load_bootstrap(&path);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_address_skipped() {
        let json = r#"{
            "version": 2,
            "peers": [
                {
                    "addresses": ["not-a-valid-addr", "10.0.0.1:48627"]
                }
            ]
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, json).unwrap();

        let targets = load_bootstrap(&path).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].addr.to_string(), "10.0.0.1:48627");
    }

    #[test]
    fn empty_peers_list() {
        let json = r#"{"version": 2, "peers": []}"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, json).unwrap();

        let targets = load_bootstrap(&path).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn did_peer_field_parsed() {
        let json = r#"{
            "version": 2,
            "peers": [
                {
                    "did": "did:peer:2.Vz6Mk...",
                    "addresses": ["10.0.0.3:48627"],
                    "dial_on_start": false
                }
            ]
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, json).unwrap();

        let targets = load_bootstrap(&path).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(targets[0].public_key_hex.is_none());
        assert!(!targets[0].dial_on_start);
    }
}
