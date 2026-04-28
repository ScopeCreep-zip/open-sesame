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
    /// X25519 transport public key hex (from `public_key_hex` or did:peer-2 `E` segment).
    pub public_key_hex: Option<String>,
    /// Ed25519 signing public key hex (from did:peer-2 `V` segment).
    pub signing_pubkey_hex: Option<String>,
    /// Display name.
    pub display_name: Option<String>,
    /// Whether to dial on startup.
    pub dial_on_start: bool,
}

/// Keys extracted from a `did:peer:2` string.
#[derive(Debug, Clone)]
pub struct DidPeerKeys {
    /// X25519 transport public key (32 bytes) from the `E` segment.
    pub x25519_pubkey: [u8; 32],
    /// Ed25519 signing public key (32 bytes) from the `V` segment.
    pub ed25519_pubkey: [u8; 32],
}

/// Parse a `did:peer:2` string and extract the X25519 and Ed25519 public keys.
///
/// DIF did:peer numalgo 2 format:
/// ```text
/// did:peer:2.V<multibase-ed25519>.E<multibase-x25519>[.S<service-endpoint>]
/// ```
///
/// Purpose codes: `V` = verification (Ed25519), `E` = encryption (X25519).
/// Multibase prefix `z` = base58btc. Multicodec prefixes: `0xed01` = Ed25519,
/// `0xec01` = X25519 (varint-encoded).
///
/// # Errors
///
/// Returns `None` if the DID is malformed, has wrong prefix, missing segments,
/// invalid base58btc, wrong multicodec, or wrong key length.
#[must_use]
pub fn parse_did_peer_2(did: &str) -> Option<DidPeerKeys> {
    let body = did.strip_prefix("did:peer:2.")?;

    let mut ed25519_pubkey: Option<[u8; 32]> = None;
    let mut x25519_pubkey: Option<[u8; 32]> = None;

    for segment in body.split('.') {
        if segment.is_empty() {
            continue;
        }
        let purpose = segment.as_bytes()[0];
        let multibase_key = &segment[1..];

        // Multibase prefix 'z' = base58btc.
        let encoded = multibase_key.strip_prefix('z')?;
        let decoded = bs58::decode(encoded).into_vec().ok()?;

        match purpose {
            b'V' => {
                // Ed25519: multicodec 0xed01 (varint: 0xed 0x01), then 32 bytes.
                if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
                    return None;
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded[2..34]);
                ed25519_pubkey = Some(key);
            }
            b'E' => {
                // X25519: multicodec 0xec01 (varint: 0xec 0x01), then 32 bytes.
                if decoded.len() != 34 || decoded[0] != 0xec || decoded[1] != 0x01 {
                    return None;
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded[2..34]);
                x25519_pubkey = Some(key);
            }
            // Service endpoint (b'S') and unknown purpose codes: skip per spec extensibility.
            _ => {}
        }
    }

    Some(DidPeerKeys {
        x25519_pubkey: x25519_pubkey?,
        ed25519_pubkey: ed25519_pubkey?,
    })
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
        // Resolve keys: prefer did:peer-2 if present, fall back to raw public_key_hex.
        let (transport_key_hex, signing_key_hex) = if let Some(did) = &peer.did {
            if let Some(keys) = parse_did_peer_2(did) {
                (
                    Some(hex::encode(keys.x25519_pubkey)),
                    Some(hex::encode(keys.ed25519_pubkey)),
                )
            } else {
                tracing::warn!(did = %did, "failed to parse did:peer-2, falling back to public_key_hex");
                (peer.public_key_hex.clone(), None)
            }
        } else {
            (peer.public_key_hex.clone(), None)
        };

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
                public_key_hex: transport_key_hex.clone(),
                signing_pubkey_hex: signing_key_hex.clone(),
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

    /// Build a valid did:peer:2 string from known 32-byte keys.
    fn build_test_did(ed25519: &[u8; 32], x25519: &[u8; 32]) -> String {
        // V segment: 0xed01 multicodec prefix + 32 bytes Ed25519
        let mut v_bytes = vec![0xed, 0x01];
        v_bytes.extend_from_slice(ed25519);
        let v_encoded = bs58::encode(&v_bytes).into_string();

        // E segment: 0xec01 multicodec prefix + 32 bytes X25519
        let mut e_bytes = vec![0xec, 0x01];
        e_bytes.extend_from_slice(x25519);
        let e_encoded = bs58::encode(&e_bytes).into_string();

        format!("did:peer:2.Vz{v_encoded}.Ez{e_encoded}")
    }

    #[test]
    fn parse_did_peer_2_round_trip() {
        let ed25519 = [0xAA; 32];
        let x25519 = [0xBB; 32];
        let did = build_test_did(&ed25519, &x25519);

        let keys = parse_did_peer_2(&did).expect("should parse valid did:peer:2");
        assert_eq!(keys.ed25519_pubkey, ed25519);
        assert_eq!(keys.x25519_pubkey, x25519);
    }

    #[test]
    fn parse_did_peer_2_wrong_prefix() {
        assert!(parse_did_peer_2("did:key:z6Mk...").is_none());
        assert!(parse_did_peer_2("did:peer:1.Vz...").is_none());
        assert!(parse_did_peer_2("not-a-did").is_none());
    }

    #[test]
    fn parse_did_peer_2_missing_segment() {
        // Only V, no E.
        let mut v_bytes = vec![0xed, 0x01];
        v_bytes.extend_from_slice(&[0xAA; 32]);
        let v_encoded = bs58::encode(&v_bytes).into_string();
        let did = format!("did:peer:2.Vz{v_encoded}");
        assert!(parse_did_peer_2(&did).is_none());
    }

    #[test]
    fn parse_did_peer_2_wrong_multicodec() {
        // V segment with X25519 multicodec (wrong — should be Ed25519).
        let mut v_bytes = vec![0xec, 0x01]; // X25519 prefix in V segment
        v_bytes.extend_from_slice(&[0xAA; 32]);
        let v_encoded = bs58::encode(&v_bytes).into_string();

        let mut e_bytes = vec![0xec, 0x01];
        e_bytes.extend_from_slice(&[0xBB; 32]);
        let e_encoded = bs58::encode(&e_bytes).into_string();

        let did = format!("did:peer:2.Vz{v_encoded}.Ez{e_encoded}");
        assert!(parse_did_peer_2(&did).is_none());
    }

    #[test]
    fn did_peer_in_bootstrap_json() {
        let ed25519 = [0xCC; 32];
        let x25519 = [0xDD; 32];
        let did = build_test_did(&ed25519, &x25519);

        let json = format!(r#"{{
            "version": 2,
            "peers": [
                {{
                    "did": "{did}",
                    "addresses": ["10.0.0.3:48627"],
                    "dial_on_start": false
                }}
            ]
        }}"#);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, json).unwrap();

        let targets = load_bootstrap(&path).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].public_key_hex.as_deref(), Some(hex::encode(x25519).as_str()));
        assert_eq!(targets[0].signing_pubkey_hex.as_deref(), Some(hex::encode(ed25519).as_str()));
        assert!(!targets[0].dial_on_start);
    }
}
