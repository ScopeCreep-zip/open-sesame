//! BEP-44 mutable data item record format specification.
//!
//! Defines the exact schema for Open Sesame's presence records on the
//! Mainline DHT. Each installation publishes a signed mutable data item
//! keyed by its Ed25519 signing public key.
//!
//! Wire format follows BEP-44: `{ v: <bencode>, seq: i64, sig: [u8; 64] }`
//!
//! The `v` field contains a JSON-encoded `PresenceRecord`:
//!
//! ```json
//! {
//!   "addrs": ["10.0.0.1:48627", "[2001:db8::1]:48627"],
//!   "signing_pubkey": "<hex 64 chars>",
//!   "noise_pubkey": "<hex 64 chars>",
//!   "display_name": "kat-laptop",
//!   "version": 1
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Presence record published as BEP-44 mutable data item value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceRecord {
    /// Network addresses this installation is reachable at.
    pub addrs: Vec<String>,
    /// Ed25519 signing public key (hex, 64 chars). Same key used for BEP-44 signing.
    pub signing_pubkey: String,
    /// X25519 Noise static public key (hex, 64 chars).
    pub noise_pubkey: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Schema version (currently 1).
    pub version: u32,
}

impl PresenceRecord {
    /// Serialise to JSON bytes for BEP-44 `v` field.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialisation fails (should not happen).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Parse from JSON bytes (BEP-44 `v` field).
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the JSON is malformed.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_record_round_trip() {
        let record = PresenceRecord {
            addrs: vec!["10.0.0.1:48627".into(), "[::1]:48627".into()],
            signing_pubkey: "aa".repeat(32),
            noise_pubkey: "bb".repeat(32),
            display_name: "test-node".into(),
            version: 1,
        };
        let bytes = record.to_json_bytes().unwrap();
        let parsed = PresenceRecord::from_json_bytes(&bytes).unwrap();
        assert_eq!(parsed.addrs.len(), 2);
        assert_eq!(parsed.display_name, "test-node");
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn presence_record_json_contains_fields() {
        let record = PresenceRecord {
            addrs: vec!["1.2.3.4:48627".into()],
            signing_pubkey: "cc".repeat(32),
            noise_pubkey: "dd".repeat(32),
            display_name: "my-peer".into(),
            version: 1,
        };
        let json = String::from_utf8(record.to_json_bytes().unwrap()).unwrap();
        assert!(json.contains("signing_pubkey"));
        assert!(json.contains("noise_pubkey"));
        assert!(json.contains("my-peer"));
    }
}
