//! BEP-44 mutable data item publish to Mainline DHT.
//!
//! Publishes an Ed25519-signed presence record containing this installation's
//! network addresses, public keys, and display name. The record is keyed by
//! the Ed25519 signing public key — resolvers query the DHT for this key
//! to discover the installation's addresses.

use super::schema::PresenceRecord;
use mainline::{Dht, MutableItem, SigningKey};

/// Publish a presence record to the Mainline DHT.
///
/// The `signing_key` is the Ed25519 key from `InstallationId.signing_pubkey`.
/// The `seq` number must be monotonically increasing across publishes.
///
/// `Dht` implements `Clone` (wraps a channel sender), so the caller
/// retains their handle.
///
/// # Errors
///
/// Returns an error if DHT put fails.
pub async fn publish_presence(
    dht: &Dht,
    signing_key: &SigningKey,
    record: &PresenceRecord,
    seq: i64,
) -> Result<(), PublishError> {
    let value = record.to_json_bytes().map_err(PublishError::Serialise)?;

    if value.len() > 1000 {
        return Err(PublishError::ValueTooLarge(value.len()));
    }

    // v6 API: MutableItem::new(signer, value: &[u8], seq, salt: Option<&[u8]>)
    let item = MutableItem::new(signing_key.clone(), &value, seq, None);

    // Dht implements Clone (wraps a channel sender). as_async() consumes self.
    // put_mutable(item, cas) — cas=None for unconditional put.
    dht.clone()
        .as_async()
        .put_mutable(item, None)
        .await
        .map_err(PublishError::Dht)?;

    tracing::info!(
        seq,
        addrs = record.addrs.len(),
        "BEP-44 presence record published"
    );
    Ok(())
}

/// Errors from BEP-44 publishing.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// JSON serialisation failed.
    #[error("serialise error: {0}")]
    Serialise(#[from] serde_json::Error),
    /// BEP-44 value exceeds 1000-byte limit.
    #[error("BEP-44 value too large: {0} bytes (max 1000)")]
    ValueTooLarge(usize),
    /// DHT put failed.
    #[error("DHT put failed: {0}")]
    Dht(#[from] mainline::errors::PutMutableError),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic signing key from seed byte. Uses `from_bytes` instead of
    /// `generate` because mainline v6's ed25519-dalek v3 requires rand_core 0.10
    /// which conflicts with our stable rand_core 0.9 deps.
    fn test_signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_mul(7);
        SigningKey::from_bytes(&bytes)
    }

    fn test_record() -> PresenceRecord {
        PresenceRecord {
            addrs: vec!["10.0.0.1:48627".into()],
            signing_pubkey: "aa".repeat(32),
            noise_pubkey: "bb".repeat(32),
            display_name: "test-node".into(),
            version: 1,
        }
    }

    #[test]
    fn value_too_large_rejected() {
        // A record with addrs long enough to exceed 1000 bytes.
        let record = PresenceRecord {
            addrs: (0..200).map(|i| format!("10.0.0.{i}:48627")).collect(),
            signing_pubkey: "aa".repeat(32),
            noise_pubkey: "bb".repeat(32),
            display_name: "x".repeat(500),
            version: 1,
        };
        let value = record.to_json_bytes().unwrap();
        assert!(value.len() > 1000, "test record must exceed 1000 bytes");
    }

    #[test]
    fn small_record_serialises_under_limit() {
        let record = test_record();
        let value = record.to_json_bytes().unwrap();
        assert!(
            value.len() <= 1000,
            "standard record should be under 1000 bytes, got {}",
            value.len()
        );
    }

    #[test]
    fn mutable_item_construction() {
        // Verify MutableItem::new works with our record's serialised bytes.
        let record = test_record();
        let value = record.to_json_bytes().unwrap();
        let signing_key = test_signing_key(0xAA);
        let item = MutableItem::new(signing_key, &value, 1, None);
        assert_eq!(item.value(), &value);
        assert_eq!(item.seq(), 1);
    }

    #[test]
    fn publish_resolve_round_trip_on_testnet() {
        // Spin up a 3-node local DHT testnet. No real internet.
        let testnet = mainline::Testnet::new(10).unwrap();
        let dht = Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .unwrap();

        let signing_key = test_signing_key(0xAA);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();

        let record = test_record();
        let value = record.to_json_bytes().unwrap();
        let item = MutableItem::new(signing_key, &value, 1, None);

        // Publish synchronously (testnet is local, fast).
        dht.put_mutable(item, None).unwrap();

        // Resolve: get the first result from the stream.
        let resolved = dht.get_mutable(&pubkey_bytes, None, None).next();
        assert!(resolved.is_some(), "should find the published record");

        let resolved = resolved.unwrap();
        assert_eq!(resolved.seq(), 1);

        let parsed = PresenceRecord::from_json_bytes(resolved.value()).unwrap();
        assert_eq!(parsed.display_name, "test-node");
        assert_eq!(parsed.addrs, vec!["10.0.0.1:48627"]);
    }
}
