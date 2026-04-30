//! BEP-44 mutable data item resolution from Mainline DHT.
//!
//! Given an Ed25519 public key (from bootstrap.json, TOFU store, or gossip),
//! resolves the peer's current network addresses by querying the DHT for
//! the BEP-44 mutable data item signed by that key.

use super::schema::PresenceRecord;
use futures_util::StreamExt;
use mainline::Dht;
use mainline::MutableItem;

/// Resolve a peer's presence record from the Mainline DHT.
///
/// The `target_pubkey` is the peer's Ed25519 signing public key (32 bytes).
/// The DHT is queried for the BEP-44 mutable data item at the target hash
/// derived from `SHA-1(pubkey)`.
///
/// Returns `None` if the record is not found or cannot be parsed.
pub async fn resolve_presence(dht: &Dht, target_pubkey: &[u8; 32]) -> Option<ResolvedPeer> {
    // v6 API: get_mutable(pubkey, salt, more_recent_than) returns GetStream<MutableItem>.
    // GetStream implements Stream<Item = MutableItem>.
    // Dht::as_async() consumes self; Dht implements Clone.
    let mut stream = dht
        .clone()
        .as_async()
        .get_mutable(target_pubkey, None, None);

    // Take the first result from the stream (most recent).
    let item: MutableItem = stream.next().await?;

    let record = PresenceRecord::from_json_bytes(item.value()).ok()?;

    let seq = item.seq();
    tracing::debug!(
        addrs = record.addrs.len(),
        display_name = %record.display_name,
        seq,
        "BEP-44 presence record resolved"
    );

    Some(ResolvedPeer {
        record,
        seq,
        pubkey: *target_pubkey,
    })
}

/// A peer resolved from the Mainline DHT.
#[derive(Debug, Clone)]
pub struct ResolvedPeer {
    /// The presence record with addresses and keys.
    pub record: PresenceRecord,
    /// BEP-44 sequence number (for freshness comparison).
    pub seq: i64,
    /// The Ed25519 public key used to resolve this peer.
    pub pubkey: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bep44::schema::PresenceRecord;
    use mainline::SigningKey;

    fn test_signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_mul(7);
        SigningKey::from_bytes(&bytes)
    }

    #[tokio::test]
    async fn resolve_from_testnet() {
        let testnet = mainline::Testnet::new(10).unwrap();
        let dht = mainline::Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .unwrap();

        let signing_key = test_signing_key(0xCC);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();

        let record = PresenceRecord {
            addrs: vec!["10.0.0.5:48627".into()],
            signing_pubkey: hex::encode(pubkey_bytes),
            noise_pubkey: "cc".repeat(32),
            display_name: "resolve-test".into(),
            version: 1,
        };
        let value = record.to_json_bytes().unwrap();
        let item = MutableItem::new(signing_key, &value, 42, None);

        // Publish synchronously.
        dht.put_mutable(item, None).unwrap();

        // Resolve via async path.
        let resolved = resolve_presence(&dht, &pubkey_bytes).await;
        assert!(resolved.is_some(), "should resolve the published record");

        let peer = resolved.unwrap();
        assert_eq!(peer.seq, 42);
        assert_eq!(peer.record.display_name, "resolve-test");
        assert_eq!(peer.record.addrs, vec!["10.0.0.5:48627"]);
        assert_eq!(peer.pubkey, pubkey_bytes);
    }

    #[tokio::test]
    async fn resolve_unknown_key_returns_none() {
        let testnet = mainline::Testnet::new(10).unwrap();
        let dht = mainline::Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .unwrap();

        // Random key that was never published.
        let unknown_key = [0xFFu8; 32];
        let resolved = resolve_presence(&dht, &unknown_key).await;
        assert!(resolved.is_none());
    }
}
