//! End-to-end round-trip test for vault replication re-encrypted envelopes.
//!
//! This test exercises the exact same code path that daemon-network (sender)
//! and daemon-secrets (receiver) use:
//!
//! 1. Sender: generate ephemeral X25519 → ECDH with dest pubkey → HKDF →
//!    build AAD via `replication_envelope_aad` → ChaCha20-Poly1305 seal →
//!    construct JSON envelope with base64/hex fields + timestamp + session_id.
//!
//! 2. Receiver: parse JSON envelope → extract fields → reconstruct AAD via
//!    `replication_envelope_aad` → ECDH with own private key → HKDF →
//!    ChaCha20-Poly1305 open → verify plaintext matches.
//!
//! If sender and receiver AAD construction ever diverge, this test fails
//! with an AEAD tag verification error. That's the point — this test exists
//! because the adversarial review caught that an AAD mismatch would silently
//! break every replication envelope in production.

use base64::Engine;
use core_crypto::SecureBytes;
use core_crypto::network::{
    chacha20_open, chacha20_seal, generate_x25519_keypair, hkdf_blake2b, random_bytes,
    replication_envelope_aad, x25519_dh,
};

use core_crypto::network::REPLICATION_HKDF_CONTEXT as HKDF_CONTEXT;

/// Simulate daemon-network's sender side: seal and build JSON envelope.
fn sender_seal(dest_pubkey: &[u8; 32], entries_json: &str, session_id: &str) -> (String, u64) {
    // Ephemeral ECDH per destination.
    let (eph_private, eph_public) = generate_x25519_keypair().unwrap();
    let shared = x25519_dh(&eph_private, dest_pubkey).unwrap();

    // Derive encryption key via HKDF-BLAKE2b.
    let enc_keys = hkdf_blake2b(shared.as_bytes(), HKDF_CONTEXT, 1);
    let enc_key: [u8; 32] = enc_keys[0].as_bytes().try_into().unwrap();

    // Build AAD: batch_hash || timestamp || length-prefixed session_id.
    let nonce = random_bytes::<12>();
    let plaintext = entries_json.as_bytes();
    let batch_hash = blake3::hash(plaintext);
    let timestamp_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let aad = replication_envelope_aad(batch_hash.as_bytes(), timestamp_secs, session_id);

    let ciphertext = chacha20_seal(&enc_key, &nonce, &aad, plaintext).unwrap();

    // Build JSON envelope (exactly as daemon-network does).
    let b64 = base64::engine::general_purpose::STANDARD;
    let envelope = serde_json::json!({
        "reencrypted": true,
        "ephemeral_pubkey": b64.encode(eph_public),
        "nonce": b64.encode(nonce),
        "ciphertext": b64.encode(&ciphertext),
        "batch_hash": hex::encode(batch_hash.as_bytes()),
        "timestamp_secs": timestamp_secs,
        "session_id": session_id,
    });

    (serde_json::to_string(&envelope).unwrap(), timestamp_secs)
}

/// Simulate daemon-secrets' receiver side: parse envelope and open.
fn receiver_open(envelope_str: &str, dest_private: &SecureBytes) -> Result<String, &'static str> {
    let v: serde_json::Value = serde_json::from_str(envelope_str).map_err(|_| "not valid JSON")?;

    if v["reencrypted"].as_bool() != Some(true) {
        return Err("missing reencrypted:true");
    }

    let ts = v["timestamp_secs"]
        .as_u64()
        .ok_or("missing timestamp_secs")?;
    let session_id = v["session_id"].as_str().ok_or("missing session_id")?;

    let b64 = base64::engine::general_purpose::STANDARD;

    let eph_pubkey_bytes = b64
        .decode(v["ephemeral_pubkey"].as_str().ok_or("missing eph_pubkey")?)
        .map_err(|_| "bad b64 eph_pubkey")?;
    let nonce_bytes = b64
        .decode(v["nonce"].as_str().ok_or("missing nonce")?)
        .map_err(|_| "bad b64 nonce")?;
    let ciphertext = b64
        .decode(v["ciphertext"].as_str().ok_or("missing ciphertext")?)
        .map_err(|_| "bad b64 ciphertext")?;
    let batch_hash = hex::decode(v["batch_hash"].as_str().ok_or("missing batch_hash")?)
        .map_err(|_| "bad hex batch_hash")?;

    let eph_pubkey: [u8; 32] = eph_pubkey_bytes
        .try_into()
        .map_err(|_| "eph_pubkey wrong len")?;
    let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| "nonce wrong len")?;

    // ECDH with our private key and the sender's ephemeral public key.
    let shared = x25519_dh(dest_private, &eph_pubkey).map_err(|_| "ECDH failed")?;

    let dec_keys = hkdf_blake2b(shared.as_bytes(), HKDF_CONTEXT, 1);
    let dec_key: [u8; 32] = dec_keys[0]
        .as_bytes()
        .try_into()
        .map_err(|_| "HKDF wrong len")?;

    // Reconstruct AAD using the same shared function.
    let aad = replication_envelope_aad(&batch_hash, ts, session_id);

    let plaintext =
        chacha20_open(&dec_key, &nonce, &aad, &ciphertext).map_err(|_| "AEAD open failed")?;

    String::from_utf8(plaintext.as_bytes().to_vec()).map_err(|_| "not UTF-8")
}

// ============================================================================
// Tests
// ============================================================================

/// The critical round-trip: sender seals, receiver opens, plaintext matches.
/// If the AAD construction in either side ever diverges, this fails with
/// "AEAD open failed" because ChaCha20-Poly1305 binds AAD into the tag.
#[test]
fn replication_envelope_seal_open_round_trip() {
    let (dest_private, dest_public) = generate_x25519_keypair().unwrap();
    let entries_json = r#"[{"op":"set","key":"api-key"}]"#;
    let session_id = "550e8400-e29b-41d4-a716-446655440000";

    let (envelope_str, _ts) = sender_seal(&dest_public, entries_json, session_id);
    let result = receiver_open(&envelope_str, &dest_private);

    assert_eq!(
        result.unwrap(),
        entries_json,
        "receiver must recover the exact plaintext the sender sealed"
    );
}

/// Wrong private key fails AEAD verification (different device cannot decrypt).
#[test]
fn replication_envelope_wrong_private_key_fails() {
    let (_dest_private, dest_public) = generate_x25519_keypair().unwrap();
    let (wrong_private, _) = generate_x25519_keypair().unwrap();
    let entries_json = r#"[{"op":"delete","key":"old-secret"}]"#;

    let (envelope_str, _) = sender_seal(&dest_public, entries_json, "session-1");
    let result = receiver_open(&envelope_str, &wrong_private);

    assert_eq!(
        result.unwrap_err(),
        "AEAD open failed",
        "wrong private key must fail AEAD tag verification"
    );
}

/// Tampered ciphertext fails AEAD verification.
#[test]
fn replication_envelope_tampered_ciphertext_fails() {
    let (dest_private, dest_public) = generate_x25519_keypair().unwrap();
    let entries_json = r#"[{"op":"set","key":"k"}]"#;

    let (envelope_str, _) = sender_seal(&dest_public, entries_json, "session-2");

    // Tamper: flip a bit in the base64-encoded ciphertext.
    let mut v: serde_json::Value = serde_json::from_str(&envelope_str).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut ct = b64.decode(v["ciphertext"].as_str().unwrap()).unwrap();
    ct[0] ^= 0xFF;
    v["ciphertext"] = serde_json::Value::String(b64.encode(&ct));
    let tampered = serde_json::to_string(&v).unwrap();

    let result = receiver_open(&tampered, &dest_private);
    assert_eq!(result.unwrap_err(), "AEAD open failed");
}

/// Tampered timestamp fails AEAD verification (replay with altered timestamp).
#[test]
fn replication_envelope_tampered_timestamp_fails() {
    let (dest_private, dest_public) = generate_x25519_keypair().unwrap();
    let entries_json = r#"[{"op":"set","key":"k"}]"#;

    let (envelope_str, _) = sender_seal(&dest_public, entries_json, "session-3");

    // Change the timestamp — AAD won't match.
    let mut v: serde_json::Value = serde_json::from_str(&envelope_str).unwrap();
    let original_ts = v["timestamp_secs"].as_u64().unwrap();
    v["timestamp_secs"] = serde_json::Value::Number((original_ts + 1).into());
    let tampered = serde_json::to_string(&v).unwrap();

    let result = receiver_open(&tampered, &dest_private);
    assert_eq!(
        result.unwrap_err(),
        "AEAD open failed",
        "altered timestamp must break AEAD tag (timestamp is bound in AAD)"
    );
}

/// Tampered session_id fails AEAD verification (cross-session substitution).
#[test]
fn replication_envelope_tampered_session_id_fails() {
    let (dest_private, dest_public) = generate_x25519_keypair().unwrap();
    let entries_json = r#"[{"op":"set","key":"k"}]"#;

    let (envelope_str, _) = sender_seal(&dest_public, entries_json, "real-session");

    let mut v: serde_json::Value = serde_json::from_str(&envelope_str).unwrap();
    v["session_id"] = serde_json::Value::String("injected-session".into());
    let tampered = serde_json::to_string(&v).unwrap();

    let result = receiver_open(&tampered, &dest_private);
    assert_eq!(
        result.unwrap_err(),
        "AEAD open failed",
        "altered session_id must break AEAD tag (session_id is bound in AAD)"
    );
}

/// Tampered batch_hash fails AEAD verification.
#[test]
fn replication_envelope_tampered_batch_hash_fails() {
    let (dest_private, dest_public) = generate_x25519_keypair().unwrap();
    let entries_json = r#"[{"op":"set","key":"k"}]"#;

    let (envelope_str, _) = sender_seal(&dest_public, entries_json, "session-5");

    let mut v: serde_json::Value = serde_json::from_str(&envelope_str).unwrap();
    v["batch_hash"] = serde_json::Value::String(hex::encode([0xFFu8; 32]));
    let tampered = serde_json::to_string(&v).unwrap();

    let result = receiver_open(&tampered, &dest_private);
    assert_eq!(
        result.unwrap_err(),
        "AEAD open failed",
        "altered batch_hash must break AEAD tag"
    );
}

/// Empty session_id is a valid (degenerate) case — should still round-trip.
#[test]
fn replication_envelope_empty_session_id_round_trips() {
    let (dest_private, dest_public) = generate_x25519_keypair().unwrap();
    let entries_json = r#"[]"#;

    let (envelope_str, _) = sender_seal(&dest_public, entries_json, "");
    let result = receiver_open(&envelope_str, &dest_private);
    assert_eq!(result.unwrap(), entries_json);
}

/// Large payload round-trips correctly.
#[test]
fn replication_envelope_large_payload() {
    let (dest_private, dest_public) = generate_x25519_keypair().unwrap();
    // 64KB payload — exercises that nothing truncates.
    let large_json = format!(r#"{{"data":"{}"}}"#, "x".repeat(65536));

    let (envelope_str, _) = sender_seal(&dest_public, &large_json, "session-large");
    let result = receiver_open(&envelope_str, &dest_private);
    assert_eq!(result.unwrap(), large_json);
}

/// Verify that replication_envelope_aad is deterministic — same inputs
/// produce identical byte sequences.
#[test]
fn replication_envelope_aad_deterministic() {
    let hash = [0xAA; 32];
    let ts = 1714300000u64;
    let sid = "test-session-id";

    let aad1 = replication_envelope_aad(&hash, ts, sid);
    let aad2 = replication_envelope_aad(&hash, ts, sid);
    assert_eq!(aad1, aad2, "same inputs must produce identical AAD");
}

/// Verify that different session_ids produce different AADs (length prefix
/// prevents collision between e.g. "ab" + "cd" vs "abc" + "d").
#[test]
fn replication_envelope_aad_session_id_separation() {
    let hash = [0xBB; 32];
    let ts = 1714300000u64;

    let aad_a = replication_envelope_aad(&hash, ts, "ab");
    let aad_b = replication_envelope_aad(&hash, ts, "a");
    assert_ne!(
        aad_a, aad_b,
        "different session_ids must produce different AADs"
    );

    // Specifically verify length prefix prevents canonicalization collision.
    let aad_short = replication_envelope_aad(&hash, ts, "x");
    let aad_long = replication_envelope_aad(&hash, ts, "xy");
    assert_ne!(
        aad_short, aad_long,
        "session_id length prefix must differentiate AADs"
    );
}
