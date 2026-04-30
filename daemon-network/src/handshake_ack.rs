//! Signed `HandshakeAck` construction and verification.
//!
//! After the Noise XX handshake completes, both parties exchange a
//! `HandshakeAck` payload that cryptographically binds the `InstallationId`
//! to the Noise static key via an Ed25519 signature.
//!
//! The signature covers `canonical_json(payload_without_signature) || noise_static_pubkey_bytes`.
//! The receiver verifies:
//! 1. `network_pubkey` in the payload matches the Noise static key from the handshake.
//! 2. The Ed25519 signature verifies against `signing_pubkey`.

use core_types::HandshakeAck;

/// Construct a signed `HandshakeAck` payload.
///
/// The `signing_key` signs `canonical_json(payload) || noise_static_pubkey`.
#[must_use]
pub fn build_handshake_ack(
    installation_id: &str,
    display_name: Option<&str>,
    network_pubkey: &[u8; 32],
    signing_pubkey: &[u8; 32],
    cipher_suite: &str,
    signing_key: &core_crypto::network::Ed25519SigningKey,
) -> HandshakeAck {
    let mut ack = HandshakeAck {
        installation_id: installation_id.to_string(),
        display_name: display_name.map(String::from),
        network_pubkey: hex::encode(network_pubkey),
        signing_pubkey: hex::encode(signing_pubkey),
        cipher_suite: cipher_suite.to_string(),
        signature: String::new(), // Placeholder — filled after signing.
    };

    // Canonical JSON of the payload (without the signature field).
    let sign_payload = canonical_sign_payload(&ack, network_pubkey);
    let sig = core_crypto::network::ed25519_sign(signing_key, &sign_payload);
    ack.signature = hex::encode(sig);

    ack
}

/// Verify a received `HandshakeAck` payload.
///
/// Checks:
/// 1. `network_pubkey` in payload matches the Noise static key from the handshake.
/// 2. Ed25519 signature verifies against `signing_pubkey`.
///
/// # Errors
///
/// Returns `Err(reason)` if the `network_pubkey` does not match the Noise
/// static key, or if the Ed25519 signature verification fails.
pub fn verify_handshake_ack(ack: &HandshakeAck, noise_static_key: &[u8; 32]) -> Result<(), String> {
    // Check 1: network_pubkey matches the Noise static key.
    let claimed_key =
        hex::decode(&ack.network_pubkey).map_err(|e| format!("invalid network_pubkey hex: {e}"))?;
    if claimed_key.as_slice() != noise_static_key {
        return Err("network_pubkey does not match Noise static key".into());
    }

    // Check 2: Ed25519 signature verification.
    let signing_pubkey_bytes: [u8; 32] = hex::decode(&ack.signing_pubkey)
        .map_err(|e| format!("invalid signing_pubkey hex: {e}"))?
        .try_into()
        .map_err(|_| "signing_pubkey wrong length")?;

    let sig_bytes: [u8; 64] = hex::decode(&ack.signature)
        .map_err(|e| format!("invalid signature hex: {e}"))?
        .try_into()
        .map_err(|_| "signature wrong length")?;

    let sign_payload = canonical_sign_payload(ack, noise_static_key);

    if !core_crypto::network::ed25519_verify(&signing_pubkey_bytes, &sign_payload, &sig_bytes) {
        return Err("Ed25519 signature verification failed".into());
    }

    Ok(())
}

/// Build the canonical byte string that is signed/verified.
///
/// Format: `JSON(ack without signature) || noise_static_pubkey_bytes`
fn canonical_sign_payload(ack: &HandshakeAck, noise_static_key: &[u8; 32]) -> Vec<u8> {
    // Build a copy without the signature for canonical serialisation.
    let canonical = serde_json::json!({
        "installation_id": ack.installation_id,
        "display_name": ack.display_name,
        "network_pubkey": ack.network_pubkey,
        "signing_pubkey": ack.signing_pubkey,
        "cipher_suite": ack.cipher_suite,
    });
    let json_bytes = serde_json::to_vec(&canonical).unwrap_or_default();

    let mut payload = json_bytes;
    payload.extend_from_slice(noise_static_key);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::SecureBytes;

    fn test_signing_key() -> (core_crypto::network::Ed25519SigningKey, [u8; 32]) {
        let master = SecureBytes::from_slice(&[0xDD; 32]);
        let id = uuid::Uuid::from_u128(42);
        let key = core_crypto::network::derive_signing_keypair(&master, &id).unwrap();
        let pubkey = key.public_key();
        (key, pubkey)
    }

    #[test]
    fn build_and_verify_round_trip() {
        let (signing_key, signing_pubkey) = test_signing_key();
        let network_pubkey = [0xAA; 32];

        let ack = build_handshake_ack(
            "550e8400-e29b-41d4-a716-446655440000",
            Some("test-peer"),
            &network_pubkey,
            &signing_pubkey,
            "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            &signing_key,
        );

        assert!(!ack.signature.is_empty());
        assert_eq!(ack.cipher_suite, "Noise_XX_25519_ChaChaPoly_BLAKE2s");

        // Verify with matching Noise static key.
        verify_handshake_ack(&ack, &network_pubkey).expect("verification should pass");
    }

    #[test]
    fn verify_fails_with_wrong_noise_key() {
        let (signing_key, signing_pubkey) = test_signing_key();
        let network_pubkey = [0xAA; 32];
        let wrong_key = [0xBB; 32];

        let ack = build_handshake_ack(
            "test-id",
            None,
            &network_pubkey,
            &signing_pubkey,
            "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            &signing_key,
        );

        let result = verify_handshake_ack(&ack, &wrong_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match"));
    }

    #[test]
    fn verify_fails_with_tampered_signature() {
        let (signing_key, signing_pubkey) = test_signing_key();
        let network_pubkey = [0xAA; 32];

        let mut ack = build_handshake_ack(
            "test-id",
            None,
            &network_pubkey,
            &signing_pubkey,
            "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            &signing_key,
        );

        // Tamper with signature.
        let mut sig_bytes = hex::decode(&ack.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        ack.signature = hex::encode(sig_bytes);

        let result = verify_handshake_ack(&ack, &network_pubkey);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification failed"));
    }

    #[test]
    fn verify_fails_with_tampered_payload() {
        let (signing_key, signing_pubkey) = test_signing_key();
        let network_pubkey = [0xAA; 32];

        let mut ack = build_handshake_ack(
            "test-id",
            None,
            &network_pubkey,
            &signing_pubkey,
            "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            &signing_key,
        );

        // Tamper with installation_id after signing.
        ack.installation_id = "tampered-id".into();

        let result = verify_handshake_ack(&ack, &network_pubkey);
        assert!(result.is_err());
    }

    #[test]
    fn cipher_suite_field_preserved() {
        let (signing_key, signing_pubkey) = test_signing_key();
        let network_pubkey = [0xAA; 32];

        let ack = build_handshake_ack(
            "test-id",
            None,
            &network_pubkey,
            &signing_pubkey,
            "Noise_XX_XWing_ChaChaPoly_BLAKE2b",
            &signing_key,
        );

        assert_eq!(ack.cipher_suite, "Noise_XX_XWing_ChaChaPoly_BLAKE2b");
        verify_handshake_ack(&ack, &network_pubkey).expect("should verify with PQ suite");
    }
}
