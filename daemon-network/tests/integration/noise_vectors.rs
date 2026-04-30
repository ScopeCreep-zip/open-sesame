//! Noise XX protocol compliance: cacophony test vectors + wrapper integration.
//!
//! Test 1 (`cacophony_xx_vector`): Bypasses our wrappers entirely. Uses snow's
//! `Builder` directly with fixed static and ephemeral keys from the cacophony
//! vector set. Compares every message's ciphertext byte-for-byte against the
//! reference output. Verifies the handshake hash matches. This proves the
//! cryptographic layer produces spec-compliant Noise XX output.
//!
//! Test 2+ (`wrapper_*`): Uses our `xx_initiator`/`xx_responder` wrappers
//! with known static keys. Verifies the wrappers correctly exchange remote
//! static keys, produce matching handshake hashes, and transport-phase
//! encrypt/decrypt works. This proves our wiring is correct.
//!
//! Together: test 1 proves the crypto is right, test 2 proves the wiring is
//! right. Neither alone is sufficient.
//!
//! Vector source: <https://github.com/haskell-cryptography/cacophony>

mod common;

use daemon_network::noise::state::{
    NOISE_XX, derive_psk_from_handshake, xx_initiator, xx_responder,
};

// ============================================================================
// Cacophony test vector: Noise_XX_25519_ChaChaPoly_BLAKE2s
// ============================================================================

const INIT_STATIC: &str = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
const INIT_EPHEMERAL: &str = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
const RESP_STATIC: &str = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
const RESP_EPHEMERAL: &str = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
const PROLOGUE: &str = "4a6f686e2047616c74";
const EXPECTED_HANDSHAKE_HASH: &str =
    "6c4c56cf71612f72d05ceb96c0155e6f4ea54a26b504c93de632a2db4a49d200";

const MESSAGES: &[(&str, &str)] = &[
    (
        "4c756477696720766f6e204d69736573",
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
    ),
    (
        "4d757272617920526f746862617264",
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088437c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec55a2298d2dbff80eff034d20595153f63a196a6cead1e11b2bb13e336fa13616dd3e8b0a070c882ed3f1a78c7c06c93",
    ),
    (
        "462e20412e20486179656b",
        "46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d415b670c114f79b9a4f80541570f77ce88802efa4220cff733e7b5668ba38059ec904b4b8eef9448085faf51",
    ),
    (
        "4361726c204d656e676572",
        "d5e83adfaac5dc324a68f1862df54549e56d209fba707205f328b2",
    ),
    (
        "4a65616e2d426170746973746520536179",
        "d102c9029b1f55c788f561ba7737afbccef9c9f1bf2f238167fd40ba9c1c134867",
    ),
    (
        "457567656e2042f6686d20766f6e2042617765726b",
        "cb1ce80960382c6d5d5e740ffb724d1432f0310b200fb6f8424120f506092744baa415e155",
    ),
];

/// Byte-for-byte cacophony vector verification using snow directly.
///
/// No wrappers, no framing. Pure snow Builder with fixed keys, comparing
/// every message's ciphertext against the reference output.
#[test]
fn cacophony_xx_vector() {
    let init_s = hex::decode(INIT_STATIC).unwrap();
    let init_e = hex::decode(INIT_EPHEMERAL).unwrap();
    let resp_s = hex::decode(RESP_STATIC).unwrap();
    let resp_e = hex::decode(RESP_EPHEMERAL).unwrap();
    let prologue = hex::decode(PROLOGUE).unwrap();

    let mut init = snow::Builder::new(NOISE_XX.parse().unwrap())
        .local_private_key(&init_s)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&init_e)
        .prologue(&prologue)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut resp = snow::Builder::new(NOISE_XX.parse().unwrap())
        .local_private_key(&resp_s)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&resp_e)
        .prologue(&prologue)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut sendbuf = vec![0u8; 65535];
    let mut recvbuf = vec![0u8; 65535];

    // Handshake phase: messages 0, 1, 2.
    for (i, &(payload_hex, expected_ct_hex)) in MESSAGES[..3].iter().enumerate() {
        let payload = hex::decode(payload_hex).unwrap();
        let expected_ct = hex::decode(expected_ct_hex).unwrap();

        let (send, recv) = if i % 2 == 0 {
            (&mut init, &mut resp)
        } else {
            (&mut resp, &mut init)
        };

        let len = send
            .write_message(&payload, &mut sendbuf)
            .unwrap_or_else(|e| panic!("write_message failed on msg {i}: {e}"));
        assert_eq!(
            &sendbuf[..len],
            &expected_ct[..],
            "msg {i} ciphertext mismatch\n  expected: {expected_ct_hex}\n  actual:   {}",
            hex::encode(&sendbuf[..len])
        );

        let recv_len = recv
            .read_message(&sendbuf[..len], &mut recvbuf)
            .unwrap_or_else(|e| panic!("read_message failed on msg {i}: {e}"));
        assert_eq!(
            &recvbuf[..recv_len],
            &payload[..],
            "msg {i} plaintext mismatch"
        );
    }

    // Verify handshake hash.
    let hh = init.get_handshake_hash();
    let expected_hh = hex::decode(EXPECTED_HANDSHAKE_HASH).unwrap();
    assert_eq!(
        &hh[..expected_hh.len()],
        &expected_hh[..],
        "handshake hash mismatch\n  expected: {EXPECTED_HANDSHAKE_HASH}\n  actual:   {}",
        hex::encode(&hh[..expected_hh.len()])
    );

    // Transport phase: messages 3, 4, 5.
    let mut init_t = init.into_transport_mode().unwrap();
    let mut resp_t = resp.into_transport_mode().unwrap();

    for (i, &(payload_hex, expected_ct_hex)) in MESSAGES[3..].iter().enumerate() {
        let msg_idx = i + 3;
        let payload = hex::decode(payload_hex).unwrap();
        let expected_ct = hex::decode(expected_ct_hex).unwrap();

        let (send, recv) = if msg_idx % 2 == 0 {
            (&mut init_t, &mut resp_t)
        } else {
            (&mut resp_t, &mut init_t)
        };

        let len = send
            .write_message(&payload, &mut sendbuf)
            .unwrap_or_else(|e| panic!("write_message failed on transport msg {msg_idx}: {e}"));
        assert_eq!(
            &sendbuf[..len],
            &expected_ct[..],
            "transport msg {msg_idx} ciphertext mismatch\n  expected: {expected_ct_hex}\n  actual:   {}",
            hex::encode(&sendbuf[..len])
        );

        let recv_len = recv
            .read_message(&sendbuf[..len], &mut recvbuf)
            .unwrap_or_else(|e| panic!("read_message failed on transport msg {msg_idx}: {e}"));
        assert_eq!(
            &recvbuf[..recv_len],
            &payload[..],
            "transport msg {msg_idx} plaintext mismatch"
        );
    }
}

// ============================================================================
// Wrapper integration tests: verify our xx_initiator/xx_responder wiring
// ============================================================================

/// Wrappers correctly exchange remote static keys using the vector's keypairs.
#[tokio::test]
async fn wrapper_exchanges_static_keys() {
    let init_kp = keypair_from_private(INIT_STATIC);
    let resp_kp = keypair_from_private(RESP_STATIC);

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &init_kp),
        xx_responder(&mut br, &mut bw, &resp_kp),
    );
    let ta = ra.unwrap();
    let tb = rb.unwrap();

    assert_eq!(ta.remote_static().unwrap(), resp_kp.public.as_slice());
    assert_eq!(tb.remote_static().unwrap(), init_kp.public.as_slice());
}

/// Wrappers produce identical handshake hashes on both sides.
#[tokio::test]
async fn wrapper_handshake_hash_agreement() {
    let init_kp = keypair_from_private(INIT_STATIC);
    let resp_kp = keypair_from_private(RESP_STATIC);

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &init_kp),
        xx_responder(&mut br, &mut bw, &resp_kp),
    );
    let ta = ra.unwrap();
    let tb = rb.unwrap();

    let hh_a = ta.handshake_hash();
    let hh_b = tb.handshake_hash();

    assert_eq!(
        hh_a, hh_b,
        "both sides must produce identical handshake hash"
    );
    assert_ne!(hh_a, [0u8; 32], "handshake hash must not be zero");
}

/// Wrapper transport encrypts/decrypts correctly with the vector's keys.
#[tokio::test]
async fn wrapper_transport_round_trip() {
    let init_kp = keypair_from_private(INIT_STATIC);
    let resp_kp = keypair_from_private(RESP_STATIC);

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &init_kp),
        xx_responder(&mut br, &mut bw, &resp_kp),
    );
    let mut ta = ra.unwrap();
    let mut tb = rb.unwrap();

    // Initiator → responder.
    let ct = ta.encrypt(b"hello from initiator").unwrap();
    let pt = tb.decrypt(&ct).unwrap();
    assert_eq!(pt, b"hello from initiator");

    // Responder → initiator.
    let ct = tb.encrypt(b"hello from responder").unwrap();
    let pt = ta.decrypt(&ct).unwrap();
    assert_eq!(pt, b"hello from responder");
}

/// PSK derived from the wrapper's handshake hash is non-zero and distinct
/// from the hash itself.
#[tokio::test]
async fn wrapper_psk_derivation_properties() {
    let init_kp = keypair_from_private(INIT_STATIC);
    let resp_kp = keypair_from_private(RESP_STATIC);

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &init_kp),
        xx_responder(&mut br, &mut bw, &resp_kp),
    );
    let ta = ra.unwrap();
    let hh = ta.handshake_hash();
    let psk = derive_psk_from_handshake(&hh);

    assert_ne!(psk, [0u8; 32], "PSK must not be zero");
    assert_ne!(psk, hh, "PSK must not equal the handshake hash");
}

// ============================================================================
// Helper
// ============================================================================

/// Construct a `snow::Keypair` from a hex-encoded private key.
///
/// Derives the public key via X25519 scalar basepoint multiplication
/// using `core_crypto::network::x25519_public_from_private`.
fn keypair_from_private(private_hex: &str) -> snow::Keypair {
    let private = hex::decode(private_hex).unwrap();
    let priv_array: [u8; 32] = private.as_slice().try_into().unwrap();
    let public = core_crypto::network::x25519_public_from_private(&priv_array);
    snow::Keypair {
        private,
        public: public.to_vec(),
    }
}
