//! Integration test: two daemon-network instances performing a full Noise XX
//! handshake over TCP, TOFU pinning, data exchange, PSK caching, and `IKpsk2`
//! reconnection.
//!
//! Runs entirely in-process — no systemd, no daemon-profile, no real sockets
//! beyond a TCP loopback pair.

use daemon_network::metrics::Metrics;
use daemon_network::noise::state::{
    self, derive_psk_from_handshake, xx_initiator, xx_responder,
    ikpsk2_initiator, ikpsk2_responder,
};
use daemon_network::send;
use daemon_network::session::state::PeerState;
use daemon_network::session::table::PeerTable;
use daemon_network::tofu::store::TofuStore;
use daemon_network::tofu::fingerprint;
use daemon_network::session::replay::{ReplayWindow, ReplayCheck};
use daemon_network::transport::frame::{Frame, SessionId, HEADER_SIZE};
use core_types::TofuTrustLevel;
use std::sync::Arc;

fn generate_keypair() -> snow::Keypair {
    snow::Builder::new(state::NOISE_XX.parse().unwrap())
        .generate_keypair()
        .unwrap()
}

#[tokio::test]
async fn xx_handshake_tofu_pin_data_round_trip() {
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    // TCP loopback pair via tokio duplex.
    let (stream_a, stream_b) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(stream_a);
    let (mut br, mut bw) = tokio::io::split(stream_b);

    // Noise XX handshake.
    let (result_a, result_b) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let mut transport_a = result_a.expect("initiator handshake failed");
    let mut transport_b = result_b.expect("responder handshake failed");

    // Verify remote static keys match.
    let a_sees_b = transport_a.remote_static().expect("no remote static on A");
    let b_sees_a = transport_b.remote_static().expect("no remote static on B");
    assert_eq!(a_sees_b, kp_b.public.as_slice(), "A should see B's public key");
    assert_eq!(b_sees_a, kp_a.public.as_slice(), "B should see A's public key");

    // TOFU pinning: both sides pin the other's key.
    let dir = tempfile::tempdir().unwrap();
    let store_a = TofuStore::open(&dir.path().join("tofu-a.db")).unwrap();
    let store_b = TofuStore::open(&dir.path().join("tofu-b.db")).unwrap();

    let key_b_hex = hex::encode(a_sees_b);
    let key_a_hex = hex::encode(b_sees_a);

    store_a.pin(&key_b_hex, "127.0.0.1:48627", TofuTrustLevel::Tofu).unwrap();
    store_b.pin(&key_a_hex, "127.0.0.1:48628", TofuTrustLevel::Tofu).unwrap();

    // Verify pins.
    let peer_b = store_a.lookup_key(&key_b_hex).unwrap().unwrap();
    assert_eq!(peer_b.trust_level, TofuTrustLevel::Tofu);
    let peer_a = store_b.lookup_key(&key_a_hex).unwrap().unwrap();
    assert_eq!(peer_a.trust_level, TofuTrustLevel::Tofu);

    // Data exchange: A → B.
    let plaintext = b"hello from peer A";
    let ct = transport_a.encrypt(plaintext).unwrap();
    let pt = transport_b.decrypt(&ct).unwrap();
    assert_eq!(pt, plaintext);

    // Data exchange: B → A.
    let plaintext2 = b"hello from peer B";
    let ct2 = transport_b.encrypt(plaintext2).unwrap();
    let pt2 = transport_a.decrypt(&ct2).unwrap();
    assert_eq!(pt2, plaintext2);

    // PSK derivation and caching.
    let psk_a = derive_psk_from_handshake(&transport_a.handshake_hash());
    let psk_b = derive_psk_from_handshake(&transport_b.handshake_hash());
    assert_eq!(psk_a, psk_b, "both sides derive the same PSK");

    store_a.store_psk(&key_b_hex, &psk_a).unwrap();
    store_b.store_psk(&key_a_hex, &psk_b).unwrap();

    let cached_a = store_a.get_psk(&key_b_hex).unwrap().unwrap();
    assert_eq!(cached_a, psk_a.to_vec());
}

#[tokio::test]
async fn ikpsk2_reconnection_after_xx() {
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    // First: XX handshake to establish keys and PSK.
    let (s1a, s1b) = tokio::io::duplex(65536);
    let (mut ar1, mut aw1) = tokio::io::split(s1a);
    let (mut br1, mut bw1) = tokio::io::split(s1b);

    let (ra, rb) = tokio::join!(
        xx_initiator(&mut ar1, &mut aw1, &kp_a),
        xx_responder(&mut br1, &mut bw1, &kp_b),
    );
    let ta = ra.unwrap();
    let _tb = rb.unwrap();

    let psk = derive_psk_from_handshake(&ta.handshake_hash());
    let remote_b_static = ta.remote_static().unwrap();

    // Second: IKpsk2 reconnection.
    let (s2a, s2b) = tokio::io::duplex(65536);
    let (mut ar2, mut aw2) = tokio::io::split(s2a);
    let (mut br2, mut bw2) = tokio::io::split(s2b);

    let (ra2, rb2) = tokio::join!(
        ikpsk2_initiator(&mut ar2, &mut aw2, &kp_a, &remote_b_static, &psk),
        ikpsk2_responder(&mut br2, &mut bw2, &kp_b, &psk),
    );

    let mut ta2 = ra2.expect("IKpsk2 initiator failed");
    let mut tb2 = rb2.expect("IKpsk2 responder failed");

    // Verify data exchange works on reconnected session.
    let ct = ta2.encrypt(b"reconnected message").unwrap();
    let pt = tb2.decrypt(&ct).unwrap();
    assert_eq!(pt, b"reconnected message");
}

#[tokio::test]
async fn tofu_mismatch_detection() {
    let dir = tempfile::tempdir().unwrap();
    let store = TofuStore::open(&dir.path().join("tofu.db")).unwrap();

    // Pin key A.
    store.pin("aabbccdd", "10.0.0.1:48627", TofuTrustLevel::Tofu).unwrap();

    // Record a mismatch when a different key presents from the same address.
    store.record_mismatch("aabbccdd", "eeff0011", "10.0.0.1:48627").unwrap();

    // Fork-evidence log should have 2 entries: pin + mismatch.
    assert_eq!(store.event_count().unwrap(), 2);
}

#[test]
fn fingerprint_encoding_round_trip() {
    let key = [0xAB_u8; 32];
    let words = fingerprint::pgp_words(&key);
    assert_eq!(words.split(' ').count(), 32);

    let hex = fingerprint::hex_fingerprint(&key);
    assert!(hex.contains(':'));
    assert_eq!(hex.len(), 32 * 3 - 1); // "ab:ab:...:ab"

    let key_b = [0xCD_u8; 32];
    let sas = fingerprint::numeric_sas(&key, &key_b);
    assert_eq!(sas.len(), 6);
    assert_eq!(sas, fingerprint::numeric_sas(&key_b, &key)); // symmetric
}

#[test]
fn frame_codec_round_trip() {
    let sid = SessionId::random();
    let frame = Frame::new(core_types::FrameType::Data as u8, sid, 42, vec![1, 2, 3, 4]);
    let bytes = frame.serialise();
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed.session_id, sid);
    assert_eq!(parsed.sequence, 42);
    assert_eq!(parsed.body, vec![1, 2, 3, 4]);
    assert_eq!(frame.header_bytes(), bytes[..HEADER_SIZE]);
}

#[test]
fn replay_window_comprehensive() {
    let mut w = ReplayWindow::new();

    // Sequential acceptance.
    for i in 0..100 {
        assert_eq!(w.check_and_update(i), ReplayCheck::Accept);
    }
    assert_eq!(w.top(), 99);

    // Duplicate rejection.
    assert_eq!(w.check_and_update(99), ReplayCheck::Duplicate);
    assert_eq!(w.check_and_update(50), ReplayCheck::Duplicate); // Already seen in sequential run

    // Too old (99 - 35 = 64, one past the 64-entry window).
    assert_eq!(w.check_and_update(35), ReplayCheck::TooOld);

    // Large advance resets.
    assert_eq!(w.check_and_update(1000), ReplayCheck::Accept);
    assert_eq!(w.check_and_update(99), ReplayCheck::TooOld);
}

#[tokio::test]
async fn udp_send_data_round_trip() {
    // Bind two real UDP sockets on localhost ephemeral ports.
    let socket_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    // Perform Noise XX handshake over a duplex stream (TCP-like).
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let (stream_a, stream_b) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(stream_a);
    let (mut br, mut bw) = tokio::io::split(stream_b);

    let (result_a, result_b) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport_a = result_a.unwrap();
    let mut transport_b = result_b.unwrap();

    let _remote_static_a = transport_b.remote_static().unwrap();
    let remote_static_b = transport_a.remote_static().unwrap();

    // Create session on peer A's table pointing to B's address.
    let sid = SessionId::random();
    let peer_table_a = Arc::new(PeerTable::new(256));
    let peer_state_a = PeerState::new(
        sid,
        remote_static_b,
        addr_b,
        transport_a,
        TofuTrustLevel::Tofu,
    );
    assert!(peer_table_a.insert(peer_state_a));

    let metrics_a = Arc::new(Metrics::new());

    // Send a Data frame from A to B via real UDP.
    let payload = b"\x00\x01hello over UDP"; // NetworkMessageType::Control + payload
    send::send_data(&sid, payload, &peer_table_a, &socket_a, &metrics_a)
        .await
        .expect("send_data failed");

    // Receive the raw UDP datagram on B's socket.
    let mut recv_buf = vec![0u8; 1280];
    let (len, from_addr) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket_b.recv_from(&mut recv_buf),
    )
    .await
    .expect("recv timeout")
    .expect("recv_from failed");

    assert_eq!(from_addr, addr_a);

    // Parse the wire frame.
    let frame = Frame::parse(&recv_buf[..len]).expect("frame parse failed");
    assert_eq!(frame.session_id, sid);
    assert_eq!(frame.frame_type, core_types::FrameType::Data as u8);
    assert_eq!(frame.sequence, 0); // First frame sent.

    // Decrypt through B's transport.
    let plaintext = transport_b.decrypt(&frame.body).expect("decrypt failed");
    assert_eq!(plaintext, payload);

    // Verify metrics were updated.
    assert_eq!(
        metrics_a.frames_sent_total.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}
