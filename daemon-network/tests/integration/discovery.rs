//! Discovery convergence integration test.
//!
//! Verifies that two daemon-network instances can discover each other via
//! the discovery subsystem and establish a session. Uses in-process Noise XX
//! handshake over TCP loopback — no real mDNS multicast (requires root/caps).

mod common;

use common::generate_keypair;
use daemon_network::noise::state::{self, xx_initiator, xx_responder};
use daemon_network::session::state::PeerState;
use daemon_network::session::table::PeerTable;
use daemon_network::tofu::store::TofuStore;
use daemon_network::transport::frame::WireSessionId;
use daemon_discovery::queue::{DialEntry, DialQueue, DiscoverySource};
use core_types::TofuTrustLevel;
use std::sync::Arc;
use std::time::Instant;

#[tokio::test]
async fn dial_queue_drives_handshake() {
    // Simulate discovery feeding the dial queue, then daemon-network
    // consuming it to establish a session.

    // Set up responder listening on a random port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let responder_addr = listener.local_addr().unwrap();

    // Responder keypair.
    let responder_kp = generate_keypair();
    let initiator_kp = generate_keypair();

    // Discovery feeds the responder's address into the dial queue.
    let queue = Arc::new(DialQueue::new(10));
    let entry = DialEntry {
        addr: responder_addr,
        source: DiscoverySource::Bootstrap,
        advisory_pubkey_hex: Some(hex::encode(&responder_kp.public[..16])),
        next_dial_at: Instant::now(),
        consecutive_failures: 0,
    };
    assert!(queue.push(entry));
    assert_eq!(queue.len(), 1);

    // Pop the entry (simulating daemon-network's dial tick).
    let dial_entry = queue.pop_ready().unwrap();
    assert_eq!(dial_entry.addr, responder_addr);

    // Save responder public key before moving keypair into spawn.
    let responder_pub: [u8; 32] = responder_kp.public.clone().try_into().unwrap();

    // Spawn responder handshake.
    let responder_handle = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        xx_responder(&mut reader, &mut writer, &responder_kp).await.unwrap()
    });

    // Initiator dials and handshakes.
    let stream = tokio::net::TcpStream::connect(responder_addr).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let init_transport = xx_initiator(&mut reader, &mut writer, &initiator_kp).await.unwrap();
    let resp_transport = responder_handle.await.unwrap();

    // Both sides see each other's static keys.
    let init_sees = init_transport.remote_static().unwrap();
    let resp_sees = resp_transport.remote_static().unwrap();
    assert_eq!(init_sees, responder_pub.as_slice());
    assert_eq!(resp_sees, initiator_kp.public.as_slice());

    // Initiator creates session in peer table.
    let peer_table = PeerTable::new(256);
    let sid = WireSessionId::random();
    let peer_state = PeerState::new(
        sid,
        init_sees,
        responder_addr,
        init_transport,
        TofuTrustLevel::Tofu,
    );
    assert!(peer_table.insert(peer_state));
    assert_eq!(peer_table.len(), 1);

    // TOFU pin.
    let dir = tempfile::tempdir().unwrap();
    let tofu = TofuStore::open(&dir.path().join("tofu.db"), "test-install").unwrap();
    tofu.pin(&hex::encode(init_sees), &responder_addr.to_string(), TofuTrustLevel::Tofu).unwrap();

    let peer = tofu.lookup_key(&hex::encode(init_sees)).unwrap().unwrap();
    assert_eq!(peer.trust_level, TofuTrustLevel::Tofu);
}

#[test]
fn dial_queue_requeue_with_backoff() {
    let queue = DialQueue::new(10);
    let entry = DialEntry {
        addr: "127.0.0.1:9999".parse().unwrap(),
        source: DiscoverySource::Mdns,
        advisory_pubkey_hex: None,
        next_dial_at: Instant::now(),
        consecutive_failures: 0,
    };
    queue.push(entry.clone());
    let popped = queue.pop_ready().unwrap();
    assert_eq!(popped.consecutive_failures, 0);

    // Requeue simulates failed dial.
    queue.requeue_failed(popped);
    assert_eq!(queue.len(), 1);

    // Should NOT be ready immediately (30s backoff for failure 1).
    assert!(queue.pop_ready().is_none());
}

#[test]
fn peer_removed_clears_queue_entry() {
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let mgr = daemon_discovery::manager::DiscoveryManager::new(100, tx);

    let addr: std::net::SocketAddr = "10.0.0.5:48627".parse().unwrap();
    mgr.add_peer(addr, DiscoverySource::Mdns, Some("aabb".into()));
    assert_eq!(mgr.queue_depth(), 1);

    // Simulate peer departure.
    mgr.remove_peer(addr, DiscoverySource::Mdns);
    assert_eq!(mgr.queue_depth(), 0);

    // Peer can be re-discovered after removal (dedup cleared).
    mgr.add_peer(addr, DiscoverySource::Mdns, Some("aabb".into()));
    assert_eq!(mgr.queue_depth(), 1);
}

#[tokio::test]
async fn discovery_event_peer_removed_tears_down_session() {
    // Verify that PeerRemoved removes a session from the peer table.
    let kp_a = snow::Builder::new(state::NOISE_XX.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let kp_b = snow::Builder::new(state::NOISE_XX.parse().unwrap())
        .generate_keypair()
        .unwrap();

    let (stream_a, stream_b) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(stream_a);
    let (mut br, mut bw) = tokio::io::split(stream_b);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote_static = transport.remote_static().unwrap();

    let addr: std::net::SocketAddr = "10.0.0.99:48627".parse().unwrap();
    let peer_table = PeerTable::new(256);
    let sid = WireSessionId::random();
    let peer_state = PeerState::new(sid, remote_static, addr, transport, TofuTrustLevel::Tofu);
    assert!(peer_table.insert(peer_state));
    assert_eq!(peer_table.len(), 1);

    // Simulate PeerRemoved: look up by address, remove.
    let found_sid = peer_table.lookup_addr(&addr);
    assert!(found_sid.is_some());
    peer_table.remove(&found_sid.unwrap());
    assert_eq!(peer_table.len(), 0);
    assert!(peer_table.lookup_addr(&addr).is_none());
}

#[test]
fn bootstrap_seeds_populate_dial_queue() {
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let mgr = daemon_discovery::manager::DiscoveryManager::new(100, tx);

    let targets = vec![
        daemon_discovery::bootstrap::DialTarget {
            addr: "10.0.0.1:48627".parse().unwrap(),
            public_key_hex: Some("aabb".into()),
            signing_pubkey_hex: None,
            display_name: Some("seed-1".into()),
            dial_on_start: true,
        },
        daemon_discovery::bootstrap::DialTarget {
            addr: "10.0.0.2:48627".parse().unwrap(),
            public_key_hex: None,
            signing_pubkey_hex: None,
            display_name: None,
            dial_on_start: false,
        },
    ];

    mgr.load_bootstrap(&targets);
    assert_eq!(mgr.queue_depth(), 2);
}
