//! Session lifecycle tests: close frame delivery, idle timeout eviction,
//! rekey detection, and keepalive behavior.
//!
//! Time-dependent tests use `std::thread::sleep` for real wall-clock
//! advancement since `PeerState` timestamps use `std::time::Instant`.

mod common;

use common::generate_keypair;
use common::test_daemon::TestDaemon;
use core_types::{FrameType, TofuTrustLevel};
use daemon_network::dispatch;
use daemon_network::lifecycle as daemon_lifecycle;
use daemon_network::metrics::Metrics;
use daemon_network::noise::state::{xx_initiator, xx_responder};
use daemon_network::send;
use daemon_network::session::state::PeerState;
use daemon_network::session::table::PeerTable;
use daemon_network::transport::frame::{Frame, WireSessionId};
use daemon_network::transport::udp::UdpInbound;
use std::sync::Arc;

// ============================================================================
// Close frame delivery
// ============================================================================

#[tokio::test]
async fn close_session_removes_from_table_unconditionally() {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();

    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote = transport.remote_static().unwrap();

    let sid = WireSessionId::random();
    let table = Arc::new(PeerTable::new(256));
    let peer = PeerState::new(sid, remote, addr, transport, TofuTrustLevel::Tofu);
    assert!(table.insert(peer));
    assert_eq!(table.len(), 1);

    let metrics = Arc::new(Metrics::new());
    send::close_session(&sid, &table, &socket, &metrics);

    // Session must be removed from the table immediately (synchronous).
    assert_eq!(
        table.len(),
        0,
        "close_session must remove session from table"
    );
    assert!(
        table.get(&sid).is_none(),
        "session must not be findable after close"
    );
}

#[tokio::test]
async fn close_session_with_unreachable_peer_still_removes() {
    // Peer address is unreachable — the Close frame send will fail,
    // but the session must still be removed from the table.
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let unreachable_addr: std::net::SocketAddr = "10.255.255.1:48627".parse().unwrap();

    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote = transport.remote_static().unwrap();

    let sid = WireSessionId::random();
    let table = Arc::new(PeerTable::new(256));
    let peer = PeerState::new(
        sid,
        remote,
        unreachable_addr,
        transport,
        TofuTrustLevel::Tofu,
    );
    assert!(table.insert(peer));
    assert_eq!(table.len(), 1);

    let metrics = Arc::new(Metrics::new());
    send::close_session(&sid, &table, &socket, &metrics);

    // Session removed regardless of send failure.
    assert_eq!(
        table.len(),
        0,
        "unreachable peer session must still be removed"
    );
}

#[tokio::test]
async fn close_session_on_missing_session_is_harmless() {
    // Closing a session that doesn't exist should not panic.
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let table = Arc::new(PeerTable::new(256));
    let metrics = Arc::new(Metrics::new());
    let sid = WireSessionId::random();

    // This must not panic — encrypt fails, remove is a no-op.
    send::close_session(&sid, &table, &socket, &metrics);
    assert_eq!(table.len(), 0);
}

// ============================================================================
// Idle session detection
// ============================================================================

#[tokio::test]
async fn idle_sessions_detected_after_threshold() {
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote = transport.remote_static().unwrap();
    let addr: std::net::SocketAddr = "10.0.0.1:48627".parse().unwrap();

    let table = PeerTable::new(256);
    let sid = WireSessionId::random();
    let peer = PeerState::new(sid, remote, addr, transport, TofuTrustLevel::Tofu);
    table.insert(peer);

    // A freshly created session must NOT be idle at any reasonable threshold.
    assert!(
        table.idle_sessions(10).is_empty(),
        "fresh session must not be idle"
    );

    // Wait real wall time so Instant::elapsed() advances past the threshold.
    // idle_sessions() uses strict `>`, and elapsed().as_secs() truncates,
    // so after 1.1s real time, elapsed returns 1 and `1 > 0` is true.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let idle = table.idle_sessions(0);
    assert_eq!(
        idle.len(),
        1,
        "session must be idle after 1.1s with threshold=0"
    );
    assert_eq!(idle[0], sid);
}

// ============================================================================
// Rekey detection
// ============================================================================

#[tokio::test]
async fn session_needs_rekey_detected_by_age() {
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote = transport.remote_static().unwrap();
    let addr: std::net::SocketAddr = "10.0.0.1:48627".parse().unwrap();

    let table = PeerTable::new(256);
    let sid = WireSessionId::random();
    let peer = PeerState::new(sid, remote, addr, transport, TofuTrustLevel::Tofu);
    table.insert(peer);

    // A freshly created session must NOT need rekey at any reasonable interval.
    assert!(
        table.sessions_needing_rekey(120).is_empty(),
        "fresh session must not need rekey"
    );

    // Wait real wall time so Instant::elapsed() advances past the threshold.
    // sessions_needing_rekey() uses strict `>`, and age_secs() truncates,
    // so after 1.1s real time, age returns 1 and `1 > 0` is true.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let rekey = table.sessions_needing_rekey(0);
    assert_eq!(
        rekey.len(),
        1,
        "session must need rekey after 1.1s with max_age=0"
    );
    assert_eq!(rekey[0], sid);
}

// ============================================================================
// Keepalive send path
// ============================================================================

#[tokio::test]
async fn send_keepalive_succeeds_on_active_session() {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();

    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote = transport.remote_static().unwrap();

    let sid = WireSessionId::random();
    let table = Arc::new(PeerTable::new(256));
    let peer = PeerState::new(sid, remote, addr, transport, TofuTrustLevel::Tofu);
    table.insert(peer);

    let metrics = Arc::new(Metrics::new());
    let result = send::send_keepalive(&sid, &table, &socket, &metrics).await;
    assert!(result.is_ok(), "keepalive must succeed on active session");

    assert_eq!(
        metrics
            .frames_sent_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "keepalive must increment frames_sent_total"
    );
}

#[tokio::test]
async fn send_keepalive_on_missing_session_returns_error() {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let table = Arc::new(PeerTable::new(256));
    let metrics = Arc::new(Metrics::new());
    let sid = WireSessionId::random();

    let result = send::send_keepalive(&sid, &table, &socket, &metrics).await;
    assert!(
        result.is_err(),
        "keepalive on nonexistent session must error"
    );
}

// ============================================================================
// `RehandshakeRequest` send path
// ============================================================================

#[tokio::test]
async fn send_rehandshake_request_succeeds() {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();

    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        xx_initiator(&mut ar, &mut aw, &kp_a),
        xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote = transport.remote_static().unwrap();

    let sid = WireSessionId::random();
    let table = Arc::new(PeerTable::new(256));
    let peer = PeerState::new(sid, remote, addr, transport, TofuTrustLevel::Tofu);
    table.insert(peer);

    let metrics = Arc::new(Metrics::new());
    let result = send::send_rehandshake_request(&sid, &table, &socket, &metrics).await;
    assert!(
        result.is_ok(),
        "`RehandshakeRequest` must succeed on active session"
    );

    // Session must still be in the table (not removed like close).
    assert_eq!(
        table.len(),
        1,
        "rehandshake request must NOT remove session"
    );
}

// ============================================================================
// `TCP` frame at `MAX_TCP_BODY` boundary
// ============================================================================

#[tokio::test]
async fn tcp_frame_max_body_round_trips() {
    use daemon_network::transport::frame::{tcp_read_frame, tcp_write_frame};

    let sid = WireSessionId::random();
    // Maximum TCP body size (65535 bytes).
    let body = vec![0xCD; 65535];
    let frame = Frame::new(core_types::FrameType::Data as u8, sid, 42, body.clone());

    let (client, server) = tokio::io::duplex(131072); // big enough for header + body
    let (_cr, mut cw) = tokio::io::split(client);
    let (mut sr, _sw) = tokio::io::split(server);

    tcp_write_frame(&mut cw, &frame).await.unwrap();
    drop(cw);

    let parsed = tcp_read_frame(&mut sr).await.unwrap().unwrap();
    assert_eq!(parsed.session_id, sid);
    assert_eq!(parsed.sequence, 42);
    assert_eq!(parsed.body.len(), 65535);
    assert_eq!(parsed.body, body);
}

// ============================================================================
// mDNS goodbye packet construction and parsing
// ============================================================================

#[test]
fn mdns_goodbye_packet_round_trips_through_codec() {
    use daemon_discovery::mdns::announce;
    use daemon_discovery::mdns::packet::DnsPacket;

    let pubkey = [0xEE; 32];
    let goodbye = announce::build_goodbye(&pubkey, "test-install", 48627, None);

    // Serialise and re-parse.
    let bytes = goodbye.serialise();
    let parsed = DnsPacket::parse(&bytes).expect("goodbye packet must parse");

    // Must be a response (flags bit 15 set).
    assert!(parsed.flags & 0x8000 != 0, "goodbye must be a response");

    // All answer records must have TTL=0.
    assert!(
        !parsed.answers.is_empty(),
        "goodbye must have answer records"
    );
    for rr in &parsed.answers {
        assert_eq!(rr.ttl, 0, "goodbye answer TTL must be 0");
    }
}

// ============================================================================
// Dispatch-level tests (require `TestDaemon` harness)
// ============================================================================

#[tokio::test]
async fn test_daemon_harness_smoke() {
    // Verify the `TestDaemon` harness constructs successfully and the
    // daemon state is usable for dispatch calls.
    let td = TestDaemon::new().await;
    assert_eq!(td.state.peer_table.len(), 0);
    assert_eq!(td.metric(&td.state.metrics.frames_received_total), 0);
}

#[tokio::test]
async fn dispatch_handshake_init_returns_cookie() {
    // Send a `HandshakeInit` frame to the daemon and verify it responds
    // with a `CookieRequest` containing a 33-byte payload (type + cookie).
    let td = TestDaemon::new().await;

    let knock = Frame::new(
        FrameType::HandshakeInit as u8,
        WireSessionId::zero(),
        0,
        vec![],
    );
    td.send_frame(&knock).await;

    // The daemon's `handle_udp_frame` runs synchronously in main, but here
    // we need to drive it manually since we're not in the event loop.
    // Construct a `UdpInbound` and call dispatch directly.
    let client_addr = td.client_socket.local_addr().unwrap();
    let inbound = UdpInbound {
        frame: knock,
        src_addr: client_addr,
    };
    dispatch::udp::handle_udp_frame(&inbound, &td.state);

    // The handler spawns a send task. Yield to let it run.
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Receive the `CookieRequest` on the client socket.
    let response = td.recv_frame().await;
    assert!(response.is_some(), "daemon must respond to HandshakeInit");
    let resp = response.unwrap();
    assert_eq!(
        resp.frame_type,
        FrameType::CookieRequest as u8,
        "response must be CookieRequest"
    );
    // Tier-1 cookie: [0x00][32 bytes] = 33 bytes.
    assert_eq!(resp.body.len(), 33, "cookie payload must be 33 bytes");
    assert_eq!(resp.body[0], 0x00, "type byte must be 0x00 for cookie");
}

#[tokio::test]
async fn dispatch_replay_detected_increments_metric() {
    // Send a Data frame, then send the same frame again (same sequence).
    // The second dispatch must increment `replay_detected_total`.
    let td = TestDaemon::new().await;
    let peer_addr: std::net::SocketAddr = "10.0.0.1:48627".parse().unwrap();
    let (sid, mut peer_transport) = td.insert_session(peer_addr).await;

    // Encrypt a payload to create a valid Data frame.
    let ct = peer_transport.encrypt(b"test payload").unwrap();
    let frame = Frame::new(FrameType::Data as u8, sid, 0, ct);

    let inbound = UdpInbound {
        frame: frame.clone(),
        src_addr: peer_addr,
    };

    // First dispatch: accepted.
    dispatch::udp::handle_udp_frame(&inbound, &td.state);
    assert_eq!(td.metric(&td.state.metrics.replay_detected_total), 0);

    // Second dispatch with same sequence: replay.
    dispatch::udp::handle_udp_frame(&inbound, &td.state);
    assert_eq!(
        td.metric(&td.state.metrics.replay_detected_total),
        1,
        "duplicate frame must increment replay_detected_total"
    );
}

#[tokio::test]
async fn dispatch_close_frame_removes_session() {
    // A Close frame from a peer must remove the session from the table.
    let td = TestDaemon::new().await;
    let peer_addr: std::net::SocketAddr = "10.0.0.2:48627".parse().unwrap();
    let (sid, mut peer_transport) = td.insert_session(peer_addr).await;
    assert_eq!(td.state.peer_table.len(), 1);

    let ct = peer_transport.encrypt(&[]).unwrap();
    let frame = Frame::new(FrameType::Close as u8, sid, 0, ct);
    let inbound = UdpInbound {
        frame,
        src_addr: peer_addr,
    };
    dispatch::udp::handle_udp_frame(&inbound, &td.state);

    assert_eq!(
        td.state.peer_table.len(),
        0,
        "Close frame must remove session"
    );
    assert_eq!(td.metric(&td.state.metrics.sessions_closed_total), 1);
}

#[tokio::test]
async fn maintenance_cleans_idle_sessions() {
    // Create a session, wait for it to become idle, run maintenance,
    // verify it's cleaned up. Idle timeout is 1s; we sleep 3s to be well
    // past the threshold (idle_sessions uses strict `>` on truncated seconds).
    let td = TestDaemon::with_config(4, 100, 1, 120).await;
    let peer_addr: std::net::SocketAddr = "10.0.0.3:48627".parse().unwrap();
    let (_sid, _transport) = td.insert_session(peer_addr).await;
    assert_eq!(td.state.peer_table.len(), 1);

    std::thread::sleep(std::time::Duration::from_secs(3));

    daemon_lifecycle::run_maintenance(&td.state);

    // close_session removes synchronously — no yield needed.
    assert_eq!(
        td.state.peer_table.len(),
        0,
        "maintenance must clean idle session"
    );
}

#[tokio::test]
async fn discovery_peer_removed_does_not_tear_down_session() {
    // PeerRemoved from an unauthenticated discovery source (mDNS, SWIM)
    // must NOT tear down an authenticated Noise session. It only removes
    // the peer from the dial queue. Session teardown requires an AEAD-
    // verified Close frame or idle timeout.
    let td = TestDaemon::new().await;
    let peer_addr: std::net::SocketAddr = "10.0.0.4:48627".parse().unwrap();
    let (_sid, _transport) = td.insert_session(peer_addr).await;
    assert_eq!(td.state.peer_table.len(), 1);

    // Add the peer to the dial queue so we can verify removal.
    td.state.discovery.add_peer(
        peer_addr,
        daemon_discovery::queue::DiscoverySource::Mdns,
        None,
    );
    assert!(td.state.discovery.queue_depth() > 0);

    let event = daemon_discovery::manager::DiscoveryEvent::PeerRemoved {
        addr: peer_addr,
        source: daemon_discovery::queue::DiscoverySource::Mdns,
    };
    dispatch::discovery::handle_discovery_event(event, &td.state);

    // Session must still be alive — unauthenticated source cannot kill it.
    assert_eq!(
        td.state.peer_table.len(),
        1,
        "PeerRemoved must NOT tear down authenticated session"
    );
    assert_eq!(
        td.metric(&td.state.metrics.sessions_closed_total),
        0,
        "no session close on unauthenticated PeerRemoved"
    );
}

// ============================================================================
// Cookie/`PoW` dispatch-level tests
// ============================================================================

#[tokio::test]
async fn dispatch_cookie_response_validates_correctly() {
    // Send a `HandshakeInit`, capture the `CookieRequest`, echo the cookie
    // back as a `CookieResponse`, and verify validation via metrics.
    let td = TestDaemon::new().await;
    let client_addr = td.client_socket.local_addr().unwrap();

    // Step 1: trigger cookie challenge.
    let knock = Frame::new(
        FrameType::HandshakeInit as u8,
        WireSessionId::zero(),
        0,
        vec![],
    );
    let inbound = UdpInbound {
        frame: knock,
        src_addr: client_addr,
    };
    dispatch::udp::handle_udp_frame(&inbound, &td.state);

    // Let the spawned UDP send complete.
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Step 2: receive the `CookieRequest`.
    let cookie_req = td.recv_frame().await.expect("must receive CookieRequest");
    assert_eq!(cookie_req.frame_type, FrameType::CookieRequest as u8);
    assert_eq!(cookie_req.body[0], 0x00, "must be tier-1 cookie");

    // Step 3: echo it back as `CookieResponse`.
    let response = Frame::new(
        FrameType::CookieResponse as u8,
        cookie_req.session_id,
        0,
        cookie_req.body.clone(),
    );
    let resp_inbound = UdpInbound {
        frame: response,
        src_addr: client_addr,
    };
    dispatch::udp::handle_cookie_response(&resp_inbound.frame, resp_inbound.src_addr, &td.state);

    assert!(
        td.metric(&td.state.metrics.cookie_challenges_total) >= 2,
        "cookie challenge + validation must both increment"
    );
}

#[tokio::test]
async fn dispatch_pow_stale_epoch_rejected() {
    // Construct a `PoW` `CookieResponse` with a stale epoch (>300s old).
    // The dispatch must reject it (frames_dropped increments).
    let td = TestDaemon::new().await;
    let client_addr = td.client_socket.local_addr().unwrap();

    let stale_epoch: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(400); // 400s ago — well past 300s limit

    let mut body = vec![0x01u8]; // `PoW` type
    body.extend_from_slice(&stale_epoch.to_be_bytes());
    body.extend_from_slice(&[0xAA; 16]); // fake solution

    let frame = Frame::new(
        FrameType::CookieResponse as u8,
        WireSessionId::zero(),
        0,
        body,
    );
    let before_dropped = td.metric(&td.state.metrics.frames_dropped_total);

    dispatch::udp::handle_cookie_response(&frame, client_addr, &td.state);

    assert!(
        td.metric(&td.state.metrics.frames_dropped_total) > before_dropped,
        "stale epoch must be rejected"
    );
}

#[tokio::test]
async fn dispatch_pow_future_epoch_rejected() {
    // Construct a `PoW` `CookieResponse` with a future epoch.
    let td = TestDaemon::new().await;
    let client_addr = td.client_socket.local_addr().unwrap();

    let future_epoch: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 100; // 100s in the future

    let mut body = vec![0x01u8];
    body.extend_from_slice(&future_epoch.to_be_bytes());
    body.extend_from_slice(&[0xBB; 16]);

    let frame = Frame::new(
        FrameType::CookieResponse as u8,
        WireSessionId::zero(),
        0,
        body,
    );
    let before_dropped = td.metric(&td.state.metrics.frames_dropped_total);

    dispatch::udp::handle_cookie_response(&frame, client_addr, &td.state);

    assert!(
        td.metric(&td.state.metrics.frames_dropped_total) > before_dropped,
        "future epoch must be rejected"
    );
}

// ============================================================================
// Handshake — `HandshakeContext`-based tests
// ============================================================================

#[tokio::test]
async fn handshake_invalid_pattern_byte_rejected() {
    // Send 0xFF as the pattern discriminant byte then close the connection.
    // The responder falls through to XX (default for unknown bytes),
    // which fails on the closed connection. Must not panic or hang.
    let td = TestDaemon::new().await;
    let ctx = daemon_network::handshake::HandshakeContext::from_state(&td.state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        daemon_network::handshake::handle_inbound_handshake(stream, peer_addr, &ctx).await
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    stream.write_all(&[0xFF]).await.unwrap();
    drop(stream);

    let result = tokio::time::timeout(std::time::Duration::from_secs(3), server).await;

    match result {
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Rejected { .. })) => {}
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Established { .. })) => {
            panic!("invalid pattern byte must not produce established session");
        }
        Ok(Err(_)) => panic!("server task panicked"),
        Err(_) => panic!("handshake must not hang on invalid pattern byte"),
    }
}

#[tokio::test]
async fn handshake_ikpsk2_no_cached_psk_rejected() {
    // Connect with pattern byte 0x02 (`IKpsk2`) but the TOFU store has
    // no PSK for the connecting address. Must be rejected.
    let td = TestDaemon::new().await;
    let ctx = daemon_network::handshake::HandshakeContext::from_state(&td.state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        daemon_network::handshake::handle_inbound_handshake(stream, peer_addr, &ctx).await
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    stream.write_all(&[0x02]).await.unwrap();
    stream.write_all(&48u16.to_be_bytes()).await.unwrap();
    stream.write_all(&[0xCC; 48]).await.unwrap();
    stream.flush().await.unwrap();
    drop(stream);

    let result = tokio::time::timeout(std::time::Duration::from_secs(3), server).await;

    match result {
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Rejected { reason })) => {
            assert!(
                reason.contains("no cached PSK") || reason.contains("IKpsk2"),
                "rejection must mention PSK or `IKpsk2`, got: {reason}"
            );
        }
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Established { .. })) => {
            panic!("`IKpsk2` without PSK must not establish");
        }
        Ok(Err(_)) => panic!("server task panicked"),
        Err(_) => panic!("must not hang"),
    }
}

#[tokio::test]
async fn handshake_tofu_revoked_peer_rejected() {
    // Pin a peer as revoked in the TOFU store, then complete a handshake
    // with that peer's key. The TOFU check must reject.
    let td = TestDaemon::new().await;

    let peer_kp = common::generate_keypair();
    let peer_key_hex = hex::encode(&peer_kp.public);
    td.state
        .tofu_store
        .lock()
        .unwrap()
        .pin(
            &peer_key_hex,
            "10.0.0.1:48627",
            core_types::TofuTrustLevel::Revoked,
        )
        .unwrap();

    let ctx = daemon_network::handshake::HandshakeContext::from_state(&td.state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        daemon_network::handshake::handle_inbound_handshake(stream, peer_addr, &ctx).await
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    use tokio::io::AsyncWriteExt;
    writer.write_all(&[0x01]).await.unwrap(); // XX pattern

    // The initiator side may error if the responder rejects mid-handshake.
    let _peer_result =
        daemon_network::noise::state::xx_initiator(&mut reader, &mut writer, &peer_kp).await;

    let result = tokio::time::timeout(std::time::Duration::from_secs(3), server).await;

    match result {
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Rejected { reason })) => {
            assert!(
                reason.contains("REVOKED"),
                "rejection must mention REVOKED, got: {reason}"
            );
        }
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Established { .. })) => {
            panic!("revoked peer must not establish a session");
        }
        Ok(Err(_)) => panic!("server task panicked"),
        Err(_) => panic!("must not hang"),
    }
}

// ============================================================================
// Discovery channel back-pressure
// ============================================================================

#[tokio::test]
async fn discovery_channel_backpressure() {
    // Fill the discovery event channel beyond capacity (256).
    // Events should be silently dropped without panic.
    let td = TestDaemon::new().await;

    for i in 0..300u32 {
        let addr: std::net::SocketAddr = format!("10.0.{}.{}:48627", i / 256, i % 256)
            .parse()
            .unwrap();
        td.state
            .discovery
            .add_peer(addr, daemon_discovery::queue::DiscoverySource::Mdns, None);
    }

    // The channel has 256 capacity. 300 events means some were dropped.
    // The queue itself has 1024 capacity so all 300 addresses are in the queue.
    // The important thing: no panic, no hang.
    assert!(
        td.state.discovery.queue_depth() > 0,
        "queue must have entries"
    );
}

// ============================================================================
// Handshake timeout
// ============================================================================

#[tokio::test]
async fn handshake_responder_times_out_on_slow_peer() {
    // Connect to the responder, send the pattern byte, then stall.
    // The responder wraps handle_inbound_handshake in a 10s timeout
    // in production. We test a 2s timeout here to keep CI fast.
    let td = TestDaemon::new().await;
    let ctx = daemon_network::handshake::HandshakeContext::from_state(&td.state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        // Use a short timeout (2s) instead of the production 10s.
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            daemon_network::handshake::handle_inbound_handshake(stream, peer_addr, &ctx),
        )
        .await
    });

    // Connect but only send the pattern byte, then stall (don't send msg1).
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    stream.write_all(&[0x01]).await.unwrap(); // XX pattern
    // Hold the connection open but send nothing more.

    let result = server.await.unwrap();
    assert!(result.is_err(), "handshake must time out when peer stalls");
    // Connection is still alive — drop it now.
    drop(stream);
}

// ============================================================================
// `HandshakeAck` timeout (peer stalls after Noise XX completes)
// ============================================================================

#[tokio::test]
async fn handshake_ack_exchange_times_out_on_slow_peer() {
    // Complete the Noise XX handshake, then stall on the HandshakeAck
    // exchange. The responder's 5s timeout must fire.
    let td = TestDaemon::new().await;
    let ctx = daemon_network::handshake::HandshakeContext::from_state(&td.state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        daemon_network::handshake::handle_inbound_handshake(stream, peer_addr, &ctx).await
    });

    // Initiator: send pattern byte + complete XX handshake, then stall.
    let peer_kp = common::generate_keypair();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    use tokio::io::AsyncWriteExt;
    writer.write_all(&[0x01]).await.unwrap(); // XX pattern

    // Complete the XX handshake from the initiator side.
    let _transport = daemon_network::noise::state::xx_initiator(&mut reader, &mut writer, &peer_kp)
        .await
        .unwrap();

    // Now the responder expects HandshakeAck exchange (5s timeout).
    // We hold the connection but send nothing. The responder times out
    // and still establishes the session (ack timeout is non-fatal, returns None
    // for peer_install_id but still creates the session).

    let result = tokio::time::timeout(std::time::Duration::from_secs(8), server).await;

    match result {
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Established { .. })) => {
            // Ack timeout is non-fatal — session established without peer identity.
        }
        Ok(Ok(daemon_network::handshake::HandshakeOutcome::Rejected { .. })) => {
            // Also acceptable — responder may reject if ack is required.
        }
        Ok(Err(_)) => panic!("server task panicked"),
        Err(_) => panic!("server must not hang past ack timeout"),
    }
    // Clean up.
    drop(reader);
    drop(writer);
}

// ============================================================================
// Close frame verified by receiver
// ============================================================================

#[tokio::test]
async fn close_session_sends_frame_to_peer() {
    // Create a session where the peer address is a real UDP socket we control.
    // Call close_session, then verify the peer socket receives a Close frame.
    let daemon_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer_addr = peer_socket.local_addr().unwrap();

    let kp_a = common::generate_keypair();
    let kp_b = common::generate_keypair();

    let (sa, sb) = tokio::io::duplex(65536);
    let (mut ar, mut aw) = tokio::io::split(sa);
    let (mut br, mut bw) = tokio::io::split(sb);

    let (ra, _rb) = tokio::join!(
        daemon_network::noise::state::xx_initiator(&mut ar, &mut aw, &kp_a),
        daemon_network::noise::state::xx_responder(&mut br, &mut bw, &kp_b),
    );
    let transport = ra.unwrap();
    let remote = transport.remote_static().unwrap();

    let sid = daemon_network::transport::frame::WireSessionId::random();
    let table = Arc::new(daemon_network::session::table::PeerTable::new(256));
    let peer = daemon_network::session::state::PeerState::new(
        sid,
        remote,
        peer_addr,
        transport,
        core_types::TofuTrustLevel::Tofu,
    );
    table.insert(peer);

    let metrics = Arc::new(daemon_network::metrics::Metrics::new());
    daemon_network::send::close_session(&sid, &table, &daemon_socket, &metrics);

    // Session must be removed immediately (synchronous).
    assert_eq!(table.len(), 0);

    // The spawned Close frame send should arrive at the peer socket.
    // Give the spawned task a moment to run.
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut buf = vec![0u8; 1500];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        peer_socket.recv_from(&mut buf),
    )
    .await;

    match result {
        Ok(Ok((len, _src))) => {
            let frame = daemon_network::transport::frame::Frame::parse(&buf[..len])
                .expect("received data must parse as a frame");
            assert_eq!(
                frame.frame_type,
                core_types::FrameType::Close as u8,
                "peer must receive a Close frame"
            );
        }
        Ok(Err(e)) => panic!("peer socket recv error: {e}"),
        Err(_) => panic!("peer must receive Close frame within 2s"),
    }
}

// ============================================================================
// `PeerDiscovered` immediate dial completes handshake
// ============================================================================

#[tokio::test]
async fn discovery_peer_discovered_dials_and_establishes() {
    // Spawn a TCP listener as a "remote peer", then dispatch a PeerDiscovered
    // event. The daemon should dial immediately and complete a handshake.
    let td = TestDaemon::new().await;

    // The "remote peer" listens on a random port.
    let peer_kp = common::generate_keypair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();

    // Spawn the remote peer's responder. It reads the pattern byte, does XX.
    let peer_kp_clone = snow::Keypair {
        private: peer_kp.private.clone(),
        public: peer_kp.public.clone(),
    };
    let responder = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        use tokio::io::AsyncReadExt;
        let mut pat = [0u8; 1];
        reader.read_exact(&mut pat).await.unwrap();
        daemon_network::noise::state::xx_responder(&mut reader, &mut writer, &peer_kp_clone).await
    });

    // Dispatch PeerDiscovered — the handler spawns an immediate dial.
    dispatch::discovery::handle_discovery_event(
        daemon_discovery::manager::DiscoveryEvent::PeerDiscovered {
            addr: peer_addr,
            source: daemon_discovery::queue::DiscoverySource::Mdns,
            advisory_pubkey_hex: Some(hex::encode(&peer_kp.public[..16])),
        },
        &td.state,
    );

    // Wait for the spawned dial to complete.
    let resp_result = tokio::time::timeout(std::time::Duration::from_secs(5), responder).await;

    match resp_result {
        Ok(Ok(Ok(_transport))) => {
            // Give the dial task a moment to insert the session.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert!(
                td.state.peer_table.len() > 0,
                "PeerDiscovered must result in an established session"
            );
        }
        Ok(Ok(Err(e))) => panic!("responder handshake failed: {e}"),
        Ok(Err(e)) => panic!("responder task panicked: {e}"),
        Err(_) => panic!("dial must complete within 5s"),
    }
}
