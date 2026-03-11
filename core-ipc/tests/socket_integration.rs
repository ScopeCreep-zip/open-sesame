//! Integration tests for IPC socket communication.
//!
//! All tests use Noise IK encrypted transport — the same code path as production.
//! There is no plaintext transport path.

use core_ipc::{BusClient, BusServer, ClearanceRegistry, Message, ZeroizingKeypair, generate_keypair};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::time::Duration;
use uuid::Uuid;

/// Helper: start an encrypted bus server with pre-registered client keypairs.
///
/// `client_count` keypairs are generated and registered at `SecurityLevel::Internal`.
/// Returns (server, temp_dir, server_public_key, client_keypairs).
async fn start_server_with_clients(
    client_count: usize,
) -> (BusServer, tempfile::TempDir, [u8; 32], Vec<ZeroizingKeypair>) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let mut registry = ClearanceRegistry::new();
    let mut client_keypairs = Vec::with_capacity(client_count);

    for i in 0..client_count {
        let kp = generate_keypair().unwrap();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(kp.public());
        registry.register(pubkey, format!("test-client-{i}"), SecurityLevel::Internal);
        client_keypairs.push(kp);
    }

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    (server, dir, server_pub, client_keypairs)
}

/// Helper: start an encrypted bus server with an empty registry (all clients get Open).
async fn start_server() -> (BusServer, tempfile::TempDir, [u8; 32]) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let keypair = generate_keypair().unwrap();
    let server_pub: [u8; 32] = keypair.public().try_into().unwrap();
    let server = BusServer::bind(&sock, keypair.into_inner(), ClearanceRegistry::new()).unwrap();
    (server, dir, server_pub)
}

/// Helper: connect a client with a specific keypair.
async fn connect_with_keypair(
    id: DaemonId,
    sock: &std::path::Path,
    server_pub: &[u8; 32],
    kp: &ZeroizingKeypair,
) -> BusClient {
    BusClient::connect_encrypted(id, sock, server_pub, kp.as_inner())
        .await
        .unwrap()
}

/// Helper: connect a client with an ephemeral (unregistered) keypair.
async fn connect_client(
    id: DaemonId,
    sock: &std::path::Path,
    server_pub: &[u8; 32],
) -> BusClient {
    let kp = generate_keypair().unwrap();
    BusClient::connect_encrypted(id, sock, server_pub, kp.as_inner())
        .await
        .unwrap()
}

/// Helper: make a DaemonId from a u128.
fn did(n: u128) -> DaemonId {
    DaemonId::from_uuid(Uuid::from_u128(n))
}

#[tokio::test]
async fn server_bind_creates_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("pds/bus.sock");
    let keypair = generate_keypair().unwrap();
    let _server = BusServer::bind(&sock, keypair.into_inner(), ClearanceRegistry::new()).unwrap();
    assert!(sock.exists(), "socket file should exist after bind");
}

#[tokio::test]
async fn client_connect_and_server_accept() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    let server_handle = tokio::spawn(async move {
        tokio::select! {
            _ = server.run() => unreachable!(),
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                server.connection_count().await
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let _client = connect_client(did(1), &sock, &server_pub).await;

    let count = server_handle.await.unwrap();
    assert_eq!(count, 1, "server should have 1 connected client");
}

#[tokio::test]
async fn publish_subscribe_roundtrip() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;
    let mut client_b = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    client_a
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(1),
                version: "0.1.0".into(),
                capabilities: vec!["test".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), client_b.recv())
        .await
        .expect("timeout waiting for message")
        .expect("channel closed");

    assert!(
        matches!(msg.payload, EventKind::DaemonStarted { .. }),
        "expected DaemonStarted, got {:?}",
        msg.payload
    );
}

#[tokio::test]
async fn request_response_correlation() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;
    let mut client_b = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    let response_handle = tokio::spawn(async move {
        client_a
            .request(
                EventKind::SecretList { profile: TrustProfileName::try_from("test").unwrap() },
                SecurityLevel::Internal,
                Duration::from_secs(2),
            )
            .await
    });

    let request_msg = tokio::time::timeout(Duration::from_millis(500), client_b.recv())
        .await
        .expect("timeout waiting for request")
        .expect("channel closed");

    assert!(matches!(request_msg.payload, EventKind::SecretList { .. }));

    let msg_ctx = core_ipc::MessageContext::new(did(2));
    let response = Message::new(
        &msg_ctx,
        EventKind::SecretListResponse {
            keys: vec!["api-key".into(), "db-pass".into()],
            denial: None,
        },
        SecurityLevel::Internal,
        client_b.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    client_b.send(&response).await.unwrap();

    let result = response_handle.await.unwrap().unwrap();
    match result.payload {
        EventKind::SecretListResponse { keys, .. } => {
            assert_eq!(keys, vec!["api-key".to_string(), "db-pass".to_string()]);
        }
        other => panic!("expected SecretListResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn launch_execute_response_roundtrip() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let cli_client = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;
    let mut launcher = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    // CLI sends LaunchExecute request.
    let response_handle = tokio::spawn(async move {
        cli_client
            .request(
                EventKind::LaunchExecute {
                    entry_id: "firefox".into(),
                    profile: Some(TrustProfileName::try_from("default").unwrap()),
                    tags: Vec::new(),
                },
                SecurityLevel::Internal,
                Duration::from_secs(2),
            )
            .await
    });

    // Launcher receives the request.
    let request_msg = tokio::time::timeout(Duration::from_millis(500), launcher.recv())
        .await
        .expect("timeout waiting for LaunchExecute")
        .expect("channel closed");

    assert!(matches!(request_msg.payload, EventKind::LaunchExecute { .. }));

    // Launcher sends success response with pid and no error.
    let msg_ctx = core_ipc::MessageContext::new(did(2));
    let response = Message::new(
        &msg_ctx,
        EventKind::LaunchExecuteResponse { pid: 12345, error: None },
        SecurityLevel::Internal,
        launcher.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    launcher.send(&response).await.unwrap();

    let result = response_handle.await.unwrap().unwrap();
    match result.payload {
        EventKind::LaunchExecuteResponse { pid, error } => {
            assert_eq!(pid, 12345);
            assert!(error.is_none());
        }
        other => panic!("expected LaunchExecuteResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn launch_execute_error_roundtrip() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let cli_client = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;
    let mut launcher = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    let response_handle = tokio::spawn(async move {
        cli_client
            .request(
                EventKind::LaunchExecute {
                    entry_id: "nonexistent".into(),
                    profile: None,
                    tags: Vec::new(),
                },
                SecurityLevel::Internal,
                Duration::from_secs(2),
            )
            .await
    });

    let request_msg = tokio::time::timeout(Duration::from_millis(500), launcher.recv())
        .await
        .expect("timeout waiting for LaunchExecute")
        .expect("channel closed");

    // Launcher sends failure response with error message.
    let msg_ctx = core_ipc::MessageContext::new(did(2));
    let response = Message::new(
        &msg_ctx,
        EventKind::LaunchExecuteResponse {
            pid: 0,
            error: Some("desktop entry 'nonexistent' not found".into()),
        },
        SecurityLevel::Internal,
        launcher.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    launcher.send(&response).await.unwrap();

    let result = response_handle.await.unwrap().unwrap();
    match result.payload {
        EventKind::LaunchExecuteResponse { pid, error } => {
            assert_eq!(pid, 0);
            assert!(error.as_ref().is_some_and(|e| e.contains("not found")));
        }
        other => panic!("expected LaunchExecuteResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn sender_does_not_receive_own_message() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut client = connect_client(did(1), &sock, &server_pub).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(1),
                version: "0.1.0".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_millis(100), client.recv()).await;
    assert!(result.is_err(), "sender should not receive own broadcast");
}

#[tokio::test]
async fn client_connect_retry_on_missing_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let fake_pub = [0u8; 32];

    let kp = generate_keypair().unwrap();
    let result = BusClient::connect_encrypted(did(1), &sock, &fake_pub, kp.as_inner()).await;
    let err = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("should fail when socket doesn't exist"),
    };
    assert!(
        err.contains("failed to connect"),
        "error should mention connection failure: {err}"
    );
}

#[tokio::test]
async fn request_timeout() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = connect_client(did(1), &sock, &server_pub).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = client
        .request(
            EventKind::StatusRequest,
            SecurityLevel::Internal,
            Duration::from_millis(100),
        )
        .await;

    assert!(result.is_err(), "should timeout with no responder");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("timed out"),
        "error should mention timeout: {err}"
    );
}

// ===== IPC Authentication — Noise Handshake Rejection =====

#[tokio::test]
async fn noise_handshake_rejects_wrong_key() {
    let (server, dir, _real_server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Generate a WRONG server public key (not the real one)
    let wrong_keypair = generate_keypair().unwrap();
    let wrong_server_pub: [u8; 32] = wrong_keypair.public().try_into().unwrap();

    // Client attempts to connect expecting the wrong server public key
    let client_kp = generate_keypair().unwrap();
    let result = BusClient::connect_encrypted(did(1), &sock, &wrong_server_pub, client_kp.as_inner()).await;

    assert!(
        result.is_err(),
        "Noise IK handshake must fail when client expects wrong server public key"
    );
}

// ===== Secret Value Never Broadcast =====

#[tokio::test]
async fn secret_response_not_received_by_bystander() {
    let (server, dir, server_pub, kps) = start_server_with_clients(3).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect requester (client A)
    let client_a = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;

    // Connect bystander (client B) — should NOT receive the response
    let mut bystander = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;

    // Connect simulated secrets daemon (client C)
    let mut secrets_daemon = connect_with_keypair(did(3), &sock, &server_pub, &kps[2]).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    // Requester sends SecretList request via request() which registers a pending waiter
    let response_handle = tokio::spawn(async move {
        client_a
            .request(
                EventKind::SecretList {
                    profile: TrustProfileName::try_from("work").unwrap(),
                },
                SecurityLevel::Internal,
                Duration::from_secs(2),
            )
            .await
    });

    // Secrets daemon receives the request
    let request_msg = tokio::time::timeout(Duration::from_millis(500), secrets_daemon.recv())
        .await
        .expect("timeout waiting for request")
        .expect("channel closed");

    assert!(matches!(request_msg.payload, EventKind::SecretList { .. }));

    // Bystander also receives the broadcast request — drain it
    let bystander_request = tokio::time::timeout(Duration::from_millis(500), bystander.recv())
        .await
        .expect("bystander should receive broadcast request")
        .expect("bystander channel closed");
    assert!(matches!(bystander_request.payload, EventKind::SecretList { .. }));

    // Secrets daemon sends correlated response
    let msg_ctx = core_ipc::MessageContext::new(did(3));
    let response = Message::new(
        &msg_ctx,
        EventKind::SecretListResponse {
            keys: vec!["api-key".into()],
            denial: None,
        },
        SecurityLevel::Internal,
        secrets_daemon.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    secrets_daemon.send(&response).await.unwrap();

    // Requester receives the response
    let result = response_handle.await.unwrap().unwrap();
    assert!(matches!(result.payload, EventKind::SecretListResponse { .. }));

    // Bystander must NOT receive the correlated response (unicast routing)
    let bystander_result = tokio::time::timeout(Duration::from_millis(200), bystander.recv()).await;
    assert!(
        bystander_result.is_err(),
        "bystander must not receive correlated response (unicast routing)"
    );
}

#[tokio::test]
async fn uncorrelated_response_is_dropped() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = connect_client(did(1), &sock, &server_pub).await;
    let mut client_b = connect_client(did(2), &sock, &server_pub).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client A sends a response with a fabricated correlation_id (no matching request)
    let msg_ctx = core_ipc::MessageContext::new(did(1));
    let orphan_response = Message::new(
        &msg_ctx,
        EventKind::SecretListResponse {
            keys: vec!["should-not-broadcast".into()],
            denial: None,
        },
        SecurityLevel::Internal,
        client_a.epoch(),
    )
    .with_correlation(Uuid::from_u128(99999));

    client_a.send(&orphan_response).await.unwrap();

    // Client B must NOT receive the orphan response
    let result = tokio::time::timeout(Duration::from_millis(200), client_b.recv()).await;
    assert!(
        result.is_err(),
        "orphan response (no matching pending request) must be dropped, not broadcast"
    );
}

#[tokio::test]
async fn multiple_clients_receive_broadcast() {
    let (server, dir, server_pub, kps) = start_server_with_clients(3).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let sender = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;
    let mut recv_a = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;
    let mut recv_b = connect_with_keypair(did(3), &sock, &server_pub, &kps[2]).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    sender
        .publish(
            EventKind::ConfigReloaded {
                daemon_id: did(1),
                changed_keys: vec!["theme".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg_a = tokio::time::timeout(Duration::from_millis(500), recv_a.recv())
        .await
        .expect("timeout")
        .expect("closed");
    let msg_b = tokio::time::timeout(Duration::from_millis(500), recv_b.recv())
        .await
        .expect("timeout")
        .expect("closed");

    assert!(matches!(msg_a.payload, EventKind::ConfigReloaded { .. }));
    assert!(matches!(msg_b.payload, EventKind::ConfigReloaded { .. }));
}

// ===== Clearance escalation blocking =====
// SECURITY INVARIANT: A client registered at Open clearance must not be able
// to send Internal-level messages. The bus server must silently drop the frame.
#[tokio::test]
async fn clearance_escalation_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    // Register one client at Open clearance, one at Internal.
    let open_kp = generate_keypair().unwrap();
    let internal_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut open_pub = [0u8; 32];
    open_pub.copy_from_slice(open_kp.public());
    registry.register(open_pub, "low-daemon".into(), SecurityLevel::Open);
    let mut internal_pub = [0u8; 32];
    internal_pub.copy_from_slice(internal_kp.public());
    registry.register(internal_pub, "high-daemon".into(), SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let open_client = connect_with_keypair(did(10), &sock, &server_pub, &open_kp).await;
    let mut internal_client = connect_with_keypair(did(11), &sock, &server_pub, &internal_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Open-clearance client attempts to send an Internal-level message.
    open_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(10),
                version: "0.1.0".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    // Internal client should NOT receive it (frame dropped by clearance check).
    let result = tokio::time::timeout(Duration::from_millis(200), internal_client.recv()).await;
    assert!(
        result.is_err(),
        "Internal-level message from Open-clearance client must be dropped"
    );
}

// ===== Sender identity change mid-session =====
// SECURITY INVARIANT: Once a connection's DaemonId is bound on its first
// message, any subsequent message with a different DaemonId must be dropped.
#[tokio::test]
async fn sender_identity_change_blocked() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let sender = connect_with_keypair(did(20), &sock, &server_pub, &kps[0]).await;
    let mut receiver = connect_with_keypair(did(21), &sock, &server_pub, &kps[1]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // First message: binds DaemonId 20 to this connection.
    sender
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(20),
                version: "0.1.0".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    // Receiver should get the first message.
    let msg = tokio::time::timeout(Duration::from_millis(500), receiver.recv())
        .await
        .expect("should receive first message")
        .expect("channel closed");
    assert!(matches!(msg.payload, EventKind::DaemonStarted { .. }));

    // Second message: different DaemonId (identity change attempt).
    let spoofed_ctx = core_ipc::MessageContext::new(did(99));
    let spoofed = Message::new(
        &spoofed_ctx, // Different from the bound did(20)
        EventKind::DaemonStarted {
            daemon_id: did(99),
            version: "0.1.0".into(),
            capabilities: vec![],
        },
        SecurityLevel::Internal,
        sender.epoch(),
    );
    sender.send(&spoofed).await.unwrap();

    // Receiver must NOT get the spoofed message.
    let result = tokio::time::timeout(Duration::from_millis(200), receiver.recv()).await;
    assert!(
        result.is_err(),
        "message with changed DaemonId mid-session must be dropped"
    );
}

// ===== verified_sender_name stamping =====
// SECURITY INVARIANT: Messages routed through the bus must have
// `verified_sender_name` stamped by the server from the Noise IK registry
// lookup, not self-declared.
#[tokio::test]
async fn verified_sender_name_stamped() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client 0 is registered as "test-client-0" in the registry.
    let sender = connect_with_keypair(did(30), &sock, &server_pub, &kps[0]).await;
    let mut receiver = connect_with_keypair(did(31), &sock, &server_pub, &kps[1]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    sender
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(30),
                version: "0.1.0".into(),
                capabilities: vec!["fake-name".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), receiver.recv())
        .await
        .expect("should receive message")
        .expect("channel closed");

    // The server must have stamped the registry name, not the self-declared capability.
    assert_eq!(
        msg.verified_sender_name.as_deref(),
        Some("test-client-0"),
        "verified_sender_name must be stamped from registry, not self-declared"
    );
}

// ===== Unregistered CLI can publish at Internal to reach daemons =====
// SecurityLevel ordering: Open < Internal < ProfileScoped < SecretsOnly.
// Unregistered clients get SecretsOnly (highest) clearance.
// daemon-wm is registered at Internal clearance.
// Publishing at Internal works because:
//   - Sender check: SecretsOnly >= Internal → allowed
//   - Recipient check: Internal >= Internal → delivered
#[tokio::test]
async fn unregistered_client_overlay_reaches_daemon_wm() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    // Register only daemon-wm (Internal clearance).
    let daemon_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register(daemon_pub, "daemon-wm".into(), SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // daemon-wm: registered, Internal clearance.
    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;

    // CLI: unregistered ephemeral key → SecretsOnly clearance.
    let cli = connect_client(did(2), &sock, &server_pub).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    // CLI publishes WmActivateOverlay at Internal level.
    cli.publish(EventKind::WmActivateOverlay, SecurityLevel::Internal)
        .await
        .unwrap();

    // daemon-wm (Internal) should receive it: Internal >= Internal.
    let msg = tokio::time::timeout(Duration::from_millis(500), daemon_wm.recv())
        .await
        .expect("daemon-wm must receive WmActivateOverlay from CLI")
        .expect("channel closed");

    assert!(
        matches!(msg.payload, EventKind::WmActivateOverlay),
        "expected WmActivateOverlay, got {:?}",
        msg.payload
    );
}

// ===== Negative: SecretsOnly-level messages don't reach Internal daemons =====
// Publishing at SecretsOnly level means only SecretsOnly-clearance recipients
// can receive it. daemon-wm (Internal) is below SecretsOnly, so it's excluded.
#[tokio::test]
async fn secrets_only_message_not_delivered_to_internal_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let daemon_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register(daemon_pub, "daemon-wm".into(), SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;
    let cli = connect_client(did(2), &sock, &server_pub).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    // CLI (SecretsOnly) publishes at SecretsOnly level — daemon-wm (Internal)
    // cannot receive it because Internal < SecretsOnly.
    cli.publish(EventKind::WmActivateOverlay, SecurityLevel::SecretsOnly)
        .await
        .unwrap();

    // daemon-wm must NOT receive it (recipient clearance Internal < SecretsOnly).
    let result = tokio::time::timeout(Duration::from_millis(200), daemon_wm.recv()).await;
    assert!(
        result.is_err(),
        "SecretsOnly-level message must not reach Internal-clearance daemon"
    );
}

// ===== shutdown() flushes outbound frames before disconnect =====
// Simulates the CLI lifecycle: connect, publish, shutdown, verify delivery.
#[tokio::test]
async fn shutdown_flushes_publish_before_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let daemon_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register(daemon_pub, "daemon-wm".into(), SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;
    let cli = connect_client(did(2), &sock, &server_pub).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // CLI publishes then gracefully shuts down (like cmd_wm_overlay).
    cli.publish(EventKind::WmActivateOverlay, SecurityLevel::Internal)
        .await
        .unwrap();
    cli.shutdown().await;

    // daemon-wm must receive the event even though CLI has disconnected.
    let msg = tokio::time::timeout(Duration::from_millis(500), daemon_wm.recv())
        .await
        .expect("shutdown must flush: daemon-wm must receive the event")
        .expect("channel closed");

    assert!(
        matches!(msg.payload, EventKind::WmActivateOverlay),
        "expected WmActivateOverlay, got {:?}",
        msg.payload
    );
}

// ===== drop without shutdown can lose outbound frames =====
// Proves the bug that shutdown() fixes: dropping BusClient immediately
// after publish races the I/O task and the frame may never reach the wire.
#[tokio::test]
async fn drop_without_shutdown_may_lose_message() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let daemon_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register(daemon_pub, "daemon-wm".into(), SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;
    let cli = connect_client(did(2), &sock, &server_pub).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // CLI publishes then drops immediately — no shutdown.
    cli.publish(EventKind::WmActivateOverlay, SecurityLevel::Internal)
        .await
        .unwrap();
    drop(cli);

    // The message may or may not arrive — the race is non-deterministic.
    // We use a short timeout; if it arrives, fine. The point is that
    // this is unreliable vs shutdown() which guarantees delivery.
    let result = tokio::time::timeout(Duration::from_millis(100), daemon_wm.recv()).await;
    // We don't assert pass or fail — this test documents the race condition.
    // The companion test (shutdown_flushes_publish_before_disconnect) proves
    // that shutdown() reliably delivers.
    let _ = result;
}
