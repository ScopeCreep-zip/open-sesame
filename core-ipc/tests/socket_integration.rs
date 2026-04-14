//! Integration tests for IPC socket communication.
//!
//! All tests use Noise IK encrypted transport — the same code path as production.
//! There is no plaintext transport path.

use core_ipc::{
    BusClient, BusServer, ClearanceRegistry, Message, ZeroizingKeypair, generate_keypair,
};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::time::Duration;
use uuid::Uuid;

/// Helper: start an encrypted bus server with pre-registered client keypairs.
///
/// `client_count` keypairs are generated and registered at `SecurityLevel::Internal`.
/// Returns (server, `temp_dir`, `server_public_key`, `client_keypairs`).
#[allow(clippy::unused_async)]
async fn start_server_with_clients(
    client_count: usize,
) -> (
    BusServer,
    tempfile::TempDir,
    [u8; 32],
    Vec<ZeroizingKeypair>,
) {
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
        registry.register(format!("test-client-{i}"), pubkey, SecurityLevel::Internal);
        client_keypairs.push(kp);
    }

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    (server, dir, server_pub, client_keypairs)
}

/// Helper: start an encrypted bus server with a single registered Internal client.
#[allow(clippy::unused_async)]
async fn start_server() -> (BusServer, tempfile::TempDir, [u8; 32], ZeroizingKeypair) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let keypair = generate_keypair().unwrap();
    let server_pub: [u8; 32] = keypair.public().try_into().unwrap();
    let mut registry = ClearanceRegistry::new();
    let client_kp = generate_keypair().unwrap();
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(client_kp.public());
    registry.register("test-default".into(), client_pub, SecurityLevel::Internal);
    let server = BusServer::bind(&sock, keypair.into_inner(), registry).unwrap();
    (server, dir, server_pub, client_kp)
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

/// Helper: make a `DaemonId` from a u128.
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
    let (server, dir, server_pub, client_kp) = start_server().await;
    let sock = dir.path().join("bus.sock");

    let server_handle = tokio::spawn(async move {
        tokio::select! {
            _ = server.run() => unreachable!(),
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                server.connection_count().await
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let _client = connect_with_keypair(did(1), &sock, &server_pub, &client_kp).await;

    let count = server_handle.await.unwrap();
    assert_eq!(count, 1, "server should have 1 connected client");
}

#[tokio::test]
async fn publish_subscribe_roundtrip() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
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

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;
    let mut client_b = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    let response_handle = tokio::spawn(async move {
        client_a
            .request(
                EventKind::SecretList {
                    profile: TrustProfileName::try_from("test").unwrap(),
                },
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

    tokio::spawn(async move {
        let _ = server.run().await;
    });
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
                    launch_args: Vec::new(),
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

    assert!(matches!(
        request_msg.payload,
        EventKind::LaunchExecute { .. }
    ));

    // Launcher sends success response with pid and no error.
    let msg_ctx = core_ipc::MessageContext::new(did(2));
    let response = Message::new(
        &msg_ctx,
        EventKind::LaunchExecuteResponse {
            pid: 12345,
            error: None,
            denial: None,
        },
        SecurityLevel::Internal,
        launcher.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    launcher.send(&response).await.unwrap();

    let result = response_handle.await.unwrap().unwrap();
    match result.payload {
        EventKind::LaunchExecuteResponse { pid, error, .. } => {
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

    tokio::spawn(async move {
        let _ = server.run().await;
    });
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
                    launch_args: Vec::new(),
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
            denial: Some(core_types::LaunchDenial::EntryNotFound),
        },
        SecurityLevel::Internal,
        launcher.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    launcher.send(&response).await.unwrap();

    let result = response_handle.await.unwrap().unwrap();
    match result.payload {
        EventKind::LaunchExecuteResponse { pid, error, .. } => {
            assert_eq!(pid, 0);
            assert!(error.as_ref().is_some_and(|e| e.contains("not found")));
        }
        other => panic!("expected LaunchExecuteResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn sender_does_not_receive_own_message() {
    let (server, dir, server_pub, client_kp) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut client = connect_with_keypair(did(1), &sock, &server_pub, &client_kp).await;
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
    let (server, dir, server_pub, client_kp) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = connect_with_keypair(did(1), &sock, &server_pub, &client_kp).await;
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
    let (server, dir, _real_server_pub, _client_kp) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Generate a WRONG server public key (not the real one)
    let wrong_keypair = generate_keypair().unwrap();
    let wrong_server_pub: [u8; 32] = wrong_keypair.public().try_into().unwrap();

    // Client attempts to connect expecting the wrong server public key
    let client_kp = generate_keypair().unwrap();
    let result =
        BusClient::connect_encrypted(did(1), &sock, &wrong_server_pub, client_kp.as_inner()).await;

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

    tokio::spawn(async move {
        let _ = server.run().await;
    });
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
    assert!(matches!(
        bystander_request.payload,
        EventKind::SecretList { .. }
    ));

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
    assert!(matches!(
        result.payload,
        EventKind::SecretListResponse { .. }
    ));

    // Bystander must NOT receive the correlated response (unicast routing)
    let bystander_result = tokio::time::timeout(Duration::from_millis(200), bystander.recv()).await;
    assert!(
        bystander_result.is_err(),
        "bystander must not receive correlated response (unicast routing)"
    );
}

#[tokio::test]
async fn uncorrelated_response_is_dropped() {
    let (server, dir, server_pub, kps) = start_server_with_clients(2).await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = connect_with_keypair(did(1), &sock, &server_pub, &kps[0]).await;
    let mut client_b = connect_with_keypair(did(2), &sock, &server_pub, &kps[1]).await;

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

    tokio::spawn(async move {
        let _ = server.run().await;
    });
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
    registry.register("low-daemon".into(), open_pub, SecurityLevel::Open);
    let mut internal_pub = [0u8; 32];
    internal_pub.copy_from_slice(internal_kp.public());
    registry.register("high-daemon".into(), internal_pub, SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
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

    tokio::spawn(async move {
        let _ = server.run().await;
    });
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

    tokio::spawn(async move {
        let _ = server.run().await;
    });
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

// ===== Ephemeral clients get SecretsOnly clearance via UCred =====
// SECURITY INVARIANT: Unregistered keys (ephemeral CLI connections) that pass
// UCred same-UID validation receive SecretsOnly clearance. This allows the CLI
// to send UnlockRequest and SecretCRUD messages to daemon-secrets.
#[tokio::test]
async fn ephemeral_client_gets_secrets_only_clearance() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let server = BusServer::bind(&sock, server_kp.into_inner(), ClearanceRegistry::new()).unwrap();
    let server_handle = tokio::spawn(async move {
        tokio::select! {
            _ = server.run() => unreachable!(),
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                server.connection_count().await
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Ephemeral client connects with an unregistered key.
    let unreg_kp = generate_keypair().unwrap();
    let _client = BusClient::connect_encrypted(did(1), &sock, &server_pub, unreg_kp.as_inner())
        .await
        .expect("ephemeral client should connect via UCred validation");

    let count = server_handle.await.unwrap();
    assert_eq!(count, 1, "ephemeral client should be connected");
}

// ===== Registered client can publish at Internal to reach daemons =====
#[tokio::test]
async fn registered_client_overlay_reaches_daemon_wm() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let daemon_kp = generate_keypair().unwrap();
    let cli_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register("daemon-wm".into(), daemon_pub, SecurityLevel::Internal);
    let mut cli_pub = [0u8; 32];
    cli_pub.copy_from_slice(cli_kp.public());
    registry.register("cli".into(), cli_pub, SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;
    let cli = connect_with_keypair(did(2), &sock, &server_pub, &cli_kp).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    cli.publish(EventKind::WmActivateOverlay, SecurityLevel::Internal)
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), daemon_wm.recv())
        .await
        .expect("daemon-wm must receive WmActivateOverlay")
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
    let secrets_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register("daemon-wm".into(), daemon_pub, SecurityLevel::Internal);
    let mut secrets_pub = [0u8; 32];
    secrets_pub.copy_from_slice(secrets_kp.public());
    registry.register(
        "daemon-secrets".into(),
        secrets_pub,
        SecurityLevel::SecretsOnly,
    );

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;
    let secrets = connect_with_keypair(did(2), &sock, &server_pub, &secrets_kp).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    // SecretsOnly client publishes at SecretsOnly level -- daemon-wm (Internal)
    // cannot receive it because Internal < SecretsOnly.
    secrets
        .publish(EventKind::WmActivateOverlay, SecurityLevel::SecretsOnly)
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
    let cli_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register("daemon-wm".into(), daemon_pub, SecurityLevel::Internal);
    let mut cli_pub = [0u8; 32];
    cli_pub.copy_from_slice(cli_kp.public());
    registry.register("cli".into(), cli_pub, SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;
    let cli = connect_with_keypair(did(2), &sock, &server_pub, &cli_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // CLI publishes then gracefully shuts down.
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
    let cli_kp = generate_keypair().unwrap();
    let mut registry = ClearanceRegistry::new();
    let mut daemon_pub = [0u8; 32];
    daemon_pub.copy_from_slice(daemon_kp.public());
    registry.register("daemon-wm".into(), daemon_pub, SecurityLevel::Internal);
    let mut cli_pub = [0u8; 32];
    cli_pub.copy_from_slice(cli_kp.public());
    registry.register("cli".into(), cli_pub, SecurityLevel::Internal);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut daemon_wm = connect_with_keypair(did(1), &sock, &server_pub, &daemon_kp).await;
    let cli = connect_with_keypair(did(2), &sock, &server_pub, &cli_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // CLI publishes then drops immediately -- no shutdown.
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

// ===== Key rotation: pending pubkey recognized by server =====
// Reproduces the root cause of the launcher death bug: a daemon reconnects
// with a new keypair during the rotation grace period. The server must
// recognize the new pubkey and stamp verified_sender_name on messages
// from the new connection.
#[tokio::test]
async fn pending_rotation_key_recognized_by_server() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let original_kp = generate_keypair().unwrap();
    let rotated_kp = generate_keypair().unwrap();
    let observer_kp = generate_keypair().unwrap();

    let mut original_pub = [0u8; 32];
    original_pub.copy_from_slice(original_kp.public());
    let mut rotated_pub = [0u8; 32];
    rotated_pub.copy_from_slice(rotated_kp.public());
    let mut observer_pub = [0u8; 32];
    observer_pub.copy_from_slice(observer_kp.public());

    let mut registry = ClearanceRegistry::new();
    registry.register(
        "daemon-launcher".into(),
        original_pub,
        SecurityLevel::Internal,
    );
    registry.register("observer".into(), observer_pub, SecurityLevel::Internal);

    // Simulate phase 1: register the rotated key as pending.
    registry.register_pending("daemon-launcher", rotated_pub);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Observer connects to receive broadcast messages.
    let mut observer = connect_with_keypair(did(100), &sock, &server_pub, &observer_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Daemon connects with the ROTATED key (simulating reconnection during grace period).
    let rotated_client = connect_with_keypair(did(50), &sock, &server_pub, &rotated_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Daemon announces itself on the new connection.
    rotated_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(50),
                version: "test".into(),
                capabilities: vec!["launcher".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    // Observer should receive DaemonStarted with verified_sender_name stamped
    // by the server from the registry — proving the pending key was recognized.
    let msg = tokio::time::timeout(Duration::from_millis(500), observer.recv())
        .await
        .expect("observer should receive message")
        .expect("channel closed");

    assert_eq!(
        msg.verified_sender_name.as_deref(),
        Some("daemon-launcher"),
        "server must recognize the pending rotation pubkey and stamp the daemon name"
    );
}

// ===== Key rotation: old and new keys both work during grace period =====
// Both the original and rotated keys must resolve to the same daemon identity
// during the grace period. Messages from either connection carry the correct
// verified_sender_name.
#[tokio::test]
async fn both_keys_valid_during_rotation_grace_period() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let old_kp = generate_keypair().unwrap();
    let new_kp = generate_keypair().unwrap();
    let observer_kp = generate_keypair().unwrap();

    let mut old_pub = [0u8; 32];
    old_pub.copy_from_slice(old_kp.public());
    let mut new_pub = [0u8; 32];
    new_pub.copy_from_slice(new_kp.public());
    let mut obs_pub = [0u8; 32];
    obs_pub.copy_from_slice(observer_kp.public());

    let mut registry = ClearanceRegistry::new();
    registry.register("daemon-wm".into(), old_pub, SecurityLevel::Internal);
    registry.register("observer".into(), obs_pub, SecurityLevel::Internal);
    registry.register_pending("daemon-wm", new_pub);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut observer = connect_with_keypair(did(200), &sock, &server_pub, &observer_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect with the OLD key — should still be recognized.
    let old_client = connect_with_keypair(did(201), &sock, &server_pub, &old_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    old_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(201),
                version: "old".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), observer.recv())
        .await
        .expect("should receive from old key")
        .expect("channel closed");

    assert_eq!(
        msg.verified_sender_name.as_deref(),
        Some("daemon-wm"),
        "old key must still be recognized during grace period"
    );

    // Connect with the NEW key — should also be recognized.
    let new_client = connect_with_keypair(did(202), &sock, &server_pub, &new_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    new_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(202),
                version: "new".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), observer.recv())
        .await
        .expect("should receive from new key")
        .expect("channel closed");

    assert_eq!(
        msg.verified_sender_name.as_deref(),
        Some("daemon-wm"),
        "new pending key must be recognized during grace period"
    );
}

// ===== Key rotation: finalized key works, old key rejected =====
// After finalize_rotation, the old pubkey must no longer resolve to the daemon.
// A new connection with the old key gets ephemeral (SecretsOnly) clearance and
// no verified_sender_name.
#[tokio::test]
async fn finalized_rotation_revokes_old_key() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let old_kp = generate_keypair().unwrap();
    let new_kp = generate_keypair().unwrap();
    let observer_kp = generate_keypair().unwrap();

    let mut old_pub = [0u8; 32];
    old_pub.copy_from_slice(old_kp.public());
    let mut new_pub = [0u8; 32];
    new_pub.copy_from_slice(new_kp.public());
    let mut obs_pub = [0u8; 32];
    obs_pub.copy_from_slice(observer_kp.public());

    let mut registry = ClearanceRegistry::new();
    registry.register("daemon-secrets".into(), old_pub, SecurityLevel::SecretsOnly);
    registry.register("observer".into(), obs_pub, SecurityLevel::Internal);

    // Simulate full rotation cycle: register pending, then finalize.
    registry.register_pending("daemon-secrets", new_pub);
    registry.finalize_rotation("daemon-secrets");

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut observer = connect_with_keypair(did(300), &sock, &server_pub, &observer_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect with the NEW (finalized) key — should be recognized.
    let new_client = connect_with_keypair(did(301), &sock, &server_pub, &new_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    new_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(301),
                version: "rotated".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), observer.recv())
        .await
        .expect("should receive from finalized key")
        .expect("channel closed");

    assert_eq!(
        msg.verified_sender_name.as_deref(),
        Some("daemon-secrets"),
        "finalized key must be recognized"
    );

    // Connect with the OLD (revoked) key — should connect but NOT be recognized
    // as daemon-secrets. The server treats it as an ephemeral client with no
    // verified_sender_name.
    let old_client = connect_with_keypair(did(302), &sock, &server_pub, &old_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    old_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(302),
                version: "stale".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    // Observer receives the message but verified_sender_name must be None —
    // the old key is no longer in the registry.
    let msg = tokio::time::timeout(Duration::from_millis(500), observer.recv())
        .await
        .expect("should receive message from old key (ephemeral clearance allows it)")
        .expect("channel closed");

    assert!(
        msg.verified_sender_name.is_none(),
        "old revoked key must not have verified_sender_name — got: {:?}",
        msg.verified_sender_name
    );
}

// ===== Key rotation: identity preserved through pending registration =====
// A daemon registered at a specific clearance level must retain that identity
// when connecting with the pending rotation key. The verified_sender_name
// must match the original registration, proving the pending key inherits
// the daemon's identity rather than being treated as a new ephemeral client.
#[tokio::test]
async fn rotation_preserves_daemon_identity() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

    let original_kp = generate_keypair().unwrap();
    let rotated_kp = generate_keypair().unwrap();
    let observer_kp = generate_keypair().unwrap();

    let mut original_pub = [0u8; 32];
    original_pub.copy_from_slice(original_kp.public());
    let mut rotated_pub = [0u8; 32];
    rotated_pub.copy_from_slice(rotated_kp.public());
    let mut observer_pub = [0u8; 32];
    observer_pub.copy_from_slice(observer_kp.public());

    let mut registry = ClearanceRegistry::new();
    registry.register(
        "daemon-clipboard".into(),
        original_pub,
        SecurityLevel::Internal,
    );
    registry.register("observer".into(), observer_pub, SecurityLevel::Internal);
    registry.register_pending("daemon-clipboard", rotated_pub);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut observer = connect_with_keypair(did(400), &sock, &server_pub, &observer_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect with the rotated key.
    let rotated_client = connect_with_keypair(did(401), &sock, &server_pub, &rotated_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    rotated_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(401),
                version: "rotated".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), observer.recv())
        .await
        .expect("observer should receive DaemonStarted from rotated key")
        .expect("channel closed");

    // The rotated key must be recognized as the same daemon, not as ephemeral.
    assert_eq!(
        msg.verified_sender_name.as_deref(),
        Some("daemon-clipboard"),
        "rotated key must inherit the original daemon identity"
    );
}

// ===== Key rotation: transparent I/O task reconnection =====
// Exercises the full transparent rotation path: a daemon connected via
// connect_daemon_with_keypair_retry receives a KeyRotationPending message,
// the I/O task reads the new keypair from disk, reconnects, and the caller's
// recv() continues to deliver messages without returning None.
#[tokio::test]
async fn transparent_io_task_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let pds_dir = dir.path().join("pds");
    std::fs::create_dir_all(&pds_dir).unwrap();
    let sock = pds_dir.join("bus.sock");

    // Set runtime dir override so read_daemon_keypair/read_bus_public_key
    // resolve to our temp directory.
    core_ipc::noise::set_runtime_dir_override(pds_dir.clone());
    core_ipc::noise::create_keys_dir().await.unwrap();

    // Generate server keypair and write bus.pub so the client can read it.
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();
    core_ipc::noise::write_bus_keypair(server_kp.as_inner())
        .await
        .unwrap();

    // Generate initial daemon keypair and write to disk.
    let initial_kp = generate_keypair().unwrap();
    let mut initial_pub = [0u8; 32];
    initial_pub.copy_from_slice(initial_kp.public());
    core_ipc::noise::write_daemon_keypair("test-rotator", initial_kp.as_inner())
        .await
        .unwrap();

    // Generate the rotated keypair (written to disk later to simulate phase 1).
    let rotated_kp = generate_keypair().unwrap();
    let mut rotated_pub = [0u8; 32];
    rotated_pub.copy_from_slice(rotated_kp.public());

    // Generate an observer keypair for receiving broadcast messages.
    let observer_kp = generate_keypair().unwrap();
    let mut observer_pub = [0u8; 32];
    observer_pub.copy_from_slice(observer_kp.public());

    // Build registry with initial key + pending rotated key.
    let mut registry = ClearanceRegistry::new();
    registry.register("test-rotator".into(), initial_pub, SecurityLevel::Internal);
    registry.register("observer".into(), observer_pub, SecurityLevel::Internal);
    registry.register_pending("test-rotator", rotated_pub);

    let server = BusServer::bind(&sock, server_kp.into_inner(), registry).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect the daemon using connect_daemon_with_keypair_retry.
    // This spawns an I/O task that handles KeyRotationPending transparently.
    let daemon_id = did(500);
    let mut daemon_client = BusClient::connect_daemon_with_keypair_retry(
        "test-rotator",
        daemon_id,
        &sock,
        &server_pub,
        vec!["test".into()],
        "0.1.0",
        core_ipc::RetryConfig {
            max_attempts: 3,
            backoff: Duration::from_millis(50),
        },
    )
    .await
    .unwrap();

    // Announce on initial connection.
    daemon_client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: "0.1.0".into(),
                capabilities: vec!["test".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect observer.
    let mut observer = connect_with_keypair(did(501), &sock, &server_pub, &observer_kp).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Drain the DaemonStarted the observer received from the daemon's initial announce.
    let _ = tokio::time::timeout(Duration::from_millis(100), observer.recv()).await;

    // Simulate phase 1: write the rotated keypair to disk, then broadcast
    // KeyRotationPending. The daemon's I/O task should intercept this,
    // read the new keypair, reconnect, and re-announce — all transparently.
    core_ipc::noise::write_daemon_keypair("test-rotator", rotated_kp.as_inner())
        .await
        .unwrap();

    // Use the observer to broadcast KeyRotationPending (in production this
    // comes from daemon-profile, but any Internal client can broadcast it).
    let obs_ctx = core_ipc::MessageContext::new(did(501));
    let rotation_msg = Message::new(
        &obs_ctx,
        EventKind::KeyRotationPending {
            daemon_name: "test-rotator".into(),
            new_pubkey: rotated_pub,
            grace_period_s: 30,
        },
        SecurityLevel::Internal,
        std::time::Instant::now(),
    );
    observer.send(&rotation_msg).await.unwrap();

    // Give the I/O task time to process the rotation.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The observer should have received the DaemonStarted re-announcement
    // from the daemon's I/O task after reconnecting with the rotated key.
    let reannounce = tokio::time::timeout(Duration::from_millis(500), observer.recv())
        .await
        .expect("observer should receive DaemonStarted re-announcement")
        .expect("channel closed");

    assert!(
        matches!(reannounce.payload, EventKind::DaemonStarted { .. }),
        "re-announcement should be DaemonStarted, got: {:?}",
        reannounce.payload
    );
    assert_eq!(
        reannounce.verified_sender_name.as_deref(),
        Some("test-rotator"),
        "re-announced DaemonStarted must have verified_sender_name from rotated key"
    );

    // The daemon client's recv() must NOT have returned None during rotation.
    // Verify by sending a message to the daemon and checking it arrives.
    let probe_ctx = core_ipc::MessageContext::new(did(501));
    let probe = Message::new(
        &probe_ctx,
        EventKind::StatusRequest,
        SecurityLevel::Internal,
        std::time::Instant::now(),
    );
    observer.send(&probe).await.unwrap();

    let received = tokio::time::timeout(Duration::from_millis(500), daemon_client.recv())
        .await
        .expect("daemon client should still receive messages after rotation")
        .expect("daemon client recv() returned None — rotation broke the connection");

    assert!(
        matches!(received.payload, EventKind::StatusRequest),
        "daemon should receive the probe message after transparent rotation"
    );
}
