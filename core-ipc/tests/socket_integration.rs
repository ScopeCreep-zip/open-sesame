//! Integration tests for IPC socket communication.
//!
//! All tests use Noise IK encrypted transport — the same code path as
//! production: clients handshake with the endpoint the server publishes.
//! There is no plaintext transport path.

use core_ipc::noise::{BusEndpoint, NoiseSuite, ZeroizingKeypair, generate_keypair};
use core_ipc::{BusClient, BusServer, ClearanceRegistry, Message};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

/// A keypair and its public half.
struct Key {
    pair: ZeroizingKeypair,
    public: [u8; 32],
}

fn key() -> Key {
    let pair = generate_keypair().unwrap();
    let public = pair.public().try_into().unwrap();
    Key { pair, public }
}

/// A registry holding each `(name, key, clearance)`, generation 0.
fn registry(entries: &[(&str, &Key, SecurityLevel)]) -> ClearanceRegistry {
    let mut registry = ClearanceRegistry::new();
    for &(name, key, level) in entries {
        registry.register(name.into(), key.public, level, 0);
    }
    registry
}

/// A running bus: its socket and the endpoint clients handshake with.
struct Bus {
    sock: PathBuf,
    endpoint: BusEndpoint,
    _dir: Option<tempfile::TempDir>,
}

impl Bus {
    /// Connect `key` as `id`.
    async fn connect(&self, id: DaemonId, key: &Key) -> BusClient {
        BusClient::connect_encrypted(id, &self.sock, &self.endpoint, key.pair.as_inner())
            .await
            .unwrap()
    }
}

/// Bind a server at `sock` with `registry` under the default suite and run
/// its accept loop.
async fn serve_at(sock: &Path, registry: ClearanceRegistry) -> BusEndpoint {
    let server = BusServer::bind(
        sock,
        generate_keypair().unwrap().into_inner(),
        registry,
        NoiseSuite::default(),
    )
    .unwrap();
    let endpoint = server.endpoint();
    tokio::spawn(async move { server.run().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    endpoint
}

/// A bus running in a fresh temporary directory.
async fn serve(registry: ClearanceRegistry) -> Bus {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let endpoint = serve_at(&sock, registry).await;
    Bus {
        sock,
        endpoint,
        _dir: Some(dir),
    }
}

/// Helper: make a `DaemonId` from a u128.
fn did(n: u128) -> DaemonId {
    DaemonId::from_uuid(Uuid::from_u128(n))
}

/// Let routing settle after connects.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(20)).await;
}

fn daemon_started(id: DaemonId, version: &str, capabilities: &[&str]) -> EventKind {
    EventKind::DaemonStarted {
        daemon_id: id,
        version: version.into(),
        capabilities: capabilities.iter().map(|&c| c.to_owned()).collect(),
    }
}

/// The next message `client` receives within 500 ms.
async fn next(client: &mut BusClient) -> Message<EventKind> {
    tokio::time::timeout(Duration::from_millis(500), client.recv())
        .await
        .expect("timeout waiting for message")
        .expect("channel closed")
}

/// Whether `client` receives nothing within 200 ms.
async fn silent(client: &mut BusClient) -> bool {
    tokio::time::timeout(Duration::from_millis(200), client.recv())
        .await
        .is_err()
}

/// Helper: verify a daemon survived transparent key rotation.
///
/// Asserts the observer receives the daemon's `DaemonStarted`
/// re-announcement stamped with `expected_name`, then sends a probe from
/// `observer_id` and asserts the daemon's `recv()` still delivers it.
async fn assert_transparent_rotation(
    observer: &mut BusClient,
    observer_id: DaemonId,
    daemon_client: &mut BusClient,
    expected_name: &str,
) {
    let reannounce = next(observer).await;
    assert!(
        matches!(reannounce.payload, EventKind::DaemonStarted { .. }),
        "re-announcement should be DaemonStarted, got: {:?}",
        reannounce.payload
    );
    assert_eq!(
        reannounce.verified_sender_name.as_deref(),
        Some(expected_name),
        "re-announced DaemonStarted must have verified_sender_name from rotated key"
    );

    // The daemon client's recv() must NOT have returned None during rotation.
    let probe = Message::new(
        &core_ipc::MessageContext::new(observer_id),
        EventKind::StatusRequest,
        SecurityLevel::Internal,
        std::time::Instant::now(),
    );
    observer.send(&probe).await.unwrap();
    let received = next(daemon_client).await;
    assert!(
        matches!(received.payload, EventKind::StatusRequest),
        "daemon should receive the probe message after transparent rotation"
    );
}

#[tokio::test]
async fn server_bind_creates_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("pds/bus.sock");
    let _server = BusServer::bind(
        &sock,
        generate_keypair().unwrap().into_inner(),
        ClearanceRegistry::new(),
        NoiseSuite::default(),
    )
    .unwrap();
    assert!(sock.exists(), "socket file should exist after bind");
}

#[tokio::test]
async fn every_suite_serves_clients_that_read_its_endpoint() {
    for suite in NoiseSuite::ALL {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("bus.sock");
        let (a, b) = (key(), key());
        let server = BusServer::bind(
            &sock,
            generate_keypair().unwrap().into_inner(),
            registry(&[
                ("a", &a, SecurityLevel::Internal),
                ("b", &b, SecurityLevel::Internal),
            ]),
            suite,
        )
        .unwrap();
        let endpoint = server.endpoint();
        assert_eq!(endpoint.suite, suite);
        tokio::spawn(async move { server.run().await });
        settle().await;
        let bus = Bus {
            sock,
            endpoint,
            _dir: Some(dir),
        };
        let sender = bus.connect(did(1), &a).await;
        let mut receiver = bus.connect(did(2), &b).await;
        settle().await;
        sender
            .publish(EventKind::WmActivateOverlay, SecurityLevel::Internal)
            .await
            .unwrap();
        assert!(
            matches!(
                next(&mut receiver).await.payload,
                EventKind::WmActivateOverlay
            ),
            "{suite:?}"
        );
    }
}

#[tokio::test]
async fn a_client_on_another_suite_is_refused() {
    let bus = serve(ClearanceRegistry::new()).await;
    let other_suite = NoiseSuite::ALL
        .into_iter()
        .find(|s| *s != bus.endpoint.suite)
        .unwrap();
    let other = BusEndpoint {
        suite: other_suite,
        ..bus.endpoint
    };
    let client = key();
    let result =
        BusClient::connect_encrypted(did(1), &bus.sock, &other, client.pair.as_inner()).await;
    assert!(result.is_err(), "a handshake under another suite must fail");
}

#[tokio::test]
async fn publish_subscribe_roundtrip() {
    let (a, b) = (key(), key());
    let bus = serve(registry(&[
        ("a", &a, SecurityLevel::Internal),
        ("b", &b, SecurityLevel::Internal),
    ]))
    .await;
    let client_a = bus.connect(did(1), &a).await;
    let mut client_b = bus.connect(did(2), &b).await;
    settle().await;

    client_a
        .publish(
            daemon_started(did(1), "0.1.0", &["test"]),
            SecurityLevel::Internal,
        )
        .await
        .unwrap();
    let msg = next(&mut client_b).await;
    assert!(
        matches!(msg.payload, EventKind::DaemonStarted { .. }),
        "expected DaemonStarted, got {:?}",
        msg.payload
    );
}

/// `requester` sends `request`; `responder` receives it and answers with
/// `response`; returns what `requester` received.
async fn exchange(
    requester: BusClient,
    responder: &mut BusClient,
    responder_id: DaemonId,
    request: EventKind,
    response: EventKind,
) -> Message<EventKind> {
    let handle = tokio::spawn(async move {
        requester
            .request(request, SecurityLevel::Internal, Duration::from_secs(2))
            .await
    });
    let request_msg = next(responder).await;
    let reply = Message::new(
        &core_ipc::MessageContext::new(responder_id),
        response,
        SecurityLevel::Internal,
        responder.epoch(),
    )
    .with_correlation(request_msg.msg_id);
    responder.send(&reply).await.unwrap();
    handle.await.unwrap().unwrap()
}

#[tokio::test]
async fn request_response_correlation() {
    let (a, b) = (key(), key());
    let bus = serve(registry(&[
        ("a", &a, SecurityLevel::Internal),
        ("b", &b, SecurityLevel::Internal),
    ]))
    .await;
    let client_a = bus.connect(did(1), &a).await;
    let mut client_b = bus.connect(did(2), &b).await;
    settle().await;

    let result = exchange(
        client_a,
        &mut client_b,
        did(2),
        EventKind::SecretList {
            profile: TrustProfileName::try_from("test").unwrap(),
        },
        EventKind::SecretListResponse {
            keys: vec!["api-key".into(), "db-pass".into()],
            denial: None,
        },
    )
    .await;
    match result.payload {
        EventKind::SecretListResponse { keys, .. } => {
            assert_eq!(keys, vec!["api-key".to_string(), "db-pass".to_string()]);
        }
        other => panic!("expected SecretListResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn launch_execute_outcomes_roundtrip() {
    for (entry_id, profile, outcome) in [
        (
            "firefox",
            Some(TrustProfileName::try_from("default").unwrap()),
            core_types::LaunchOutcome::Launched { pid: 12345 },
        ),
        (
            "nonexistent",
            None,
            core_types::LaunchOutcome::Denied(core_types::LaunchDenial::EntryNotFound),
        ),
    ] {
        let (cli, launcher_key) = (key(), key());
        let bus = serve(registry(&[
            ("cli", &cli, SecurityLevel::Internal),
            ("launcher", &launcher_key, SecurityLevel::Internal),
        ]))
        .await;
        let cli_client = bus.connect(did(1), &cli).await;
        let mut launcher = bus.connect(did(2), &launcher_key).await;
        settle().await;

        let result = exchange(
            cli_client,
            &mut launcher,
            did(2),
            EventKind::LaunchExecute {
                entry_id: entry_id.into(),
                profile,
                tags: Vec::new(),
                launch_args: Vec::new(),
            },
            EventKind::LaunchExecuteResponse {
                outcome: outcome.clone(),
            },
        )
        .await;
        match result.payload {
            EventKind::LaunchExecuteResponse { outcome: received } => {
                assert_eq!(received, outcome);
            }
            other => panic!("expected LaunchExecuteResponse, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn sender_does_not_receive_own_message() {
    let a = key();
    let bus = serve(registry(&[("a", &a, SecurityLevel::Internal)])).await;
    let mut client = bus.connect(did(1), &a).await;
    settle().await;

    client
        .publish(
            daemon_started(did(1), "0.1.0", &[]),
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
    let endpoint = BusEndpoint {
        suite: NoiseSuite::default(),
        public_key: [0u8; 32],
    };
    let client = key();
    let result =
        BusClient::connect_encrypted(did(1), &sock, &endpoint, client.pair.as_inner()).await;
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
    let a = key();
    let bus = serve(registry(&[("a", &a, SecurityLevel::Internal)])).await;
    let client = bus.connect(did(1), &a).await;
    settle().await;

    let err = client
        .request(
            EventKind::StatusRequest,
            SecurityLevel::Internal,
            Duration::from_millis(100),
        )
        .await
        .expect_err("should timeout with no responder");
    assert!(
        matches!(err, core_types::Error::Timeout { .. }),
        "a request without a response is a typed timeout: {err:?}"
    );
    assert!(err.to_string().contains("100ms"), "{err}");
}

// ===== IPC Authentication — Noise Handshake Rejection =====

#[tokio::test]
async fn noise_handshake_rejects_wrong_key() {
    let bus = serve(ClearanceRegistry::new()).await;
    // The client expects a server key that is not the real one.
    let wrong = BusEndpoint {
        public_key: key().public,
        ..bus.endpoint
    };
    let client = key();
    let result =
        BusClient::connect_encrypted(did(1), &bus.sock, &wrong, client.pair.as_inner()).await;
    assert!(
        result.is_err(),
        "Noise IK handshake must fail when client expects wrong server public key"
    );
}

// ===== Secret Value Never Broadcast =====

#[tokio::test]
async fn secret_response_not_received_by_bystander() {
    let (a, b, c) = (key(), key(), key());
    let bus = serve(registry(&[
        ("requester", &a, SecurityLevel::Internal),
        ("bystander", &b, SecurityLevel::Internal),
        ("secrets", &c, SecurityLevel::Internal),
    ]))
    .await;
    let client_a = bus.connect(did(1), &a).await;
    let mut bystander = bus.connect(did(2), &b).await;
    let mut secrets_daemon = bus.connect(did(3), &c).await;
    settle().await;

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

    let request_msg = next(&mut secrets_daemon).await;
    assert!(matches!(request_msg.payload, EventKind::SecretList { .. }));
    // The bystander also receives the broadcast request.
    assert!(matches!(
        next(&mut bystander).await.payload,
        EventKind::SecretList { .. }
    ));

    let response = Message::new(
        &core_ipc::MessageContext::new(did(3)),
        EventKind::SecretListResponse {
            keys: vec!["api-key".into()],
            denial: None,
        },
        SecurityLevel::Internal,
        secrets_daemon.epoch(),
    )
    .with_correlation(request_msg.msg_id);
    secrets_daemon.send(&response).await.unwrap();

    let result = response_handle.await.unwrap().unwrap();
    assert!(matches!(
        result.payload,
        EventKind::SecretListResponse { .. }
    ));
    assert!(
        silent(&mut bystander).await,
        "bystander must not receive correlated response (unicast routing)"
    );
}

#[tokio::test]
async fn uncorrelated_response_is_dropped() {
    let (a, b) = (key(), key());
    let bus = serve(registry(&[
        ("a", &a, SecurityLevel::Internal),
        ("b", &b, SecurityLevel::Internal),
    ]))
    .await;
    let client_a = bus.connect(did(1), &a).await;
    let mut client_b = bus.connect(did(2), &b).await;
    settle().await;

    // A response with a fabricated correlation_id (no matching request).
    let orphan_response = Message::new(
        &core_ipc::MessageContext::new(did(1)),
        EventKind::SecretListResponse {
            keys: vec!["should-not-broadcast".into()],
            denial: None,
        },
        SecurityLevel::Internal,
        client_a.epoch(),
    )
    .with_correlation(Uuid::from_u128(99999));
    client_a.send(&orphan_response).await.unwrap();

    assert!(
        silent(&mut client_b).await,
        "orphan response (no matching pending request) must be dropped, not broadcast"
    );
}

#[tokio::test]
async fn multiple_clients_receive_broadcast() {
    let (a, b, c) = (key(), key(), key());
    let bus = serve(registry(&[
        ("a", &a, SecurityLevel::Internal),
        ("b", &b, SecurityLevel::Internal),
        ("c", &c, SecurityLevel::Internal),
    ]))
    .await;
    let sender = bus.connect(did(1), &a).await;
    let mut recv_a = bus.connect(did(2), &b).await;
    let mut recv_b = bus.connect(did(3), &c).await;
    settle().await;

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
    assert!(matches!(
        next(&mut recv_a).await.payload,
        EventKind::ConfigReloaded { .. }
    ));
    assert!(matches!(
        next(&mut recv_b).await.payload,
        EventKind::ConfigReloaded { .. }
    ));
}

// ===== Clearance escalation blocking =====
// SECURITY INVARIANT: A client registered at Open clearance must not be able
// to send Internal-level messages. The bus server must silently drop the frame.
#[tokio::test]
async fn clearance_escalation_blocked() {
    let (open, internal) = (key(), key());
    let bus = serve(registry(&[
        ("low-daemon", &open, SecurityLevel::Open),
        ("high-daemon", &internal, SecurityLevel::Internal),
    ]))
    .await;
    let open_client = bus.connect(did(10), &open).await;
    let mut internal_client = bus.connect(did(11), &internal).await;
    settle().await;

    open_client
        .publish(
            daemon_started(did(10), "0.1.0", &[]),
            SecurityLevel::Internal,
        )
        .await
        .unwrap();
    assert!(
        silent(&mut internal_client).await,
        "Internal-level message from Open-clearance client must be dropped"
    );
}

// ===== Sender identity change mid-session =====
// SECURITY INVARIANT: Once a connection's DaemonId is bound on its first
// message, any subsequent message with a different DaemonId must be dropped.
#[tokio::test]
async fn sender_identity_change_blocked() {
    let (a, b) = (key(), key());
    let bus = serve(registry(&[
        ("a", &a, SecurityLevel::Internal),
        ("b", &b, SecurityLevel::Internal),
    ]))
    .await;
    let sender = bus.connect(did(20), &a).await;
    let mut receiver = bus.connect(did(21), &b).await;
    settle().await;

    // First message: binds DaemonId 20 to this connection.
    sender
        .publish(
            daemon_started(did(20), "0.1.0", &[]),
            SecurityLevel::Internal,
        )
        .await
        .unwrap();
    assert!(matches!(
        next(&mut receiver).await.payload,
        EventKind::DaemonStarted { .. }
    ));

    // Second message: different DaemonId (identity change attempt).
    let spoofed = Message::new(
        &core_ipc::MessageContext::new(did(99)),
        daemon_started(did(99), "0.1.0", &[]),
        SecurityLevel::Internal,
        sender.epoch(),
    );
    sender.send(&spoofed).await.unwrap();
    assert!(
        silent(&mut receiver).await,
        "message with changed DaemonId mid-session must be dropped"
    );
}

// ===== verified_sender_name stamping =====
// SECURITY INVARIANT: Messages routed through the bus must have
// `verified_sender_name` stamped by the server from the Noise IK registry
// lookup, not self-declared.
#[tokio::test]
async fn verified_sender_name_stamped() {
    let (a, b) = (key(), key());
    let bus = serve(registry(&[
        ("test-client-0", &a, SecurityLevel::Internal),
        ("test-client-1", &b, SecurityLevel::Internal),
    ]))
    .await;
    let sender = bus.connect(did(30), &a).await;
    let mut receiver = bus.connect(did(31), &b).await;
    settle().await;

    sender
        .publish(
            daemon_started(did(30), "0.1.0", &["fake-name"]),
            SecurityLevel::Internal,
        )
        .await
        .unwrap();
    assert_eq!(
        next(&mut receiver).await.verified_sender_name.as_deref(),
        Some("test-client-0"),
        "verified_sender_name must be stamped from registry, not self-declared"
    );
}

// ===== Ephemeral clients get SecretsOnly clearance via UCred =====
// SECURITY INVARIANT: Unregistered keys (ephemeral CLI connections) that pass
// UCred same-UID validation receive SecretsOnly clearance. This allows the CLI
// to send FactorSubmit and SecretCRUD messages to daemon-secrets.
#[tokio::test]
async fn ephemeral_client_gets_secrets_only_clearance() {
    let observer = key();
    let bus = serve(registry(&[(
        "observer",
        &observer,
        SecurityLevel::SecretsOnly,
    )]))
    .await;
    let mut observer_client = bus.connect(did(2), &observer).await;
    // The connect completes only after the server accepted the handshake.
    let ephemeral = bus.connect(did(1), &key()).await;
    settle().await;

    // A SecretsOnly-level message from the unregistered key is routed: its
    // clearance is SecretsOnly.
    ephemeral
        .publish(EventKind::StatusRequest, SecurityLevel::SecretsOnly)
        .await
        .unwrap();
    let msg = next(&mut observer_client).await;
    assert!(matches!(msg.payload, EventKind::StatusRequest));
    assert!(msg.verified_sender_name.is_none());
}

// ===== Registered client can publish at Internal to reach daemons =====
#[tokio::test]
async fn registered_client_overlay_reaches_daemon_wm() {
    let (daemon, cli) = (key(), key());
    let bus = serve(registry(&[
        ("daemon-wm", &daemon, SecurityLevel::Internal),
        ("cli", &cli, SecurityLevel::Internal),
    ]))
    .await;
    let mut daemon_wm = bus.connect(did(1), &daemon).await;
    let cli_client = bus.connect(did(2), &cli).await;
    settle().await;

    cli_client
        .publish(EventKind::WmActivateOverlay, SecurityLevel::Internal)
        .await
        .unwrap();
    let msg = next(&mut daemon_wm).await;
    assert!(
        matches!(msg.payload, EventKind::WmActivateOverlay),
        "expected WmActivateOverlay, got {:?}",
        msg.payload
    );
}

// ===== Negative: SecretsOnly-level messages don't reach Internal daemons =====
#[tokio::test]
async fn secrets_only_message_not_delivered_to_internal_daemon() {
    let (daemon, secrets) = (key(), key());
    let bus = serve(registry(&[
        ("daemon-wm", &daemon, SecurityLevel::Internal),
        ("daemon-secrets", &secrets, SecurityLevel::SecretsOnly),
    ]))
    .await;
    let mut daemon_wm = bus.connect(did(1), &daemon).await;
    let secrets_client = bus.connect(did(2), &secrets).await;
    settle().await;

    // daemon-wm (Internal) is below SecretsOnly, so it is excluded.
    secrets_client
        .publish(EventKind::WmActivateOverlay, SecurityLevel::SecretsOnly)
        .await
        .unwrap();
    assert!(
        silent(&mut daemon_wm).await,
        "SecretsOnly-level message must not reach Internal-clearance daemon"
    );
}

// ===== shutdown() flushes outbound frames before disconnect =====
// Simulates the CLI lifecycle: connect, publish, shutdown, verify delivery.
#[tokio::test]
async fn shutdown_flushes_publish_before_disconnect() {
    let (daemon, cli) = (key(), key());
    let bus = serve(registry(&[
        ("daemon-wm", &daemon, SecurityLevel::Internal),
        ("cli", &cli, SecurityLevel::Internal),
    ]))
    .await;
    let mut daemon_wm = bus.connect(did(1), &daemon).await;
    let cli_client = bus.connect(did(2), &cli).await;
    settle().await;

    cli_client
        .publish(EventKind::WmActivateOverlay, SecurityLevel::Internal)
        .await
        .unwrap();
    cli_client.shutdown().await;

    let msg = next(&mut daemon_wm).await;
    assert!(
        matches!(msg.payload, EventKind::WmActivateOverlay),
        "expected WmActivateOverlay, got {:?}",
        msg.payload
    );
}

/// `client` announces itself as `id`; the verified sender name the server
/// stamped on the announcement `observer` receives.
async fn announced_as(
    client: &BusClient,
    id: DaemonId,
    observer: &mut BusClient,
) -> Option<String> {
    client
        .publish(daemon_started(id, "test", &[]), SecurityLevel::Internal)
        .await
        .unwrap();
    next(observer).await.verified_sender_name
}

// ===== Key rotation: pending pubkey recognized by server =====
// A daemon reconnects with a new keypair during the rotation grace period.
// The server must recognize the new pubkey and stamp verified_sender_name
// on messages from the new connection, with the original identity.
#[tokio::test]
async fn pending_rotation_key_inherits_the_daemon_identity() {
    let (original, rotated, observer) = (key(), key(), key());
    let mut reg = registry(&[
        ("daemon-launcher", &original, SecurityLevel::Internal),
        ("observer", &observer, SecurityLevel::Internal),
    ]);
    reg.register_pending("daemon-launcher", rotated.public);
    let bus = serve(reg).await;

    let mut observer_client = bus.connect(did(100), &observer).await;
    settle().await;
    let rotated_client = bus.connect(did(50), &rotated).await;
    settle().await;
    assert_eq!(
        announced_as(&rotated_client, did(50), &mut observer_client)
            .await
            .as_deref(),
        Some("daemon-launcher"),
        "server must recognize the pending rotation pubkey and stamp the daemon name"
    );
}

// ===== Key rotation: old and new keys both work during grace period =====
#[tokio::test]
async fn both_keys_valid_during_rotation_grace_period() {
    let (old, new, observer) = (key(), key(), key());
    let mut reg = registry(&[
        ("daemon-wm", &old, SecurityLevel::Internal),
        ("observer", &observer, SecurityLevel::Internal),
    ]);
    reg.register_pending("daemon-wm", new.public);
    let bus = serve(reg).await;

    let mut observer_client = bus.connect(did(200), &observer).await;
    settle().await;
    for (id, k) in [(did(201), &old), (did(202), &new)] {
        let client = bus.connect(id, k).await;
        settle().await;
        assert_eq!(
            announced_as(&client, id, &mut observer_client)
                .await
                .as_deref(),
            Some("daemon-wm"),
            "both keys must be recognized during the grace period"
        );
    }
}

// ===== Key rotation: finalized key works, old key rejected =====
// After finalize_rotation, the old pubkey no longer resolves to the daemon:
// a connection with it is an ephemeral client with no verified_sender_name.
#[tokio::test]
async fn finalized_rotation_revokes_old_key() {
    let (old, new, observer) = (key(), key(), key());
    let mut reg = registry(&[
        ("daemon-secrets", &old, SecurityLevel::SecretsOnly),
        ("observer", &observer, SecurityLevel::Internal),
    ]);
    reg.register_pending("daemon-secrets", new.public);
    reg.finalize_rotation("daemon-secrets");
    let bus = serve(reg).await;

    let mut observer_client = bus.connect(did(300), &observer).await;
    settle().await;
    let new_client = bus.connect(did(301), &new).await;
    settle().await;
    assert_eq!(
        announced_as(&new_client, did(301), &mut observer_client)
            .await
            .as_deref(),
        Some("daemon-secrets"),
        "finalized key must be recognized"
    );

    let old_client = bus.connect(did(302), &old).await;
    settle().await;
    let name = announced_as(&old_client, did(302), &mut observer_client).await;
    assert!(
        name.is_none(),
        "old revoked key must not have verified_sender_name — got: {name:?}"
    );
}

// ===== Key rotation: transparent I/O task reconnection =====
// Exercises the full transparent rotation path: a daemon connected via
// connect_daemon_with_keypair_retry receives a KeyRotationPending message,
// the I/O task reads the new keypair from disk, reconnects, and the caller's
// recv() continues to deliver messages without returning None.
#[tokio::test]
async fn transparent_io_task_rotation() {
    // Every location (keys, bus socket) comes from a layout under the
    // temporary root; the daemon's key rotation reads from it too.
    let root = tempfile::tempdir().unwrap();
    let layout = core_layout::Layout::under(root.path());
    core_ipc::noise::create_keys_dir(&layout).await.unwrap();

    let initial = key();
    core_ipc::noise::write_daemon_keypair(&layout, "test-rotator", initial.pair.as_inner())
        .await
        .unwrap();
    let (rotated, observer) = (key(), key());
    let mut reg = registry(&[
        ("test-rotator", &initial, SecurityLevel::Internal),
        ("observer", &observer, SecurityLevel::Internal),
    ]);
    reg.register_pending("test-rotator", rotated.public);
    let sock = layout.bus_socket().unwrap();
    let endpoint = serve_at(&sock, reg).await;
    let bus = Bus {
        sock,
        endpoint,
        _dir: None,
    };

    let daemon_id = did(500);
    let mut daemon_client = BusClient::connect_daemon_with_keypair_retry(
        &layout,
        "test-rotator",
        daemon_id,
        &bus.endpoint,
        vec!["test".into()],
        "0.1.0",
        core_ipc::RetryConfig {
            max_attempts: 3,
            backoff: Duration::from_millis(50),
        },
    )
    .await
    .unwrap();
    daemon_client
        .publish(
            daemon_started(daemon_id, "0.1.0", &["test"]),
            SecurityLevel::Internal,
        )
        .await
        .unwrap();
    settle().await;

    let mut observer_client = bus.connect(did(501), &observer).await;
    settle().await;
    // Drain the observer's copy of the initial announcement, if routed.
    let _ = tokio::time::timeout(Duration::from_millis(100), observer_client.recv()).await;

    // Simulate phase 1: write the rotated keypair, then broadcast
    // KeyRotationPending (daemon-profile's role; any Internal client may).
    core_ipc::noise::write_daemon_keypair(&layout, "test-rotator", rotated.pair.as_inner())
        .await
        .unwrap();
    let rotation_msg = Message::new(
        &core_ipc::MessageContext::new(did(501)),
        EventKind::KeyRotationPending {
            daemon_name: "test-rotator".into(),
            new_pubkey: rotated.public,
            grace_period_s: 30,
        },
        SecurityLevel::Internal,
        std::time::Instant::now(),
    );
    observer_client.send(&rotation_msg).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_transparent_rotation(
        &mut observer_client,
        did(501),
        &mut daemon_client,
        "test-rotator",
    )
    .await;
}
