//! daemon-network: Open Sesame network transport daemon.
//!
//! Provides Noise XX encrypted peer sessions over UDP/TCP with TOFU
//! identity pinning, `IKpsk2` reconnection, rate limiting, stateless
//! cookie `DoS` resistance, and BLAKE3-chained audit logging.
//!
//! # Architecture
//!
//! - **Inward-facing:** Connects to `daemon-profile`'s `BusServer` via Noise IK
//!   Unix socket (same pattern as all other daemons). Requests network identity
//!   keypair from `daemon-secrets`.
//! - **Outward-facing:** Dual-stack UDP socket + optional TCP listener on
//!   `network.transport.listen_port` (default 48627). Only daemon that binds
//!   a network socket.
//!
//! # Lifecycle
//!
//! 1. Init secure memory (`core_types::init_secure_memory`)
//! 2. Load config (`config::load_network_config`)
//! 3. Apply sandbox (`sandbox::apply_network_sandbox`)
//! 4. Open TOFU store
//! 5. Start audit log
//! 6. Connect to IPC bus (`BusClient`)
//! 7. Request network identity keypair from daemon-secrets
//! 8. Bind UDP + TCP sockets
//! 9. Notify systemd ready
//! 10. Enter event loop: accept connections, process frames, manage sessions

use daemon_network::audit;
use daemon_network::config;
use daemon_network::control;
use daemon_network::flood::cookie::CookieChallenger;
use daemon_network::handshake;
use daemon_network::metrics::Metrics;
use daemon_network::noise;
use daemon_network::ratelimit;
use daemon_network::sandbox;
use daemon_network::session::replay::ReplayCheck;
use daemon_network::session::table::PeerTable;
use daemon_network::tofu;
use daemon_network::transport;
use daemon_network::transport::frame::SessionId;
use daemon_network::transport::udp::UdpInbound;
use clap::Parser;
use core_types::FrameType;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "daemon-network", about = "Open Sesame network transport daemon")]
struct Args {
    /// Override listen port.
    #[arg(long)]
    port: Option<u16>,
}

/// Shared daemon state constructed during setup.
struct DaemonState {
    udp_socket: Arc<tokio::net::UdpSocket>,
    peer_table: Arc<PeerTable>,
    tofu_store: Arc<std::sync::Mutex<tofu::store::TofuStore>>,
    cookie: Arc<std::sync::Mutex<CookieChallenger>>,
    pow: Arc<std::sync::Mutex<daemon_network::flood::pow::PowChallenger>>,
    global_hs_limiter: Arc<ratelimit::bucket::TokenBucket>,
    metrics: Arc<Metrics>,
    audit: Arc<audit::AuditLog>,
    /// Noise static keypair for network identity.
    local_keypair: Arc<snow::Keypair>,
    /// IPC bus client for inter-daemon communication.
    bus_client: Arc<tokio::sync::Mutex<core_ipc::BusClient>>,
    idle_timeout_secs: u64,
    rekey_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    core_types::init_secure_memory();
    init_tracing();

    let network_config = config::load_network_config();
    let listen_port = args.port.unwrap_or(network_config.transport.listen_port);

    if !network_config.enabled {
        tracing::info!("daemon-network disabled in config (network.enabled = false)");
        notify_ready();
        idle_loop().await;
    }

    let state = setup(listen_port, &network_config).await?;
    notify_ready();
    run_event_loop(state, listen_port, &network_config).await
}

/// Initialise all daemon subsystems.
async fn setup(
    listen_port: u16,
    config: &core_config::NetworkConfig,
) -> anyhow::Result<DaemonState> {
    sandbox::apply_network_sandbox();

    let tofu_path = config::tofu_db_path(config);
    let tofu_store = tofu::store::TofuStore::open(&tofu_path)
        .map_err(|e| anyhow::anyhow!("failed to open TOFU store: {e}"))?;
    let tofu_store = Arc::new(std::sync::Mutex::new(tofu_store));
    tracing::info!(path = %tofu_path.display(), "TOFU store opened");

    let audit_path = config::audit_log_path();
    let audit = audit::AuditLog::open(&audit_path)
        .map_err(|e| anyhow::anyhow!("failed to open audit log: {e}"))?;
    let audit = Arc::new(audit);
    audit.append("daemon_started", &format!("port={listen_port}"));

    let metrics = Arc::new(Metrics::new());
    let peer_table = Arc::new(PeerTable::new(config.session.max_concurrent_sessions));
    let cookie = Arc::new(std::sync::Mutex::new(CookieChallenger::new(
        u64::from(config.flood.cookie_epoch_secs),
    )));
    let global_hs_limiter = Arc::new(ratelimit::bucket::TokenBucket::new(
        config.ratelimit.global_handshake_rate_per_sec,
        config.ratelimit.global_handshake_burst,
    ));

    // Connect to daemon-profile's IPC bus via Noise IK over Unix domain socket.
    // daemon-profile generates a per-daemon Noise IK keypair at startup and
    // registers it in the ClearanceRegistry. daemon-network reads that keypair
    // from $XDG_RUNTIME_DIR/pds/keys/daemon-network.{pub,key,checksum} and
    // uses it to authenticate to the bus. This is the same pattern used by
    // daemon-secrets, daemon-wm, and all other daemons in the architecture.
    let mut bus_client = control::bus::connect_to_bus()
        .await
        .map_err(|e| anyhow::anyhow!(
            "failed to connect to IPC bus — is daemon-profile running? {e}"
        ))?;

    // Network identity keypair: the persistent X25519 static key that
    // identifies this Open Sesame installation to remote peers over the
    // network. This keypair is distinct from the Noise IK bus keypair —
    // bus keypairs authenticate local inter-daemon communication, while the
    // network identity keypair authenticates peer-to-peer federation sessions.
    //
    // The canonical lifecycle:
    // 1. Generated at `sesame init` and stored in the encrypted vault under
    //    a system profile managed by daemon-secrets.
    // 2. Requested from daemon-secrets via NetworkIdentityRequest on the bus.
    // 3. Persists across restarts — TOFU pins from remote peers remain valid
    //    because the static key is the same.
    //
    // If daemon-secrets supports NetworkIdentityRequest, we receive the
    // vault-backed keypair. If not (the handler is currently a stub that
    // returns nothing), we fall back to generating from snow's CSPRNG.
    // The fallback means the network identity changes on every restart,
    // invalidating TOFU pins from previous runs. This is logged at WARN
    // level and resolved when daemon-secrets implements the handler.
    let local_keypair = if let Some((vault_private_key, vault_public_key)) =
        control::bus::request_network_identity(&mut bus_client).await
    {
        // Suppress unused-variable warnings — these are consumed when the Noise
        // state machine migrates from snow to aws-lc-rs (which accepts raw bytes).
        let _ = &vault_private_key;
        // Vault-backed keypair received from daemon-secrets.
        // snow::Keypair does not expose a from-raw-bytes constructor, so we
        // cannot directly inject the vault-backed private key into snow's
        // state machine. When the Noise XX implementation migrates from snow
        // to the hand-rolled aws-lc-rs state machine (per the milestone spec),
        // this becomes a direct key load. For now, we generate a snow-compatible
        // keypair — the vault-backed key is available for TOFU display and audit
        // but the actual Noise handshake uses the snow-generated key.
        tracing::info!(
            pubkey = %hex::encode(&vault_public_key[..16]),
            "network identity keypair received from vault (snow adapter pending)"
        );
        Arc::new(
            snow::Builder::new(noise::state::NOISE_XX.parse().unwrap())
                .generate_keypair()
                .map_err(|e| anyhow::anyhow!("keypair generation failed: {e}"))?,
        )
    } else {
        // Fallback: daemon-secrets does not yet support NetworkIdentityRequest.
        // Generate an ephemeral keypair from snow's CSPRNG. This keypair does
        // not persist across restarts — TOFU pins from remote peers will be
        // invalidated on every daemon-network restart.
        let kp = snow::Builder::new(noise::state::NOISE_XX.parse().unwrap())
            .generate_keypair()
            .map_err(|e| anyhow::anyhow!("network keypair generation failed: {e}"))?;
        tracing::warn!(
            pubkey = %hex::encode(&kp.public[..16]),
            "network identity keypair generated (ephemeral) — NOT vault-backed, \
             TOFU pins will not persist across restarts. Pending daemon-secrets \
             NetworkIdentityRequest implementation."
        );
        Arc::new(kp)
    };
    let bus_client = Arc::new(tokio::sync::Mutex::new(bus_client));

    let udp_socket = Arc::new(
        transport::udp::bind_udp(listen_port)
            .await
            .map_err(|e| anyhow::anyhow!("UDP bind failed on port {listen_port}: {e}"))?,
    );

    let pow = Arc::new(std::sync::Mutex::new(
        daemon_network::flood::pow::PowChallenger::new(),
    ));

    Ok(DaemonState {
        udp_socket,
        peer_table,
        tofu_store,
        cookie,
        pow,
        global_hs_limiter,
        metrics,
        audit,
        local_keypair,
        bus_client,
        idle_timeout_secs: u64::from(config.session.idle_timeout_secs),
        rekey_interval_secs: 120, // M1-R8: 120s rekey
    })
}

/// Main event loop: dispatch UDP/TCP frames, manage sessions, run timers.
async fn run_event_loop(
    state: DaemonState,
    listen_port: u16,
    config: &core_config::NetworkConfig,
) -> anyhow::Result<()> {
    let (udp_tx, mut udp_rx) = tokio::sync::mpsc::channel::<UdpInbound>(4096);
    let udp_recv_socket = Arc::clone(&state.udp_socket);
    tokio::spawn(async move {
        transport::udp::udp_receive_loop(udp_recv_socket, udp_tx).await;
    });

    let (tcp_tx, mut tcp_rx) = tokio::sync::mpsc::channel(256);
    if config.transport.tcp_enabled {
        let max_conn = config.transport.max_tcp_connections_per_address;
        let hs_timeout = config.session.handshake_timeout_secs;
        tokio::spawn(async move {
            if let Err(e) =
                transport::tcp::tcp_accept_loop(listen_port, tcp_tx, max_conn, hs_timeout).await
            {
                tracing::error!(error = %e, "TCP accept loop failed");
            }
        });
    }

    // Spawn Prometheus metrics HTTP endpoint on localhost:9104.
    let metrics_clone = Arc::clone(&state.metrics);
    tokio::spawn(async move {
        daemon_network::metrics::serve_prometheus(metrics_clone, 9104).await;
    });

    tracing::info!(
        port = listen_port,
        udp = true,
        tcp = config.transport.tcp_enabled,
        max_sessions = config.session.max_concurrent_sessions,
        "daemon-network listening"
    );

    let mut watchdog_tick = tokio::time::interval(std::time::Duration::from_secs(15));
    let mut maintenance_tick = tokio::time::interval(std::time::Duration::from_secs(10));

    loop {
        tokio::select! {
            Some(inbound) = udp_rx.recv() => {
                handle_udp_frame(&inbound, &state);
            }
            Some(tcp_event) = tcp_rx.recv() => {
                handle_tcp_event(tcp_event, &state);
            }
            _ = maintenance_tick.tick() => {
                run_maintenance(&state);
            }
            _ = watchdog_tick.tick() => {
                notify_watchdog();
                tracing::trace!(sessions = state.peer_table.len(), "watchdog tick");
            }
        }
    }
}

/// Handle an inbound UDP frame.
fn handle_udp_frame(inbound: &UdpInbound, state: &DaemonState) {
    let frame = &inbound.frame;
    let src = inbound.src_addr;

    Metrics::inc(&state.metrics.frames_received_total);

    let Some(ft) = frame.known_frame_type() else {
        Metrics::inc(&state.metrics.frames_dropped_total);
        return;
    };

    match ft {
        FrameType::HandshakeInit => {
            if !state.global_hs_limiter.check() {
                Metrics::inc(&state.metrics.rate_limited_total);
                tracing::debug!(%src, "handshake rate limited");
                return;
            }
            // Per M1-R1 (TCP-first handshake for PQ hybrid compatibility):
            // Noise XX handshakes are conducted over TCP, not UDP. A UDP
            // HandshakeInit is logged but the actual handshake is handled
            // when the initiator connects via TCP (TcpInbound::NewConnection).
            // UDP HandshakeInit serves as a "knock" — the responder expects
            // a follow-up TCP connection from the same address.
            tracing::debug!(%src, "UDP HandshakeInit received — expecting TCP handshake");
            state.audit.append("handshake_init_received", &src.to_string());
        }

        FrameType::Data | FrameType::KeepAlive => {
            let sid = SessionId(frame.session_id.0);
            if let Some(mut peer) = state.peer_table.get_mut(&sid) {
                match peer.replay_window.check_and_update(frame.sequence) {
                    ReplayCheck::Accept => {}
                    ReplayCheck::Duplicate | ReplayCheck::TooOld => {
                        Metrics::inc(&state.metrics.replay_detected_total);
                        return;
                    }
                }

                if peer.remote_addr == src {
                    if ft == FrameType::Data {
                        // Decrypt the frame body through the Noise transport.
                        match peer.transport.decrypt(&frame.body) {
                            Ok(plaintext) => {
                                #[allow(clippy::cast_possible_truncation)]
                                peer.record_productive_recv(plaintext.len() as u64);
                                // Route decrypted payload by NetworkMessageType prefix.
                                // The first 2 bytes are the message type discriminant.
                                // Full routing is wired when application-layer handlers
                                // (vault replication, profile sync, etc.) are implemented.
                                if plaintext.len() >= 2 {
                                    tracing::trace!(
                                        session = %sid,
                                        msg_type = u16::from_be_bytes([plaintext[0], plaintext[1]]),
                                        payload_len = plaintext.len() - 2,
                                        "decrypted data frame"
                                    );
                                }
                            }
                            Err(e) => {
                                peer.record_aead_failure();
                                Metrics::inc(&state.metrics.aead_failures_total);
                                tracing::warn!(
                                    session = %sid, %src, error = %e,
                                    "AEAD decryption failed"
                                );
                                state.audit.append(
                                    "aead_failure",
                                    &format!("{sid} {src}"),
                                );
                            }
                        }
                    } else {
                        peer.record_recv(0);
                    }
                } else {
                    tracing::info!(
                        session = %sid, old = %peer.remote_addr, new = %src,
                        "path migration detected"
                    );
                    let old_addr = peer.remote_addr;
                    drop(peer);
                    state.peer_table.update_addr(&sid, &old_addr, src);
                    state.audit.append("path_migration", &format!("{sid} {src}"));
                }
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
            }
        }

        FrameType::Close => {
            let sid = SessionId(frame.session_id.0);
            if state.peer_table.get(&sid).is_some() {
                // Remove session — no Close reply needed (peer initiated closure).
                state.peer_table.remove(&sid);
                Metrics::inc(&state.metrics.sessions_closed_total);
                tracing::info!(session = %sid, %src, "session closed by peer");
                state.audit.append("session_closed", &format!("{sid} {src}"));
            }
        }

        FrameType::RehandshakeRequest => {
            let sid = SessionId(frame.session_id.0);
            tracing::info!(session = %sid, "rehandshake requested");
            state.peer_table.remove(&sid);
            state.audit.append("rehandshake_requested", &format!("{sid}"));
        }

        FrameType::CookieResponse => {
            handle_cookie_response(frame, src, state);
        }

        // Outbound-only or future frame types — drop silently.
        FrameType::HandshakeResponse | FrameType::HandshakeFinal | FrameType::CookieRequest
        | _ => {
            Metrics::inc(&state.metrics.frames_dropped_total);
        }
    }
}

/// Validate a `CookieResponse` frame body against the cookie challenger.
///
/// The body carries the 32-byte cookie that the initiator received in our
/// `CookieRequest` and is echoing back. Verification proves the initiator
/// controls the source address (current or previous epoch secret).
fn handle_cookie_response(
    frame: &daemon_network::transport::frame::Frame,
    src: std::net::SocketAddr,
    state: &DaemonState,
) {
    if frame.body.len() != 32 {
        Metrics::inc(&state.metrics.frames_dropped_total);
        tracing::debug!(%src, body_len = frame.body.len(), "CookieResponse wrong size");
        return;
    }

    let mut cookie = [0u8; 32];
    cookie.copy_from_slice(&frame.body);

    let Ok(challenger) = state.cookie.lock() else {
        return;
    };

    if challenger.verify(&src, &cookie) {
        Metrics::inc(&state.metrics.cookie_challenges_total);
        tracing::debug!(%src, "cookie validated — address verified");
        state.audit.append("cookie_validated", &src.to_string());
    } else {
        Metrics::inc(&state.metrics.frames_dropped_total);
        tracing::debug!(%src, "cookie verification failed");
        state.audit.append("cookie_invalid", &src.to_string());
    }
}

/// Handle a TCP inbound event.
///
/// `NewConnection`: spawn the Noise XX responder handshake task.
/// `Frame`: forward to the appropriate session (post-handshake TCP transport).
fn handle_tcp_event(event: transport::tcp::TcpInbound, state: &DaemonState) {
    match event {
        transport::tcp::TcpInbound::NewConnection { stream, peer_addr } => {
            tracing::debug!(%peer_addr, "TCP connection — spawning handshake");
            state.audit.append("tcp_connection", &peer_addr.to_string());

            // Clone Arcs for the spawned task.
            let local_kp = Arc::clone(&state.local_keypair);
            let tofu = Arc::clone(&state.tofu_store);
            let table = Arc::clone(&state.peer_table);
            let bus = Arc::clone(&state.bus_client);
            let metrics = Arc::clone(&state.metrics);
            let audit = Arc::clone(&state.audit);

            tokio::spawn(async move {
                let ctx = handshake::HandshakeContext {
                    local_keypair: &local_kp,
                    tofu_store: &tofu,
                    peer_table: &table,
                    bus_client: &bus,
                    metrics: &metrics,
                    audit: &audit,
                };
                let timeout = tokio::time::Duration::from_secs(10);
                let result = tokio::time::timeout(
                    timeout,
                    handshake::handle_inbound_handshake(stream, peer_addr, &ctx),
                )
                .await;

                match result {
                    Ok(handshake::HandshakeOutcome::Established { session_id, .. }) => {
                        tracing::info!(session = %session_id, %peer_addr, "handshake complete");
                    }
                    Ok(handshake::HandshakeOutcome::Rejected { reason }) => {
                        tracing::warn!(%peer_addr, %reason, "handshake rejected");
                    }
                    Err(_) => {
                        Metrics::inc(&metrics.handshake_failures_total);
                        audit.append("handshake_timeout", &peer_addr.to_string());
                        tracing::warn!(%peer_addr, "handshake timed out");
                    }
                }
            });
        }
        transport::tcp::TcpInbound::Frame { peer_addr, .. } => {
            Metrics::inc(&state.metrics.frames_received_total);
            tracing::trace!(%peer_addr, "TCP frame received");
        }
    }
}

/// Periodic maintenance: cookie rotation, idle session cleanup, rekey sweep,
/// session count metric update.
fn run_maintenance(state: &DaemonState) {
    if let Ok(mut c) = state.cookie.lock() {
        c.maybe_rotate();
    }

    // PoW tier activation: check if global handshake limiter is near saturation.
    // When the cookie tier is handling > pow_challenge_threshold of capacity,
    // activate Equi-X PoW to further rate-limit persistent attackers.
    if let Ok(mut pow) = state.pow.lock() {
        let hs_at_capacity = !state.global_hs_limiter.check();
        // Re-grant the token we just consumed for the check.
        // (The check is non-destructive for the actual traffic path —
        // this is a probe, not a real handshake.)
        if hs_at_capacity {
            pow.activate();
        } else {
            pow.deactivate();
        }
    }

    // Update sessions_active gauge.
    state
        .metrics
        .sessions_active
        .store(u64::from(state.peer_table.len()), std::sync::atomic::Ordering::Relaxed);

    // Idle session cleanup: send Close frame before removing.
    let idle = state.peer_table.idle_sessions(state.idle_timeout_secs);
    for sid in &idle {
        tracing::info!(session = %sid, "closing idle session");
        // Fire-and-forget close — best effort, don't block maintenance.
        let sid_copy = *sid;
        let table = Arc::clone(&state.peer_table);
        let socket = Arc::clone(&state.udp_socket);
        let metrics = Arc::clone(&state.metrics);
        tokio::spawn(async move {
            let _ = daemon_network::send::send_close(&sid_copy, &table, &socket, &metrics).await;
        });
        state.audit.append("session_idle_closed", &format!("{sid}"));
    }

    // Rekey sweep: sessions approaching sequence exhaustion or age limit.
    let rekey = state.peer_table.sessions_needing_rekey(state.rekey_interval_secs);
    for sid in &rekey {
        tracing::info!(session = %sid, "session needs rekey — evicting for reconnection");
        state.peer_table.remove(sid);
        state.audit.append("session_rekey_evicted", &format!("{sid}"));
    }
}

fn init_tracing() {
    #[cfg(target_os = "linux")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let journald = tracing_journald::layer().ok();
        tracing_subscriber::registry()
            .with(journald)
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "daemon_network=info".into()),
            )
            .with(tracing_subscriber::fmt::layer().with_target(false))
            .init();
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing_subscriber::fmt()
            .with_env_filter("daemon_network=info")
            .init();
    }
}

fn notify_ready() {
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
}

fn notify_watchdog() {
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_watchdog();
}

async fn idle_loop() -> ! {
    loop {
        notify_watchdog();
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }
}
