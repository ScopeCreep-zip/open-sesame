//! daemon-network: Open Sesame network transport daemon.
//!
//! Provides Noise XX encrypted peer sessions over UDP/TCP with TOFU
//! identity pinning, `IKpsk2` reconnection, rate limiting, stateless
//! cookie `DoS` resistance, and BLAKE3-chained audit logging.
//!
//! # Architecture
//!
//! - **Inward-facing:** Connects to daemon-profile's `BusServer` via Noise IK
//!   Unix socket. Requests network identity keypair and signing seed from
//!   daemon-secrets via the IPC bus.
//! - **Outward-facing:** Dual-stack UDP socket + optional TCP listener on
//!   `network.transport.listen_port` (default 48627).
//!
//! # Lifecycle
//!
//! 1. Init secure memory
//! 2. Load network config + installation identity
//! 3. Apply sandbox
//! 4. Open TOFU store
//! 5. Start audit log
//! 6. Connect to IPC bus
//! 7. Request network identity keypair from daemon-secrets
//! 8. Request signing seed from daemon-secrets (`SecretGet`)
//! 9. Construct `snow::Keypair` from vault bytes, `Ed25519SigningKey` from seed
//! 10. Bind UDP + TCP sockets
//! 11. Notify systemd ready
//! 12. Enter event loop

mod audit;
mod config;
mod control;
mod flood;
mod handshake;
mod handshake_ack;
mod metrics;
mod noise;
mod ratelimit;
mod sandbox;
mod send;
mod session;
mod tofu;
mod transport;

use audit::AuditLog;
use config::load_network_config;
use flood::cookie::CookieChallenger;
use handshake::HandshakeContext;
use metrics::Metrics;
use ratelimit::bucket::TokenBucket;
use session::replay::ReplayCheck;
use session::table::PeerTable;
use transport::frame::WireSessionId;
use transport::udp::UdpInbound;

use clap::Parser;
use core_types::FrameType;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "daemon-network", about = "Open Sesame network transport daemon")]
struct Args {
    #[arg(long)]
    port: Option<u16>,
}

/// Installation identity loaded from installation.toml at startup.
struct InstallationIdentity {
    id: String,
    network_pubkey: [u8; 32],
    signing_pubkey: Option<[u8; 32]>,
}

/// Shared daemon state.
struct DaemonState {
    udp_socket: Arc<tokio::net::UdpSocket>,
    peer_table: Arc<PeerTable>,
    tofu_store: Arc<std::sync::Mutex<tofu::store::TofuStore>>,
    cookie: Arc<std::sync::Mutex<CookieChallenger>>,
    pow: Arc<std::sync::Mutex<flood::pow::PowChallenger>>,
    global_hs_limiter: Arc<TokenBucket>,
    metrics: Arc<Metrics>,
    audit: Arc<AuditLog>,
    local_keypair: Arc<snow::Keypair>,
    bus_client: Arc<tokio::sync::Mutex<core_ipc::BusClient>>,
    discovery: Arc<daemon_discovery::manager::DiscoveryManager>,
    #[allow(dead_code)]
    discovery_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<daemon_discovery::manager::DiscoveryEvent>>,
    listen_port: u16,
    idle_timeout_secs: u64,
    rekey_interval_secs: u64,
    bep44_enabled: bool,
    dns_srv_domains: Vec<String>,
    identity: InstallationIdentity,
    /// Ed25519 signing seed (32 bytes). The keypair is derived on demand via
    /// `derive_signing_keypair(seed, installation_id)` at the moment of
    /// signing, then immediately dropped. Raw bytes are Copy + Send --
    /// no mutex, no lifetime entanglement, minimal memory exposure window.
    signing_seed: Option<[u8; 32]>,
    /// Channel sender for TCP inbound events (post-handshake frame loop).
    tcp_tx: tokio::sync::mpsc::Sender<transport::tcp::TcpInbound>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    core_types::init_secure_memory();
    init_tracing();

    let network_config = load_network_config();
    let listen_port = args.port.unwrap_or(network_config.transport.listen_port);

    if !network_config.enabled {
        tracing::info!("daemon-network disabled in config (network.enabled = false)");
        notify_ready();
        idle_loop().await;
    }

    let (state, tcp_rx) = setup(listen_port, &network_config).await?;
    notify_ready();
    run_event_loop(state, tcp_rx, listen_port, &network_config).await
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn setup(
    listen_port: u16,
    config: &core_config::NetworkConfig,
) -> anyhow::Result<(DaemonState, tokio::sync::mpsc::Receiver<transport::tcp::TcpInbound>)> {
    sandbox::apply_network_sandbox();

    // Load installation identity from installation.toml.
    let install_config = core_config::load_installation()
        .map_err(|e| anyhow::anyhow!("failed to load installation.toml: {e}"))?;
    let installation_id = install_config.id.to_string();

    let network_pubkey: [u8; 32] = install_config
        .network_pubkey_hex
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .unwrap_or([0u8; 32]);

    let signing_pubkey: Option<[u8; 32]> = install_config
        .signing_pubkey_hex
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok());

    let identity = InstallationIdentity {
        id: installation_id.clone(),
        network_pubkey,
        signing_pubkey,
    };

    // TOFU store.
    let tofu_path = config::tofu_db_path(config);
    let tofu_store = Arc::new(std::sync::Mutex::new(
        tofu::store::TofuStore::open(&tofu_path, &installation_id)
            .map_err(|e| anyhow::anyhow!("TOFU store: {e}"))?,
    ));

    // Audit log.
    let audit = Arc::new(
        AuditLog::open(&config::audit_log_path())
            .map_err(|e| anyhow::anyhow!("audit log: {e}"))?,
    );
    audit.append("daemon_started", &format!("port={listen_port} install={installation_id}"));

    // Metrics + rate limiting.
    let metrics = Arc::new(Metrics::new());
    let peer_table = Arc::new(PeerTable::new(config.session.max_concurrent_sessions));
    let cookie = Arc::new(std::sync::Mutex::new(
        CookieChallenger::new(u64::from(config.flood.cookie_epoch_secs)),
    ));
    let pow = Arc::new(std::sync::Mutex::new(flood::pow::PowChallenger::new()));
    let global_hs_limiter = Arc::new(TokenBucket::new(
        config.ratelimit.global_handshake_rate_per_sec,
        config.ratelimit.global_handshake_burst,
    ));

    // IPC bus connection.
    let mut bus_client = control::bus::connect_to_bus()
        .await
        .map_err(|e| anyhow::anyhow!("IPC bus connect failed: {e}"))?;

    // Request network identity keypair from daemon-secrets.
    // The private key was stored in the vault during `sesame init` under
    // the system key `_network-identity-private`. daemon-secrets returns
    // the raw bytes via NetworkIdentityResponse.
    let local_keypair = if let Some((vault_private, _vault_public)) =
        control::bus::request_network_identity(&mut bus_client).await
    {
        let priv_array: &[u8; 32] = vault_private
            .as_slice()
            .try_into()
            .unwrap_or(&[0u8; 32]);
        let computed_pub = core_crypto::network::x25519_public_from_private(priv_array);
        if computed_pub != network_pubkey && network_pubkey != [0u8; 32] {
            tracing::warn!(
                "vault private key does not match installation.toml network_pubkey_hex"
            );
        }
        let kp = snow::Keypair {
            private: vault_private,
            public: computed_pub.to_vec(),
        };
        tracing::info!(
            pubkey = %hex::encode(&computed_pub[..16]),
            "network identity keypair loaded from vault"
        );
        Arc::new(kp)
    } else {
        let kp = snow::Builder::new(noise::state::NOISE_XX.parse().unwrap())
            .generate_keypair()
            .map_err(|e| anyhow::anyhow!("keypair generation: {e}"))?;
        tracing::warn!(
            pubkey = %hex::encode(&kp.public[..16]),
            "ephemeral keypair -- vault locked, TOFU pins will not persist"
        );
        Arc::new(kp)
    };

    // Request signing seed from daemon-secrets via SecretGet.
    // The seed was stored during `sesame init` under `_signing-seed`.
    // We store the raw 32-byte seed, not the derived Ed25519KeyPair, because:
    // - [u8; 32] is Copy + Send (Ed25519KeyPair from aws-lc-rs is neither)
    // - The keypair is derived on demand at signing time (~50us) then dropped
    // - Minimizes the memory exposure window for key material
    let signing_seed: Option<[u8; 32]> = match control::bus::request_secret(
        &mut bus_client,
        "_signing-seed",
    ).await {
        Some(seed_bytes) if seed_bytes.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);

            // Verify the seed produces the expected public key from installation.toml.
            let seed_secure = core_crypto::SecureBytes::from_slice(&seed);
            match core_crypto::network::derive_signing_keypair(&seed_secure, &install_config.id) {
                Ok(key) => {
                    let derived_pub = key.public_key();
                    if let Some(expected) = signing_pubkey
                        && derived_pub != expected
                    {
                        tracing::warn!(
                            "signing seed produces different pubkey than installation.toml"
                        );
                    }
                    tracing::info!(
                        pubkey = %hex::encode(&derived_pub[..16]),
                        "signing seed loaded from vault"
                    );
                    Some(seed)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "signing seed derivation failed");
                    None
                }
            }
        }
        Some(seed_bytes) => {
            tracing::warn!(len = seed_bytes.len(), "signing seed wrong length (expected 32)");
            None
        }
        None => {
            tracing::info!("signing seed not available -- vault locked or not yet initialized");
            None
        }
    };

    let bus_client = Arc::new(tokio::sync::Mutex::new(bus_client));

    // UDP + TCP sockets.
    let udp_socket = Arc::new(
        transport::udp::bind_udp(listen_port)
            .await
            .map_err(|e| anyhow::anyhow!("UDP bind port {listen_port}: {e}"))?,
    );

    // Discovery.
    let (discovery_tx, discovery_rx) = tokio::sync::mpsc::channel(256);
    let discovery = Arc::new(daemon_discovery::manager::DiscoveryManager::new(1024, discovery_tx));

    let bootstrap_path = dirs::config_dir()
        .unwrap_or_default()
        .join("pds")
        .join("bootstrap.json");
    if let Ok(targets) = daemon_discovery::bootstrap::load_bootstrap(&bootstrap_path) {
        discovery.load_bootstrap(&targets);
    }

    // TCP inbound channel — shared between tcp_accept_loop and post-handshake
    // tcp_read_loop tasks. Both send TcpInbound events to the main event loop.
    let (tcp_tx, tcp_rx) = tokio::sync::mpsc::channel(256);

    Ok((DaemonState {
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
        discovery,
        discovery_rx: tokio::sync::Mutex::new(discovery_rx),
        listen_port,
        idle_timeout_secs: u64::from(config.session.idle_timeout_secs),
        rekey_interval_secs: 120,
        bep44_enabled: config.discovery.bep44.enabled,
        dns_srv_domains: config.discovery.dns_srv.domains.clone(),
        identity,
        signing_seed,
        tcp_tx,
    }, tcp_rx))
}

// ---------------------------------------------------------------------------
// Event Loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn run_event_loop(
    state: DaemonState,
    mut tcp_rx: tokio::sync::mpsc::Receiver<transport::tcp::TcpInbound>,
    listen_port: u16,
    config: &core_config::NetworkConfig,
) -> anyhow::Result<()> {
    // UDP receive task.
    let (udp_tx, mut udp_rx) = tokio::sync::mpsc::channel::<UdpInbound>(4096);
    let udp_recv_socket = Arc::clone(&state.udp_socket);
    tokio::spawn(async move {
        transport::udp::udp_receive_loop(udp_recv_socket, udp_tx).await;
    });

    // TCP accept task — uses the shared tcp_tx from DaemonState.
    if config.transport.tcp_enabled {
        let tcp_tx_accept = state.tcp_tx.clone();
        let max_conn = config.transport.max_tcp_connections_per_address;
        let hs_timeout = config.session.handshake_timeout_secs;
        tokio::spawn(async move {
            if let Err(e) = transport::tcp::tcp_accept_loop(listen_port, tcp_tx_accept, max_conn, hs_timeout).await {
                tracing::error!(error = %e, "TCP accept loop failed");
            }
        });
    }

    // Prometheus metrics endpoint.
    let metrics_clone = Arc::clone(&state.metrics);
    tokio::spawn(async move {
        metrics::serve_prometheus(metrics_clone, 9104).await;
    });

    tracing::info!(
        port = listen_port,
        udp = true,
        tcp = config.transport.tcp_enabled,
        max_sessions = config.session.max_concurrent_sessions,
        "daemon-network listening"
    );

    // Spawn discovery backends (mDNS, BEP-44, DNS SRV).
    spawn_discovery(&state, config);

    // IPC bus message forwarding.
    let (ipc_tx, mut ipc_rx) = tokio::sync::mpsc::channel::<core_ipc::Message<core_types::EventKind>>(64);
    let ipc_bus = Arc::clone(&state.bus_client);
    tokio::spawn(async move {
        loop {
            let msg = {
                let mut client = ipc_bus.lock().await;
                client.recv().await
            };
            match msg {
                Some(m) => { if ipc_tx.send(m).await.is_err() { break; } }
                None => break,
            }
        }
    });

    let mut watchdog_tick = tokio::time::interval(std::time::Duration::from_secs(15));
    let mut maintenance_tick = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut dial_tick = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut keepalive_tick = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            Some(inbound) = udp_rx.recv() => {
                handle_udp_frame(&inbound, &state);
            }
            Some(tcp_event) = tcp_rx.recv() => {
                handle_tcp_event(tcp_event, &state);
            }
            _ = dial_tick.tick() => {
                run_dial_queue(&state);
            }
            _ = keepalive_tick.tick() => {
                run_keepalives(&state);
            }
            Some(ipc_msg) = ipc_rx.recv() => {
                handle_ipc_message(ipc_msg, &state).await;
            }
            _ = maintenance_tick.tick() => {
                run_maintenance(&state);
            }
            _ = watchdog_tick.tick() => {
                notify_watchdog();
                tracing::trace!(sessions = state.peer_table.len(), "watchdog");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UDP frame dispatch
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
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
            // TCP-first handshake (M1-R1): Noise XX runs over TCP.
            // UDP HandshakeInit is a knock. Respond with cookie or PoW challenge
            // so the initiator proves source address before TCP connect.
            let pow_active = state.pow.lock().ok().is_some_and(|p| p.is_active());

            if pow_active {
                // Tier 2: Equi-X PoW challenge.
                let cookie_secret = state.cookie.lock().ok()
                    .map_or([0u8; 32], |c| c.generate(&src));
                let epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let seed = flood::pow::PowChallenger::generate_seed(
                    &cookie_secret, epoch, &src.to_string(),
                );
                let mut body = vec![0x01u8]; // PoW type byte
                body.extend_from_slice(&seed);
                let resp = transport::frame::Frame::new(
                    FrameType::CookieRequest as u8, frame.session_id, 0, body,
                );
                let socket = Arc::clone(&state.udp_socket);
                tokio::spawn(async move {
                    let _ = transport::udp::udp_send(&socket, &resp, &src).await;
                });
                Metrics::inc(&state.metrics.cookie_challenges_total);
                state.audit.append("pow_challenge_sent", &src.to_string());
            } else {
                // Tier 1: BLAKE3 cookie challenge.
                if let Ok(challenger) = state.cookie.lock() {
                    let cookie = challenger.generate(&src);
                    let mut body = vec![0x00u8]; // Cookie type byte
                    body.extend_from_slice(&cookie);
                    let resp = transport::frame::Frame::new(
                        FrameType::CookieRequest as u8, frame.session_id, 0, body,
                    );
                    let socket = Arc::clone(&state.udp_socket);
                    tokio::spawn(async move {
                        let _ = transport::udp::udp_send(&socket, &resp, &src).await;
                    });
                    Metrics::inc(&state.metrics.cookie_challenges_total);
                }
            }
            tracing::debug!(%src, pow = pow_active, "HandshakeInit knock — challenge sent");
            state.audit.append("handshake_init_udp", &src.to_string());
        }

        FrameType::Data | FrameType::KeepAlive => {
            let sid = WireSessionId(frame.session_id.0);
            // Primary lookup by session ID. Fallback: reverse lookup by source address
            // (handles path migration where the session ID is correct but the source
            // address changed before the peer table was updated).
            let resolved_sid = if state.peer_table.get(&sid).is_some() {
                sid
            } else if let Some(addr_sid) = state.peer_table.lookup_addr(&src) {
                addr_sid
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            };
            if let Some(mut peer) = state.peer_table.get_mut(&resolved_sid) {
                match peer.replay_window.check_and_update(frame.sequence) {
                    ReplayCheck::Accept => {}
                    ReplayCheck::Duplicate | ReplayCheck::TooOld => {
                        Metrics::inc(&state.metrics.replay_detected_total);
                        return;
                    }
                }

                if peer.remote_addr != src {
                    tracing::info!(session = %sid, old = %peer.remote_addr, new = %src, "path migration");
                    let old_addr = peer.remote_addr;
                    drop(peer);
                    state.peer_table.update_addr(&sid, &old_addr, src);
                    state.audit.append("path_migration", &format!("{sid} {src}"));
                    return;
                }

                if ft == FrameType::Data {
                    match peer.transport.decrypt(&frame.body) {
                        Ok(plaintext) => {
                            #[allow(clippy::cast_possible_truncation)]
                            peer.record_productive_recv(plaintext.len() as u64);
                        }
                        Err(e) => {
                            peer.record_aead_failure();
                            Metrics::inc(&state.metrics.aead_failures_total);
                            tracing::warn!(session = %sid, %src, error = %e, "AEAD failure");
                            state.audit.append("aead_failure", &format!("{sid} {src}"));
                        }
                    }
                } else {
                    peer.record_recv(0);
                }
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
            }
        }

        FrameType::Close => {
            let sid = WireSessionId(frame.session_id.0);
            if state.peer_table.get(&sid).is_some() {
                state.peer_table.remove(&sid);
                Metrics::inc(&state.metrics.sessions_closed_total);
                tracing::info!(session = %sid, %src, "session closed by peer");
                state.audit.append("session_closed", &format!("{sid} {src}"));
            }
        }

        FrameType::RehandshakeRequest => {
            let sid = WireSessionId(frame.session_id.0);
            tracing::info!(session = %sid, "rehandshake requested by peer");
            state.peer_table.remove(&sid);
            state.audit.append("rehandshake_requested", &format!("{sid}"));
        }

        FrameType::CookieResponse => {
            handle_cookie_response(frame, src, state);
        }

        _ => {
            Metrics::inc(&state.metrics.frames_dropped_total);
        }
    }
}

fn handle_cookie_response(
    frame: &transport::frame::Frame,
    src: std::net::SocketAddr,
    state: &DaemonState,
) {
    // Frame body format: [1-byte type][payload]
    // Type 0x00: cookie echo (32-byte cookie)
    // Type 0x01: PoW solution (16-byte Equi-X solution)
    if frame.body.is_empty() {
        Metrics::inc(&state.metrics.frames_dropped_total);
        return;
    }

    let type_byte = frame.body[0];
    let payload = &frame.body[1..];

    match type_byte {
        0x00 => {
            // Cookie verification.
            if payload.len() != 32 {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            }
            let mut cookie = [0u8; 32];
            cookie.copy_from_slice(payload);
            let Ok(challenger) = state.cookie.lock() else { return };
            if challenger.verify(&src, &cookie) {
                Metrics::inc(&state.metrics.cookie_challenges_total);
                state.audit.append("cookie_validated", &src.to_string());
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
            }
        }
        0x01 => {
            // PoW solution verification.
            if payload.len() != 16 {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            }
            // Regenerate the seed for this client to verify against.
            let cookie_secret = state.cookie.lock().ok()
                .map_or([0u8; 32], |c| c.generate(&src));
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let seed = flood::pow::PowChallenger::generate_seed(
                &cookie_secret, epoch, &src.to_string(),
            );
            let solution: equix::SolutionByteArray = payload.try_into().unwrap_or([0u8; 16]);
            if flood::pow::PowChallenger::verify_solution(&seed, &solution) {
                Metrics::inc(&state.metrics.cookie_challenges_total);
                state.audit.append("pow_validated", &src.to_string());
                tracing::debug!(%src, "PoW solution verified");
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
                state.audit.append("pow_invalid", &src.to_string());
            }
        }
        _ => {
            Metrics::inc(&state.metrics.frames_dropped_total);
        }
    }
}

// ---------------------------------------------------------------------------
// TCP event dispatch
// ---------------------------------------------------------------------------

fn handle_tcp_event(event: transport::tcp::TcpInbound, state: &DaemonState) {
    match event {
        transport::tcp::TcpInbound::NewConnection { stream, peer_addr } => {
            if !state.global_hs_limiter.check() {
                Metrics::inc(&state.metrics.rate_limited_total);
                tracing::debug!(%peer_addr, "TCP handshake rate limited");
                drop(stream);
                return;
            }
            state.audit.append("tcp_connection", &peer_addr.to_string());

            let local_kp = Arc::clone(&state.local_keypair);
            let tofu = Arc::clone(&state.tofu_store);
            let table = Arc::clone(&state.peer_table);
            let bus = Arc::clone(&state.bus_client);
            let metrics = Arc::clone(&state.metrics);
            let audit = Arc::clone(&state.audit);
            let udp_sock = Arc::clone(&state.udp_socket);
            let tcp_sender = state.tcp_tx.clone();
            let signing_seed = state.signing_seed;
            let install_id = state.identity.id.clone();
            let net_pub = state.identity.network_pubkey;
            let sign_pub = state.identity.signing_pubkey;

            tokio::spawn(async move {
                let ctx = HandshakeContext {
                    local_keypair: &local_kp,
                    tofu_store: &tofu,
                    peer_table: &table,
                    bus_client: &bus,
                    metrics: &metrics,
                    audit: &audit,
                    signing_seed,
                    installation_id: &install_id,
                    network_pubkey: &net_pub,
                    signing_pubkey: sign_pub,
                    udp_socket: &udp_sock,
                    tcp_tx: &tcp_sender,
                };

                let timeout = tokio::time::Duration::from_secs(10);
                let result = tokio::time::timeout(
                    timeout,
                    handshake::handle_inbound_handshake(stream, peer_addr, &ctx),
                ).await;

                match result {
                    Ok(handshake::HandshakeOutcome::Established { session_id, remote_key_hex, .. }) => {
                        tracing::info!(session = %session_id, %peer_addr, key = %&remote_key_hex[..16.min(remote_key_hex.len())], "handshake complete");
                    }
                    Ok(handshake::HandshakeOutcome::Rejected { reason }) => {
                        tracing::warn!(%peer_addr, %reason, "handshake rejected");
                    }
                    Err(_) => {
                        Metrics::inc(&metrics.handshake_failures_total);
                        let timeout_err = crate::noise::state::NoiseError::Timeout;
                        audit.append("handshake_timeout", &peer_addr.to_string());
                        tracing::warn!(%peer_addr, error = %timeout_err, "handshake timed out");
                    }
                }
            });
        }
        transport::tcp::TcpInbound::Frame { frame, peer_addr } => {
            Metrics::inc(&state.metrics.frames_received_total);
            // Route TCP frames the same as UDP Data frames.
            let sid = WireSessionId(frame.session_id.0);
            if let Some(mut peer) = state.peer_table.get_mut(&sid) {
                if let Ok(plaintext) = peer.transport.decrypt(&frame.body) {
                    #[allow(clippy::cast_possible_truncation)]
                    peer.record_productive_recv(plaintext.len() as u64);
                    tracing::trace!(session = %sid, %peer_addr, len = plaintext.len(), "TCP data frame");
                } else {
                    peer.record_aead_failure();
                    Metrics::inc(&state.metrics.aead_failures_total);
                    tracing::warn!(session = %sid, %peer_addr, "TCP AEAD failure");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IPC message handling
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // IPC dispatch routes many EventKind variants.
async fn handle_ipc_message(
    msg: core_ipc::Message<core_types::EventKind>,
    state: &DaemonState,
) {
    use core_types::EventKind;

    let response = match &msg.payload {
        EventKind::NetworkStatusRequest => {
            let tofu_count = state.tofu_store.lock()
                .ok()
                .and_then(|s| s.list_peers().ok())
                .map_or(0, |p| p.len());

            // Log session details at DEBUG for diagnostics.
            if !state.peer_table.is_empty() {
                for sid in state.peer_table.session_ids() {
                    if let Some(peer) = state.peer_table.get(&sid) {
                        tracing::debug!(
                            session = %sid,
                            addr = %peer.remote_addr,
                            key = %&peer.remote_key_hex()[..16],
                            initiator = peer.is_initiator(),
                            age = peer.age_secs(),
                            idle = peer.idle_secs(),
                            "session status"
                        );
                    }
                }
            }

            let event_count = state.tofu_store.lock()
                .ok()
                .and_then(|s| s.event_count().ok())
                .unwrap_or(0);

            Some(EventKind::NetworkStatusResponse {
                active_sessions: state.peer_table.len(),
                #[allow(clippy::cast_possible_truncation)]
                tofu_peers: tofu_count as u32,
                #[allow(clippy::cast_possible_truncation)]
                tofu_events: event_count as u32,
                #[allow(clippy::cast_possible_truncation)]
                dial_queue_depth: state.discovery.queue_depth() as u32,
                listen_port: state.listen_port,
                enabled: true,
            })
        }
        EventKind::NetworkDialRequest { addr } => {
            match addr.parse::<std::net::SocketAddr>() {
                Ok(target) => {
                    let ctx = build_handshake_ctx(state);
                    let result = handshake::dial_peer(target, &ctx).await;
                    match result {
                        handshake::HandshakeOutcome::Established { session_id, remote_key_hex, .. } => {
                            tracing::info!(key = %&remote_key_hex[..16.min(remote_key_hex.len())], "dial established");
                            Some(EventKind::NetworkDialResponse {
                                success: true,
                                session_id: Some(format!("{session_id}")),
                                error: None,
                            })
                        }
                        handshake::HandshakeOutcome::Rejected { reason } => {
                            Some(EventKind::NetworkDialResponse {
                                success: false,
                                session_id: None,
                                error: Some(reason),
                            })
                        }
                    }
                }
                Err(e) => Some(EventKind::NetworkDialResponse {
                    success: false,
                    session_id: None,
                    error: Some(format!("invalid address: {e}")),
                }),
            }
        }
        EventKind::NetworkDiscoverRequest => {
            Some(EventKind::NetworkDiscoverResponse {
                mdns_peers: state.discovery.mdns_peer_count(),
                bep44_published: state.bep44_enabled && state.signing_seed.is_some(),
                dns_srv_domains: state.dns_srv_domains.clone(),
                #[allow(clippy::cast_possible_truncation)]
                dial_queue_depth: state.discovery.queue_depth() as u32,
                swim_members: 0, // SWIM deferred
            })
        }
        // Forward vault replication responses to network peers.
        // The profile_id in the response identifies which peer requested it;
        // routing by peer is deferred to M3 when the replication protocol
        // maps profile_id → peer session. For now, broadcast to all sessions.
        EventKind::VaultReplicationPullResponse { entries_json, .. } => {
            let payload = entries_json.as_bytes();
            let sids = state.peer_table.session_ids();
            for sid in &sids {
                let table = Arc::clone(&state.peer_table);
                let socket = Arc::clone(&state.udp_socket);
                let metrics = Arc::clone(&state.metrics);
                let sid = *sid;
                let data = payload.to_vec();
                tokio::spawn(async move {
                    // Prefix with NetworkMessageType::VaultReplication (0x0100).
                    let mut framed = vec![0x01, 0x00];
                    framed.extend_from_slice(&data);
                    let _ = send::send_data(&sid, &framed, &table, &socket, &metrics).await;
                });
            }
            None
        }
        EventKind::NetworkUnpinRequest { public_key_hex } => {
            let result = state.tofu_store.lock()
                .map_err(|e| format!("TOFU lock: {e}"))
                .and_then(|store| {
                    store.unpin(public_key_hex)
                        .map_err(|e| format!("unpin failed: {e}"))
                });
            match result {
                Ok(()) => {
                    state.audit.append("peer_unpinned", public_key_hex);
                    Some(EventKind::NetworkUnpinResponse {
                        success: true,
                        error: None,
                    })
                }
                Err(e) => Some(EventKind::NetworkUnpinResponse {
                    success: false,
                    error: Some(e),
                }),
            }
        }
        _ => None,
    };

    if let Some(event) = response {
        let client = state.bus_client.lock().await;
        if let Err(e) = client.publish(event, core_types::SecurityLevel::Internal).await {
            tracing::warn!(error = %e, "IPC response failed");
        }
    }
}

/// Build a `HandshakeContext` from `DaemonState` for synchronous use
/// (not across spawn boundaries -- references borrow from state).
fn build_handshake_ctx(state: &DaemonState) -> HandshakeContext<'_> {
    HandshakeContext {
        local_keypair: &state.local_keypair,
        tofu_store: &state.tofu_store,
        peer_table: &state.peer_table,
        bus_client: &state.bus_client,
        metrics: &state.metrics,
        audit: &state.audit,
        signing_seed: state.signing_seed,
        installation_id: &state.identity.id,
        network_pubkey: &state.identity.network_pubkey,
        signing_pubkey: state.identity.signing_pubkey,
        udp_socket: &state.udp_socket,
        tcp_tx: &state.tcp_tx,
    }
}

// ---------------------------------------------------------------------------
// Dial queue consumer
// ---------------------------------------------------------------------------

/// Spawn discovery backend tasks (mDNS, BEP-44, DNS SRV).
///
/// Each backend pushes discovered peers into the `DiscoveryManager` dial queue.
/// The main event loop's `dial_tick` consumes the queue and initiates handshakes.
#[allow(clippy::too_many_lines)]
fn spawn_discovery(state: &DaemonState, config: &core_config::NetworkConfig) {
    let disc = &config.discovery;

    // mDNS: bind multicast socket, announce, listen.
    if disc.mdns.enabled {
        let pubkey: [u8; 32] = state.local_keypair.public[..32]
            .try_into()
            .unwrap_or([0; 32]);
        let install_id = state.identity.id.clone();
        let port = state.listen_port;
        let srv_ttl = disc.mdns.srv_ttl;
        let ptr_ttl = disc.mdns.ptr_ttl;
        let mgr = Arc::clone(&state.discovery);

        match daemon_discovery::mdns::socket::bind_mdns_socket() {
            Ok(mdns_socket) => {
                let socket = Arc::new(mdns_socket);

                // Initial announcement (3 packets at 0s, 1s, 2s).
                let s_announce = Arc::clone(&socket);
                let id_announce = install_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = daemon_discovery::mdns::announce::initial_announce(
                        &s_announce, &pubkey, &id_announce, port, None, srv_ttl, ptr_ttl,
                    ).await {
                        tracing::warn!(error = %e, "mDNS initial announce failed");
                    }
                });

                // Listen loop: receive mDNS responses, extract peers, feed dial queue.
                let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(64);
                let listen_config = daemon_discovery::mdns::listen::MdnsListenConfig {
                    our_pubkey: pubkey,
                    our_install_id: install_id,
                    our_port: port,
                    our_ipv4: None,
                    srv_ttl,
                    ptr_ttl,
                };
                tokio::spawn(async move {
                    daemon_discovery::mdns::listen::mdns_listen_loop(
                        socket, listen_config, peer_tx,
                    ).await;
                });

                // Drain mDNS peer channel into dial queue.
                tokio::spawn(async move {
                    while let Some(peer) = peer_rx.recv().await {
                        mgr.add_peer(
                            peer.addr,
                            daemon_discovery::queue::DiscoverySource::Mdns,
                            Some(peer.pubkey_hex),
                        );
                    }
                });

                tracing::info!("mDNS discovery started");
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS socket bind failed — LAN discovery disabled");
            }
        }
    }

    // BEP-44: publish presence to Mainline DHT.
    if disc.bep44.enabled {
        if let Some(seed) = state.signing_seed {
            let signing_key = mainline::SigningKey::from_bytes(&seed);
            let port = state.listen_port;
            let noise_pubkey_hex = hex::encode(state.local_keypair.public.as_slice());
            let signing_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
            let install_id = state.identity.id.clone();

            tokio::spawn(async move {
                let dht = match mainline::Dht::builder().build() {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!(error = %e, "BEP-44 DHT init failed");
                        return;
                    }
                };

                let record = daemon_discovery::bep44::schema::PresenceRecord {
                    addrs: vec![format!("0.0.0.0:{port}")],
                    signing_pubkey: signing_pubkey_hex,
                    noise_pubkey: noise_pubkey_hex,
                    display_name: install_id,
                    version: 1,
                };

                match daemon_discovery::bep44::publish::publish_presence(
                    &dht, &signing_key, &record, 1,
                ).await {
                    Ok(()) => tracing::info!("BEP-44 presence published to Mainline DHT"),
                    Err(e) => tracing::warn!(error = %e, "BEP-44 publish failed"),
                }
            });
            // Periodic resolve loop: resolve known peers from TOFU store.
            let tofu_resolve = Arc::clone(&state.tofu_store);
            let mgr_resolve = Arc::clone(&state.discovery);
            tokio::spawn(async move {
                let resolve_dht = match mainline::Dht::builder().build() {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!(error = %e, "BEP-44 resolve DHT init failed");
                        return;
                    }
                };
                loop {
                    let pubkeys = tofu_resolve.lock().ok()
                        .and_then(|s| s.pinned_pubkeys().ok())
                        .unwrap_or_default();
                    for key_hex in &pubkeys {
                        if let Ok(key_bytes) = hex::decode(key_hex)
                            && let Ok(pubkey) = <[u8; 32]>::try_from(key_bytes)
                            && let Some(peer) = daemon_discovery::bep44::resolve::resolve_presence(
                                &resolve_dht, &pubkey,
                            ).await
                        {
                            for addr_str in &peer.record.addrs {
                                if let Ok(addr) = addr_str.parse() {
                                    mgr_resolve.add_peer(
                                        addr,
                                        daemon_discovery::queue::DiscoverySource::Bep44,
                                        Some(key_hex.clone()),
                                    );
                                }
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                }
            });
        } else {
            tracing::info!("BEP-44 skipped — signing seed not available");
        }
    }

    // DNS SRV: periodic resolution of configured domains.
    if disc.dns_srv.enabled && !disc.dns_srv.domains.is_empty() {
        let domains = disc.dns_srv.domains.clone();
        let interval = std::time::Duration::from_secs(u64::from(disc.dns_srv.min_refresh_secs));
        let mgr = Arc::clone(&state.discovery);

        tokio::spawn(async move {
            loop {
                for domain in &domains {
                    match daemon_discovery::dns_srv::resolve_srv(domain).await {
                        Ok(peers) => {
                            for peer in peers {
                                mgr.add_peer(
                                    peer.addr,
                                    daemon_discovery::queue::DiscoverySource::DnsSrv,
                                    peer.pubkey_hex,
                                );
                            }
                        }
                        Err(e) => {
                            tracing::debug!(domain, error = %e, "DNS SRV resolve failed");
                        }
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });

        tracing::info!(domains = ?disc.dns_srv.domains, "DNS SRV discovery started");
    }

    // SWIM gossip: bind separate UDP port, create foca instance, drive event loop.
    let gossip_port = config.transport.gossip_port;
    let pubkey_prefix = hex::encode(&state.local_keypair.public[..8]);
    let gossip_addr: std::net::SocketAddr = format!("[::]:{gossip_port}").parse().unwrap();

    let mgr_swim = Arc::clone(&state.discovery);
    tokio::spawn(async move {
        use foca::Identity as _; // Bring addr() method into scope for PeerId.
        let gossip_socket = match tokio::net::UdpSocket::bind(gossip_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::warn!(port = gossip_port, error = %e, "SWIM gossip socket bind failed");
                return;
            }
        };

        let local_addr: std::net::SocketAddr = format!("0.0.0.0:{gossip_port}").parse().unwrap();
        let identity = daemon_discovery::gossip::swim::PeerId {
            addr: local_addr,
            generation: 0,
            key_prefix: pubkey_prefix,
        };
        let swim_config = daemon_discovery::gossip::swim::default_swim_config();
        let mut swim = daemon_discovery::gossip::runtime::new_swim(identity, swim_config);
        let mut runtime = daemon_discovery::gossip::runtime::AccumulatingRuntime::new();

        // Pending timers: foca schedules probes/suspect transitions via submit_after.
        // We store (deadline, timer) and fire them when the deadline passes.
        let mut pending_timers: Vec<(
            tokio::time::Instant,
            foca::Timer<daemon_discovery::gossip::swim::PeerId>,
        )> = Vec::new();

        let mut buf = vec![0u8; 65535];
        loop {
            // Next timer deadline or 30s default.
            let next_deadline = pending_timers
                .iter()
                .map(|(d, _)| *d)
                .min()
                .unwrap_or_else(|| tokio::time::Instant::now() + std::time::Duration::from_secs(30));

            tokio::select! {
                result = gossip_socket.recv_from(&mut buf) => {
                    if let Ok((len, _src)) = result {
                        let _ = swim.handle_data(&buf[..len], &mut runtime);
                    }
                }
                () = tokio::time::sleep_until(next_deadline) => {
                    // Fire expired timers.
                    let now = tokio::time::Instant::now();
                    let expired: Vec<usize> = pending_timers
                        .iter()
                        .enumerate()
                        .filter(|(_, (d, _))| *d <= now)
                        .map(|(i, _)| i)
                        .collect();
                    for i in expired.into_iter().rev() {
                        let (_, timer) = pending_timers.remove(i);
                        let _ = swim.handle_timer(timer, &mut runtime);
                    }
                }
            }

            // Drain runtime after every interaction.
            while let Some((dest, data)) = runtime.to_send() {
                let _ = gossip_socket.send_to(&data, dest.addr()).await;
            }
            while let Some((delay, timer)) = runtime.to_schedule() {
                let deadline = tokio::time::Instant::now() + delay;
                pending_timers.push((deadline, timer));
            }
            while let Some(notification) = runtime.to_notify() {
                match notification {
                    foca::OwnedNotification::MemberUp(peer) => {
                        tracing::info!(peer = %peer, "SWIM member up");
                        mgr_swim.add_peer(
                            peer.addr,
                            daemon_discovery::queue::DiscoverySource::Bootstrap,
                            Some(peer.key_prefix.clone()),
                        );
                    }
                    foca::OwnedNotification::MemberDown(peer) => {
                        tracing::info!(peer = %peer, "SWIM member down");
                    }
                    _ => {}
                }
            }
        }
    });
    tracing::info!(port = gossip_port, "SWIM gossip started");
}

fn run_dial_queue(state: &DaemonState) {
    while let Some(entry) = state.discovery.queue.pop_ready() {
        let local_kp = Arc::clone(&state.local_keypair);
        let tofu = Arc::clone(&state.tofu_store);
        let table = Arc::clone(&state.peer_table);
        let bus = Arc::clone(&state.bus_client);
        let metrics = Arc::clone(&state.metrics);
        let audit = Arc::clone(&state.audit);
        let udp_sock = Arc::clone(&state.udp_socket);
        let tcp_sender = state.tcp_tx.clone();
        let discovery = Arc::clone(&state.discovery);
        let signing_seed = state.signing_seed;
        let install_id = state.identity.id.clone();
        let net_pub = state.identity.network_pubkey;
        let sign_pub = state.identity.signing_pubkey;

        tokio::spawn(async move {
            let ctx = HandshakeContext {
                local_keypair: &local_kp,
                tofu_store: &tofu,
                peer_table: &table,
                bus_client: &bus,
                metrics: &metrics,
                audit: &audit,
                signing_seed,
                installation_id: &install_id,
                network_pubkey: &net_pub,
                signing_pubkey: sign_pub,
                udp_socket: &udp_sock,
                tcp_tx: &tcp_sender,
            };
            let result = handshake::dial_peer(entry.addr, &ctx).await;
            match result {
                handshake::HandshakeOutcome::Established { session_id, remote_key_hex, trust_level } => {
                    tracing::info!(addr = %entry.addr, session = %session_id, key = %&remote_key_hex[..16.min(remote_key_hex.len())], ?trust_level, "dial succeeded");
                }
                handshake::HandshakeOutcome::Rejected { reason } => {
                    tracing::debug!(addr = %entry.addr, %reason, "dial failed");
                    discovery.queue.requeue_failed(entry);
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Keepalive
// ---------------------------------------------------------------------------

/// Send keepalive probes to sessions idle longer than half the idle timeout.
/// Prevents sessions from being evicted by the maintenance sweep.
fn run_keepalives(state: &DaemonState) {
    let half_idle = state.idle_timeout_secs / 2;
    let candidates = state.peer_table.idle_sessions(half_idle);
    for sid in &candidates {
        let sid_copy = *sid;
        let table = Arc::clone(&state.peer_table);
        let socket = Arc::clone(&state.udp_socket);
        let metrics = Arc::clone(&state.metrics);
        tokio::spawn(async move {
            if let Err(e) = send::send_keepalive(&sid_copy, &table, &socket, &metrics).await {
                tracing::trace!(session = %sid_copy, error = %e, "keepalive failed");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

fn run_maintenance(state: &DaemonState) {
    // Cookie secret rotation.
    if let Ok(mut c) = state.cookie.lock() {
        c.maybe_rotate();
    }

    // PoW tier activation: when session table exceeds 75% capacity, activate
    // Equi-X PoW as second-tier DoS gate beyond the cookie challenge.
    if let Ok(mut pow) = state.pow.lock() {
        let max = state.peer_table.max_sessions();
        let current = state.peer_table.len();
        if current > max * 3 / 4 {
            pow.activate();
        } else {
            pow.deactivate();
        }
    }

    // Update sessions_active gauge.
    state.metrics.sessions_active.store(
        u64::from(state.peer_table.len()),
        std::sync::atomic::Ordering::Relaxed,
    );

    // Idle session cleanup.
    let idle = state.peer_table.idle_sessions(state.idle_timeout_secs);
    for sid in &idle {
        tracing::info!(session = %sid, "closing idle session");
        let sid_copy = *sid;
        let table = Arc::clone(&state.peer_table);
        let socket = Arc::clone(&state.udp_socket);
        let metrics = Arc::clone(&state.metrics);
        tokio::spawn(async move {
            let _ = send::send_close(&sid_copy, &table, &socket, &metrics).await;
        });
        state.audit.append("session_idle_closed", &format!("{sid}"));
    }

    // Rekey sweep: send RehandshakeRequest instead of evicting.
    // The peer receives the request and initiates a fresh XX handshake.
    // The old session remains active until the new one replaces it or
    // the idle timeout fires.
    let rekey = state.peer_table.sessions_needing_rekey(state.rekey_interval_secs);
    for sid in &rekey {
        tracing::info!(session = %sid, "sending RehandshakeRequest");
        let sid_copy = *sid;
        let table = Arc::clone(&state.peer_table);
        let socket = Arc::clone(&state.udp_socket);
        let metrics = Arc::clone(&state.metrics);
        tokio::spawn(async move {
            let _ = send::send_rehandshake_request(&sid_copy, &table, &socket, &metrics).await;
        });
        state.audit.append("rehandshake_sent", &format!("{sid}"));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
