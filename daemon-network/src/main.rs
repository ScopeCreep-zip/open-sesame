//! daemon-network: Open Sesame network transport daemon.
//!
//! Process lifecycle: arg parsing, tracing, systemd, config, bus connection,
//! and the `tokio::select!` event loop. All business logic lives in the
//! library crate (`lib.rs` modules) for testability.

use daemon_network::audit::AuditLog;
use daemon_network::config;
use daemon_network::control;
use daemon_network::dispatch;
use daemon_network::flood;
use daemon_network::lifecycle;
use daemon_network::metrics::Metrics;
use daemon_network::noise;
use daemon_network::ratelimit::bucket::TokenBucket;
use daemon_network::session::table::PeerTable;
use daemon_network::state::{DaemonState, InstallationIdentity};
use daemon_network::transport;

use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "daemon-network",
    about = "Open Sesame network transport daemon"
)]
struct Args {
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    core_types::init_secure_memory();
    init_tracing();

    // Single config load — network settings come from [network] in config.toml,
    // not a separate network.toml. config.toml is the single source of truth.
    let full_config = core_config::load_config(None).map_err(|e| {
        tracing::error!(error = %e, "failed to load config.toml");
        anyhow::anyhow!("config load failed: {e}")
    })?;
    let network_config = full_config.network.clone();
    let listen_port = args.port.unwrap_or(network_config.transport.listen_port);

    if !network_config.enabled {
        tracing::info!("daemon-network disabled in config (network.enabled = false)");
        notify_ready();
        idle_loop().await;
    }

    let default_profile = full_config.global.default_profile.to_string();
    if default_profile.is_empty() {
        return Err(anyhow::anyhow!(
            "default_profile is empty in config — cannot replicate without a profile name"
        ));
    }

    let (state, tcp_rx, repl_rx) = setup(listen_port, &network_config).await?;
    notify_ready();
    run_event_loop(
        state,
        tcp_rx,
        repl_rx,
        listen_port,
        &network_config,
        &default_profile,
    )
    .await
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn setup(
    listen_port: u16,
    config: &core_config::NetworkConfig,
) -> anyhow::Result<(
    DaemonState,
    tokio::sync::mpsc::Receiver<transport::tcp::TcpInbound>,
    tokio::sync::mpsc::Receiver<(String, String)>,
)> {
    daemon_network::sandbox::apply_network_sandbox();

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

    let tofu_path = config::tofu_db_path(config);
    let tofu_store = Arc::new(std::sync::Mutex::new(
        daemon_network::tofu::store::TofuStore::open(&tofu_path, &installation_id)
            .map_err(|e| anyhow::anyhow!("TOFU store: {e}"))?,
    ));

    let audit = Arc::new(
        AuditLog::open(&config::audit_log_path()).map_err(|e| anyhow::anyhow!("audit log: {e}"))?,
    );
    audit.append(
        "daemon_started",
        &format!("port={listen_port} install={installation_id}"),
    );

    let metrics = Arc::new(Metrics::new());
    let peer_table = Arc::new(PeerTable::new(config.session.max_concurrent_sessions));
    let cookie = Arc::new(std::sync::Mutex::new(
        daemon_network::flood::cookie::CookieChallenger::new(u64::from(
            config.flood.cookie_epoch_secs,
        )),
    ));
    let pow = Arc::new(std::sync::Mutex::new(flood::pow::PowChallenger::new()));
    let global_hs_limiter = Arc::new(TokenBucket::new(
        config.ratelimit.global_handshake_rate_per_sec,
        config.ratelimit.global_handshake_burst,
    ));

    let mut bus_client = control::bus::connect_to_bus()
        .await
        .map_err(|e| anyhow::anyhow!("IPC bus connect failed: {e}"))?;

    let local_keypair = if let Some((vault_private, _vault_public)) =
        control::bus::request_network_identity(&mut bus_client).await
    {
        let priv_array: &[u8; 32] = vault_private.as_slice().try_into().unwrap_or(&[0u8; 32]);
        let computed_pub = core_crypto::network::x25519_public_from_private(priv_array);
        if computed_pub != network_pubkey && network_pubkey != [0u8; 32] {
            tracing::warn!("vault private key does not match installation.toml network_pubkey_hex");
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

    let signing_seed: Option<zeroize::Zeroizing<[u8; 32]>> =
        match control::bus::request_secret(&mut bus_client, "_signing-seed").await {
            Some(seed_bytes) if seed_bytes.len() == 32 => {
                let mut seed = zeroize::Zeroizing::new([0u8; 32]);
                seed.copy_from_slice(&seed_bytes);
                let seed_secure = core_crypto::SecureBytes::from_slice(&*seed);
                match core_crypto::network::derive_signing_keypair(&seed_secure, &install_config.id)
                {
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
                tracing::warn!(
                    len = seed_bytes.len(),
                    "signing seed wrong length (expected 32)"
                );
                None
            }
            None => {
                tracing::info!("signing seed not available -- vault locked or not yet initialized");
                None
            }
        };

    let bus_client = Arc::new(tokio::sync::Mutex::new(bus_client));

    let udp_socket = Arc::new(
        transport::udp::bind_udp(listen_port)
            .await
            .map_err(|e| anyhow::anyhow!("UDP bind port {listen_port}: {e}"))?,
    );

    let (discovery_tx, discovery_rx) = tokio::sync::mpsc::channel(256);
    let discovery = Arc::new(daemon_discovery::manager::DiscoveryManager::new(
        1024,
        discovery_tx,
    ));

    let bootstrap_path = dirs::config_dir()
        .unwrap_or_default()
        .join("pds")
        .join("bootstrap.json");
    let gossip_hmac_key = match daemon_discovery::bootstrap::load_bootstrap(&bootstrap_path) {
        Ok(result) => {
            discovery.load_bootstrap(&result.targets);
            result.gossip_hmac_key
        }
        Err(e) => {
            tracing::warn!(error = %e, "bootstrap.json load failed");
            None
        }
    };

    let (tcp_tx, tcp_rx) = tokio::sync::mpsc::channel(256);
    let (repl_tx, repl_rx) = tokio::sync::mpsc::channel::<(String, String)>(4096);

    Ok((
        DaemonState {
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
            discovery_rx,
            listen_port,
            idle_timeout_secs: u64::from(config.session.idle_timeout_secs),
            rekey_interval_secs: 120,
            bep44_enabled: config.discovery.bep44.enabled,
            dns_srv_domains: Arc::new(std::sync::RwLock::new(
                config.discovery.dns_srv.domains.clone(),
            )),
            identity,
            signing_seed,
            tcp_tx,
            require_known_peers: config.tofu.require_known_peers,
            gossip_hmac_key,
            replication_watermarks: std::sync::Mutex::new(std::collections::HashMap::new()),
            replication_rate_limiter: std::sync::Mutex::new(std::collections::HashMap::new()),
            replication_inbound_tx: repl_tx,
        },
        tcp_rx,
        repl_rx,
    ))
}

// ---------------------------------------------------------------------------
// Event Loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn run_event_loop(
    mut state: DaemonState,
    mut tcp_rx: tokio::sync::mpsc::Receiver<transport::tcp::TcpInbound>,
    mut repl_rx: tokio::sync::mpsc::Receiver<(String, String)>,
    listen_port: u16,
    config: &core_config::NetworkConfig,
    default_profile: &str,
) -> anyhow::Result<()> {
    let (udp_tx, mut udp_rx) = tokio::sync::mpsc::channel::<transport::udp::UdpInbound>(4096);
    let udp_recv_socket = Arc::clone(&state.udp_socket);
    tokio::spawn(async move {
        transport::udp::udp_receive_loop(udp_recv_socket, udp_tx).await;
    });

    if config.transport.tcp_enabled {
        let tcp_tx_accept = state.tcp_tx.clone();
        let max_conn = config.transport.max_tcp_connections_per_address;
        let hs_timeout = config.session.handshake_timeout_secs;
        tokio::spawn(async move {
            if let Err(e) =
                transport::tcp::tcp_accept_loop(listen_port, tcp_tx_accept, max_conn, hs_timeout)
                    .await
            {
                tracing::error!(error = %e, "TCP accept loop failed");
            }
        });
    }

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

    spawn_discovery(&state, config);

    let (ipc_tx, mut ipc_rx) =
        tokio::sync::mpsc::channel::<core_ipc::Message<core_types::EventKind>>(64);
    let ipc_bus = Arc::clone(&state.bus_client);
    tokio::spawn(async move {
        loop {
            let msg = {
                let mut client = ipc_bus.lock().await;
                client.recv().await
            };
            match msg {
                Some(m) => {
                    if ipc_tx.send(m).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    });

    let mut watchdog_tick = tokio::time::interval(std::time::Duration::from_secs(15));
    let mut maintenance_tick = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut dial_tick = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut keepalive_tick = tokio::time::interval(std::time::Duration::from_mins(1));
    let mut replication_tick = tokio::time::interval(std::time::Duration::from_mins(1));

    loop {
        tokio::select! {
            Some(inbound) = udp_rx.recv() => {
                dispatch::udp::handle_udp_frame(&inbound, &state);
            }
            Some(tcp_event) = tcp_rx.recv() => {
                dispatch::tcp::handle_tcp_event(tcp_event, &state);
            }
            Some(disc_event) = state.discovery_rx.recv() => {
                dispatch::discovery::handle_discovery_event(disc_event, &state);
            }
            _ = dial_tick.tick() => {
                lifecycle::run_dial_queue(&state);
            }
            _ = keepalive_tick.tick() => {
                lifecycle::run_keepalives(&state);
            }
            Some(ipc_msg) = ipc_rx.recv() => {
                dispatch::ipc::handle_ipc_message(ipc_msg, &state).await;
            }
            Some((install_id, envelope_json)) = repl_rx.recv() => {
                // Forward received replication data to daemon-secrets via IPC.
                let peer_uuid = match uuid::Uuid::parse_str(&install_id) {
                    Ok(u) if !u.is_nil() => u,
                    _ => {
                        tracing::warn!(install_id, "dropping replication entry: peer installation ID is invalid or nil");
                        continue;
                    }
                };
                let client = state.bus_client.lock().await;
                let _ = client.publish(
                    core_types::EventKind::VaultLogEntryReceived {
                        peer_installation_id: peer_uuid,
                        entry_json: envelope_json,
                    },
                    core_types::SecurityLevel::Internal,
                ).await;
            }
            _ = replication_tick.tick() => {
                lifecycle::run_replication_pull(&state, default_profile).await;
            }
            _ = maintenance_tick.tick() => {
                lifecycle::run_maintenance(&state);
            }
            _ = watchdog_tick.tick() => {
                notify_watchdog();
                tracing::trace!(sessions = state.peer_table.len(), "watchdog");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery backend spawning
// ---------------------------------------------------------------------------

/// Timer entry for the SWIM gossip `BinaryHeap`.
///
/// `Ord` is reversed (`other.deadline.cmp(&self.deadline)`) so that
/// `std::collections::BinaryHeap` (a max-heap) yields the *earliest*
/// deadline first, giving min-heap behavior.
struct SwimTimerEntry {
    deadline: tokio::time::Instant,
    timer: foca::Timer<daemon_discovery::gossip::swim::PeerId>,
}
impl Eq for SwimTimerEntry {}
impl PartialEq for SwimTimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}
impl Ord for SwimTimerEntry {
    // Reversed for min-heap via std `BinaryHeap` (which is a max-heap).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.deadline.cmp(&self.deadline)
    }
}
impl PartialOrd for SwimTimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(clippy::too_many_lines)]
fn spawn_discovery(state: &DaemonState, config: &core_config::NetworkConfig) {
    let disc = &config.discovery;

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

                let s_announce = Arc::clone(&socket);
                let id_announce = install_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = daemon_discovery::mdns::announce::initial_announce(
                        &s_announce,
                        &pubkey,
                        &id_announce,
                        port,
                        None,
                        srv_ttl,
                        ptr_ttl,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "mDNS initial announce failed");
                    }
                });

                let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(64);
                let listen_config = daemon_discovery::mdns::listen::MdnsListenConfig {
                    our_pubkey: pubkey,
                    our_install_id: install_id,
                    our_port: port,
                    our_ipv4: None,
                    srv_ttl,
                    ptr_ttl,
                };
                let s_probe = Arc::clone(&socket);
                tokio::spawn(async move {
                    daemon_discovery::mdns::listen::mdns_listen_loop(
                        socket,
                        listen_config,
                        peer_tx,
                    )
                    .await;
                });

                // Active mDNS query probing: send PTR queries on startup and
                // periodically (every ptr_ttl seconds) to discover peers that
                // started before us or whose announcements we missed.
                tokio::spawn(async move {
                    // Initial probe — immediate.
                    let query = daemon_discovery::mdns::packet::DnsPacket::query(
                        daemon_discovery::mdns::announce::SERVICE_TYPE,
                    );
                    let _ =
                        daemon_discovery::mdns::announce::send_multicast(&s_probe, &query).await;
                    // Periodic probes.
                    let interval = std::time::Duration::from_secs(u64::from(ptr_ttl));
                    loop {
                        tokio::time::sleep(interval).await;
                        let q = daemon_discovery::mdns::packet::DnsPacket::query(
                            daemon_discovery::mdns::announce::SERVICE_TYPE,
                        );
                        let _ =
                            daemon_discovery::mdns::announce::send_multicast(&s_probe, &q).await;
                    }
                });

                tokio::spawn(async move {
                    while let Some(event) = peer_rx.recv().await {
                        match event {
                            daemon_discovery::mdns::listen::MdnsPeerEvent::Discovered(peer) => {
                                mgr.add_peer(
                                    peer.addr,
                                    daemon_discovery::queue::DiscoverySource::Mdns,
                                    Some(peer.pubkey_hex),
                                );
                            }
                            daemon_discovery::mdns::listen::MdnsPeerEvent::Goodbye { addr } => {
                                // Only remove from the dial queue — do NOT tear
                                // down active sessions. mDNS is unauthenticated
                                // (multicast UDP, any LAN device can forge a
                                // goodbye). Session teardown requires Noise-
                                // authenticated Close frame or idle timeout.
                                mgr.queue.remove(&addr);
                                tracing::info!(%addr, "mDNS goodbye — removed from dial queue");
                            }
                        }
                    }
                });

                tracing::info!("mDNS discovery started");
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS socket bind failed — LAN discovery disabled");
            }
        }
    }

    if disc.bep44.enabled {
        if let Some(seed) = state.signing_seed.as_deref() {
            let signing_key = mainline::SigningKey::from_bytes(seed);
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
                    &dht,
                    &signing_key,
                    &record,
                    1,
                )
                .await
                {
                    Ok(()) => tracing::info!("BEP-44 presence published to Mainline DHT"),
                    Err(e) => tracing::warn!(error = %e, "BEP-44 publish failed"),
                }
            });

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
                let mut consecutive_failures: u32 = 0;
                loop {
                    let pubkeys = tofu_resolve
                        .lock()
                        .ok()
                        .and_then(|s| s.pinned_pubkeys().ok())
                        .unwrap_or_default();
                    let mut any_success = false;
                    for key_hex in &pubkeys {
                        if let Ok(key_bytes) = hex::decode(key_hex)
                            && let Ok(pubkey) = <[u8; 32]>::try_from(key_bytes)
                            && let Some(peer) = daemon_discovery::bep44::resolve::resolve_presence(
                                &resolve_dht,
                                &pubkey,
                            )
                            .await
                        {
                            any_success = true;
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
                    if any_success || pubkeys.is_empty() {
                        consecutive_failures = 0;
                    } else {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                    }
                    let delay = std::cmp::min(300 * 2u64.pow(consecutive_failures), 1800);
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                }
            });
        } else {
            tracing::info!("BEP-44 skipped — signing seed not available");
        }
    }

    if disc.dns_srv.enabled && !disc.dns_srv.domains.is_empty() {
        let domains = Arc::clone(&state.dns_srv_domains);
        let interval = std::time::Duration::from_secs(u64::from(disc.dns_srv.min_refresh_secs));
        let mgr = Arc::clone(&state.discovery);

        tokio::spawn(async move {
            loop {
                // Read the current domain list (hot-reloadable via
                // NetworkDiscoveryReloadRequest).
                let current_domains = domains.read().map(|d| d.clone()).unwrap_or_default();
                for domain in &current_domains {
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

    // SWIM gossip: only enabled when a shared gossip_secret is configured
    // in bootstrap.json. Unauthenticated gossip is not permitted — an
    // attacker on the network could inject MemberUp/MemberDown events to
    // poison the membership list. Generate a key with `sesame network keygen`.
    let Some(gossip_hmac_key) = state.gossip_hmac_key else {
        tracing::info!(
            "SWIM gossip disabled — no gossip_secret in bootstrap.json. \
             Generate one with: sesame network keygen"
        );
        return;
    };
    let gossip_port = config.transport.gossip_port;
    let pubkey_prefix = hex::encode(&state.local_keypair.public[..8]);
    let gossip_addr: std::net::SocketAddr = format!("[::]:{gossip_port}").parse().unwrap();

    let mgr_swim = Arc::clone(&state.discovery);
    tokio::spawn(async move {
        use foca::Identity as _;
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
        let mut swim = daemon_discovery::gossip::runtime::new_swim(identity.clone(), swim_config);
        let mut runtime = daemon_discovery::gossip::runtime::AccumulatingRuntime::new();

        // Seed SWIM with known peers from the dial queue so probing starts
        // immediately instead of waiting for inbound gossip.
        for entry in mgr_swim.queue.snapshot_addrs() {
            let seed_id = daemon_discovery::gossip::swim::PeerId {
                addr: entry,
                generation: 0,
                key_prefix: String::new(),
            };
            let _ = swim.announce(seed_id, &mut runtime);
        }

        let mut pending_timers: std::collections::BinaryHeap<SwimTimerEntry> =
            std::collections::BinaryHeap::new();

        let mut buf = vec![0u8; 65535];
        loop {
            let next_deadline = pending_timers.peek().map_or_else(
                || tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                |e| e.deadline,
            );

            tokio::select! {
                result = gossip_socket.recv_from(&mut buf) => {
                    if let Ok((len, _src)) = result {
                        // Verify HMAC-BLAKE3 tag (last 32 bytes).
                        if len < 32 {
                            continue; // Too short — no HMAC tag.
                        }
                        let payload_len = len - 32;
                        let received_tag = &buf[payload_len..len];
                        let expected_tag = blake3::keyed_hash(
                            &gossip_hmac_key,
                            &buf[..payload_len],
                        );
                        if received_tag != expected_tag.as_bytes() {
                            tracing::trace!("SWIM gossip: dropped unauthenticated packet");
                            continue;
                        }
                        let _ = swim.handle_data(&buf[..payload_len], &mut runtime);
                    }
                }
                () = tokio::time::sleep_until(next_deadline) => {
                    let now = tokio::time::Instant::now();
                    while let Some(entry) = pending_timers.peek() {
                        if entry.deadline > now { break; }
                        let entry = pending_timers.pop().unwrap();
                        let _ = swim.handle_timer(entry.timer, &mut runtime);
                    }
                }
            }

            while let Some((dest, data)) = runtime.to_send() {
                // Append HMAC-BLAKE3 tag to outgoing gossip packets.
                let tag = blake3::keyed_hash(&gossip_hmac_key, &data);
                let mut tagged = Vec::with_capacity(data.len() + 32);
                tagged.extend_from_slice(&data);
                tagged.extend_from_slice(tag.as_bytes());
                let _ = gossip_socket.send_to(&tagged, dest.addr()).await;
            }
            while let Some((delay, timer)) = runtime.to_schedule() {
                let deadline = tokio::time::Instant::now() + delay;
                pending_timers.push(SwimTimerEntry { deadline, timer });
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
                        // Only remove from the dial queue — do NOT tear down
                        // active sessions. SWIM gossip is unauthenticated (raw
                        // UDP, no Noise encryption), so a spoofed MemberDown
                        // must not be able to close an authenticated session.
                        // Session teardown happens only through the Noise-
                        // authenticated transport: Close frame, idle timeout,
                        // or rekey sweep.
                        mgr_swim.queue.remove(&peer.addr);
                    }
                    _ => {}
                }
            }
        }
    });
    tracing::info!(port = gossip_port, "SWIM gossip started");
}

// ---------------------------------------------------------------------------
// Platform helpers
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
