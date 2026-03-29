//! daemon-profile: The bus server and profile orchestrator.
//!
//! Central daemon responsibilities:
//! 1. Hosts the IPC bus server (all inter-daemon communication routes through here)
//! 2. Runs the context engine for default profile selection
//! 3. Executes profile activation/deactivation transactions (atomic, with rollback)
//! 4. Manages the hash-chained audit log
//! 5. Handles systemd/launchd readiness and watchdog
//!
//! Multiple profiles may be active concurrently. The context engine determines
//! the default profile for new unscoped launches — changing the default does
//! NOT deactivate other active profiles.
//!
//! Landlock: config (read/write for audit), runtime dir (read/write/socket)
//! No network access beyond local IPC.

mod activation;
mod context;
mod dispatch;
mod key_rotation;
mod sandbox;

use anyhow::Context;
use clap::Parser;
use core_ipc::Message;
use core_ipc::{BusServer, ClearanceRegistry};
use core_profile::{AuditAction, AuditLogger, ContextEngine, ContextSignal};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};

/// Known daemons and their security clearance levels.
const KNOWN_DAEMONS: &[(&str, SecurityLevel)] = &[
    ("daemon-secrets", SecurityLevel::SecretsOnly),
    ("daemon-wm", SecurityLevel::Internal),
    ("daemon-launcher", SecurityLevel::Internal),
    ("daemon-clipboard", SecurityLevel::Internal),
    ("daemon-input", SecurityLevel::Internal),
    ("daemon-snippets", SecurityLevel::Internal),
];
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tokio::sync::mpsc;

/// Key rotation interval. Default: 1 hour.
const KEY_ROTATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Grace period (seconds) for daemons to reconnect with new keys after rotation.
const KEY_ROTATION_GRACE: u32 = 30;

/// Level 0 namespace seed. Never use directly for ProfileId derivation — use install_ns instead.
#[allow(dead_code)]
const PROFILE_NS: uuid::Uuid = core_types::PROFILE_NAMESPACE;

/// Tracks which `DaemonId` is associated with each daemon name.
/// Detects crash-restarts when a new `DaemonStarted` arrives for an already-registered name.
pub(crate) struct DaemonTracker {
    /// daemon_name -> last known `DaemonId`
    known: HashMap<String, DaemonId>,
}

impl DaemonTracker {
    fn new() -> Self {
        Self {
            known: HashMap::new(),
        }
    }

    /// Register or detect restart. Returns `Some(old_id)` if this is a restart.
    pub(crate) fn track(&mut self, name: &str, new_id: DaemonId) -> Option<DaemonId> {
        if let Some(&old_id) = self.known.get(name)
            && old_id != new_id
        {
            self.known.insert(name.to_owned(), new_id);
            return Some(old_id);
        }
        self.known.insert(name.to_owned(), new_id);
        None
    }
}

/// PDS profile orchestrator daemon.
#[derive(Parser, Debug)]
#[command(
    name = "daemon-profile",
    about = "PDS profile orchestrator and IPC bus server"
)]
struct Cli {
    /// Config directory override.
    #[arg(long, env = "PDS_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    /// Log format: "json" or "pretty".
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // -- Logging --
    sandbox::init_logging(&cli.log_format)?;

    tracing::info!("daemon-profile starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 4096,
        memlock_bytes: 0,
    });

    // -- Directory bootstrap --
    core_config::bootstrap_dirs();

    // -- Config --
    let config = core_config::load_config(None).context("failed to load config")?;

    // Probe memfd_secret and initialize secure memory BEFORE sandbox.
    core_types::init_secure_memory();

    // -- Sandbox (Linux) --
    // apply_sandbox() ensures all Landlock target directories exist before
    // opening PathFd handles. This handles the post-wipe restart case where
    // systemd restarts daemon-profile before `sesame init` recreates dirs.
    #[cfg(target_os = "linux")]
    sandbox::apply_sandbox()?;

    // -- IPC bus server: generate Noise IK keypair and bind the Unix socket --
    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;
    let bus_keypair =
        core_ipc::generate_keypair().context("failed to generate bus Noise IK keypair")?;
    core_ipc::noise::write_bus_keypair(bus_keypair.as_inner())
        .await
        .context("failed to write bus public key")?;

    // -- Per-daemon keypair generation and clearance registry --
    core_ipc::noise::create_keys_dir()
        .await
        .context("failed to create keys directory")?;

    let mut registry = ClearanceRegistry::new();
    let noise_params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("valid noise params");
    let builder = snow::Builder::new(noise_params);

    for &(daemon_name, security_level) in KNOWN_DAEMONS {
        let keypair = core_ipc::ZeroizingKeypair::new(
            builder
                .generate_keypair()
                .context(format!("failed to generate keypair for {daemon_name}"))?,
        );

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(keypair.public());

        core_ipc::noise::write_daemon_keypair(daemon_name, keypair.as_inner())
            .await
            .context(format!("failed to write keypair for {daemon_name}"))?;

        registry.register(pubkey, daemon_name.into(), security_level);

        tracing::info!(
            daemon = daemon_name,
            clearance = ?security_level,
            "generated and registered keypair"
        );
    }

    let bus = BusServer::bind(&socket_path, bus_keypair.into_inner(), registry)
        .context("failed to bind IPC bus server")?;
    tracing::info!(path = %socket_path.display(), "IPC bus server bound (Noise IK encrypted)");

    // -- Platform readiness (early): tell systemd we are alive before blocking on installation.toml --
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    // -- Wait for installation.toml (may not exist yet on fresh multi-user VMs) --
    let install_config = if let Ok(cfg) = core_config::load_installation() {
        cfg
    } else {
        tracing::info!("waiting for sesame init — installation.toml not found");
        let mut poll_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut watchdog_interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = poll_interval.tick() => {
                    if let Ok(cfg) = core_config::load_installation() {
                        tracing::info!("installation.toml found, transitioning to full mode");
                        break cfg;
                    }
                }
                _ = watchdog_interval.tick() => {
                    #[cfg(target_os = "linux")]
                    platform_linux::systemd::notify_watchdog();
                }
                result = bus.run() => {
                    match result {
                        Ok(()) => tracing::info!("bus server exited while waiting for init"),
                        Err(e) => tracing::error!(error = %e, "bus server error while waiting for init"),
                    }
                    return Ok(());
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("SIGINT received while waiting for installation.toml");
                    return Ok(());
                }
                _ = sandbox::sigterm() => {
                    tracing::info!("SIGTERM received while waiting for installation.toml");
                    return Ok(());
                }
            }
        }
    };
    let install_ns = install_config.namespace;

    let mut default_profile_name: TrustProfileName = config.global.default_profile.clone();
    let mut config_profile_names: Vec<TrustProfileName> = config
        .profiles
        .keys()
        .filter_map(|name| TrustProfileName::try_from(name.as_str()).ok())
        .collect();
    tracing::info!(default_profile = %default_profile_name, "config loaded");

    // -- Default agent identity (needed by audit logger) --
    let uid = rustix::process::getuid().as_raw();
    let default_agent_id = core_types::AgentId::from_uuid(uuid::Uuid::new_v5(
        &install_ns,
        format!("agent:human:uid{uid}").as_bytes(),
    ));

    // -- Audit logger --
    let audit_path = core_config::config_dir().join("audit.jsonl");
    let (last_hash, sequence) = context::load_audit_state(&audit_path);
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .context("failed to open audit log")?;
    let audit_writer = std::io::BufWriter::new(audit_file);
    let mut audit = AuditLogger::new(
        audit_writer,
        last_hash,
        sequence,
        core_types::AuditHash::Blake3,
        Some(default_agent_id),
    );
    tracing::info!(
        path = %audit_path.display(),
        sequence = audit.sequence(),
        "audit logger initialized"
    );

    // -- Verify audit chain on startup if log exists --
    if sequence > 0 {
        match context::verify_audit_chain(&audit_path) {
            Ok(count) => tracing::info!(entries = count, "audit chain verified"),
            Err(e) => tracing::error!(error = %e, "audit chain verification FAILED"),
        }
    }

    // -- Context engine --
    let default_id = core_types::ProfileId::from_uuid(uuid::Uuid::new_v5(
        &install_ns,
        format!("profile:{}", default_profile_name).as_bytes(),
    ));
    let profiles = context::build_activation_rules(&config, default_id, &install_ns);
    let mut context_engine = ContextEngine::new(profiles, default_id);
    tracing::info!(
        profile = %default_id,
        "context engine initialized with default profile"
    );

    // -- Active profiles set (concurrent) --
    let mut active_profiles: HashSet<TrustProfileName> = HashSet::new();

    // -- Lock state: tracks daemon-secrets lock/unlock (S-4) --
    let mut locked = true;

    // -- Confirmed RPC channel --
    // Used by activation/deactivation/reconciliation to wait for daemon-secrets responses.
    let (confirm_tx, mut confirm_rx) = mpsc::channel::<Vec<u8>>(16);

    // -- Register daemon-profile as an in-process bus subscriber --
    // This lets daemon-profile receive and process messages (StatusRequest,
    // ProfileActivate, ProfileList, etc.) that clients send to the bus.
    let daemon_id = DaemonId::new();

    // Build default AgentIdentity representing the human operator.
    let installation_id = core_types::InstallationId {
        id: install_config.id,
        org_ns: None,
        namespace: install_ns,
        machine_binding: None,
    };

    let _default_agent = core_types::AgentIdentity {
        id: default_agent_id,
        agent_type: core_types::AgentType::Human,
        local_id: core_types::LocalAgentId::UnixUid(uid),
        installation: installation_id.clone(),
        attestations: vec![],
        session_scope: core_types::CapabilitySet::all(),
        delegation_chain: vec![],
    };

    let msg_ctx = core_ipc::MessageContext {
        sender: daemon_id,
        installation: Some(installation_id),
        agent_id: Some(default_agent_id),
        trust_snapshot: None,
    };
    let (host_tx, mut host_rx) = mpsc::channel::<Vec<u8>>(256);
    let host_peer = core_ipc::PeerCredentials::in_process();
    bus.register(
        daemon_id,
        host_peer,
        SecurityLevel::Internal, // host handles StatusRequest/ProfileList — not secrets
        vec![],
        host_tx,
    )
    .await;

    // -- Context signal sources --
    let (ctx_tx, mut ctx_rx) = mpsc::channel::<ContextSignal>(64);
    let _ctx_tx = &ctx_tx; // suppress unused warning in headless builds

    // SSID monitor (Linux desktop only): spawns a long-lived task that sends
    // SsidChanged signals when the WiFi network changes.
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    {
        let ssid_tx = ctx_tx.clone();
        tokio::spawn(async move {
            let (ssid_raw_tx, mut ssid_raw_rx) = mpsc::channel::<String>(16);
            tokio::spawn(platform_linux::dbus::ssid_monitor(ssid_raw_tx));
            while let Some(ssid) = ssid_raw_rx.recv().await {
                if ssid_tx
                    .send(ContextSignal::SsidChanged(ssid))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        tracing::info!("SSID monitor spawned");
    }

    // Focused app monitor (Linux desktop only): spawns a long-lived task that sends
    // AppFocused signals when the Wayland compositor focus changes.
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    {
        let focus_tx = ctx_tx.clone();
        tokio::spawn(async move {
            use platform_linux::compositor::FocusEvent;
            let (focus_raw_tx, mut focus_raw_rx) = mpsc::channel::<FocusEvent>(16);
            tokio::spawn(platform_linux::compositor::focus_monitor(focus_raw_tx));
            while let Some(event) = focus_raw_rx.recv().await {
                let FocusEvent::Focus(app_id) = event else {
                    continue;
                };
                if focus_tx
                    .send(ContextSignal::AppFocused(core_types::AppId::new(app_id)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        tracing::info!("focus monitor spawned");
    }

    // -- Config watcher (hot-reload) --
    let config_paths = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = mpsc::channel::<()>(4);
    let reload_notify_tx = reload_tx;
    let (_watcher, live_config) = core_config::ConfigWatcher::with_callback(
        &config_paths,
        config,
        Some(Box::new(move || {
            // notify thread -> tokio: blocking_send not available without tokio handle,
            // but try_send is fine — bounded(4) absorbs bursts, we only need "at least once".
            let _ = reload_notify_tx.try_send(());
        })),
    )
    .context("failed to start config watcher")?;

    tracing::info!("daemon-profile ready");

    // -- Watchdog timer: half the WatchdogSec=30 interval --
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // -- Reconciliation counter: reconcile every other watchdog tick (30s) --
    let mut watchdog_tick_count: u64 = 0;

    // -- Key rotation timer --
    let mut rotation_timer = tokio::time::interval(KEY_ROTATION_INTERVAL);
    rotation_timer.tick().await; // Consume the first immediate tick.

    // Non-blocking rotation — grace period runs in a spawned task,
    // completion signaled via channel so the main select! loop stays responsive.
    let (rotation_done_tx, mut rotation_done_rx) = mpsc::channel::<()>(1);

    // -- Daemon crash-restart tracker --
    let mut daemon_tracker = DaemonTracker::new();

    // -- Main event loop --
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();

                // Reconcile with daemon-secrets every 30s (every other tick).
                watchdog_tick_count += 1;
                if watchdog_tick_count <= 3 || watchdog_tick_count.is_multiple_of(20) {
                    tracing::info!(watchdog_tick_count, "watchdog tick");
                }
                if watchdog_tick_count.is_multiple_of(2) {
                    dispatch::reconcile_secrets_state(
                        &bus,
                        daemon_id,
                        &mut locked,
                        &mut active_profiles,
                        &confirm_tx,
                        &mut confirm_rx,
                    ).await;
                }
            }
            _ = rotation_timer.tick() => {
                // Phase 1: generate keypairs, write to disk, announce pending.
                // Returns immediately — does NOT block the event loop.
                if let Err(e) = key_rotation::rotate_keys_phase1(&bus, daemon_id, &mut audit).await {
                    tracing::error!(error = %e, "key rotation phase 1 failed");
                } else {
                    // Schedule phase 2 after grace period in a background task.
                    let tx = rotation_done_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(u64::from(KEY_ROTATION_GRACE))).await;
                        let _ = tx.send(()).await;
                    });
                }
            }
            Some(()) = rotation_done_rx.recv() => {
                // Phase 2: atomic registry swap + announce completion.
                if let Err(e) = key_rotation::rotate_keys_phase2(&bus, daemon_id, &mut audit).await {
                    tracing::error!(error = %e, "key rotation phase 2 failed");
                }
            }
            result = bus.run() => {
                match result {
                    Ok(()) => tracing::info!("bus server exited cleanly"),
                    Err(e) => tracing::error!(error = %e, "bus server error"),
                }
                break;
            }
            Some(frame) = host_rx.recv() => {
                let msg: Message<EventKind> = match core_ipc::decode_frame(&frame) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, "malformed frame on host channel");
                        continue;
                    }
                };

                // Skip messages we sent ourselves. bus.publish() delivers to ALL
                // connections including our own host channel. Without this guard,
                // activation::activate() broadcasting ProfileActivate creates an
                // infinite feedback loop (daemon-profile re-processes its own broadcast).
                if msg.sender == daemon_id {
                    continue;
                }

                if let Some(response_event) = dispatch::handle_bus_message(
                    &msg,
                    &mut active_profiles,
                    &mut context_engine,
                    &mut audit,
                    &mut default_profile_name,
                    daemon_id,
                    &bus,
                    &mut daemon_tracker,
                    &mut locked,
                    &confirm_tx,
                    &mut confirm_rx,
                    &config_profile_names,
                    &install_ns,
                ).await {
                    let reply = Message::new(
                        &msg_ctx,
                        response_event,
                        msg.security_level,
                        bus.epoch(),
                    ).with_correlation(msg.msg_id);

                    if let Ok(mut reply_bytes) = core_ipc::encode_frame(&reply) {
                        // Unicast RPC responses to the original requester only.
                        // bus.publish() would broadcast to ALL connected daemons, leaking
                        // secret values (e.g., SecretGetResponse) to non-requesting clients.
                        if let Some(origin_conn) = bus.take_pending_request(&msg.msg_id).await {
                            if !bus.send_to(origin_conn, &reply_bytes).await {
                                tracing::warn!(
                                    conn_id = origin_conn,
                                    msg_id = %msg.msg_id,
                                    "unicast response failed: connection gone or channel full"
                                );
                            }
                        } else {
                            // No pending request found. NEVER broadcast -- the response
                            // could contain secret values (SecretGetResponse, UnlockResponse).
                            // Dropping is safe: the requester's RPC call will time out.
                            tracing::error!(
                                msg_id = %msg.msg_id,
                                "response has no tracked origin -- dropping to prevent potential secret broadcast"
                            );
                        }
                        // Zeroize postcard buffer — may contain serialized secret values.
                        zeroize::Zeroize::zeroize(&mut reply_bytes);
                    }
                }
            }
            Some(signal) = ctx_rx.recv() => {
                let previous = context_engine.default_profile();
                if let Some(new_default) = context_engine.evaluate(&signal)
                    && new_default != previous
                {
                    tracing::info!(
                        previous = %previous,
                        new_default = %new_default,
                        signal = ?signal,
                        "default profile changed by context engine"
                    );

                    // Audit the default profile change.
                    if let Err(e) = audit.append(AuditAction::DefaultProfileChanged {
                        previous,
                        current: new_default,
                    }) {
                        tracing::error!(error = %e, "failed to write default profile change audit entry");
                    }

                    // Broadcast the change on the bus.
                    let event = EventKind::DefaultProfileChanged {
                        previous,
                        current: new_default,
                    };
                    let msg = Message::new(&msg_ctx, event, SecurityLevel::Internal, bus.epoch());
                    if let Ok(payload) = core_ipc::encode_frame(&msg) {
                        bus.publish(&payload, SecurityLevel::Internal).await;
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                tracing::info!("config reload detected, rebuilding context engine rules");
                if let Ok(guard) = live_config.read() {
                    let new_default_name: TrustProfileName = guard.global.default_profile.clone();
                    let new_default_id = core_types::ProfileId::from_uuid(
                        uuid::Uuid::new_v5(&install_ns, format!("profile:{}", new_default_name).as_bytes()),
                    );
                    let new_rules = context::build_activation_rules(&guard, new_default_id, &install_ns);
                    context_engine = ContextEngine::new(new_rules, new_default_id);
                    // Update the default_profile_name used by RPC handlers.
                    default_profile_name = new_default_name;
                    // Refresh config_profile_names on hot-reload so
                    // `sesame profile list` reflects newly added/removed profiles.
                    config_profile_names = guard
                        .profiles
                        .keys()
                        .filter_map(|name| TrustProfileName::try_from(name.as_str()).ok())
                        .collect();
                    tracing::info!(
                        default_profile = %default_profile_name,
                        "context engine rebuilt from reloaded config"
                    );
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received");
                break;
            }
            _ = sandbox::sigterm() => {
                tracing::info!("SIGTERM received");
                break;
            }
        }
    }

    // -- Shutdown --
    tracing::info!(
        active_profiles = active_profiles.len(),
        audit_sequence = audit.sequence(),
        "daemon-profile shutting down"
    );

    Ok(())
}
