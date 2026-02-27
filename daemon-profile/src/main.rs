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

use anyhow::Context;
use clap::Parser;
use core_ipc::{BusServer, ClearanceRegistry};
use core_profile::{
    AuditAction, AuditLogger, ContextEngine, ContextSignal,
    context::{ProfileActivation, RuleCombinator},
};
use core_ipc::Message;
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};

/// Known daemons and their security clearance levels (IA-9, AC-4, CM-7).
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

/// Key rotation interval (NIST IA-5(1), SC-12). Default: 1 hour.
const KEY_ROTATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Grace period (seconds) for daemons to reconnect with new keys after rotation.
const KEY_ROTATION_GRACE: u32 = 30;

/// Tracks which `DaemonId` is associated with each daemon name (H-019).
/// Detects crash-restarts when a new `DaemonStarted` arrives for an already-registered name.
struct DaemonTracker {
    /// daemon_name -> last known `DaemonId`
    known: HashMap<String, DaemonId>,
}

impl DaemonTracker {
    fn new() -> Self {
        Self { known: HashMap::new() }
    }

    /// Register or detect restart. Returns `Some(old_id)` if this is a restart.
    fn track(&mut self, name: &str, new_id: DaemonId) -> Option<DaemonId> {
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
#[command(name = "daemon-profile", about = "PDS profile orchestrator and IPC bus server")]
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
    init_logging(&cli.log_format)?;

    tracing::info!("daemon-profile starting");

    // -- Process hardening (NIST SC-4, SI-11) --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    // -- Config --
    let config = core_config::load_config(None)
        .context("failed to load config")?;

    let mut default_profile_name: TrustProfileName = config.global.default_profile.clone();
    tracing::info!(default_profile = %default_profile_name, "config loaded");

    // -- Sandbox (Linux) --
    // apply_sandbox() ensures all Landlock target directories exist before
    // opening PathFd handles. This handles the post-wipe restart case where
    // systemd restarts daemon-profile before `sesame init` recreates dirs.
    #[cfg(target_os = "linux")]
    apply_sandbox()?;

    // -- IPC bus server: generate Noise IK keypair and bind the Unix socket --
    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;
    let bus_keypair = core_ipc::generate_keypair()
        .context("failed to generate bus Noise IK keypair")?;
    core_ipc::noise::write_bus_keypair(bus_keypair.as_inner()).await
        .context("failed to write bus public key")?;

    // -- Per-daemon keypair generation and clearance registry (IA-9, AC-4) --
    core_ipc::noise::create_keys_dir().await
        .context("failed to create keys directory")?;

    let mut registry = ClearanceRegistry::new();
    let noise_params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("valid noise params");
    let builder = snow::Builder::new(noise_params);

    for &(daemon_name, security_level) in KNOWN_DAEMONS {
        let keypair = core_ipc::ZeroizingKeypair::new(builder
            .generate_keypair()
            .context(format!("failed to generate keypair for {daemon_name}"))?);

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

    // -- Audit logger --
    let audit_path = core_config::config_dir().join("audit.jsonl");
    let (last_hash, sequence) = load_audit_state(&audit_path);
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .context("failed to open audit log")?;
    let audit_writer = std::io::BufWriter::new(audit_file);
    let mut audit = AuditLogger::new(audit_writer, last_hash, sequence);
    tracing::info!(
        path = %audit_path.display(),
        sequence = audit.sequence(),
        "audit logger initialized"
    );

    // -- Verify audit chain on startup if log exists --
    if sequence > 0 {
        match verify_audit_chain(&audit_path) {
            Ok(count) => tracing::info!(entries = count, "audit chain verified"),
            Err(e) => tracing::error!(error = %e, "audit chain verification FAILED"),
        }
    }

    // -- Context engine --
    let default_id = core_types::ProfileId::new();
    let profiles = build_activation_rules(&config, default_id);
    let mut context_engine = ContextEngine::new(profiles, default_id);
    tracing::info!(
        profile = %default_id,
        "context engine initialized with default profile"
    );

    // -- Active profiles set (concurrent) --
    let mut active_profiles: HashSet<TrustProfileName> = HashSet::new();

    // -- Lock state: tracks daemon-secrets lock/unlock (S-4) --
    let mut locked = true;

    // -- Register daemon-profile as an in-process bus subscriber --
    // This lets daemon-profile receive and process messages (StatusRequest,
    // ProfileActivate, ProfileList, etc.) that clients send to the bus.
    let daemon_id = DaemonId::new();
    let (host_tx, mut host_rx) = mpsc::channel::<Vec<u8>>(256);
    let host_peer = core_ipc::PeerCredentials::in_process();
    bus.register(
        daemon_id,
        host_peer,
        SecurityLevel::Internal, // host handles StatusRequest/ProfileList — not secrets (CM-7)
        vec![],
        host_tx,
    ).await;

    // -- Context signal sources --
    let (ctx_tx, mut ctx_rx) = mpsc::channel::<ContextSignal>(64);

    // SSID monitor (Linux only): spawns a long-lived task that sends
    // SsidChanged signals when the WiFi network changes.
    #[cfg(target_os = "linux")]
    {
        let ssid_tx = ctx_tx.clone();
        tokio::spawn(async move {
            let (ssid_raw_tx, mut ssid_raw_rx) = mpsc::channel::<String>(16);
            tokio::spawn(platform_linux::dbus::ssid_monitor(ssid_raw_tx));
            while let Some(ssid) = ssid_raw_rx.recv().await {
                if ssid_tx.send(ContextSignal::SsidChanged(ssid)).await.is_err() {
                    break;
                }
            }
        });
        tracing::info!("SSID monitor spawned");
    }

    // Focused app monitor (Linux only): spawns a long-lived task that sends
    // AppFocused signals when the Wayland compositor focus changes.
    #[cfg(target_os = "linux")]
    {
        let focus_tx = ctx_tx.clone();
        tokio::spawn(async move {
            use platform_linux::compositor::FocusEvent;
            let (focus_raw_tx, mut focus_raw_rx) = mpsc::channel::<FocusEvent>(16);
            tokio::spawn(platform_linux::compositor::focus_monitor(focus_raw_tx));
            while let Some(event) = focus_raw_rx.recv().await {
                let FocusEvent::Focus(app_id) = event else { continue };
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

    // -- Platform readiness --
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-profile ready");

    // -- Watchdog timer: half the WatchdogSec=30 interval --
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // -- Key rotation timer (H-018, NIST IA-5(1), SC-12) --
    let mut rotation_timer = tokio::time::interval(KEY_ROTATION_INTERVAL);
    rotation_timer.tick().await; // Consume the first immediate tick.

    // R-001: Non-blocking rotation — grace period runs in a spawned task,
    // completion signaled via channel so the main select! loop stays responsive.
    let (rotation_done_tx, mut rotation_done_rx) = mpsc::channel::<()>(1);

    // -- Daemon crash-restart tracker (H-019) --
    let mut daemon_tracker = DaemonTracker::new();

    // -- Main event loop --
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            _ = rotation_timer.tick() => {
                // Phase 1: generate keypairs, write to disk, announce pending.
                // Returns immediately — does NOT block the event loop.
                if let Err(e) = rotate_keys_phase1(&bus, daemon_id, &mut audit).await {
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
                if let Err(e) = rotate_keys_phase2(&bus, daemon_id, &mut audit).await {
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

                if let Some(response_event) = handle_bus_message(
                    &msg,
                    &mut active_profiles,
                    &mut context_engine,
                    &mut audit,
                    &mut default_profile_name,
                    daemon_id,
                    &bus,
                    &mut daemon_tracker,
                    &mut locked,
                ).await {
                    let reply = Message::new(
                        daemon_id,
                        response_event,
                        msg.security_level,
                        bus.epoch(),
                    ).with_correlation(msg.msg_id);

                    if let Ok(mut reply_bytes) = core_ipc::encode_frame(&reply) {
                        // M11 fix: unicast RPC responses to the original requester only.
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
                        // Zeroize postcard buffer — may contain serialized secret values (H-009).
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
                    let msg = Message::new(daemon_id, event, SecurityLevel::Internal, bus.epoch());
                    if let Ok(payload) = core_ipc::encode_frame(&msg) {
                        bus.publish(&payload, SecurityLevel::Internal).await;
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                tracing::info!("config reload detected, rebuilding context engine rules");
                if let Ok(guard) = live_config.read() {
                    let new_default_name: TrustProfileName = guard.global.default_profile.clone();
                    let new_default_id = core_types::ProfileId::new();
                    let new_rules = build_activation_rules(&guard, new_default_id);
                    context_engine = ContextEngine::new(new_rules, new_default_id);
                    // Update the default_profile_name used by RPC handlers.
                    default_profile_name = new_default_name;
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
            _ = sigterm() => {
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

/// Handle a message received on the bus that daemon-profile is responsible for.
///
/// Returns `Some(response_event)` for RPC requests, `None` for broadcast events.
#[allow(clippy::too_many_arguments)]
async fn handle_bus_message<W: std::io::Write>(
    msg: &Message<EventKind>,
    active_profiles: &mut HashSet<TrustProfileName>,
    _context_engine: &mut ContextEngine,
    audit: &mut AuditLogger<W>,
    default_profile_name: &mut TrustProfileName,
    daemon_id: DaemonId,
    bus: &BusServer,
    daemon_tracker: &mut DaemonTracker,
    locked: &mut bool,
) -> Option<EventKind> {
    match &msg.payload {
        // H-019: Track daemon start/restart for key revocation.
        EventKind::DaemonStarted { daemon_id: announced_id, capabilities, .. } => {
            // R-008: Use server-verified name from Noise IK registry, not self-declared
            // capabilities. Fall back to capabilities only for unregistered clients.
            let name = msg.verified_sender_name.clone()
                .or_else(|| capabilities.first().cloned())
                .unwrap_or_else(|| "unknown".into());
            if let Some(old_id) = daemon_tracker.track(&name, *announced_id) {
                tracing::warn!(
                    audit = "security",
                    event_type = "daemon-restart-detected",
                    daemon_name = %name,
                    old_id = %old_id,
                    new_id = %announced_id,
                    "daemon restart detected — revoking old key and generating new keypair"
                );

                // Find the KNOWN_DAEMONS entry for this name.
                if let Some(&(daemon_name, security_level)) = KNOWN_DAEMONS.iter()
                    .find(|(n, _)| *n == name)
                {
                    // Revoke old key, generate and register new one.
                    let noise_params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
                        .parse()
                        .expect("valid noise params");
                    let builder = snow::Builder::new(noise_params);
                    match builder.generate_keypair() {
                        Ok(raw_keypair) => {
                            let new_keypair = core_ipc::ZeroizingKeypair::new(raw_keypair);
                            let mut new_pubkey = [0u8; 32];
                            new_pubkey.copy_from_slice(new_keypair.public());

                            // Write new keypair to disk.
                            if let Err(e) = core_ipc::noise::write_daemon_keypair(daemon_name, new_keypair.as_inner()).await {
                                tracing::error!(error = %e, daemon = daemon_name, "failed to write revocation keypair");
                            } else {
                                // Revoke old key, re-register with incremented generation (P0).
                                let mut reg = bus.registry_mut().await;
                                let next_gen = if let Some((old_key, _)) = reg.find_by_name(daemon_name) {
                                    let old_key = *old_key;
                                    let old_entry = reg.revoke(&old_key);
                                    old_entry.map_or(0, |e| e.generation + 1)
                                } else {
                                    0
                                };
                                reg.register_with_generation(
                                    new_pubkey, daemon_name.into(), security_level, next_gen,
                                );
                                drop(reg); // Release lock before I/O.
                                tracing::info!(
                                    audit = "security",
                                    event_type = "key-revocation",
                                    daemon = daemon_name,
                                    generation = next_gen,
                                    "old key revoked, new key registered"
                                );
                                let _ = audit.append(AuditAction::KeyRevoked {
                                    daemon_name: daemon_name.into(),
                                    reason: "crash-restart-detected".into(),
                                    generation: next_gen,
                                });

                                // R-003: Announce KeyRotationPending to the restarted daemon
                                // so it reconnects with the new key. Without this, the daemon
                                // would use its old (revoked) key and fail handshake.
                                let rotation_event = EventKind::KeyRotationPending {
                                    daemon_name: daemon_name.into(),
                                    new_pubkey,
                                    grace_period_s: KEY_ROTATION_GRACE,
                                };
                                let rotation_msg = Message::new(
                                    daemon_id, rotation_event,
                                    SecurityLevel::Internal, bus.epoch(),
                                );
                                if let Ok(payload) = core_ipc::encode_frame(&rotation_msg) {
                                    bus.publish(&payload, SecurityLevel::Internal).await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, daemon = daemon_name, "failed to generate revocation keypair");
                        }
                    }
                }
            }
            None
        }

        EventKind::StatusRequest => {
            let profiles: Vec<TrustProfileName> = active_profiles.iter().cloned().collect();
            Some(EventKind::StatusResponse {
                active_profiles: profiles,
                default_profile: default_profile_name.clone(),
                daemon_uptimes_ms: vec![(daemon_id, 0)],
                locked: *locked,
            })
        }

        EventKind::ProfileList => {
            let profiles = active_profiles.iter().map(|name| {
                core_types::ProfileSummary {
                    id: core_types::ProfileId::new(),
                    name: name.clone(),
                    is_active: true,
                    is_default: name == &*default_profile_name,
                }
            }).collect();
            Some(EventKind::ProfileListResponse { profiles })
        }

        EventKind::ProfileActivate { profile_name, target } => {
            match activation::activate(*target, profile_name, bus, audit, daemon_id).await {
                Ok(duration_ms) => {
                    active_profiles.insert(profile_name.clone());  // TrustProfileName: Clone
                    tracing::info!(
                        profile = %profile_name,
                        duration_ms,
                        "profile activated"
                    );
                    Some(EventKind::ProfileActivateResponse { success: true })
                }
                Err(e) => {
                    tracing::error!(
                        profile = %profile_name,
                        error = %e,
                        "profile activation failed"
                    );
                    Some(EventKind::ProfileActivateResponse { success: false })
                }
            }
        }

        EventKind::ProfileDeactivate { profile_name, target } => {
            if !active_profiles.contains(profile_name) {
                tracing::warn!(profile = %profile_name, "deactivate requested but profile not active");
                return Some(EventKind::ProfileDeactivateResponse { success: false });
            }

            match activation::deactivate(*target, profile_name, bus, audit, daemon_id).await {
                Ok(duration_ms) => {
                    active_profiles.remove(profile_name);
                    tracing::info!(
                        profile = %profile_name,
                        duration_ms,
                        "profile deactivated"
                    );
                    Some(EventKind::ProfileDeactivateResponse { success: true })
                }
                Err(e) => {
                    tracing::error!(
                        profile = %profile_name,
                        error = %e,
                        "profile deactivation failed"
                    );
                    Some(EventKind::ProfileDeactivateResponse { success: false })
                }
            }
        }

        EventKind::SetDefaultProfile { profile_name } => {
            // TrustProfileName is validated at deserialization — no scattered check needed.
            tracing::info!(
                previous = %default_profile_name,
                new = %profile_name,
                "set default profile requested"
            );
            *default_profile_name = profile_name.clone();
            Some(EventKind::SetDefaultProfileResponse { success: true })
        }

        EventKind::UnlockResponse { success: true } => {
            *locked = false;
            tracing::info!("secrets daemon unlocked, lock state updated");
            None
        }

        EventKind::LockResponse { success: true } => {
            *locked = true;
            tracing::info!("secrets daemon locked, lock state updated");
            None
        }

        _ => None,
    }
}

/// Snapshot of daemon generations at phase 1 start.
/// Used by phase 2 to skip daemons that were revoked during the grace period (P0).
static ROTATION_BASELINE: tokio::sync::Mutex<Option<std::collections::HashMap<String, u64>>> =
    tokio::sync::Mutex::const_new(None);

/// Key rotation phase 1 (R-001): generate keypairs, write to disk, announce pending.
///
/// Returns immediately — does NOT sleep. The grace period is handled by a
/// spawned background task that signals phase 2 via channel.
async fn rotate_keys_phase1<W: std::io::Write>(
    bus: &BusServer,
    daemon_id: DaemonId,
    audit: &mut AuditLogger<W>,
) -> anyhow::Result<()> {
    let noise_params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("valid noise params");
    let builder = snow::Builder::new(noise_params);

    // Snapshot generations BEFORE writing any new keys (P0).
    let baseline = bus.registry_mut().await.snapshot_generations();

    for &(daemon_name, _security_level) in KNOWN_DAEMONS {
        let new_keypair = core_ipc::ZeroizingKeypair::new(builder
            .generate_keypair()
            .context(format!("failed to generate new keypair for {daemon_name}"))?);

        let mut new_pubkey = [0u8; 32];
        new_pubkey.copy_from_slice(new_keypair.public());

        core_ipc::noise::write_daemon_keypair(daemon_name, new_keypair.as_inner())
            .await
            .context(format!("failed to write rotated keypair for {daemon_name}"))?;

        let event = EventKind::KeyRotationPending {
            daemon_name: daemon_name.into(),
            new_pubkey,
            grace_period_s: KEY_ROTATION_GRACE,
        };
        let msg = Message::new(daemon_id, event, SecurityLevel::Internal, bus.epoch());
        if let Ok(payload) = core_ipc::encode_frame(&msg) {
            bus.publish(&payload, SecurityLevel::Internal).await;
        }

        tracing::info!(
            audit = "key-management",
            event_type = "key-rotation-pending",
            daemon = daemon_name,
            grace_period_s = KEY_ROTATION_GRACE,
            "key rotation announced"
        );
        let current_generation = bus.registry_mut().await
            .find_by_name(daemon_name)
            .map_or(0, |(_, e)| e.generation);
        let _ = audit.append(AuditAction::KeyRotationStarted {
            daemon_name: daemon_name.into(),
            generation: current_generation,
        });
    }

    // Store baseline for phase 2 (P0).
    *ROTATION_BASELINE.lock().await = Some(baseline);

    Ok(())
}

/// Key rotation phase 2 (R-001 + R-004): atomic registry swap + announce completion.
///
/// Called after the grace period expires. Reads all new pubkeys first, then
/// acquires the registry write lock ONCE for an atomic batch update.
async fn rotate_keys_phase2<W: std::io::Write>(
    bus: &BusServer,
    daemon_id: DaemonId,
    audit: &mut AuditLogger<W>,
) -> anyhow::Result<()> {
    let baseline = ROTATION_BASELINE.lock().await.take()
        .context("phase 2 called without phase 1 baseline")?;

    // Collect all new pubkeys before taking the lock (R-004: avoid per-daemon lock churn).
    let mut new_keys: Vec<(&str, [u8; 32], SecurityLevel)> = Vec::new();
    for &(daemon_name, security_level) in KNOWN_DAEMONS {
        let pubkey = core_ipc::noise::read_daemon_public_key(daemon_name)
            .await
            .context(format!("failed to read rotated pubkey for {daemon_name}"))?;
        new_keys.push((daemon_name, pubkey, security_level));
    }

    // Single lock acquisition — atomic swap, skipping daemons that were
    // already revoked-and-re-keyed during the grace period (P0 fix).
    {
        let mut reg = bus.registry_mut().await;
        for &(daemon_name, new_pubkey, security_level) in &new_keys {
            // Check if the daemon's generation advanced since phase 1.
            let current_gen = reg
                .find_by_name(daemon_name)
                .map(|(_, e)| e.generation);
            let baseline_gen = baseline.get(daemon_name).copied();

            if current_gen != baseline_gen {
                tracing::info!(
                    audit = "key-management",
                    event_type = "rotation-skipped",
                    daemon = daemon_name,
                    baseline_gen = ?baseline_gen,
                    current_gen = ?current_gen,
                    "skipping rotation — daemon was revoked during grace period"
                );
                continue;
            }

            if let Some((old_key, _)) = reg.find_by_name(daemon_name) {
                let old_key = *old_key;
                reg.rotate_key(&old_key, new_pubkey);
            } else {
                reg.register(new_pubkey, daemon_name.into(), security_level);
            }
        }
    }

    // Announce completion for each daemon.
    for &(daemon_name, _, _) in &new_keys {
        let event = EventKind::KeyRotationComplete {
            daemon_name: daemon_name.into(),
        };
        let msg = Message::new(daemon_id, event, SecurityLevel::Internal, bus.epoch());
        if let Ok(payload) = core_ipc::encode_frame(&msg) {
            bus.publish(&payload, SecurityLevel::Internal).await;
        }

        tracing::info!(
            audit = "key-management",
            event_type = "key-rotation-complete",
            daemon = daemon_name,
            "key rotation complete, registry updated"
        );
        let current_generation = bus.registry_mut().await
            .find_by_name(daemon_name)
            .map_or(0, |(_, e)| e.generation);
        let _ = audit.append(AuditAction::KeyRotationCompleted {
            daemon_name: daemon_name.to_string(),
            generation: current_generation,
        });
    }

    Ok(())
}

/// Build activation rules from the loaded config.
///
/// Parses `activation_rules`, `rule_combinator`, `priority` from
/// each profile's config. For now: single default profile with no context rules.
fn build_activation_rules(
    config: &core_config::Config,
    default_id: core_types::ProfileId,
) -> Vec<ProfileActivation> {
    use core_profile::context::{ActivationRule, RuleTrigger};

    let mut activations = Vec::new();

    for (idx, (name, profile)) in config.profiles.iter().enumerate() {
        let act = &profile.activation;
        let mut rules = Vec::new();

        for ssid in &act.wifi_ssids {
            rules.push(ActivationRule {
                trigger: RuleTrigger::Ssid,
                value: ssid.clone(),
            });
        }

        for usb in &act.usb_devices {
            rules.push(ActivationRule {
                trigger: RuleTrigger::UsbDevice,
                value: usb.clone(),
            });
        }

        for time_rule in &act.time_rules {
            rules.push(ActivationRule {
                trigger: RuleTrigger::TimeWindow,
                value: time_rule.clone(),
            });
        }

        if act.require_security_key {
            rules.push(ActivationRule {
                trigger: RuleTrigger::HardwareKey,
                value: "present".into(),
            });
        }

        // Derive a deterministic ProfileId from the profile name so IDs are
        // stable across restarts.  The default profile keeps its caller-supplied
        // ID for backwards compatibility with the rest of daemon-profile.
        let profile_id = if name == &config.global.default_profile.to_string() {
            default_id
        } else {
            // UUID v5 in a project-specific namespace keyed on profile name — deterministic.
            // Pre-computed: uuid5(NAMESPACE_URL, "https://scopecreep.zip/open-sesame/profiles").
            const PROFILE_NS: uuid::Uuid = uuid::Uuid::from_bytes([
                0x4c, 0x45, 0xa6, 0x4f, 0xab, 0xcd, 0x59, 0x77,
                0xbc, 0x73, 0x99, 0xd4, 0xc9, 0x3d, 0x66, 0x8b,
            ]);
            let ns = PROFILE_NS;
            core_types::ProfileId::from_uuid(
                uuid::Uuid::new_v5(&ns, name.as_bytes()),
            )
        };

        activations.push(ProfileActivation {
            profile_id,
            rules,
            combinator: RuleCombinator::Any,
            priority: idx as u32,
            switch_delay_ms: 0,
        });
    }

    if activations.is_empty() {
        activations.push(ProfileActivation {
            profile_id: default_id,
            rules: vec![],
            combinator: RuleCombinator::Any,
            priority: 0,
            switch_delay_ms: 0,
        });
    }

    activations
}

/// Load the last hash and sequence from an existing audit log.
fn load_audit_state(path: &PathBuf) -> (String, u64) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return (String::new(), 0);
    };

    let Some(last_line) = contents.lines().rev().find(|l| !l.trim().is_empty()) else {
        return (String::new(), 0);
    };

    if let Ok(entry) = serde_json::from_str::<core_profile::AuditEntry>(last_line) {
        let hash = blake3::hash(last_line.as_bytes());
        (hash.to_hex().to_string(), entry.sequence)
    } else {
        tracing::warn!(path = %path.display(), "failed to parse last audit entry; starting fresh chain");
        (String::new(), 0)
    }
}

/// Verify the audit log hash chain integrity.
fn verify_audit_chain(path: &PathBuf) -> anyhow::Result<u64> {
    let contents = std::fs::read_to_string(path)
        .context("failed to read audit log")?;
    core_profile::verify_chain(&contents)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Wait for SIGTERM (Unix).
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        sig.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

/// Apply Landlock + seccomp sandbox (Linux only).
///
/// Ensures all Landlock target directories exist before opening PathFd handles.
/// After `sesame init --wipe-reset-destroy-all-data`, systemd may restart
/// daemon-profile before `sesame init` recreates the wiped directories
/// (`~/.config/pds/` and `$XDG_RUNTIME_DIR/pds/`). Landlock PathFd::new()
/// requires every path in the ruleset to exist.
#[cfg(target_os = "linux")]
fn apply_sandbox() -> anyhow::Result<()> {
    use platform_linux::sandbox::{
        apply_sandbox, FsAccess, LandlockRule, SeccompProfile,
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| "/run/user/1000".into());

    let config_dir = core_config::config_dir();
    let pds_runtime = PathBuf::from(&runtime_dir).join("pds");

    // Ensure Landlock target directories exist before PathFd::new().
    for dir in [&config_dir, &pds_runtime] {
        if !dir.exists() {
            std::fs::create_dir_all(dir)
                .context(format!("failed to create {}", dir.display()))?;
        }
    }

    let rules = vec![
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadWrite, // audit log writes here
        },
        LandlockRule {
            path: pds_runtime,
            access: FsAccess::ReadWrite,
        },
    ];

    let seccomp = SeccompProfile {
        daemon_name: "daemon-profile".into(),
        allowed_syscalls: vec![
            // I/O basics
            "read".into(), "write".into(), "close".into(),
            "openat".into(), "lseek".into(), "pread64".into(),
            "fstat".into(), "stat".into(), "newfstatat".into(),
            "statx".into(), "access".into(), "unlink".into(),
            "mkdir".into(), "rename".into(), "chmod".into(),
            "fchmod".into(), "fchown".into(),
            "fcntl".into(), "ioctl".into(), "fsync".into(),
            "fdatasync".into(), "getdents64".into(),
            // Memory
            "mmap".into(), "mprotect".into(), "munmap".into(),
            "madvise".into(), "brk".into(),
            // Process / threading
            "futex".into(), "clone3".into(), "clone".into(),
            "set_robust_list".into(), "set_tid_address".into(),
            "rseq".into(), "sched_getaffinity".into(),
            "prlimit64".into(), "prctl".into(),
            "getpid".into(), "gettid".into(), "getuid".into(), "geteuid".into(),
            "kill".into(),
            // Epoll / event loop (tokio)
            "epoll_wait".into(), "epoll_ctl".into(),
            "epoll_create1".into(), "eventfd2".into(),
            "poll".into(), "ppoll".into(),
            // Timers (tokio runtime)
            "clock_gettime".into(), "timer_create".into(),
            "timer_settime".into(), "timer_delete".into(),
            // Networking / IPC (Unix domain sockets)
            "socket".into(), "bind".into(), "listen".into(),
            "accept4".into(), "connect".into(), "sendto".into(),
            "recvfrom".into(), "getsockname".into(),
            "getpeername".into(), "setsockopt".into(),
            "socketpair".into(), "sendmsg".into(), "recvmsg".into(),
            "shutdown".into(), "getsockopt".into(),
            // Signals
            "sigaltstack".into(), "rt_sigaction".into(),
            "rt_sigprocmask".into(), "rt_sigreturn".into(),
            "tgkill".into(),
            // Misc
            "exit_group".into(), "exit".into(), "getrandom".into(),
            "restart_syscall".into(),
            "inotify_init1".into(), "inotify_add_watch".into(),
            "inotify_rm_watch".into(), "pipe2".into(), "dup".into(),
        ],
    };

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

fn init_logging(format: &str) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }

    Ok(())
}
