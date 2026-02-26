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
use core_ipc::BusServer;
use core_profile::{
    AuditLogger, ContextEngine, ContextSignal,
    context::{ProfileActivation, RuleCombinator},
};
use core_ipc::Message;
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::collections::HashSet;
use std::path::PathBuf;
use tokio::sync::mpsc;

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

    // -- Config --
    let config = core_config::load_config(None)
        .context("failed to load config")?;

    let mut default_profile_name: TrustProfileName = config.global.default_profile.clone();
    tracing::info!(default_profile = %default_profile_name, "config loaded");

    // -- Sandbox (Linux) --
    #[cfg(target_os = "linux")]
    apply_sandbox();

    // -- IPC bus server: generate Noise IK keypair and bind the Unix socket --
    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;
    let bus_keypair = core_ipc::generate_keypair()
        .context("failed to generate bus Noise IK keypair")?;
    core_ipc::noise::write_bus_keypair(&bus_keypair).await
        .context("failed to write bus public key")?;
    let bus = BusServer::bind(&socket_path, bus_keypair)
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

    // -- Register daemon-profile as an in-process bus subscriber --
    // This lets daemon-profile receive and process messages (StatusRequest,
    // ProfileActivate, ProfileList, etc.) that clients send to the bus.
    let daemon_id = DaemonId::new();
    let (host_tx, mut host_rx) = mpsc::channel::<Vec<u8>>(256);
    let host_peer = core_ipc::PeerCredentials::in_process();
    bus.register(
        daemon_id,
        host_peer,
        SecurityLevel::SecretsOnly, // bus host sees everything
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
            let (focus_raw_tx, mut focus_raw_rx) = mpsc::channel::<String>(16);
            tokio::spawn(platform_linux::compositor::focus_monitor(focus_raw_tx));
            while let Some(app_id) = focus_raw_rx.recv().await {
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

    // -- Main event loop --
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
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

                if let Some(response_event) = handle_bus_message(
                    &msg,
                    &mut active_profiles,
                    &mut context_engine,
                    &mut audit,
                    &mut default_profile_name,
                    daemon_id,
                    &bus,
                ).await {
                    let reply = Message::new(
                        daemon_id,
                        response_event,
                        msg.security_level,
                        bus.epoch(),
                    ).with_correlation(msg.msg_id);

                    if let Ok(reply_bytes) = core_ipc::encode_frame(&reply) {
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
                    if let Err(e) = audit.append(core_profile::AuditAction::DefaultProfileChanged {
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
async fn handle_bus_message<W: std::io::Write>(
    msg: &Message<EventKind>,
    active_profiles: &mut HashSet<TrustProfileName>,
    _context_engine: &mut ContextEngine,
    audit: &mut AuditLogger<W>,
    default_profile_name: &mut TrustProfileName,
    daemon_id: DaemonId,
    bus: &BusServer,
) -> Option<EventKind> {
    match &msg.payload {
        EventKind::StatusRequest => {
            let profiles: Vec<TrustProfileName> = active_profiles.iter().cloned().collect();
            Some(EventKind::StatusResponse {
                active_profiles: profiles,
                default_profile: default_profile_name.clone(),
                daemon_uptimes_ms: vec![(daemon_id, 0)],
                locked: false,
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

        // Broadcast events — no response needed.
        _ => None,
    }
}

/// Build activation rules from the loaded config.
///
/// Parses `activation_rules`, `rule_combinator`, `priority` from
/// each profile's config. For now: single default profile with no context rules.
fn build_activation_rules(
    _config: &core_config::Config,
    default_id: core_types::ProfileId,
) -> Vec<ProfileActivation> {
    vec![ProfileActivation {
        profile_id: default_id,
        rules: vec![],
        combinator: RuleCombinator::Any,
        priority: 0,
        switch_delay_ms: 0,
    }]
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
#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{
        apply_sandbox, FsAccess, LandlockRule, SeccompProfile,
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| "/run/user/1000".into());

    let config_dir = core_config::config_dir();

    let rules = vec![
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadWrite, // audit log writes here
        },
        LandlockRule {
            path: PathBuf::from(&runtime_dir).join("pds"),
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
            "getpid".into(), "gettid".into(), "geteuid".into(),
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
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
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
