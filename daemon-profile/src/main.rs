//! daemon-profile: The bus server and profile orchestrator.
//!
//! Central daemon responsibilities:
//! 1. Hosts the IPC bus server (all inter-daemon communication routes through here)
//! 2. Runs the context engine for default profile selection
//! 3. Applies profile activation and deactivation through confirmed RPCs to
//!    daemon-secrets, reconciling with its state when one is unconfirmed
//! 4. Manages the hash-chained audit log
//! 5. Rotates the per-daemon Noise IK keypairs
//! 6. Handles systemd readiness and watchdog
//!
//! Multiple profiles may be active concurrently. The context engine determines
//! the default profile for new unscoped launches — changing the default does
//! NOT deactivate other active profiles.
//!
//! Landlock: see [`sandbox::apply_sandbox`]. No network access beyond local
//! IPC.

mod activation;
mod context;
mod dispatch;
mod key_rotation;
mod sandbox;

use anyhow::Context;
use clap::Parser;
use core_daemon::{LogFormat, Shutdown};
use core_ipc::{BusServer, ClearanceRegistry, Message};
use core_profile::ContextSignal;
use core_types::{Daemon, DaemonId, EventKind, SecurityLevel, TrustProfileName};
use dispatch::{AuditLog, Hub};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::mpsc;

/// Every bus client daemon and its security clearance.
const KNOWN_DAEMONS: &[(Daemon, SecurityLevel)] = &[
    (Daemon::Secrets, SecurityLevel::SecretsOnly),
    (Daemon::Wm, SecurityLevel::Internal),
    (Daemon::Launcher, SecurityLevel::Internal),
    (Daemon::Clipboard, SecurityLevel::Internal),
    (Daemon::Input, SecurityLevel::Internal),
    (Daemon::Snippets, SecurityLevel::Internal),
];

/// Key rotation interval.
const KEY_ROTATION_INTERVAL: Duration = Duration::from_hours(1);

/// Grace period (seconds) for daemons to reconnect with new keys after rotation.
const KEY_ROTATION_GRACE: u32 = 30;

/// Watchdog notification interval: half of the units' `WatchdogSec=30`.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(15);

/// How often `installation.toml` is looked for before `sesame init`.
const INSTALLATION_POLL: Duration = Duration::from_millis(500);

/// Tracks which `DaemonId` is associated with each daemon name.
/// Detects crash-restarts when a new `DaemonStarted` arrives for an already-registered name.
pub(crate) struct DaemonTracker {
    /// Each daemon name's last known `DaemonId`.
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
        self.known
            .insert(name.to_owned(), new_id)
            .filter(|&old_id| old_id != new_id)
    }
}

/// Start the context signal sources (Linux desktop builds: Wi-Fi network
/// changes on the system bus `layout` names, and compositor focus changes)
/// feeding `tx`. Headless builds have none, and the context engine keeps
/// its configured default.
fn spawn_context_monitors(layout: &core_layout::Layout, tx: mpsc::Sender<ContextSignal>) {
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    {
        use platform_linux::focus_monitor::FocusEvent;

        match layout.system_bus_socket() {
            Ok(system_bus) => {
                let ssid_tx = tx.clone();
                tokio::spawn(async move {
                    let (raw_tx, mut raw_rx) = mpsc::channel::<String>(16);
                    tokio::spawn(platform_linux::dbus::ssid_monitor(system_bus, raw_tx));
                    while let Some(ssid) = raw_rx.recv().await {
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
            Err(e) => tracing::warn!(error = %e, "SSID monitor unavailable"),
        }

        let (raw_tx, mut raw_rx) = mpsc::channel::<FocusEvent>(16);
        match platform_linux::focus_monitor::spawn(raw_tx) {
            Ok(()) => tracing::info!("focus monitor spawned"),
            Err(e) => tracing::warn!(error = %e, "focus monitor unavailable"),
        }
        tokio::spawn(async move {
            while let Some(event) = raw_rx.recv().await {
                let FocusEvent::Focus(app_id) = event else {
                    continue;
                };
                if tx
                    .send(ContextSignal::AppFocused(core_types::AppId::new(app_id)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    #[cfg(not(all(target_os = "linux", feature = "desktop")))]
    {
        let _ = layout;
        drop(tx);
    }
}

/// PDS profile orchestrator daemon.
#[derive(Parser, Debug)]
#[command(
    name = Daemon::Profile.name(),
    about = "PDS profile orchestrator and IPC bus server"
)]
struct Cli {
    #[arg(long, value_enum, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: LogFormat,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    core_daemon::init_logging(cli.log_format)?;

    tracing::info!("daemon-profile starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 4096,
        memlock_bytes: 0,
    });

    // An invalid config fails startup here, before the bus is bound. The
    // config used at runtime is reloaded once installation.toml exists,
    // since `sesame init` writes config.toml alongside it.
    let (layout, startup_config) = core_daemon::startup()?;

    // Probe memfd_secret and initialize secure memory BEFORE sandbox.
    core_types::init_secure_memory();

    // The sandbox is applied on the only thread; the runtime's threads
    // start inside it.
    #[cfg(target_os = "linux")]
    sandbox::apply_sandbox(&layout)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?
        .block_on(run(layout, startup_config))
}

/// A fresh keypair for every known daemon, each public key registered
/// under its clearance at generation 0.
async fn issue_keys(layout: &core_layout::Layout) -> anyhow::Result<ClearanceRegistry> {
    core_ipc::noise::create_keys_dir(layout)
        .await
        .context("failed to create keys directory")?;
    let mut registry = ClearanceRegistry::new();
    for &(daemon, security_level) in KNOWN_DAEMONS {
        let pubkey = core_ipc::noise::issue_daemon_keypair(layout, daemon.name())
            .await
            .with_context(|| format!("failed to issue keypair for {daemon}"))?;
        registry.register(daemon.name().into(), pubkey, security_level, 0);
        tracing::info!(%daemon, clearance = ?security_level, "generated and registered keypair");
    }
    Ok(registry)
}

/// The bus server bound under the configured Noise suite, its endpoint
/// published afterwards: clients that see the endpoint find a bound socket.
/// The server's private key stays in memory.
async fn bind_bus(
    layout: &core_layout::Layout,
    config: &core_config::Config,
    registry: ClearanceRegistry,
) -> anyhow::Result<BusServer> {
    let crypto = config.crypto().context("invalid [crypto] configuration")?;
    let bus = BusServer::bind(
        &layout.bus_socket()?,
        core_ipc::noise::generate_keypair()
            .context("failed to generate bus Noise IK keypair")?
            .into_inner(),
        registry,
        core_ipc::noise::NoiseSuite::new(crypto.noise_cipher, crypto.noise_hash),
    )
    .context("failed to bind IPC bus server")?;
    core_ipc::noise::publish_bus_endpoint(layout, &bus.endpoint())
        .await
        .context("failed to publish the bus endpoint")?;
    Ok(bus)
}

/// The installation identity, waiting for `sesame init` to write it while
/// serving the bus; `None` on a shutdown signal first.
///
/// While waiting, a temporary in-process subscriber answers
/// `StatusRequest` as locked with no active profiles, so `sesame status`
/// does not time out.
async fn await_installation(
    layout: &core_layout::Layout,
    bus: &BusServer,
    shutdown: &mut Shutdown,
    default_profile: &TrustProfileName,
) -> anyhow::Result<Option<core_config::InstallationConfig>> {
    if let Some(installation) = core_config::load_installation(layout)? {
        return Ok(Some(installation));
    }
    tracing::info!("waiting for sesame init — installation.toml not found");

    let pre_init = core_ipc::MessageContext::new(DaemonId::new());
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    bus.register(pre_init.sender, SecurityLevel::Internal, tx)
        .await;
    let mut poll = tokio::time::interval(INSTALLATION_POLL);
    let mut watchdog = tokio::time::interval(WATCHDOG_INTERVAL);
    let installation = loop {
        tokio::select! {
            _ = poll.tick() => {
                if let Some(installation) = core_config::load_installation(layout)? {
                    tracing::info!("installation.toml found, transitioning to full mode");
                    #[cfg(target_os = "linux")]
                    platform_linux::systemd::notify_reloading();
                    break Some(installation);
                }
            }
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            never = bus.run() => match never {},
            Some(frame) = rx.recv() => {
                let Some(msg) = dispatch::decode_host_frame(&frame, pre_init.sender) else {
                    continue;
                };
                if matches!(msg.payload, EventKind::StatusRequest) {
                    let status = EventKind::StatusResponse {
                        active_profiles: vec![],
                        default_profile: default_profile.clone(),
                        daemon_uptimes_ms: vec![],
                        locked: true,
                        // Before `sesame init` no vault exists.
                        lock_state: Some(std::collections::BTreeMap::new()),
                    };
                    let reply = Message::new(&pre_init, status, SecurityLevel::Internal, bus.epoch())
                        .with_correlation(msg.msg_id);
                    dispatch::send_reply(bus, &msg.msg_id, &reply).await;
                }
            }
            signal = shutdown.wait() => {
                tracing::info!(signal = ?signal?, "shutting down while waiting for installation.toml");
                break None;
            }
        }
    };
    bus.unregister(&pre_init.sender).await;
    Ok(installation)
}

/// The audit log, its chain verified, recording under `agent`.
///
/// A failed verification is logged at error and the daemon keeps running:
/// the log stays tamper-evident (`sesame audit verify` reports the break),
/// and refusing to start would also stop recording new events.
fn open_audit(
    layout: &core_layout::Layout,
    config: &core_config::Config,
    agent: core_types::AgentId,
) -> anyhow::Result<AuditLog> {
    let audit_hash = config
        .crypto()
        .context("invalid [crypto] configuration")?
        .audit_hash;
    let path = layout.audit_log()?;
    let audit = core_profile::open_audit_log(&path, audit_hash, Some(agent))
        .context("failed to open audit log")?;
    tracing::info!(path = %path.display(), sequence = audit.sequence(), "audit logger initialized");
    match core_profile::verify_audit_log(&path, audit_hash) {
        Ok(Some(count)) => tracing::info!(entries = count, "audit chain verified"),
        Ok(None) => {}
        Err(e) => tracing::error!(error = %e, "audit chain verification FAILED"),
    }
    Ok(audit)
}

/// What wakes the full-mode event loop besides the bus and its timers.
struct Sources {
    shutdown: Shutdown,
    /// `systemctl reload` (`Type=notify-reload`).
    sighup: tokio::signal::unix::Signal,
    config_watch: core_daemon::ConfigWatch,
    /// Messages clients send to the bus host.
    host_rx: mpsc::Receiver<Vec<u8>>,
    context_rx: mpsc::Receiver<ContextSignal>,
    /// Key rotation phase 2, signalled after the grace period.
    rotation_done_rx: mpsc::Receiver<()>,
}

impl Hub {
    /// Serve the bus and every source until a shutdown signal, notifying
    /// the watchdog, reconciling with daemon-secrets every other watchdog
    /// tick, and rotating keys every [`KEY_ROTATION_INTERVAL`].
    ///
    /// # Errors
    ///
    /// When the shutdown signal handler fails.
    async fn serve(&mut self, mut sources: Sources) -> anyhow::Result<()> {
        let mut watchdog = tokio::time::interval(WATCHDOG_INTERVAL);
        let mut reconcile_due = false;
        let mut rotation_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + KEY_ROTATION_INTERVAL,
            KEY_ROTATION_INTERVAL,
        );
        loop {
            tokio::select! {
                _ = watchdog.tick() => {
                    #[cfg(target_os = "linux")]
                    platform_linux::systemd::notify_watchdog();
                    if reconcile_due {
                        self.reconcile_secrets_state().await;
                    }
                    reconcile_due = !reconcile_due;
                }
                _ = rotation_timer.tick() => {
                    // Phase 1 returns immediately; phase 2 is scheduled after
                    // the grace period so the event loop stays responsive.
                    if let Err(e) = self.begin_key_rotation().await {
                        tracing::error!(error = %e, "key rotation phase 1 failed");
                    }
                }
                Some(()) = sources.rotation_done_rx.recv() => self.finish_key_rotation().await,
                never = self.bus.run() => match never {},
                Some(frame) = sources.host_rx.recv() => self.host_frame(&frame).await,
                Some(signal) = sources.context_rx.recv() => self.context_changed(&signal).await,
                Some(()) = sources.config_watch.reloads.recv() => {
                    self.reload(&sources.config_watch.state);
                }
                Some(()) = sources.sighup.recv() => {
                    // Type=notify-reload protocol: RELOADING=1 -> work -> READY=1.
                    tracing::info!("SIGHUP received, triggering config reload");
                    #[cfg(target_os = "linux")]
                    platform_linux::systemd::notify_reloading();
                    self.reload(&sources.config_watch.state);
                    #[cfg(target_os = "linux")]
                    platform_linux::systemd::notify_ready();
                }
                signal = sources.shutdown.wait() => {
                    tracing::info!(signal = ?signal?, "shutting down");
                    return Ok(());
                }
            }
        }
    }
}

/// The daemon, from bus bind to shutdown, inside the sandbox.
async fn run(
    layout: core_layout::Layout,
    startup_config: core_config::Config,
) -> anyhow::Result<()> {
    let mut shutdown = Shutdown::register()?;
    let registry = issue_keys(&layout).await?;
    let bus = bind_bus(&layout, &startup_config, registry).await?;

    // Registered before the first READY=1: systemd checks for a SIGHUP
    // handler then under Type=notify-reload.
    let sighup = sandbox::register_sighup().context("failed to register SIGHUP handler")?;

    // Alive before waiting on installation.toml, which may not exist yet on
    // fresh multi-user VMs.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    let Some(installation) = await_installation(
        &layout,
        &bus,
        &mut shutdown,
        &startup_config.global.default_profile,
    )
    .await?
    else {
        return Ok(());
    };
    let install_ns = installation.namespace;

    // The startup load may predate config.toml: `sesame init` writes it
    // alongside installation.toml.
    let config = core_config::load_config(&layout).context("failed to reload config after init")?;
    tracing::info!(default_profile = %config.global.default_profile, "config loaded");

    let uid = rustix::process::getuid().as_raw();
    let agent = core_types::AgentId::from_uuid(uuid::Uuid::new_v5(
        &install_ns,
        format!("agent:human:uid{uid}").as_bytes(),
    ));
    let audit = open_audit(&layout, &config, agent)?;

    // daemon-profile is an in-process bus subscriber: it receives the
    // messages clients send to the bus host (StatusRequest, ProfileActivate,
    // ProfileList, ...). Internal: the host handles no secrets.
    let ctx = core_ipc::MessageContext {
        sender: DaemonId::new(),
        installation: Some(installation.identity()?),
        agent_id: Some(agent),
        trust_snapshot: None,
    };
    let (host_tx, host_rx) = mpsc::channel::<Vec<u8>>(256);
    bus.register(ctx.sender, SecurityLevel::Internal, host_tx)
        .await;

    let (ctx_tx, ctx_rx) = mpsc::channel::<ContextSignal>(64);
    spawn_context_monitors(&layout, ctx_tx);

    let (confirm_tx, confirm_rx) = mpsc::channel::<Vec<u8>>(16);
    // Rotation phase 2 runs on the event loop, signalled after the grace period.
    let (rotation_done_tx, rotation_done_rx) = mpsc::channel::<()>(1);
    let context_engine = context::context_engine(&config, &install_ns);
    tracing::info!(profile = %context_engine.default_profile(), "context engine initialized with default profile");
    let mut hub = Hub {
        layout: layout.clone(),
        bus,
        ctx,
        audit,
        active_profiles: HashSet::new(),
        locked: true,
        default_profile_name: config.global.default_profile.clone(),
        config_profile_names: context::profile_names(&config),
        install_ns,
        context_engine,
        daemon_tracker: DaemonTracker::new(),
        confirm_tx,
        confirm_rx,
        rotation_done_tx,
        pending_rotation: None,
    };
    let config_watch = core_daemon::watch_config(&layout, config)?;

    // The second READY=1 ends the pre-install -> full mode reload cycle
    // (Type=notify-reload), making SubState observable by post-install.sh.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
    tracing::info!("daemon-profile ready");

    hub.serve(Sources {
        shutdown,
        sighup,
        config_watch,
        host_rx,
        context_rx: ctx_rx,
        rotation_done_rx,
    })
    .await?;

    tracing::info!(
        active_profiles = hub.active_profiles.len(),
        audit_sequence = hub.audit.sequence(),
        "daemon-profile shut down"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_reports_a_restart_with_the_previous_id() {
        let mut tracker = DaemonTracker::new();
        let first = DaemonId::new();
        let second = DaemonId::new();
        assert_eq!(tracker.track("daemon-wm", first), None);
        assert_eq!(
            tracker.track("daemon-wm", first),
            None,
            "same id is not a restart"
        );
        assert_eq!(tracker.track("daemon-wm", second), Some(first));
        assert_eq!(
            tracker.track("daemon-input", first),
            None,
            "names are tracked apart"
        );
    }

    #[test]
    fn every_client_daemon_has_a_clearance() {
        let mut known: Vec<Daemon> = KNOWN_DAEMONS.iter().map(|(d, _)| *d).collect();
        known.sort();
        let clients: Vec<Daemon> = Daemon::ALL
            .into_iter()
            .filter(|d| *d != Daemon::Profile)
            .collect();
        assert_eq!(known, clients);
    }
}
