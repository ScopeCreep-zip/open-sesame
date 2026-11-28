//! daemon-wm: Wayland overlay window switcher daemon.
//!
//! Tracks open windows through the compositor backend, maintains MRU
//! ordering, and serves `WmListWindows`/`WmActivateWindow` RPC requests over
//! the encrypted IPC bus. Overlay lifecycle is driven by
//! [`OverlayController`] — a single owner of all state, timing, and
//! decisions.
//!
//! Landlock: see [`daemon_wm::sandbox::apply_sandbox`].
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_config::Config;
use core_crypto::SecureVec;
use core_daemon::{DaemonIdentity, EventLoop, LogFormat, Shutdown, Wake};
use daemon_wm::commands::Runtime;
use daemon_wm::controller::{Event, OverlayController};
use daemon_wm::ipc_keys::KeyDeduplicator;
use daemon_wm::mru::MruStore;
use daemon_wm::serve::{Local, Respawns, wm_config_of};
use daemon_wm::surface::wayland::{self, OverlayCmd};
use daemon_wm::winlist::{self, Refresh, Windows};
use std::sync::Arc;

const IDENTITY: DaemonIdentity = DaemonIdentity {
    daemon: core_types::Daemon::Wm,
    version: env!("CARGO_PKG_VERSION"),
    capabilities: &["wm", "window-switcher"],
};

/// Window manager daemon.
#[derive(Parser, Debug)]
#[command(name = IDENTITY.daemon.name(), about = "Window manager overlay daemon")]
struct Cli {
    #[arg(long, value_enum, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: LogFormat,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    core_daemon::init_logging(cli.log_format)?;

    tracing::info!("daemon-wm starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 4096,
        memlock_bytes: 0,
    });

    let (layout, config) = core_daemon::startup()?;
    let mru_store = MruStore::from_layout(&layout)?;

    // Probe memfd_secret and initialize secure memory BEFORE sandbox.
    core_types::init_secure_memory();

    // The sandbox is applied on the only thread; the configuration
    // watcher, Wayland, and overlay threads start inside it.
    #[cfg(target_os = "linux")]
    daemon_wm::sandbox::apply_sandbox(&layout, &config)?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?
        .block_on(run(layout, config, mru_store))
}

/// Track the compositor's windows in `windows`: through the compositor
/// backend when one is detected (seeding the MRU stack on first launch),
/// by compositor focus alone otherwise.
///
/// # Errors
///
/// When the window list poll thread cannot be spawned.
#[cfg(target_os = "linux")]
async fn track_windows(
    windows: &Windows,
    mru: &MruStore,
) -> anyhow::Result<(daemon_wm::commands::Backend, Option<Refresh>)> {
    let backend = match platform_linux::compositor::detect_compositor() {
        Ok(backend) => backend,
        Err(e) => {
            tracing::warn!(error = %e, "no compositor backend available, tracking windows by focus");
            winlist::track_focus(windows);
            return Ok((None, None));
        }
    };
    tracing::info!(backend = backend.name(), "compositor backend detected");
    let backend: Arc<dyn platform_linux::compositor::CompositorBackend> = Arc::from(backend);
    match backend.list_windows() {
        Ok(list) => {
            mru.seed_if_empty(&list);
            *windows.lock().await = list;
        }
        Err(e) => tracing::warn!(error = %e, "initial window enumeration failed"),
    }
    let poll_backend = Arc::clone(&backend);
    let refresh = winlist::poll_compositor(move || poll_backend.list_windows(), windows)
        .context("failed to spawn window list poll thread")?;
    Ok((Some(backend), Some(refresh)))
}

/// The daemon, from bus connection to shutdown, inside the sandbox.
async fn run(
    layout: core_layout::Layout,
    config: Config,
    mru_store: MruStore,
) -> anyhow::Result<()> {
    let wm_config = wm_config_of(&config);
    tracing::info!(
        profile = %config.global.default_profile,
        hint_keys = %wm_config.hint_keys,
        overlay_delay_ms = wm_config.overlay_delay_ms,
        "wm config loaded"
    );
    let mut events = EventLoop::new(
        IDENTITY.daemon,
        Shutdown::register()?,
        core_daemon::watch_config(&layout, config)?,
    );
    let client = core_daemon::connect_bus(&layout, &IDENTITY).await?;
    core_daemon::announce_started(&client, &IDENTITY).await;

    let windows = Windows::default();
    #[cfg(target_os = "linux")]
    let (backend, refresh) = track_windows(&windows, &mru_store).await?;
    #[cfg(not(target_os = "linux"))]
    let refresh = None;

    let (overlay_cmd_tx, overlay_event_rx) =
        wayland::spawn_overlay(&wm_config).context("failed to spawn the overlay thread")?;
    let mut rt = Runtime {
        layout,
        mru: mru_store.clone(),
        overlay_cmd_tx,
        overlay_event_rx,
        #[cfg(target_os = "linux")]
        backend,
        client,
        config_state: events.application().clone(),
        controller: OverlayController::new(mru_store),
        windows,
        refresh,
        wm_config,
        dedup: KeyDeduplicator::new(),
        ipc_keyboard_confirmed: false,
        // Pre-allocated and mlock'd so password bytes are neither swapped
        // nor in core dumps; the render thread receives only dot counts.
        password_buffer: SecureVec::for_password(),
    };
    let mut respawns = Respawns::default();
    rt.reconfigure(events.candidate()?).await?;

    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
    tracing::info!("daemon-wm ready, entering event loop");

    loop {
        let local = respawns.next(
            &mut rt.overlay_event_rx,
            rt.controller.next_deadline(),
            rt.refresh.as_mut(),
        );
        match events.next(&mut rt.client, local).await? {
            Wake::Own(Local::Overlay(Some(event))) => rt.overlay_event(event).await?,
            Wake::Own(Local::Overlay(None)) => rt.overlay_died(&mut respawns).await?,
            Wake::Own(Local::Respawn) => {
                rt.respawn_overlay(&mut respawns)?;
                match events.candidate() {
                    Ok(reload) => rt.reconfigure(reload).await?,
                    Err(error) => tracing::warn!(
                        %error,
                        "overlay restored with previous settings; current configuration unavailable"
                    ),
                }
            }
            // Stops the daemon; systemd restarts it (Restart=on-failure).
            Wake::Own(Local::CompositorLost) => {
                if rt.overlay_cmd_tx.send(OverlayCmd::Quit).is_err() {
                    tracing::debug!("overlay thread already exited before Quit");
                }
                core_daemon::announce_stopped(&rt.client).await;
                anyhow::bail!("the compositor connection is dead");
            }
            Wake::Own(Local::Deadline) => rt.handle(Event::DwellTimeout).await?,
            Wake::Message(msg) => rt.message(&msg).await?,
            Wake::ConfigReloaded(reload) => {
                if respawns.pending() {
                    reload.reject("overlay recovery is pending".into());
                } else {
                    rt.reconfigure(reload).await?;
                }
            }
            Wake::Shutdown(_) => break,
        }
    }

    // A send error means the overlay thread already exited.
    if rt.overlay_cmd_tx.send(OverlayCmd::Quit).is_err() {
        tracing::debug!("overlay thread already exited before Quit");
    }
    core_daemon::announce_stopped(&rt.client).await;
    tracing::info!("daemon-wm shut down");
    Ok(())
}
