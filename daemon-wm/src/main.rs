//! daemon-wm: Wayland overlay window switcher daemon.
//!
//! Tracks open windows via wlr-foreign-toplevel-management-v1, maintains MRU
//! ordering, and serves WmListWindows/WmActivateWindow RPC requests over the
//! encrypted IPC bus. Overlay lifecycle is driven by [`OverlayController`] —
//! a single owner of all state, timing, and decisions.
//!
//! Landlock: Wayland socket, fontconfig, cache dir (MRU state).
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_crypto::SecureVec;
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, SecurityLevel, Window};
use daemon_wm::controller::{Event, OverlayController};
use daemon_wm::ipc_keys::{KeyDeduplicator, map_ipc_key_to_event};
use daemon_wm::mru;
use daemon_wm::overlay::{self, OverlayCmd, OverlayEvent};
use daemon_wm::render::OverlayTheme;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum overlay thread respawns within the time window before exit(1).
const OVERLAY_MAX_RESPAWNS: usize = 5;
/// Time window (seconds) for overlay respawn rate limiting.
const OVERLAY_RESPAWN_WINDOW_SECS: u64 = 120;
/// Delay (seconds) before respawning overlay thread after death.
const OVERLAY_RESPAWN_DELAY_SECS: u64 = 2;

/// Window manager daemon.
#[derive(Parser, Debug)]
#[command(name = "daemon-wm", about = "Window manager overlay daemon")]
struct Cli {
    /// Log format: "json" or "pretty".
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(&cli.log_format)?;

    tracing::info!("daemon-wm starting");

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

    // Load config.
    let config = core_config::load_config(None).context("failed to load config")?;
    let wm_config = config
        .profiles
        .values()
        .next()
        .map(|p| p.wm.clone())
        .unwrap_or_default();

    tracing::info!(
        hint_keys = %wm_config.hint_keys,
        overlay_delay_ms = wm_config.overlay_delay_ms,
        "wm config loaded"
    );

    // Config hot-reload.
    let config_paths = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, config_state) = core_config::ConfigWatcher::with_callback(
        &config_paths,
        config,
        Some(Box::new(move || {
            let _ = reload_tx.blocking_send(());
        })),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Mutable config for hot-reload.
    let wm_config = Arc::new(Mutex::new(wm_config));

    // Connect to IPC bus: read keypair BEFORE sandbox.
    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key()
        .await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);

    // Connect with keypair retry (daemon-profile may regenerate on crash-restart).
    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-wm",
        daemon_id,
        &socket_path,
        &server_pub,
        5,
        std::time::Duration::from_millis(500),
    )
    .await
    .context("failed to connect to IPC bus")?;
    // ZeroizingKeypair: private key zeroized on drop (no manual zeroize needed).
    drop(_client_keypair);

    // Probe memfd_secret and initialize secure memory BEFORE sandbox.
    core_types::init_secure_memory();

    // Sandbox (Linux) — applied AFTER keypair read + connect, BEFORE IPC traffic.
    #[cfg(target_os = "linux")]
    daemon_wm::sandbox::apply_sandbox();

    // Announce startup.
    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["wm".into(), "window-switcher".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    // Window list — populated by compositor backend (when available).
    let windows: Arc<Mutex<Vec<Window>>> = Arc::new(Mutex::new(Vec::new()));

    // Compositor backend: shared via Arc for both polling and activation.
    #[cfg(target_os = "linux")]
    let backend: Option<Arc<Box<dyn platform_linux::compositor::CompositorBackend>>> = {
        match platform_linux::compositor::detect_compositor() {
            Ok(backend) => {
                tracing::info!(backend = backend.name(), "compositor backend detected");
                let arc = Arc::new(backend);
                let poll_backend = Arc::clone(&arc);
                let win_ref = Arc::clone(&windows);
                // Window list polling runs on a dedicated OS thread because the
                // compositor backend does synchronous Wayland roundtrips with
                // libc::poll(). On the current_thread runtime this would block
                // the single tokio thread and stall all IPC message processing.
                let (win_tx, mut win_rx) = tokio::sync::mpsc::channel(1);
                std::thread::Builder::new()
                    .name("wm-winlist-poll".into())
                    .spawn(move || {
                        let mut consecutive_failures: u32 = 0;
                        const MAX_CONSECUTIVE_FAILURES: u32 = 10;
                        loop {
                            // list_windows() returns BoxFuture wrapping sync Wayland I/O.
                            // Use a noop-waker poll since the future never yields.
                            let result = {
                                let waker = std::task::Waker::noop();
                                let mut cx = std::task::Context::from_waker(waker);
                                let mut fut = poll_backend.list_windows();
                                match std::pin::Pin::as_mut(&mut fut).poll(&mut cx) {
                                    std::task::Poll::Ready(r) => r,
                                    std::task::Poll::Pending => {
                                        tracing::warn!("list_windows unexpectedly yielded Pending");
                                        continue;
                                    }
                                }
                            };
                            match result {
                                Ok(win_list) => {
                                    consecutive_failures = 0;
                                    let _ = win_tx.blocking_send(win_list);
                                }
                                Err(e) => {
                                    consecutive_failures += 1;
                                    tracing::warn!(
                                        error = %e,
                                        consecutive_failures,
                                        "failed to refresh window list"
                                    );
                                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                                        tracing::error!(
                                            "compositor connection dead after {MAX_CONSECUTIVE_FAILURES} \
                                             consecutive failures, exiting for systemd restart"
                                        );
                                        std::process::exit(1);
                                    }
                                }
                            }
                            std::thread::sleep(std::time::Duration::from_secs(2));
                        }
                    })
                    .expect("failed to spawn window list poll thread");
                tokio::spawn(async move {
                    while let Some(win_list) = win_rx.recv().await {
                        *win_ref.lock().await = win_list;
                    }
                });
                Some(arc)
            }
            Err(e) => {
                tracing::warn!(error = %e, "no compositor backend available");

                // Try D-Bus focus monitor as a fallback.
                use platform_linux::compositor::FocusEvent;
                let win_ref = Arc::clone(&windows);
                tokio::spawn(async move {
                    let (focus_tx, mut focus_rx) = tokio::sync::mpsc::channel::<FocusEvent>(16);
                    tokio::spawn(platform_linux::compositor::focus_monitor(focus_tx));
                    while let Some(event) = focus_rx.recv().await {
                        match event {
                            FocusEvent::Focus(app_id) => {
                                let mut guard = win_ref.lock().await;
                                for w in guard.iter_mut() {
                                    w.is_focused = false;
                                }
                                if !guard.iter().any(|w| w.app_id.as_str() == app_id) {
                                    guard.push(Window {
                                        id: core_types::WindowId::new(),
                                        app_id: core_types::AppId::new(&app_id),
                                        title: app_id.clone(),
                                        workspace_id: core_types::CompositorWorkspaceId::new(),
                                        monitor_id: core_types::MonitorId::new(),
                                        geometry: core_types::Geometry {
                                            x: 0,
                                            y: 0,
                                            width: 0,
                                            height: 0,
                                        },
                                        is_focused: true,
                                        is_minimized: false,
                                        is_fullscreen: false,
                                        profile_id: core_types::ProfileId::new(),
                                    });
                                } else {
                                    for w in guard.iter_mut() {
                                        if w.app_id.as_str() == app_id {
                                            w.is_focused = true;
                                        }
                                    }
                                }
                            }
                            FocusEvent::Closed(app_id) => {
                                let mut guard = win_ref.lock().await;
                                guard.retain(|w| w.app_id.as_str() != app_id);
                            }
                        }
                    }
                });
                None
            }
        }
    };

    // Seed MRU from current window list if empty (first launch or after crash).
    #[cfg(target_os = "linux")]
    if let Some(ref b) = backend {
        match b.list_windows().await {
            Ok(win_list) => {
                mru::seed_if_empty(&win_list);
                *windows.lock().await = win_list;
            }
            Err(e) => tracing::warn!(error = %e, "initial window enumeration failed"),
        }
    }

    // -- Overlay lifecycle --
    let mut controller = OverlayController::new();
    let mut dedup = KeyDeduplicator::new();
    let mut ipc_keyboard_confirmed = false;

    let (mut overlay_cmd_tx, mut overlay_event_rx) = {
        let cfg = wm_config.lock().await;
        let theme = OverlayTheme::from_config(&cfg);
        let show_app_id = cfg.show_app_id;
        let show_title = cfg.show_title;
        drop(cfg);
        overlay::spawn_overlay(theme, show_app_id, show_title)
    };

    // Password buffer for inline vault unlock. Pre-allocated and mlock'd
    // to prevent password bytes from being swapped to disk or included in
    // core dumps. Lives in the tokio executor context — never crosses thread
    // boundaries to the render thread (which receives only dot counts).
    let mut password_buffer = SecureVec::for_password();

    // -- Overlay respawn tracking --
    let mut overlay_respawn_times: Vec<std::time::Instant> = Vec::new();
    // Pending respawn: set to a deadline when the overlay thread dies.
    // The select loop waits for this deadline before spawning a new thread.
    let mut overlay_respawn_at: Option<tokio::time::Instant> = None;

    // Platform readiness.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-wm ready, entering event loop");

    // Watchdog timer: half the WatchdogSec=30 interval.
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // -----------------------------------------------------------------------
    // Event loop — thin orchestrator
    // -----------------------------------------------------------------------
    let mut watchdog_count: u64 = 0;
    loop {
        // Compute the controller's next deadline for dwell/activation timeout.
        let deadline = controller.next_deadline();

        tokio::select! {
            // Biased: overlay events always polled before deadline timer.
            biased;

            _ = watchdog.tick() => {
                watchdog_count += 1;
                if watchdog_count <= 3 || watchdog_count.is_multiple_of(20) {
                    tracing::info!(watchdog_count, "watchdog tick");
                }
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }

            // Deferred overlay respawn — non-blocking delay before thread recreation.
            _ = async {
                match overlay_respawn_at {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            }, if overlay_respawn_at.is_some() => {
                overlay_respawn_at = None;

                // Respawn overlay thread with fresh channels.
                let (new_cmd_tx, new_event_rx) = {
                    let cfg = wm_config.lock().await;
                    let theme = OverlayTheme::from_config(&cfg);
                    let show_app_id = cfg.show_app_id;
                    let show_title = cfg.show_title;
                    drop(cfg);
                    overlay::spawn_overlay(theme, show_app_id, show_title)
                };
                overlay_cmd_tx = new_cmd_tx;
                overlay_event_rx = new_event_rx;

                tracing::info!(
                    respawn_count = overlay_respawn_times.len(),
                    "overlay thread respawned successfully"
                );
            }

            // Overlay keyboard events — highest priority.
            overlay_msg = overlay_event_rx.recv() => {
                let event = match overlay_msg {
                    Some(ev) => ev,
                    None => {
                        // Respawn already scheduled — don't re-process.
                        if overlay_respawn_at.is_some() {
                            // Channel is closed; yield to let the respawn deadline arm fire.
                            tokio::task::yield_now().await;
                            continue;
                        }

                        // Overlay thread died — channel closed.
                        tracing::error!("overlay thread has died (event channel closed), scheduling respawn");

                        // Prune old respawn timestamps outside the window.
                        let now = std::time::Instant::now();
                        let window = std::time::Duration::from_secs(OVERLAY_RESPAWN_WINDOW_SECS);
                        overlay_respawn_times.retain(|t| now.duration_since(*t) < window);

                        if overlay_respawn_times.len() >= OVERLAY_MAX_RESPAWNS {
                            tracing::error!(
                                respawns_in_window = overlay_respawn_times.len(),
                                window_secs = OVERLAY_RESPAWN_WINDOW_SECS,
                                "overlay respawn limit exceeded, exiting for systemd restart"
                            );
                            std::process::exit(1);
                        }

                        overlay_respawn_times.push(now);

                        // Force controller to idle and clear sensitive state.
                        controller.force_idle();
                        password_buffer.clear();
                        ipc_keyboard_confirmed = false;
                        dedup = KeyDeduplicator::new();

                        // Release any keyboard grab that was active.
                        client.publish(
                            EventKind::InputGrabRelease {
                                requester: client.daemon_id(),
                            },
                            SecurityLevel::Internal,
                        ).await.ok();

                        // Schedule deferred respawn — does not block the event loop.
                        overlay_respawn_at = Some(tokio::time::Instant::now()
                            + std::time::Duration::from_secs(OVERLAY_RESPAWN_DELAY_SECS));
                        continue;
                    }
                };

                // Log at trace level — event may contain keystroke content (KeyChar).
                tracing::trace!(?event, "overlay event received");
                let ctrl_event = match event {
                    OverlayEvent::KeyChar(ch) => {
                        if dedup.accept(ch as u32, true) {
                            Some(Event::Char(ch))
                        } else {
                            None
                        }
                    }
                    OverlayEvent::Backspace => {
                        if dedup.accept(0xFF08, true) {
                            Some(Event::Backspace)
                        } else {
                            None
                        }
                    }
                    OverlayEvent::SelectionDown => {
                        if dedup.accept(0xFF54, true) {
                            Some(Event::SelectionDown)
                        } else {
                            None
                        }
                    }
                    OverlayEvent::SelectionUp => {
                        if dedup.accept(0xFF52, true) {
                            Some(Event::SelectionUp)
                        } else {
                            None
                        }
                    }
                    OverlayEvent::Confirm => {
                        if dedup.accept(0xFF0D, true) {
                            Some(Event::Confirm)
                        } else {
                            None
                        }
                    }
                    OverlayEvent::Escape => {
                        if dedup.accept(0xFF1B, true) {
                            Some(Event::Escape)
                        } else {
                            None
                        }
                    }
                    OverlayEvent::ModifierReleased => {
                        if dedup.accept(0xFFE9, false) {
                            Some(Event::ModifierReleased)
                        } else {
                            None
                        }
                    }
                    OverlayEvent::Dismiss => Some(Event::Dismiss),
                    OverlayEvent::SurfaceUnmapped => None,
                };
                if let Some(evt) = ctrl_event {
                    let win_list = windows.lock().await;
                    let cfg = wm_config.lock().await;
                    let cmds = controller.handle(evt, &win_list, &cfg);
                    drop(cfg);
                    drop(win_list);
                    daemon_wm::commands::execute_commands(
                        cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                        #[cfg(target_os = "linux")] &backend,
                        &mut client, &config_state,
                        &mut controller, &windows, &wm_config,
                        &mut ipc_keyboard_confirmed,
                        &mut password_buffer,
                    ).await;
                }
            }

            // Controller deadline (dwell timeout or activation timeout).
            _ = async {
                match deadline {
                    Some(dl) => tokio::time::sleep_until(tokio::time::Instant::from_std(dl)).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let win_list = windows.lock().await;
                let cfg = wm_config.lock().await;
                let cmds = controller.handle(Event::DwellTimeout, &win_list, &cfg);
                drop(cfg);
                drop(win_list);
                daemon_wm::commands::execute_commands(
                    cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                    #[cfg(target_os = "linux")] &backend,
                    &mut client, &config_state,
                    &mut controller, &windows, &wm_config,
                    &mut ipc_keyboard_confirmed,
                    &mut password_buffer,
                ).await;
            }

            // IPC bus messages.
            Some(msg) = client.recv() => {
                // Skip self-published messages to prevent feedback loops.
                if msg.sender == daemon_id {
                    continue;
                }

                let response_event = match &msg.payload {
                    EventKind::WmListWindows => {
                        let mut win_list = windows.lock().await.clone();
                        let mru_state = mru::load();
                        mru::reorder(&mut win_list, |w| w.id.to_string(), &mru_state);
                        Some(EventKind::WmListWindowsResponse { windows: win_list })
                    }

                    EventKind::WmActivateWindow { window_id } => {
                        let win_list = windows.lock().await;
                        let found_window_id = win_list.iter().find(|w| {
                            w.id.to_string() == *window_id
                                || w.app_id.as_str() == window_id
                        }).map(|w| w.id);

                        if let Some(wid) = found_window_id {
                            drop(win_list);
                            mru::save(window_id);

                            #[cfg(target_os = "linux")]
                            if let Some(ref backend) = backend
                                && let Err(e) = backend.activate_window(&wid).await
                            {
                                tracing::warn!(error = %e, "compositor activate_window failed");
                            }

                            tracing::info!(window_id, "window activated");
                            Some(EventKind::WmActivateWindowResponse { success: true })
                        } else {
                            drop(win_list);
                            tracing::warn!(window_id, "window not found for activation");
                            Some(EventKind::WmActivateWindowResponse { success: false })
                        }
                    }

                    EventKind::WmActivateOverlay => {
                        tracing::info!("overlay activation requested via IPC");
                        let win_list = windows.lock().await;
                        let cfg = wm_config.lock().await;
                        let cmds = controller.handle(Event::Activate, &win_list, &cfg);
                        drop(cfg);
                        drop(win_list);
                        daemon_wm::commands::execute_commands(
                            cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                            #[cfg(target_os = "linux")] &backend,
                            &mut client, &config_state,
                            &mut controller, &windows, &wm_config,
                            &mut ipc_keyboard_confirmed,
                            &mut password_buffer,
                        ).await;
                        None
                    }

                    EventKind::WmActivateOverlayBackward => {
                        tracing::info!("overlay activation (backward) requested via IPC");
                        let win_list = windows.lock().await;
                        let cfg = wm_config.lock().await;
                        let cmds = controller.handle(Event::ActivateBackward, &win_list, &cfg);
                        drop(cfg);
                        drop(win_list);
                        daemon_wm::commands::execute_commands(
                            cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                            #[cfg(target_os = "linux")] &backend,
                            &mut client, &config_state,
                            &mut controller, &windows, &wm_config,
                            &mut ipc_keyboard_confirmed,
                            &mut password_buffer,
                        ).await;
                        None
                    }

                    EventKind::WmActivateOverlayLauncherBackward => {
                        tracing::info!("launcher-mode overlay activation (backward) requested via IPC");
                        let win_list = windows.lock().await;
                        let cfg = wm_config.lock().await;
                        let cmds = controller.handle(Event::ActivateLauncherBackward, &win_list, &cfg);
                        drop(cfg);
                        drop(win_list);
                        daemon_wm::commands::execute_commands(
                            cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                            #[cfg(target_os = "linux")] &backend,
                            &mut client, &config_state,
                            &mut controller, &windows, &wm_config,
                            &mut ipc_keyboard_confirmed,
                            &mut password_buffer,
                        ).await;
                        None
                    }

                    EventKind::WmActivateOverlayLauncher => {
                        tracing::info!("launcher-mode overlay activation requested via IPC");
                        let win_list = windows.lock().await;
                        let cfg = wm_config.lock().await;
                        let cmds = controller.handle(Event::ActivateLauncher, &win_list, &cfg);
                        drop(cfg);
                        drop(win_list);
                        daemon_wm::commands::execute_commands(
                            cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                            #[cfg(target_os = "linux")] &backend,
                            &mut client, &config_state,
                            &mut controller, &windows, &wm_config,
                            &mut ipc_keyboard_confirmed,
                            &mut password_buffer,
                        ).await;
                        None
                    }

                    // Key rotation — reconnect with new keypair.
                    EventKind::KeyRotationPending { daemon_name, new_pubkey, grace_period_s }
                        if daemon_name == "daemon-wm" =>
                    {
                        tracing::info!(grace_period_s, "key rotation pending, will reconnect with new keypair");
                        match BusClient::handle_key_rotation(
                            "daemon-wm", daemon_id, &socket_path, &server_pub, new_pubkey,
                            vec!["wm".into(), "window-switcher".into()], env!("CARGO_PKG_VERSION"),
                        ).await {
                            Ok(new_client) => {
                                client = new_client;
                                tracing::info!("reconnected with rotated keypair");
                            }
                            Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
                        }
                        None
                    }

                    EventKind::InputKeyEvent { keyval, keycode: _, pressed, modifiers, unicode } => {
                        if !controller.is_idle() {
                            // On the first IPC key event this activation cycle,
                            // tell the overlay thread that keyboard input is
                            // working via IPC. This stops the stale activation
                            // timeout and Exclusive-mode hammering.
                            if !ipc_keyboard_confirmed {
                                ipc_keyboard_confirmed = true;
                                let _ = overlay_cmd_tx.send(OverlayCmd::ConfirmKeyboardInput);
                            }
                            if *pressed {
                                if dedup.accept(*keyval, true)
                                    && let Some(evt) = map_ipc_key_to_event(*keyval, *modifiers, *unicode)
                                {
                                    let win_list = windows.lock().await;
                                    let cfg = wm_config.lock().await;
                                    let cmds = controller.handle(evt, &win_list, &cfg);
                                    drop(cfg);
                                    drop(win_list);
                                    daemon_wm::commands::execute_commands(
                                        cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                                        #[cfg(target_os = "linux")] &backend,
                                        &mut client, &config_state,
                                        &mut controller, &windows, &wm_config,
                                        &mut ipc_keyboard_confirmed,
                                        &mut password_buffer,
                                    ).await;
                                }
                            } else {
                                // Key release — check for Alt/Meta release.
                                let is_alt = matches!(
                                    *keyval,
                                    0xFFE7..=0xFFEA // Meta_L, Meta_R, Alt_L, Alt_R
                                );
                                if is_alt && dedup.accept(*keyval, false) {
                                    let win_list = windows.lock().await;
                                    let cfg = wm_config.lock().await;
                                    let cmds = controller.handle(Event::ModifierReleased, &win_list, &cfg);
                                    drop(cfg);
                                    drop(win_list);
                                    daemon_wm::commands::execute_commands(
                                        cmds, &overlay_cmd_tx, &mut overlay_event_rx,
                                        #[cfg(target_os = "linux")] &backend,
                                        &mut client, &config_state,
                                        &mut controller, &windows, &wm_config,
                                        &mut ipc_keyboard_confirmed,
                                        &mut password_buffer,
                                    ).await;
                                }
                            }
                        }
                        None
                    }

                    // Ignore events not addressed to us.
                    _ => None,
                };

                if let Some(event) = response_event {
                    let response = Message::new(
                        &msg_ctx,
                        event,
                        msg.security_level,
                        client.epoch(),
                    )
                    .with_correlation(msg.msg_id);
                    if let Err(e) = client.send(&response).await {
                        tracing::warn!(error = %e, "failed to send response");
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                tracing::info!("config reloaded");
                let new_wm = {
                    let guard = config_state.read().map_err(|e| anyhow::anyhow!("{e}"))?;
                    guard
                        .profiles
                        .values()
                        .next()
                        .map(|p| p.wm.clone())
                        .unwrap_or_default()
                };

                let theme = OverlayTheme::from_config(&new_wm);
                let _ = overlay_cmd_tx.send(OverlayCmd::UpdateTheme(Box::new(theme)));

                *wm_config.lock().await = new_wm;

                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["wm".into()],
                    },
                    SecurityLevel::Internal,
                ).await.ok();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received, shutting down");
                break;
            }
            _ = sigterm() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
        }
    }

    // Shutdown overlay thread.
    let _ = overlay_cmd_tx.send(OverlayCmd::Quit);

    // Shutdown.
    client
        .publish(
            EventKind::DaemonStopped {
                daemon_id,
                reason: "shutdown".into(),
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    tracing::info!("daemon-wm shut down");
    Ok(())
}

/// Wait for SIGTERM (Unix).
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        sig.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

fn init_logging(format: &str) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    Ok(())
}
