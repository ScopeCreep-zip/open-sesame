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
use core_types::{DaemonId, EventKind, ProfileId, SecurityLevel, UnlockRejectedReason, Window};
use daemon_wm::controller::{Command, Event, OverlayController};
use daemon_wm::mru;
use daemon_wm::overlay::{self, OverlayCmd, OverlayEvent};
use daemon_wm::render::OverlayTheme;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Window manager daemon.
#[derive(Parser, Debug)]
#[command(name = "daemon-wm", about = "Window manager overlay daemon")]
struct Cli {
    /// Log format: "json" or "pretty".
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

// ---------------------------------------------------------------------------
// IPC keyboard event support
// ---------------------------------------------------------------------------

/// Tracks recently processed key events to deduplicate GTK4 and IPC sources.
///
/// When compositor keyboard focus is working, both the GTK4 `EventControllerKey`
/// and the IPC `InputKeyEvent` will fire for the same physical keystroke. This
/// ring buffer ensures only the first arrival is processed.
struct KeyDeduplicator {
    recent: [(u32, bool, u64); 8],
    idx: usize,
}

impl KeyDeduplicator {
    fn new() -> Self {
        Self {
            recent: [(0, false, 0); 8],
            idx: 0,
        }
    }

    /// Returns true if this event should be processed (not a duplicate).
    ///
    /// An event is a duplicate if an event with the same keyval and pressed
    /// state was processed within the last 50ms.
    fn accept(&mut self, keyval: u32, pressed: bool) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        for &(kv, pr, ts) in &self.recent {
            if kv == keyval && pr == pressed && now_ms.saturating_sub(ts) < 50 {
                return false;
            }
        }

        self.recent[self.idx] = (keyval, pressed, now_ms);
        self.idx = (self.idx + 1) % self.recent.len();
        true
    }
}

/// Map an IPC keyboard event (XKB keysym) to a controller Event.
///
/// Uses X11 keysym values which are identical to GDK key constants.
/// Returns None for keys that the overlay does not handle (space, modifiers, etc.).
fn map_ipc_key_to_event(keyval: u32, modifiers: u32, unicode: Option<char>) -> Option<Event> {
    const ESCAPE: u32 = 0xFF1B;
    const RETURN: u32 = 0xFF0D;
    const KP_ENTER: u32 = 0xFF8D;
    const TAB: u32 = 0xFF09;
    const DOWN: u32 = 0xFF54;
    const UP: u32 = 0xFF52;
    const BACKSPACE: u32 = 0xFF08;
    const SPACE: u32 = 0x0020;
    const SHIFT_MASK: u32 = 1 << 0;

    match keyval {
        ESCAPE => Some(Event::Escape),
        RETURN | KP_ENTER => Some(Event::Confirm),
        TAB => {
            if modifiers & SHIFT_MASK != 0 {
                Some(Event::SelectionUp)
            } else {
                Some(Event::SelectionDown)
            }
        }
        DOWN => Some(Event::SelectionDown),
        UP => Some(Event::SelectionUp),
        BACKSPACE => Some(Event::Backspace),
        SPACE => Some(Event::Char(' ')),
        _ => unicode.filter(|ch| ch.is_ascii_graphic() || *ch == ' ').map(Event::Char),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(&cli.log_format)?;

    tracing::info!("daemon-wm starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    // Load config.
    let config = core_config::load_config(None)
        .context("failed to load config")?;
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
        Some(Box::new(move || { let _ = reload_tx.blocking_send(()); })),
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Mutable config for hot-reload.
    let wm_config = Arc::new(Mutex::new(wm_config));

    // Connect to IPC bus: read keypair BEFORE sandbox.
    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key().await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);

    // Connect with keypair retry (daemon-profile may regenerate on crash-restart).
    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-wm", daemon_id, &socket_path, &server_pub, 5,
        std::time::Duration::from_millis(500),
    ).await.context("failed to connect to IPC bus")?;
    // ZeroizingKeypair: private key zeroized on drop (no manual zeroize needed).
    drop(_client_keypair);

    // Sandbox (Linux) — applied AFTER keypair read + connect, BEFORE IPC traffic.
    #[cfg(target_os = "linux")]
    apply_sandbox();

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
                                    let _ = win_tx.blocking_send(win_list);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "failed to refresh window list");
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
                                        geometry: core_types::Geometry { x: 0, y: 0, width: 0, height: 0 },
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

    let (overlay_cmd_tx, mut overlay_event_rx) = {
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
    let mut password_buffer = SecureVec::with_capacity(128);

    // Platform readiness.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-wm ready, entering event loop");

    // Watchdog timer: half the WatchdogSec=30 interval.
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // -----------------------------------------------------------------------
    // Event loop — thin orchestrator
    // -----------------------------------------------------------------------
    loop {
        // Compute the controller's next deadline for dwell/activation timeout.
        let deadline = controller.next_deadline();

        tokio::select! {
            // Biased: overlay events always polled before deadline timer.
            biased;

            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }

            // Overlay keyboard events — highest priority.
            Some(event) = overlay_event_rx.recv() => {
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
                    execute_commands(
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
                execute_commands(
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
                        let win_list = windows.lock().await.clone();
                        Some(EventKind::WmListWindowsResponse { windows: win_list })
                    }

                    EventKind::WmActivateWindow { window_id } => {
                        let win_list = windows.lock().await;
                        let found_window_id = win_list.iter().find(|w| {
                            w.id.to_string() == *window_id
                                || w.app_id.as_str() == window_id
                        }).map(|w| w.id);

                        if let Some(wid) = found_window_id {
                            let origin = win_list.iter()
                                .find(|w| w.is_focused)
                                .map(|w| w.id.to_string());
                            drop(win_list);
                            mru::save(origin.as_deref(), window_id);

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
                        execute_commands(
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
                        execute_commands(
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
                        execute_commands(
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
                                    execute_commands(
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
                                    execute_commands(
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

// ---------------------------------------------------------------------------
// Command executor — dumb switch, no decisions
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn execute_commands(
    commands: Vec<Command>,
    overlay_cmd_tx: &std::sync::mpsc::Sender<OverlayCmd>,
    overlay_event_rx: &mut tokio::sync::mpsc::Receiver<OverlayEvent>,
    #[cfg(target_os = "linux")] backend: &Option<Arc<Box<dyn platform_linux::compositor::CompositorBackend>>>,
    client: &mut BusClient,
    config_state: &std::sync::Arc<std::sync::RwLock<core_config::Config>>,
    controller: &mut daemon_wm::controller::OverlayController,
    windows: &Arc<Mutex<Vec<core_types::Window>>>,
    wm_config: &Arc<Mutex<core_config::WmConfig>>,
    ipc_keyboard_confirmed: &mut bool,
    password_buffer: &mut SecureVec,
) {
    for cmd in commands {
        match cmd {
            Command::ShowBorder => {
                // Reset IPC keyboard confirmation for new activation cycle.
                *ipc_keyboard_confirmed = false;
                if overlay_cmd_tx.send(OverlayCmd::ShowBorder).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
                // Request keyboard event forwarding from daemon-input.
                client.publish(
                    EventKind::InputGrabRequest { requester: client.daemon_id() },
                    SecurityLevel::Internal,
                ).await.ok();
            }
            Command::ShowPicker { windows, hints } => {
                if overlay_cmd_tx.send(OverlayCmd::ShowFull { windows, hints }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::UpdatePicker { input, selection } => {
                if overlay_cmd_tx.send(OverlayCmd::UpdateInput { input, selection }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::HideAndSync => {
                // Release keyboard grab BEFORE hiding — daemon-input stops forwarding.
                client.publish(
                    EventKind::InputGrabRelease { requester: client.daemon_id() },
                    SecurityLevel::Internal,
                ).await.ok();

                if overlay_cmd_tx.send(OverlayCmd::HideAndSync).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                    continue;
                }
                while let Some(ev) = overlay_event_rx.recv().await {
                    if matches!(ev, OverlayEvent::SurfaceUnmapped) {
                        break;
                    }
                }
            }
            Command::Hide => {
                client.publish(
                    EventKind::InputGrabRelease { requester: client.daemon_id() },
                    SecurityLevel::Internal,
                ).await.ok();

                if overlay_cmd_tx.send(OverlayCmd::Hide).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ActivateWindow { window, origin } => {
                let target_id = window.id.to_string();
                mru::save(origin.as_deref(), &target_id);

                #[cfg(target_os = "linux")]
                let activate_ok = if let Some(backend) = backend {
                    match backend.activate_window(&window.id).await {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::warn!(error = %e, target = %target_id, "compositor activate_window failed");
                            false
                        }
                    }
                } else {
                    true
                };

                #[cfg(not(target_os = "linux"))]
                let activate_ok = true;

                if activate_ok {
                    tracing::info!(target = %target_id, app_id = %window.app_id, "window activated via overlay");
                }
            }
            Command::LaunchApp { command, tags, launch_args } => {
                tracing::info!(command = %command, ?tags, ?launch_args, "launch-or-focus: launching app");

                // Release keyboard grab — no more key forwarding needed.
                client.publish(
                    EventKind::InputGrabRelease { requester: client.daemon_id() },
                    SecurityLevel::Internal,
                ).await.ok();

                // Keep the "Launching..." toast visible during the IPC request.
                // The overlay runs on a separate GTK4 thread so it keeps rendering
                // while tokio blocks on the launch request. This gives the user
                // visual feedback that the action was received.
                // (ShowLaunching was already sent by the controller before this command.)

                // Capture retry context before moving into IPC request.
                let retry_command = command.clone();
                let retry_tags = tags.clone();
                let retry_launch_args = launch_args.clone();

                let active_profile = {
                    let cfg_guard = config_state.read().ok();
                    cfg_guard.and_then(|c| {
                        core_types::TrustProfileName::try_from(
                            c.global.default_profile.as_ref()
                        ).ok()
                    })
                };
                let result = client.request(
                    EventKind::LaunchExecute {
                        entry_id: command,
                        profile: active_profile,
                        tags,
                        launch_args,
                    },
                    SecurityLevel::Internal,
                    std::time::Duration::from_secs(10),
                ).await;

                let launch_event = match result {
                    Ok(msg) => match msg.payload {
                        EventKind::LaunchExecuteResponse { pid, error, denial } => {
                            if pid > 0 && error.is_none() && denial.is_none() {
                                daemon_wm::controller::Event::LaunchResult {
                                    success: true,
                                    error: None,
                                    denial: None,
                                    original_command: None,
                                    original_tags: None,
                                    original_launch_args: None,
                                }
                            } else {
                                daemon_wm::controller::Event::LaunchResult {
                                    success: false,
                                    error: error.or_else(|| Some("launch failed".into())),
                                    denial,
                                    original_command: Some(retry_command.clone()),
                                    original_tags: Some(retry_tags.clone()),
                                    original_launch_args: Some(retry_launch_args.clone()),
                                }
                            }
                        }
                        _ => daemon_wm::controller::Event::LaunchResult {
                            success: false,
                            error: Some("unexpected response from launcher".into()),
                            denial: None,
                            original_command: None,
                            original_tags: None,
                            original_launch_args: None,
                        },
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "launch request failed");
                        daemon_wm::controller::Event::LaunchResult {
                            success: false,
                            error: Some(format!("IPC error: {e}")),
                            denial: None,
                            original_command: None,
                            original_tags: None,
                            original_launch_args: None,
                        }
                    }
                };

                let win_list = windows.lock().await;
                let cfg = wm_config.lock().await;
                let result_cmds = controller.handle(launch_event, &win_list, &cfg);
                drop(cfg);
                drop(win_list);
                // Process launch result commands via the full command executor.
                // This handles all command variants including unlock flow
                // commands (AttemptAutoUnlock, ShowPasswordPrompt, etc.)
                // emitted when the launcher returns VaultsLocked denial.
                Box::pin(execute_commands(
                    result_cmds, overlay_cmd_tx, overlay_event_rx,
                    #[cfg(target_os = "linux")] backend,
                    client, config_state, controller, windows, wm_config,
                    ipc_keyboard_confirmed,
                    password_buffer,
                )).await;
            }
            Command::ShowLaunchStaged { command } => {
                if overlay_cmd_tx.send(OverlayCmd::ShowLaunchStaged { command }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ResetGrace => {
                if overlay_cmd_tx.send(OverlayCmd::ResetGrace).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowLaunching => {
                if overlay_cmd_tx.send(OverlayCmd::ShowLaunching).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowLaunchError { message, .. } => {
                if overlay_cmd_tx.send(OverlayCmd::ShowLaunchError { message }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::Publish(event, level) => {
                client.publish(event, level).await.ok();
            }
            // -- Unlock flow commands --
            //
            // The AttemptAutoUnlock handler cannot be unit-tested in isolation
            // because it requires a live IPC bus (BusClient), a running
            // daemon-secrets for the request/response cycle, and filesystem
            // access for salt files and enrollment blobs. The underlying
            // crypto round-trip is covered by core-auth's
            // `full_enrollment_unlock_round_trip` test. The controller's
            // state machine transitions for AutoUnlockResult are covered
            // by the controller unit tests in controller.rs.
            Command::AttemptAutoUnlock { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "auto-unlock-attempt",
                    %profile,
                    "attempting auto-unlock for vault"
                );

                let config_dir = core_config::config_dir();
                let salt_path = config_dir.join("vaults").join(format!("{profile}.salt"));
                let salt = tokio::fs::read(&salt_path).await.ok();

                let (success, needs_touch) = if let Some(salt_bytes) = &salt {
                    let auth = core_auth::AuthDispatcher::new();
                    if let Some(auto_backend) = auth.find_auto_backend(&profile, &config_dir).await {
                        match auto_backend.unlock(&profile, &config_dir, salt_bytes).await {
                            Ok(outcome) => {
                                let fp = outcome.audit_metadata.get("ssh_fingerprint")
                                    .cloned().unwrap_or_default();
                                // Transfer master key bytes without creating an
                                // unprotected intermediate copy.
                                let event = core_types::EventKind::SshUnlockRequest {
                                    master_key: core_types::SensitiveBytes::new(
                                        outcome.master_key.into_vec()
                                    ),
                                    profile: profile.clone(),
                                    ssh_fingerprint: fp.clone(),
                                };
                                // Use request() (RPC with response) instead of
                                // publish() (fire-and-forget) so we confirm
                                // daemon-secrets actually accepted the master key.
                                // 30s timeout accommodates Argon2id KDF parameters.
                                match client.request(
                                    event,
                                    core_types::SecurityLevel::SecretsOnly,
                                    std::time::Duration::from_secs(30),
                                ).await {
                                    Ok(msg) => match msg.payload {
                                        EventKind::UnlockResponse { success: true, .. } => {
                                            tracing::info!(%profile, %fp, "SSH auto-unlock accepted by daemon-secrets");
                                            (true, false)
                                        }
                                        EventKind::UnlockRejected {
                                            reason: UnlockRejectedReason::AlreadyUnlocked, ..
                                        } => {
                                            tracing::info!(%profile, "vault already unlocked, treating as success");
                                            (true, false)
                                        }
                                        EventKind::UnlockResponse { success: false, .. } => {
                                            tracing::warn!(%profile, "SSH auto-unlock rejected by daemon-secrets");
                                            (false, false)
                                        }
                                        other => {
                                            tracing::warn!(%profile, ?other, "unexpected response to SshUnlockRequest");
                                            (false, false)
                                        }
                                    },
                                    Err(e) => {
                                        tracing::error!(error = %e, %profile, "SshUnlockRequest IPC failed");
                                        (false, false)
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, %profile, audit = "unlock-flow", "auto-unlock backend failed, falling back to password");
                                (false, false)
                            }
                        }
                    } else {
                        tracing::info!(%profile, audit = "unlock-flow", "no auto-unlock backend available (not enrolled or agent unavailable)");
                        (false, false)
                    }
                } else {
                    tracing::warn!(%profile, audit = "unlock-flow", "no salt file found, cannot attempt auto-unlock");
                    (false, false)
                };

                let win_list = windows.lock().await;
                let cfg = wm_config.lock().await;
                let sub_cmds = controller.handle(
                    daemon_wm::controller::Event::AutoUnlockResult {
                        success,
                        profile,
                        needs_touch,
                    },
                    &win_list,
                    &cfg,
                );
                drop(cfg);
                drop(win_list);
                Box::pin(execute_commands(
                    sub_cmds, overlay_cmd_tx, overlay_event_rx,
                    #[cfg(target_os = "linux")] backend,
                    client, config_state, controller, windows, wm_config,
                    ipc_keyboard_confirmed,
                    password_buffer,
                )).await;
            }
            Command::ShowPasswordPrompt { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "password-prompt-shown",
                    %profile,
                    "showing password prompt for vault unlock"
                );
                // Re-acquire keyboard grab for password input. The LaunchApp
                // handler releases the grab before the IPC request, but the
                // VaultsLocked fallback needs keyboard input for password entry.
                *ipc_keyboard_confirmed = false;
                client.publish(
                    EventKind::InputGrabRequest { requester: client.daemon_id() },
                    SecurityLevel::Internal,
                ).await.ok();
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockPrompt {
                    profile: profile.to_string(),
                    password_len: 0,
                    error: None,
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowTouchPrompt { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "touch-prompt-shown",
                    %profile,
                    "showing touch prompt for vault unlock"
                );
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockProgress {
                    profile: profile.to_string(),
                    message: format!("Touch your security key for \u{201C}{profile}\u{201D}\u{2026}"),
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowAutoUnlockProgress { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "auto-unlock-progress",
                    %profile,
                    "showing auto-unlock progress"
                );
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockProgress {
                    profile: profile.to_string(),
                    message: format!("Authenticating \u{201C}{profile}\u{201D}\u{2026}"),
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowVerifying => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "verifying",
                    "showing verification progress for vault unlock"
                );
                let profile = controller.current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockProgress {
                    profile,
                    message: "Verifying\u{2026}".into(),
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::PasswordChar(ch) => {
                password_buffer.push_char(ch);
                let profile = controller.current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockPrompt {
                    profile,
                    password_len: password_buffer.char_count(),
                    error: None,
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::PasswordBackspace => {
                password_buffer.pop_char();
                let profile = controller.current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockPrompt {
                    profile,
                    password_len: password_buffer.char_count(),
                    error: None,
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::SubmitPasswordUnlock { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "password-unlock-submit",
                    %profile,
                    "submitting password unlock for vault"
                );

                // Show "Verifying..." overlay BEFORE the IPC round-trip so the
                // user sees immediate feedback. This must happen here (not as a
                // separate Command after SubmitPasswordUnlock) because the IPC
                // call and its recursive result processing happen inline — a
                // ShowVerifying command after this one would execute AFTER the
                // unlock result is already processed and displayed.
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockProgress {
                    profile: profile.to_string(),
                    message: "Verifying\u{2026}".into(),
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }

                let password_bytes = password_buffer.take();

                if password_bytes.is_empty() {
                    tracing::warn!(%profile, "empty password buffer on submit");
                    let win_list = windows.lock().await;
                    let cfg = wm_config.lock().await;
                    let sub_cmds = controller.handle(
                        daemon_wm::controller::Event::UnlockResult {
                            success: false,
                            profile,
                        },
                        &win_list,
                        &cfg,
                    );
                    drop(cfg);
                    drop(win_list);
                    Box::pin(execute_commands(
                        sub_cmds, overlay_cmd_tx, overlay_event_rx,
                        #[cfg(target_os = "linux")] backend,
                        client, config_state, controller, windows, wm_config,
                        ipc_keyboard_confirmed,
                        password_buffer,
                    )).await;
                    continue;
                }

                // SensitiveBytes wraps the password and zeroizes on drop.
                let unlock_event = EventKind::UnlockRequest {
                    password: core_types::SensitiveBytes::new(password_bytes),
                    profile: Some(profile.clone()),
                };

                // 30s timeout accommodates Argon2id KDF with high memory parameters.
                let result = client.request(
                    unlock_event,
                    SecurityLevel::Internal,
                    std::time::Duration::from_secs(30),
                ).await;

                let unlock_result = match result {
                    Ok(msg) => match msg.payload {
                        EventKind::UnlockResponse { success, profile: resp_profile } => {
                            daemon_wm::controller::Event::UnlockResult {
                                success,
                                profile: resp_profile,
                            }
                        }
                        EventKind::UnlockRejected { reason, profile: resp_profile } => {
                            let already = reason == UnlockRejectedReason::AlreadyUnlocked;
                            if already {
                                tracing::info!(?resp_profile, "vault already unlocked, treating as success");
                            } else {
                                tracing::info!(?reason, ?resp_profile, "unlock rejected");
                            }
                            daemon_wm::controller::Event::UnlockResult {
                                success: already,
                                profile: resp_profile.unwrap_or(profile),
                            }
                        }
                        other => {
                            tracing::warn!(?other, "unexpected response to UnlockRequest");
                            daemon_wm::controller::Event::UnlockResult {
                                success: false,
                                profile,
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "unlock request failed");
                        daemon_wm::controller::Event::UnlockResult {
                            success: false,
                            profile,
                        }
                    }
                };

                let win_list = windows.lock().await;
                let cfg = wm_config.lock().await;
                let sub_cmds = controller.handle(unlock_result, &win_list, &cfg);
                drop(cfg);
                drop(win_list);
                Box::pin(execute_commands(
                    sub_cmds, overlay_cmd_tx, overlay_event_rx,
                    #[cfg(target_os = "linux")] backend,
                    client, config_state, controller, windows, wm_config,
                    ipc_keyboard_confirmed,
                    password_buffer,
                )).await;
            }
            Command::ClearPasswordBuffer => {
                password_buffer.clear();
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "password-buffer-cleared",
                    "password buffer cleared and zeroized"
                );
            }
            Command::ActivateProfiles { profiles } => {
                for profile_name in &profiles {
                    let target = ProfileId::new();
                    let activate_event = EventKind::ProfileActivate {
                        target,
                        profile_name: profile_name.clone(),
                    };
                    tracing::info!(
                        audit = "unlock-flow",
                        event_type = "profile-activate",
                        %profile_name,
                        "activating profile after vault unlock"
                    );
                    match client.request(
                        activate_event,
                        SecurityLevel::Internal,
                        std::time::Duration::from_secs(10),
                    ).await {
                        Ok(msg) => match msg.payload {
                            EventKind::ProfileActivateResponse { success: true } => {
                                tracing::info!(
                                    audit = "unlock-flow",
                                    event_type = "profile-activated",
                                    %profile_name,
                                    "profile activated successfully"
                                );
                            }
                            EventKind::ProfileActivateResponse { success: false } => {
                                tracing::error!(
                                    audit = "unlock-flow",
                                    event_type = "profile-activate-failed",
                                    %profile_name,
                                    "profile activation rejected by daemon-profile"
                                );
                            }
                            other => {
                                tracing::warn!(?other, %profile_name, "unexpected response to ProfileActivate");
                            }
                        },
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                %profile_name,
                                "profile activation IPC failed"
                            );
                        }
                    }
                }
            }
            Command::ShowUnlockError { message } => {
                tracing::warn!(
                    audit = "unlock-flow",
                    event_type = "unlock-error",
                    %message,
                    "unlock error displayed to user"
                );
                let profile = controller.current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx.send(OverlayCmd::ShowUnlockPrompt {
                    profile,
                    password_len: password_buffer.char_count(),
                    error: Some(message),
                }).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
        }
    }
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
        apply_sandbox_with_scope, FsAccess, LandlockRule, LandlockScope, SeccompProfile,
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| "/run/user/1000".into());

    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("open-sesame");

    let pds_dir = std::path::PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    let mut rules = vec![
        LandlockRule {
            path: keys_dir.clone(),
            access: FsAccess::ReadOnly,
        },
        // Bus public key: needed if reconnect ever happens.
        LandlockRule {
            path: pds_dir.join("bus.pub"),
            access: FsAccess::ReadOnly,
        },
        // Bus socket: connect + read/write IPC traffic.
        LandlockRule {
            path: pds_dir.join("bus.sock"),
            access: FsAccess::ReadWriteFile,
        },
        // Wayland socket access (use $WAYLAND_DISPLAY, default wayland-1 for COSMIC).
        // ReadWriteFile because the socket is a non-directory fd — directory-only
        // landlock flags (ReadDir, MakeDir, etc.) cause PartiallyEnforced.
        LandlockRule {
            path: std::path::PathBuf::from(&runtime_dir).join(
                std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-1".into()),
            ),
            access: FsAccess::ReadWriteFile,
        },
        // MRU state file.
        LandlockRule {
            path: cache_dir,
            access: FsAccess::ReadWrite,
        },
        // Fontconfig (read-only).
        LandlockRule {
            path: std::path::PathBuf::from("/etc/fonts"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: std::path::PathBuf::from("/usr/share/fonts"),
            access: FsAccess::ReadOnly,
        },
        // COSMIC desktop theme (read-only, for native theme integration).
        LandlockRule {
            path: dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/nonexistent"))
                .join("cosmic"),
            access: FsAccess::ReadOnly,
        },
        // Nix store (read-only, GTK4/GLib shared libs, schemas, locale data, XKB).
        LandlockRule {
            path: std::path::PathBuf::from("/nix/store"),
            access: FsAccess::ReadOnly,
        },
        // /proc (read-only, xdg-desktop-portal needs /proc/PID/root for verification).
        LandlockRule {
            path: std::path::PathBuf::from("/proc"),
            access: FsAccess::ReadOnly,
        },
        // D-Bus session socket (GTK4 portal communication).
        LandlockRule {
            path: std::path::PathBuf::from(&runtime_dir).join("bus"),
            access: FsAccess::ReadWriteFile,
        },
        // System shared data (GTK schemas, icons, mime, locale).
        LandlockRule {
            path: std::path::PathBuf::from("/usr/share"),
            access: FsAccess::ReadOnly,
        },
        // XKB system rules (evdev on non-NixOS).
        LandlockRule {
            path: std::path::PathBuf::from("/usr/share/X11/xkb"),
            access: FsAccess::ReadOnly,
        },
        // GDK/GTK user data.
        LandlockRule {
            path: dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/nonexistent")),
            access: FsAccess::ReadOnly,
        },
        // DRI devices: GPU-accelerated rendering for GTK4/Cairo overlay.
        // Without this, GTK4 falls back to software rendering (llvmpipe) which
        // takes ~5 seconds per frame vs <16ms with hardware acceleration.
        LandlockRule {
            path: std::path::PathBuf::from("/dev/dri"),
            access: FsAccess::ReadWrite,
        },
        // sysfs (GPU driver discovery): Mesa's DRI loader resolves kernel
        // driver names via /sys/dev/char/226:* → /sys/devices/pci*/*/drm/*
        // → device/driver symlink. Four subtrees cover all GPU topologies
        // without exposing unrelated kernel state.
        LandlockRule {
            path: std::path::PathBuf::from("/sys/dev/char"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: std::path::PathBuf::from("/sys/class/drm"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: std::path::PathBuf::from("/sys/devices"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: std::path::PathBuf::from("/sys/bus"),
            access: FsAccess::ReadOnly,
        },
        // GTK4 user CSS (theme overrides).
        LandlockRule {
            path: dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/nonexistent"))
                .join("gtk-4.0"),
            access: FsAccess::ReadOnly,
        },
        // PDS vaults directory: salt files and SSH enrollment blobs needed
        // for auto-unlock (SSH-agent backend reads salt + blob at unlock time).
        LandlockRule {
            path: core_config::config_dir().join("vaults"),
            access: FsAccess::ReadOnly,
        },
    ];

    // SSH agent socket: needed for SSH-agent auto-unlock (can_unlock + sign).
    // Only added if $SSH_AUTH_SOCK is set and the socket exists.
    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        let sock_path = std::path::PathBuf::from(&sock);
        if sock_path.exists() {
            rules.push(LandlockRule {
                path: sock_path,
                access: FsAccess::ReadWriteFile,
            });
        }
    }

    let seccomp = SeccompProfile {
        daemon_name: "daemon-wm".into(),
        allowed_syscalls: vec![
            // I/O basics
            "read".into(), "write".into(), "close".into(),
            "openat".into(), "lseek".into(), "pread64".into(),
            "fstat".into(), "stat".into(), "newfstatat".into(),
            "statx".into(), "access".into(), "fcntl".into(),
            "flock".into(), "ftruncate".into(), "mkdir".into(),
            "rename".into(), "chmod".into(), "fchmod".into(),
            "fsync".into(), "fdatasync".into(), "ioctl".into(),
            "getdents64".into(),
            // Memory
            "mmap".into(), "mprotect".into(), "munmap".into(),
            "madvise".into(), "brk".into(),
            // Process / threading
            "futex".into(), "clone3".into(), "clone".into(),
            "set_robust_list".into(), "set_tid_address".into(),
            "rseq".into(), "sched_getaffinity".into(),
            "prlimit64".into(), "prctl".into(),
            "getpid".into(), "gettid".into(), "getuid".into(), "geteuid".into(),
            "getresuid".into(), "getresgid".into(), "getgid".into(), "getegid".into(),
            "kill".into(),
            // Epoll / event loop (tokio)
            "epoll_wait".into(), "epoll_ctl".into(),
            "epoll_create1".into(), "eventfd2".into(),
            "poll".into(), "ppoll".into(),
            // Timers (tokio runtime)
            "clock_gettime".into(), "timer_create".into(),
            "timer_settime".into(), "timer_delete".into(),
            // Networking / IPC (Wayland compositor protocol)
            "socket".into(), "connect".into(), "sendto".into(),
            "recvfrom".into(), "recvmsg".into(), "sendmsg".into(),
            "getsockname".into(), "getpeername".into(),
            "setsockopt".into(), "socketpair".into(),
            "shutdown".into(), "getsockopt".into(),
            // Signals
            "sigaltstack".into(), "rt_sigaction".into(),
            "rt_sigprocmask".into(), "rt_sigreturn".into(),
            "tgkill".into(),
            // GTK4/GLib runtime
            "inotify_init1".into(), "inotify_add_watch".into(), "inotify_rm_watch".into(),
            "statfs".into(), "fstatfs".into(), "memfd_create".into(),
            "writev".into(), "readv".into(),
            "readlink".into(), "readlinkat".into(), "uname".into(),
            "accept4".into(), "bind".into(), "listen".into(),
            "nanosleep".into(), "clock_nanosleep".into(), "sched_yield".into(),
            "timerfd_create".into(), "timerfd_settime".into(), "timerfd_gettime".into(),
            "mlock".into(), "mlock2".into(), "mremap".into(),
            "unlink".into(), "sched_get_priority_max".into(),
            // Misc
            "exit_group".into(), "exit".into(), "getrandom".into(),
            "restart_syscall".into(), "getcwd".into(),
            "pipe2".into(), "dup".into(), "ioctl".into(),
        ],
    };

    // daemon-wm needs D-Bus for GTK4 portal communication — use SignalOnly
    // scope to allow abstract Unix sockets while still blocking cross-process signals.
    match apply_sandbox_with_scope(&rules, &seccomp, LandlockScope::SignalOnly) {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // map_ipc_key_to_event
    // ============================================================================

    #[test]
    fn map_escape() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF1B, 0, None),
            Some(Event::Escape)
        ));
    }

    #[test]
    fn map_return() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF0D, 0, None),
            Some(Event::Confirm)
        ));
    }

    #[test]
    fn map_kp_enter() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF8D, 0, None),
            Some(Event::Confirm)
        ));
    }

    #[test]
    fn map_tab_forward() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF09, 0, None),
            Some(Event::SelectionDown)
        ));
    }

    #[test]
    fn map_tab_with_shift() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF09, 1, None),
            Some(Event::SelectionUp)
        ));
    }

    #[test]
    fn map_down_arrow() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF54, 0, None),
            Some(Event::SelectionDown)
        ));
    }

    #[test]
    fn map_up_arrow() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF52, 0, None),
            Some(Event::SelectionUp)
        ));
    }

    #[test]
    fn map_backspace() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF08, 0, None),
            Some(Event::Backspace)
        ));
    }

    #[test]
    fn map_space_is_char() {
        assert!(matches!(
            map_ipc_key_to_event(0x0020, 0, Some(' ')),
            Some(Event::Char(' '))
        ));
    }

    #[test]
    fn map_alphanumeric_char() {
        assert!(matches!(
            map_ipc_key_to_event(0x0067, 0, Some('g')),
            Some(Event::Char('g'))
        ));
    }

    #[test]
    fn map_printable_non_alphanumeric_accepted() {
        // Printable ASCII like '/' should now pass through to controller.
        assert!(matches!(
            map_ipc_key_to_event(0x002F, 0, Some('/')),
            Some(Event::Char('/'))
        ));
    }

    #[test]
    fn map_modifier_key_ignored() {
        // Alt_L keysym — no unicode, should be None.
        assert!(map_ipc_key_to_event(0xFFE9, 0, None).is_none());
    }

    // ============================================================================
    // KeyDeduplicator
    // ============================================================================

    #[test]
    fn dedup_accepts_first() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_rejects_immediate_duplicate() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(!dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_accepts_different_key() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(dedup.accept(0x68, true));
    }

    #[test]
    fn dedup_accepts_same_key_different_direction() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(dedup.accept(0x67, false));
    }

    #[test]
    fn dedup_accepts_after_window_expires() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_ring_buffer_wraps() {
        let mut dedup = KeyDeduplicator::new();
        // Fill the ring buffer (8 entries).
        for i in 0..8 {
            assert!(dedup.accept(i, true));
        }
        // 9th entry wraps — still accepted because it's a different key.
        assert!(dedup.accept(8, true));
    }
}
