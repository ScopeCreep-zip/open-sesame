//! daemon-wm: Wayland overlay window switcher daemon.
//!
//! Tracks open windows via wlr-foreign-toplevel-management-v1, maintains MRU
//! ordering, and serves WmListWindows/WmActivateWindow RPC requests over the
//! encrypted IPC bus. When activated (via WmActivateOverlay IPC), drives the
//! overlay lifecycle through the state machine: border-only phase, full overlay
//! with letter hints, hint matching, selection, and window activation via the
//! compositor backend.
//!
//! Landlock: Wayland socket, fontconfig, cache dir (MRU state).
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, SecurityLevel, Window};
use daemon_wm::hints::{self, MatchResult};
use daemon_wm::mru;
use daemon_wm::overlay::{self, OverlayCmd, OverlayEvent, WindowInfo};
use daemon_wm::render::OverlayTheme;
use daemon_wm::state::{Action, WmState};
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
    // Per-daemon Landlock key file isolation.
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
                tokio::spawn(async move {
                    loop {
                        match poll_backend.list_windows().await {
                            Ok(win_list) => {
                                *win_ref.lock().await = win_list;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to refresh window list");
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                });
                Some(arc)
            }
            Err(e) => {
                tracing::warn!(error = %e, "compositor backend detection failed, falling back to focus_monitor");
                let win_ref = Arc::clone(&windows);
                tokio::spawn(async move {
                    use platform_linux::compositor::FocusEvent;
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
                                        workspace_id: core_types::WorkspaceId::new(),
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
    // State machine lives on the tokio thread. Overlay GTK4 surface on a
    // dedicated thread, communicating via channels.
    let mut wm_state = WmState::new();
    let mut current_hints: Vec<String> = Vec::new();
    let mut current_windows: Vec<Window> = Vec::new();

    let (overlay_cmd_tx, mut overlay_event_rx) = {
        let cfg = wm_config.lock().await;
        let theme = OverlayTheme::from_config(&cfg);
        let show_app_id = cfg.show_app_id;
        let show_title = cfg.show_title;
        drop(cfg);
        overlay::spawn_overlay(theme, show_app_id, show_title)
    };

    // Border-only -> FullOverlay transition timer.
    let mut border_tick: Option<tokio::time::Interval> = None;
    // PendingActivation timeout timer.
    let mut activation_tick: Option<tokio::time::Interval> = None;

    // Platform readiness.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-wm ready, entering event loop");

    // Watchdog timer: half the WatchdogSec=30 interval.
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // Event loop.
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }

            // Border-only frame tick — drives overlay_delay transition.
            Some(()) = async {
                if let Some(ref mut tick) = border_tick {
                    tick.tick().await;
                    Some(())
                } else {
                    std::future::pending::<Option<()>>().await
                }
            } => {
                let cfg = wm_config.lock().await;
                let action = wm_state.on_frame(cfg.overlay_delay_ms);
                drop(cfg);
                handle_action(
                    &action, &mut wm_state, &wm_config, &windows,
                    &mut current_hints, &mut current_windows,
                    &overlay_cmd_tx, &mut overlay_event_rx,
                    #[cfg(target_os = "linux")] &backend,
                    &mut client,
                    &mut border_tick, &mut activation_tick,
                ).await;
            }

            // PendingActivation timeout tick.
            Some(()) = async {
                if let Some(ref mut tick) = activation_tick {
                    tick.tick().await;
                    Some(())
                } else {
                    std::future::pending::<Option<()>>().await
                }
            } => {
                let cfg = wm_config.lock().await;
                let action = wm_state.check_activation_timeout(cfg.activation_delay_ms);
                drop(cfg);
                handle_action(
                    &action, &mut wm_state, &wm_config, &windows,
                    &mut current_hints, &mut current_windows,
                    &overlay_cmd_tx, &mut overlay_event_rx,
                    #[cfg(target_os = "linux")] &backend,
                    &mut client,
                    &mut border_tick, &mut activation_tick,
                ).await;
            }

            // Overlay keyboard events.
            Some(event) = overlay_event_rx.recv() => {
                let action = {
                    let cfg = wm_config.lock().await;
                    match event {
                        OverlayEvent::KeyChar(ch) => {
                            let action = wm_state.on_char(ch);
                            // If transitioning from BorderOnly, dispatch ShowOverlay
                            // first to populate hints before checking for match.
                            if action == Action::ShowOverlay {
                                drop(cfg);
                                handle_action(
                                    &action, &mut wm_state, &wm_config, &windows,
                                    &mut current_hints, &mut current_windows,
                                    &overlay_cmd_tx, &mut overlay_event_rx,
                                    #[cfg(target_os = "linux")] &backend,
                                    &mut client,
                                    &mut border_tick, &mut activation_tick,
                                ).await;
                                // Now check for hint match with populated hints.
                                if let Some(input) = wm_state.input_buffer() {
                                    let match_action = match hints::match_input(input, &current_hints) {
                                        MatchResult::Exact(idx) => wm_state.on_hint_match(idx),
                                        _ => Action::Redraw,
                                    };
                                    handle_action(
                                        &match_action, &mut wm_state, &wm_config, &windows,
                                        &mut current_hints, &mut current_windows,
                                        &overlay_cmd_tx, &mut overlay_event_rx,
                                        #[cfg(target_os = "linux")] &backend,
                                        &mut client,
                                        &mut border_tick, &mut activation_tick,
                                    ).await;
                                }
                                continue;
                            }
                            // Check for hint match after character input.
                            if let Some(input) = wm_state.input_buffer() {
                                match hints::match_input(input, &current_hints) {
                                    MatchResult::Exact(idx) => wm_state.on_hint_match(idx),
                                    MatchResult::NoMatch => {
                                        // Launch-or-focus: if input is a single key with a launch command
                                        // and no windows matched, launch the app.
                                        if input.len() == 1 {
                                            let key = input.chars().next().unwrap();
                                            if let Some(cmd) = hints::launch_for_key(key, &cfg.key_bindings) {
                                                Action::LaunchApp(cmd.to_string())
                                            } else {
                                                action
                                            }
                                        } else {
                                            action
                                        }
                                    }
                                    _ => action,
                                }
                            } else {
                                action
                            }
                        }
                        OverlayEvent::Backspace => wm_state.on_backspace(),
                        OverlayEvent::SelectionDown => wm_state.on_selection_down(),
                        OverlayEvent::SelectionUp => wm_state.on_selection_up(),
                        OverlayEvent::Confirm => wm_state.on_confirm(),
                        OverlayEvent::Escape => wm_state.on_escape(),
                        OverlayEvent::ModifierReleased => {
                            wm_state.on_modifier_release(cfg.quick_switch_threshold_ms, cfg.overlay_delay_ms)
                        }
                        OverlayEvent::SurfaceUnmapped => Action::None,
                    }
                };
                handle_action(
                    &action, &mut wm_state, &wm_config, &windows,
                    &mut current_hints, &mut current_windows,
                    &overlay_cmd_tx, &mut overlay_event_rx,
                    #[cfg(target_os = "linux")] &backend,
                    &mut client,
                    &mut border_tick, &mut activation_tick,
                ).await;
            }

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
                            // Record MRU state.
                            let origin = win_list.iter()
                                .find(|w| w.is_focused)
                                .map(|w| w.id.to_string());
                            drop(win_list);
                            mru::save(origin.as_deref(), window_id);

                            // Actually activate the window via compositor backend.
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
                        let action = wm_state.on_activate();
                        handle_action(
                            &action, &mut wm_state, &wm_config, &windows,
                            &mut current_hints, &mut current_windows,
                            &overlay_cmd_tx, &mut overlay_event_rx,
                            #[cfg(target_os = "linux")] &backend,
                            &mut client,
                            &mut border_tick, &mut activation_tick,
                        ).await;
                        None // WmOverlayShown published by handle_action
                    }

                    EventKind::WmActivateOverlayBackward => {
                        tracing::info!("overlay activation (backward) requested via IPC");
                        let action = wm_state.on_activate();
                        handle_action(
                            &action, &mut wm_state, &wm_config, &windows,
                            &mut current_hints, &mut current_windows,
                            &overlay_cmd_tx, &mut overlay_event_rx,
                            #[cfg(target_os = "linux")] &backend,
                            &mut client,
                            &mut border_tick, &mut activation_tick,
                        ).await;
                        None
                    }

                    EventKind::WmActivateOverlayLauncher => {
                        tracing::info!("launcher-mode overlay activation requested via IPC");
                        let action = wm_state.on_activate_launcher();
                        handle_action(
                            &action, &mut wm_state, &wm_config, &windows,
                            &mut current_hints, &mut current_windows,
                            &overlay_cmd_tx, &mut overlay_event_rx,
                            #[cfg(target_os = "linux")] &backend,
                            &mut client,
                            &mut border_tick, &mut activation_tick,
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
                // Update WmConfig from hot-reloaded config.
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

/// Dispatch a state machine `Action` to the overlay and compositor.
///
/// Translates abstract state machine actions into concrete overlay commands,
/// compositor backend calls, MRU state updates, and IPC event publications.
#[allow(clippy::too_many_arguments)]
async fn handle_action(
    action: &Action,
    wm_state: &mut WmState,
    wm_config: &Arc<Mutex<core_config::WmConfig>>,
    windows: &Arc<Mutex<Vec<Window>>>,
    current_hints: &mut Vec<String>,
    current_windows: &mut Vec<Window>,
    overlay_cmd_tx: &std::sync::mpsc::Sender<OverlayCmd>,
    overlay_event_rx: &mut tokio::sync::mpsc::Receiver<OverlayEvent>,
    #[cfg(target_os = "linux")] backend: &Option<Arc<Box<dyn platform_linux::compositor::CompositorBackend>>>,
    client: &mut BusClient,
    border_tick: &mut Option<tokio::time::Interval>,
    activation_tick: &mut Option<tokio::time::Interval>,
) {
    // TASK-12: Detect overlay thread crash on channel send failure.
    let send_overlay = |cmd: OverlayCmd| -> bool {
        if overlay_cmd_tx.send(cmd).is_err() {
            tracing::error!("overlay thread has exited unexpectedly");
            false
        } else {
            true
        }
    };

    match action {
        Action::ShowBorder => {
            if !send_overlay(OverlayCmd::ShowBorder) {
                *wm_state = WmState::Idle;
                return;
            }

            // Start frame tick for border -> full overlay transition (~60fps).
            *border_tick = Some(tokio::time::interval(std::time::Duration::from_millis(16)));

            client.publish(EventKind::WmOverlayShown, SecurityLevel::Internal).await.ok();
        }

        Action::ShowOverlay => {
            // Stop border tick, we're now in full overlay.
            *border_tick = None;

            let cfg = wm_config.lock().await;
            let mut win_list = windows.lock().await.clone();

            // MRU reorder: move currently focused to end.
            mru::reorder(&mut win_list, |w| w.id.to_string());

            // Truncate to max visible.
            win_list.truncate(cfg.max_visible_windows as usize);

            // Assign hints based on app IDs.
            let app_ids: Vec<&str> = win_list.iter().map(|w| w.app_id.as_str()).collect();
            let app_hints = hints::assign_app_hints(&app_ids, &cfg.hint_keys, &cfg.key_bindings);
            let hint_strings: Vec<String> = app_hints.iter().map(|(h, _)| h.clone()).collect();

            // Update state machine with window count.
            wm_state.set_window_count(win_list.len());

            // Store for hint matching.
            *current_hints = hint_strings.clone();
            *current_windows = win_list.clone();

            let overlay_windows: Vec<WindowInfo> = win_list.iter().map(|w| WindowInfo {
                app_id: w.app_id.to_string(),
                title: w.title.clone(),
            }).collect();
            if !send_overlay(OverlayCmd::ShowFull {
                windows: overlay_windows,
                hints: hint_strings,
            }) {
                *wm_state = WmState::Idle;
            }
        }

        Action::ActivateWindow(idx) => {
            // Hide overlay and wait for Wayland roundtrip confirmation BEFORE
            // activating the target window. The overlay holds a layer-shell
            // surface with KeyboardMode::Exclusive; cosmic-comp's
            // exclusive_layer_surface_layer() rejects toplevel focus while it
            // exists, causing a connection teardown.
            *wm_state = WmState::Idle;
            send_overlay(OverlayCmd::HideAndSync);
            *border_tick = None;
            *activation_tick = None;

            // Wait for the GTK4 thread to confirm the surface is unmapped
            // (display.sync() roundtrip completed).
            while let Some(ev) = overlay_event_rx.recv().await {
                if matches!(ev, OverlayEvent::SurfaceUnmapped) {
                    break;
                }
            }

            if let Some(window) = current_windows.get(*idx) {
                let origin = current_windows.iter()
                    .find(|w| w.is_focused)
                    .map(|w| w.id.to_string());
                let target_id = window.id.to_string();
                mru::save(origin.as_deref(), &target_id);

                #[cfg(target_os = "linux")]
                if let Some(backend) = backend
                    && let Err(e) = backend.activate_window(&window.id).await
                {
                    tracing::warn!(error = %e, "compositor activate_window failed");
                }

                tracing::info!(window_id = %target_id, app_id = %window.app_id, "window activated via overlay");
            }

            *current_hints = Vec::new();
            *current_windows = Vec::new();

            client.publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal).await.ok();
        }

        Action::QuickSwitch => {
            // Hide overlay and wait for Wayland roundtrip — same as ActivateWindow.
            *wm_state = WmState::Idle;
            send_overlay(OverlayCmd::HideAndSync);
            *border_tick = None;
            *activation_tick = None;

            while let Some(ev) = overlay_event_rx.recv().await {
                if matches!(ev, OverlayEvent::SurfaceUnmapped) {
                    break;
                }
            }

            #[cfg(target_os = "linux")]
            if let Some(backend) = backend {
                let win_list = windows.lock().await;
                let prev_id = mru::previous_window();

                // Find the target: MRU previous if it still exists, else first non-focused.
                let target = prev_id.as_ref()
                    .and_then(|pid| win_list.iter().find(|w| w.id.to_string() == *pid))
                    .or_else(|| win_list.iter().find(|w| !w.is_focused));

                if let Some(w) = target {
                    let target_id = w.id.to_string();
                    let origin = win_list.iter()
                        .find(|w| w.is_focused)
                        .map(|w| w.id.to_string());
                    tracing::info!(target = %target_id, "quick-switch activating");
                    if let Err(e) = backend.activate_window(&w.id).await {
                        tracing::warn!(error = %e, "quick-switch activate failed");
                    }
                    drop(win_list);
                    mru::save(origin.as_deref(), &target_id);
                } else {
                    tracing::warn!("quick-switch: no target window available");
                }
            }

            client.publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal).await.ok();
        }

        Action::Dismiss => {
            *wm_state = WmState::Idle;

            send_overlay(OverlayCmd::Hide);

            *border_tick = None;
            *activation_tick = None;
            *current_hints = Vec::new();
            *current_windows = Vec::new();

            client.publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal).await.ok();
        }

        Action::Redraw => {
            // Send updated input/selection to overlay for redraw.
            let input = wm_state.input_buffer().unwrap_or("").to_string();
            let selection = wm_state.selection().unwrap_or(0);
            send_overlay(OverlayCmd::UpdateInput { input, selection });

            // If we entered PendingActivation, start the activation timeout.
            if matches!(wm_state, WmState::PendingActivation { .. }) && activation_tick.is_none() {
                *activation_tick = Some(tokio::time::interval(std::time::Duration::from_millis(50)));
            }
        }

        Action::LaunchApp(cmd) => {
            tracing::info!(command = %cmd, "launch-or-focus: launching app");

            // Hide overlay and reset to idle.
            *wm_state = WmState::Idle;
            send_overlay(OverlayCmd::Hide);
            *border_tick = None;
            *activation_tick = None;
            *current_hints = Vec::new();
            *current_windows = Vec::new();

            // Publish launch request via IPC for daemon-launcher to handle.
            client.publish(
                EventKind::LaunchExecute {
                    entry_id: cmd.clone(),
                    profile: None,
                },
                SecurityLevel::Internal,
            ).await.ok();

            client.publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal).await.ok();
        }

        Action::None => {}
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

    let rules = vec![
        // Per-daemon key file isolation. Only daemon-wm's keypair.
        LandlockRule {
            path: keys_dir.join("daemon-wm.key"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: keys_dir.join("daemon-wm.pub"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: keys_dir.join("daemon-wm.checksum"),
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
    ];

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
