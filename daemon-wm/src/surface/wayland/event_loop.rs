//! SCTK overlay main loop — poll-based event dispatch on dedicated thread.

use cosmic_text::{FontSystem, SwashCache};
use smithay_client_toolkit::{
    compositor::{CompositorState, Region},
    output::OutputState,
    registry::RegistryState,
    seat::SeatState,
    shell::{
        WaylandSurface,
        wlr_layer::{Anchor, KeyboardInteractivity, Layer, LayerShell},
    },
    shm::Shm,
};
use std::sync::mpsc;
use wayland_client::{Connection, globals::registry_queue_init};

use super::app::OverlayApp;
use super::blur::BlurManager;
use super::poll::POLL_INTERVAL_MS;
use super::{OverlayCmd, OverlayEvent, OverlayPhase};
use crate::render::OverlayTheme;

pub fn run_sctk_overlay(
    cmd_rx: mpsc::Receiver<OverlayCmd>,
    event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,
    theme: OverlayTheme,
    show_app_id: bool,
    show_title: bool,
) {
    let conn = match Connection::connect_to_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to connect to Wayland display: {e}");
            return;
        }
    };

    let (globals, mut event_queue) = match registry_queue_init(&conn) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("failed to initialize Wayland registry: {e}");
            return;
        }
    };

    let qh = event_queue.handle();

    let compositor_state = match CompositorState::bind(&globals, &qh) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to bind wl_compositor: {e}");
            return;
        }
    };
    let shm = match Shm::bind(&globals, &qh) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to bind wl_shm: {e}");
            return;
        }
    };
    let layer_shell = match LayerShell::bind(&globals, &qh) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("failed to bind zwlr_layer_shell_v1: {e}. Overlay disabled.");
            run_stub_loop(cmd_rx, event_tx);
            return;
        }
    };

    let empty_input_region = match Region::new(&compositor_state) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("failed to create wl_region: {e}");
            run_stub_loop(cmd_rx, event_tx);
            return;
        }
    };

    // Bind blur manager (optional — gracefully degrades on non-COSMIC compositors).
    let blur_manager = BlurManager::new(&globals, &qh).ok();
    if blur_manager.is_some() {
        tracing::info!("ext_background_effect_v1 manager bound");
    }

    // Create layer surface.
    let surface = compositor_state.create_surface(&qh);
    let layer_surface =
        layer_shell.create_layer_surface(&qh, surface, Layer::Overlay, Some("sesame"), None);
    layer_surface.set_anchor(Anchor::TOP | Anchor::BOTTOM | Anchor::LEFT | Anchor::RIGHT);
    layer_surface.set_exclusive_zone(-1);
    layer_surface.set_keyboard_interactivity(KeyboardInteractivity::None);
    layer_surface.commit();

    // Create blur surface object if blur manager is available.
    let blur_surface = blur_manager
        .as_ref()
        .map(|bm| bm.get_blur_surface(layer_surface.wl_surface(), &qh));

    let font_system = {
        let mut db = cosmic_text::fontdb::Database::new();
        db.load_system_fonts();
        FontSystem::new_with_locale_and_db("en-US".to_string(), db)
    };

    let mut app = OverlayApp {
        registry_state: RegistryState::new(&globals),
        compositor_state,
        output_state: OutputState::new(&globals, &qh),
        seat_state: SeatState::new(&globals, &qh),
        shm,
        layer_shell,
        layer_surface: Some(layer_surface),
        slot_pool: None,
        configured_size: (0, 0),
        blur_manager,
        blur_surface,
        font_system,
        swash_cache: SwashCache::new(),
        phase: OverlayPhase::Hidden,
        windows: Vec::new(),
        hints: Vec::new(),
        input_buffer: String::new(),
        selection: 0,
        theme,
        show_app_id,
        show_title,
        activated_at: None,
        received_key_event: false,
        ipc_keyboard_active: false,
        last_real_input_at: None,
        error_message: String::new(),
        staged_launch: None,
        unlock_profile: String::new(),
        unlock_password_len: 0,
        unlock_message: String::new(),
        alt_held: false,
        modifier_released_sent: false,
        event_tx,
        running: true,
        needs_redraw: false,
        pending_sync: false,
        output_scale: 1.0,
        scale_known: false,
        empty_input_region,
    };

    while app.running {
        if let Err(e) = conn.flush() {
            tracing::error!(error = %e, "Wayland flush failed, thread exiting");
            if app.pending_sync {
                app.send_event(OverlayEvent::SurfaceUnmapped);
            }
            break;
        }

        let read_guard = match event_queue.prepare_read() {
            Some(g) => g,
            None => {
                if let Err(e) = event_queue.dispatch_pending(&mut app) {
                    tracing::error!(error = %e, "Wayland dispatch error, thread exiting");
                    if app.pending_sync {
                        app.send_event(OverlayEvent::SurfaceUnmapped);
                    }
                    break;
                }
                drain_commands(&mut app, &qh, &cmd_rx);
                app.poll_modifiers();
                if app.needs_redraw {
                    app.render_frame(&qh);
                }
                continue;
            }
        };

        let fd = read_guard.connection_fd();
        let mut poll_fd = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: (POLL_INTERVAL_MS as i64) * 1_000_000,
        };
        let _ = rustix::event::poll(&mut poll_fd, Some(&timeout));

        match read_guard.read() {
            Ok(_) => {}
            Err(wayland_client::backend::WaylandError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                tracing::error!(error = %e, "Wayland read error, thread exiting");
                if app.pending_sync {
                    app.send_event(OverlayEvent::SurfaceUnmapped);
                }
                break;
            }
        }

        if let Err(e) = event_queue.dispatch_pending(&mut app) {
            tracing::error!(error = %e, "Wayland dispatch error, thread exiting");
            if app.pending_sync {
                app.send_event(OverlayEvent::SurfaceUnmapped);
            }
            break;
        }

        drain_commands(&mut app, &qh, &cmd_rx);
        app.poll_modifiers();
        if app.needs_redraw {
            app.render_frame(&qh);
        }
    }

    // Cleanup blur surface on exit.
    if let Some(blur_surface) = app.blur_surface.take() {
        blur_surface.destroy();
    }

    tracing::info!("overlay thread exiting");
}

/// Stub loop for compositors without layer-shell.
pub fn run_stub_loop(
    cmd_rx: mpsc::Receiver<OverlayCmd>,
    event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,
) {
    tracing::info!("overlay stub loop running (layer-shell unavailable)");
    let mut warned = false;
    loop {
        match cmd_rx.recv() {
            Ok(OverlayCmd::Quit) => break,
            Ok(OverlayCmd::HideAndSync) => {
                let _ = event_tx.blocking_send(OverlayEvent::SurfaceUnmapped);
            }
            Ok(OverlayCmd::ShowBorder) | Ok(OverlayCmd::ShowFull { .. }) => {
                if !warned {
                    tracing::warn!(
                        "overlay not available: compositor does not support wlr-layer-shell"
                    );
                    warned = true;
                }
                let _ = event_tx.blocking_send(OverlayEvent::Dismiss);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    tracing::info!("overlay stub loop exiting");
}

fn drain_commands(
    app: &mut OverlayApp,
    qh: &wayland_client::QueueHandle<OverlayApp>,
    cmd_rx: &mpsc::Receiver<OverlayCmd>,
) {
    while let Ok(cmd) = cmd_rx.try_recv() {
        app.process_command(cmd, qh);
    }
}
