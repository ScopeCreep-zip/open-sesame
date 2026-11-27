//! The SCTK overlay thread's loop: Wayland dispatch, daemon commands,
//! modifier polling, and rendering, every [`POLL_TIMEOUT`] at most.

use anyhow::Context;
use cosmic_text::{FontSystem, SwashCache};
use smithay_client_toolkit::{
    background_effect::BackgroundEffectState,
    compositor::{CompositorState, Region},
    output::OutputState,
    registry::RegistryState,
    seat::SeatState,
    shell::wlr_layer::LayerShell,
    shm::Shm,
};
use std::sync::mpsc::{self, TryRecvError};
use wayland_client::{Connection, EventQueue, globals::registry_queue_init};

use super::app::{OverlayApp, View};
use super::poll::Activation;
use super::{OverlayCmd, OverlayEvent};
use crate::render::{Columns, OverlayTheme};

/// The longest wait for Wayland events: the modifier poll interval.
const POLL_TIMEOUT: rustix::event::Timespec = rustix::event::Timespec {
    tv_sec: 0,
    tv_nsec: 4_000_000,
};

/// Why the overlay could not be set up.
enum SetupError {
    /// No overlay is possible: the thread ends.
    Fatal(anyhow::Error),
    /// The compositor has no layer shell: commands are answered without
    /// an overlay.
    NoLayerShell(anyhow::Error),
}

/// The Wayland connection, its event queue, and the overlay state.
fn connect(
    event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,
    theme: OverlayTheme,
    columns: Columns,
) -> Result<(Connection, EventQueue<OverlayApp>, OverlayApp), SetupError> {
    let conn = Connection::connect_to_env()
        .context("failed to connect to the Wayland display")
        .map_err(SetupError::Fatal)?;
    let (globals, event_queue) = registry_queue_init(&conn)
        .context("failed to initialize the Wayland registry")
        .map_err(SetupError::Fatal)?;
    let qh = event_queue.handle();
    let compositor_state = CompositorState::bind(&globals, &qh)
        .context("failed to bind wl_compositor")
        .map_err(SetupError::Fatal)?;
    let shm = Shm::bind(&globals, &qh)
        .context("failed to bind wl_shm")
        .map_err(SetupError::Fatal)?;
    let layer_shell = LayerShell::bind(&globals, &qh)
        .context("failed to bind zwlr_layer_shell_v1")
        .map_err(SetupError::NoLayerShell)?;
    let empty_input_region = Region::new(&compositor_state)
        .context("failed to create a wl_region")
        .map_err(SetupError::NoLayerShell)?;

    // Blur is optional: without ext_background_effect_manager_v1 the card
    // renders without a backdrop effect.
    let background_effect = BackgroundEffectState::new(&globals, &qh);
    if background_effect.ext_background_effect_manager_v1().is_ok() {
        tracing::info!("ext_background_effect_v1 manager bound");
    }

    let mut app = OverlayApp {
        registry_state: RegistryState::new(&globals),
        compositor_state,
        output_state: OutputState::new(&globals, &qh),
        seat_state: SeatState::new(&globals, &qh),
        shm,
        layer_shell,
        layer_surface: None,
        slot_pool: None,
        configured_size: (0, 0),
        output_scale: 1,
        empty_input_region,
        background_effect,
        blur_surface: None,
        // System fonts, with the session locale choosing script fallbacks.
        font_system: FontSystem::new(),
        swash_cache: SwashCache::new(),
        theme,
        columns,
        view: View::Hidden,
        activation: Activation::default(),
        alt_held: false,
        event_tx,
        running: true,
        needs_redraw: false,
    };
    app.recreate_layer_surface(&qh);
    Ok((conn, event_queue, app))
}

/// Run the overlay until `Quit`, a dropped command channel, or a failed
/// Wayland connection.
pub fn run_sctk_overlay(
    cmd_rx: &mpsc::Receiver<OverlayCmd>,
    event_tx: &tokio::sync::mpsc::Sender<OverlayEvent>,
    theme: OverlayTheme,
    columns: Columns,
) {
    let (conn, mut event_queue, mut app) = match connect(event_tx.clone(), theme, columns) {
        Ok(setup) => setup,
        Err(SetupError::Fatal(e)) => {
            tracing::error!(error = %format!("{e:#}"), "overlay unavailable");
            return;
        }
        Err(SetupError::NoLayerShell(e)) => {
            tracing::warn!(error = %format!("{e:#}"), "overlay disabled");
            run_stub_loop(cmd_rx, event_tx);
            return;
        }
    };
    while app.running {
        if let Err(e) = pump(&conn, &mut event_queue, &mut app) {
            tracing::error!(error = %format!("{e:#}"), "Wayland connection failed, overlay thread exiting");
            break;
        }
        loop {
            match cmd_rx.try_recv() {
                Ok(cmd) => app.process_command(cmd),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    app.running = false;
                    break;
                }
            }
        }
        app.poll_modifiers();
        if app.needs_redraw {
            app.render_frame();
        }
    }
    if let Some(blur_surface) = app.blur_surface.take() {
        blur_surface.destroy();
    }
    tracing::info!("overlay thread exiting");
}

/// Flush requests, wait up to [`POLL_TIMEOUT`] for and read Wayland
/// events, and dispatch them.
fn pump(
    conn: &Connection,
    event_queue: &mut EventQueue<OverlayApp>,
    app: &mut OverlayApp,
) -> anyhow::Result<()> {
    conn.flush().context("flush failed")?;
    // `None`: events are already queued; dispatch them without reading.
    if let Some(read_guard) = event_queue.prepare_read() {
        let fd = read_guard.connection_fd();
        let mut fds = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut fds, Some(&POLL_TIMEOUT)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e).context("poll failed"),
        }
        match read_guard.read() {
            Ok(_) => {}
            Err(wayland_client::backend::WaylandError::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e).context("read failed"),
        }
    }
    event_queue
        .dispatch_pending(app)
        .context("dispatch failed")?;
    Ok(())
}

/// Answer commands without an overlay (compositors without layer-shell):
/// activations are dismissed and hides acknowledged, so the daemon never
/// waits on a surface that does not exist.
fn run_stub_loop(
    cmd_rx: &mpsc::Receiver<OverlayCmd>,
    event_tx: &tokio::sync::mpsc::Sender<OverlayEvent>,
) {
    tracing::info!("overlay stub loop running (layer-shell unavailable)");
    let mut warned = false;
    while let Ok(cmd) = cmd_rx.recv() {
        let reply = match cmd {
            OverlayCmd::Quit => break,
            OverlayCmd::HideAndSync => OverlayEvent::SurfaceUnmapped,
            OverlayCmd::ShowBorder | OverlayCmd::ShowFull { .. } => {
                if !warned {
                    tracing::warn!(
                        "overlay not available: compositor does not support wlr-layer-shell"
                    );
                    warned = true;
                }
                OverlayEvent::Dismiss
            }
            _ => continue,
        };
        if event_tx.blocking_send(reply).is_err() {
            break;
        }
    }
    tracing::info!("overlay stub loop exiting");
}
