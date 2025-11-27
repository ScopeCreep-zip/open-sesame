//! Application orchestration
//!
//! Clean architecture with:
//! - Pure state machine (state.rs)
//! - Frame-callback rendering (renderer.rs)
//! - Thin Wayland integration layer (this file)

mod renderer;
mod state;

pub use state::{ActivationResult, AppState};

use crate::config::Config;
use crate::core::WindowHint;
use crate::util::{IpcCommand, IpcServer, Result};
use renderer::Renderer;
use smithay_client_toolkit::{
    compositor::{CompositorHandler, CompositorState},
    delegate_compositor, delegate_keyboard, delegate_layer, delegate_output, delegate_registry,
    delegate_seat, delegate_shm,
    output::{OutputHandler, OutputState},
    registry::{ProvidesRegistryState, RegistryState},
    registry_handlers,
    seat::{
        Capability, SeatHandler, SeatState,
        keyboard::{KeyEvent, KeyboardHandler, Keysym, Modifiers, RawModifiers},
    },
    shell::{
        WaylandSurface,
        wlr_layer::{
            Anchor, KeyboardInteractivity, Layer, LayerShell, LayerShellHandler, LayerSurface,
            LayerSurfaceConfigure,
        },
    },
    shm::{Shm, ShmHandler},
};
use state::{Action, Event, Transition};
use std::sync::Arc;
use wayland_client::{
    Connection, QueueHandle,
    globals::registry_queue_init,
    protocol::{wl_keyboard, wl_output, wl_seat, wl_surface},
};

/// Main application - thin wrapper around state machine
pub struct App {
    // Wayland state
    registry_state: RegistryState,
    seat_state: SeatState,
    output_state: OutputState,
    compositor_state: CompositorState,
    layer_shell: LayerShell,
    shm: Shm,

    // Application state machine
    state: AppState,
    config: Arc<Config>,
    hints: Vec<WindowHint>,
    previous_window_id: Option<String>,

    // Rendering
    renderer: Renderer,
    layer_surface: Option<LayerSurface>,

    // Wayland event loop control
    running: bool,

    // Modifier state tracking for Alt release detection
    alt_held: bool,
    shift_held: bool,

    // IPC server for receiving commands from other instances
    ipc_server: Option<IpcServer>,
}

impl App {
    /// Create and run the application
    pub fn run(
        config: Config,
        hints: Vec<WindowHint>,
        previous_window_id: Option<String>,
        launcher_mode: bool,
        ipc_server: Option<IpcServer>,
    ) -> Result<Option<(usize, String)>> {
        let conn = Connection::connect_to_env()
            .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;

        let (globals, mut event_queue) = registry_queue_init(&conn)
            .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;
        let qh = event_queue.handle();

        let registry_state = RegistryState::new(&globals);
        let seat_state = SeatState::new(&globals, &qh);
        let output_state = OutputState::new(&globals, &qh);
        let compositor_state = CompositorState::bind(&globals, &qh)
            .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;
        let shm = Shm::bind(&globals, &qh)
            .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;
        let layer_shell = LayerShell::bind(&globals, &qh)
            .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;

        let config = Arc::new(config);

        tracing::info!(
            "App::run starting with {} hints, mode={}",
            hints.len(),
            if launcher_mode {
                "launcher"
            } else {
                "switcher"
            }
        );
        tracing::info!("  Previous window: {:?}", previous_window_id);
        for (i, hint) in hints.iter().enumerate() {
            tracing::info!(
                "  Hint[{}]: {} -> {} ({})",
                i,
                hint.hint,
                hint.app_id,
                hint.window_id
            );
        }

        let initial_state = AppState::initial(launcher_mode, &hints, previous_window_id.as_deref());

        let mut app = App {
            registry_state,
            seat_state,
            output_state,
            compositor_state,
            layer_shell,
            shm,
            state: initial_state,
            config,
            hints,
            previous_window_id,
            renderer: Renderer::new(),
            layer_surface: None,
            running: true,
            alt_held: !launcher_mode, // Alt held state initialized based on mode (switcher assumes held)
            shift_held: false,
            ipc_server,
        };

        // Create layer surface
        app.create_layer_surface(&qh);
        tracing::info!("Layer surface created");

        // Event loop
        let mut event_loop = calloop::EventLoop::try_new()
            .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;
        let loop_handle = event_loop.handle();
        tracing::info!("Event loop created");

        // Insert Wayland source
        loop_handle
            .insert_source(
                calloop::generic::Generic::new(conn, calloop::Interest::READ, calloop::Mode::Level),
                move |_, conn, app: &mut App| {
                    if let Some(guard) = conn.prepare_read() {
                        match guard.read() {
                            Ok(_) => {}
                            Err(wayland_client::backend::WaylandError::Io(io_err))
                                if io_err.kind() == std::io::ErrorKind::WouldBlock =>
                            {
                                // EAGAIN is normal - just means no data ready
                            }
                            Err(e) => {
                                tracing::error!("Wayland read error: {}. Shutting down.", e);
                                app.running = false;
                                return Ok(calloop::PostAction::Remove);
                            }
                        }
                    }
                    Ok(calloop::PostAction::Continue)
                },
            )
            .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;

        tracing::info!("Entering event loop, running={}", app.running);
        let mut loop_count = 0u64;
        while app.running {
            loop_count += 1;
            if loop_count <= 5 || loop_count.is_multiple_of(100) {
                tracing::debug!("Event loop iteration {}", loop_count);
            }

            // Dispatch pending Wayland events
            event_queue
                .dispatch_pending(&mut app)
                .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;

            // Flush outgoing requests
            event_queue
                .flush()
                .map_err(|e| crate::util::Error::WaylandConnection(Box::new(e)))?;

            // Process tick event (for timeouts)
            app.process_event(Event::Tick, &qh);

            // Process IPC commands from other instances
            // Commands collected before processing to avoid borrow conflict
            let ipc_commands: Vec<IpcCommand> = app
                .ipc_server
                .as_ref()
                .map(|s| {
                    let mut cmds = Vec::new();
                    while let Some(cmd) = s.try_recv() {
                        cmds.push(cmd);
                    }
                    cmds
                })
                .unwrap_or_default();

            for cmd in ipc_commands {
                match cmd {
                    IpcCommand::CycleForward => {
                        tracing::info!("IPC: FORWARD command received");
                        app.process_event(Event::CycleForward, &qh);
                    }
                    IpcCommand::CycleBackward => {
                        tracing::info!("IPC: BACKWARD command received");
                        app.process_event(Event::CycleBackward, &qh);
                    }
                    IpcCommand::Ping => {
                        // Ping is handled by the server automatically
                    }
                }
            }

            // Render if needed
            if app.renderer.needs_redraw() {
                app.draw(&qh);
            }

            // Poll for events (10ms timeout)
            event_loop
                .dispatch(std::time::Duration::from_millis(10), &mut app)
                .ok();
        }
        tracing::info!("Exited event loop after {} iterations", loop_count);

        // Log exit
        tracing::info!("BORDER DEACTIVATING");

        // Return result based on final state
        match app.state.activation_result() {
            Some(ActivationResult::Window(idx)) if *idx < app.hints.len() => {
                let hint = &app.hints[*idx];
                tracing::info!("Activating window: {} ({})", hint.app_id, hint.window_id);
                Ok(Some((*idx, hint.window_id.to_string())))
            }
            Some(ActivationResult::Window(idx)) => {
                // Index out of bounds - fallback to first window
                tracing::warn!("Window index {} out of bounds, falling back", idx);
                if !app.hints.is_empty() {
                    let hint = &app.hints[0];
                    Ok(Some((0, hint.window_id.to_string())))
                } else {
                    Ok(None)
                }
            }
            Some(ActivationResult::QuickSwitch) => {
                // Quick switch to previous or first window
                if let Some(ref prev_id) = app.previous_window_id
                    && let Some((idx, hint)) = app
                        .hints
                        .iter()
                        .enumerate()
                        .find(|(_, h)| h.window_id.as_str() == prev_id)
                {
                    tracing::info!("Quick switch to: {} ({})", hint.app_id, hint.window_id);
                    return Ok(Some((idx, hint.window_id.to_string())));
                }
                // Fallback to first
                if !app.hints.is_empty() {
                    let hint = &app.hints[0];
                    tracing::info!(
                        "Quick switch fallback: {} ({})",
                        hint.app_id,
                        hint.window_id
                    );
                    Ok(Some((0, hint.window_id.to_string())))
                } else {
                    Ok(None)
                }
            }
            Some(ActivationResult::Launch(key)) => {
                tracing::info!("Launching: {}", key);
                Ok(Some((usize::MAX, key.clone())))
            }
            Some(ActivationResult::Cancelled) => {
                tracing::info!("Cancelled");
                Ok(None)
            }
            None => {
                tracing::info!("No result");
                Ok(None)
            }
        }
    }

    /// Process an event through the state machine
    fn process_event(&mut self, event: Event, qh: &QueueHandle<Self>) {
        let Transition { new_state, actions } = self.state.handle_event(
            event,
            &self.config,
            &self.hints,
            self.previous_window_id.as_deref(),
        );

        self.state = new_state;

        let had_actions = !actions.is_empty();
        for action in actions {
            match action {
                Action::ScheduleRedraw => {
                    self.renderer.schedule_redraw();
                }
                Action::Exit => {
                    self.running = false;
                }
            }
        }

        // Redraw triggered when state transitions produce visual changes
        if had_actions {
            self.draw(qh);
        }
    }

    /// Create the layer surface
    fn create_layer_surface(&mut self, qh: &QueueHandle<Self>) {
        let surface = self.compositor_state.create_surface(qh);

        let layer_surface = self.layer_shell.create_layer_surface(
            qh,
            surface,
            Layer::Overlay,
            Some("sesame"),
            None,
        );

        layer_surface.set_anchor(Anchor::all());
        layer_surface.set_exclusive_zone(-1);
        layer_surface.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
        layer_surface.commit();

        self.layer_surface = Some(layer_surface);
    }

    /// Draw current state
    fn draw(&mut self, _qh: &QueueHandle<Self>) {
        let Some(layer_surface) = &self.layer_surface else {
            return;
        };

        let show_full = self.state.is_full_overlay();
        let selected = self.state.selected_hint_index();
        let input = self.state.input();

        if let Some(result) = self.renderer.render(
            &self.shm,
            &self.config,
            &self.hints,
            input,
            selected,
            show_full,
        ) {
            layer_surface
                .wl_surface()
                .attach(Some(result.buffer.wl_buffer()), 0, 0);
            layer_surface
                .wl_surface()
                .damage_buffer(0, 0, result.width, result.height);
            layer_surface.commit();

            tracing::debug!(
                "Frame rendered: {}x{}, full={}, selected={}",
                result.width,
                result.height,
                show_full,
                selected
            );
        }
    }
}

// === Wayland protocol implementations ===

impl CompositorHandler for App {
    fn scale_factor_changed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        self.renderer.set_scale(new_factor as f32);
    }

    fn transform_changed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _new_transform: wl_output::Transform,
    ) {
    }

    fn frame(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _time: u32,
    ) {
        // Frame callback - process through state machine
        self.process_event(Event::FrameCallback, qh);
    }

    fn surface_enter(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _output: &wl_output::WlOutput,
    ) {
    }

    fn surface_leave(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _output: &wl_output::WlOutput,
    ) {
    }
}

impl OutputHandler for App {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.output_state
    }

    fn new_output(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _output: wl_output::WlOutput,
    ) {
    }
    fn update_output(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _output: wl_output::WlOutput,
    ) {
    }
    fn output_destroyed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _output: wl_output::WlOutput,
    ) {
    }
}

impl LayerShellHandler for App {
    fn closed(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _layer: &LayerSurface) {
        self.running = false;
    }

    fn configure(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        layer: &LayerSurface,
        configure: LayerSurfaceConfigure,
        _serial: u32,
    ) {
        tracing::info!(
            "CONFIGURE EVENT: {}x{}",
            configure.new_size.0,
            configure.new_size.1
        );

        self.renderer
            .configure(configure.new_size.0, configure.new_size.1);
        layer.set_size(configure.new_size.0, configure.new_size.1);

        // Process configure as an event
        self.process_event(
            Event::Configure {
                width: configure.new_size.0,
                height: configure.new_size.1,
            },
            qh,
        );

        // Initial draw
        self.draw(qh);
        tracing::info!("CONFIGURE done, draw called");
    }
}

impl SeatHandler for App {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seat_state
    }

    fn new_seat(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _seat: wl_seat::WlSeat) {}

    fn new_capability(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        seat: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard
            && let Err(e) = self.seat_state.get_keyboard(qh, &seat, None)
        {
            tracing::error!("Failed to get keyboard: {}", e);
        }
    }

    fn remove_capability(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _seat: wl_seat::WlSeat,
        _capability: Capability,
    ) {
    }

    fn remove_seat(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _seat: wl_seat::WlSeat) {
    }
}

impl KeyboardHandler for App {
    fn enter(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _surface: &wl_surface::WlSurface,
        _serial: u32,
        raw: &[u32],
        keysyms: &[Keysym],
    ) {
        tracing::info!(
            "KEYBOARD ENTER: {} raw keys, {} keysyms",
            raw.len(),
            keysyms.len()
        );
    }

    fn leave(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _surface: &wl_surface::WlSurface,
        _serial: u32,
    ) {
        tracing::info!("KEYBOARD LEAVE");
    }

    fn press_key(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _serial: u32,
        event: KeyEvent,
    ) {
        tracing::info!(
            "KEY PRESS: keysym={:?} raw={:#x} shift={}",
            event.keysym,
            event.keysym.raw(),
            self.shift_held
        );

        self.process_event(
            Event::KeyPress {
                keysym: event.keysym,
                shift: self.shift_held,
            },
            qh,
        );
    }

    fn release_key(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _serial: u32,
        _event: KeyEvent,
    ) {
    }

    fn repeat_key(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _serial: u32,
        event: KeyEvent,
    ) {
        self.process_event(
            Event::KeyPress {
                keysym: event.keysym,
                shift: self.shift_held,
            },
            qh,
        );
    }

    fn update_modifiers(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _serial: u32,
        modifiers: Modifiers,
        _raw_modifiers: RawModifiers,
        _layout: u32,
    ) {
        let was_alt_held = self.alt_held;
        self.alt_held = modifiers.alt;
        self.shift_held = modifiers.shift;

        tracing::debug!(
            "Modifiers: alt={} (was {}), shift={}",
            self.alt_held,
            was_alt_held,
            self.shift_held
        );

        // Alt released state processed through state machine
        if was_alt_held && !self.alt_held {
            self.process_event(Event::AltReleased, qh);
        }
    }
}

impl ShmHandler for App {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

impl ProvidesRegistryState for App {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }

    registry_handlers!(OutputState, SeatState);
}

delegate_compositor!(App);
delegate_output!(App);
delegate_shm!(App);
delegate_seat!(App);
delegate_keyboard!(App);
delegate_layer!(App);
delegate_registry!(App);
