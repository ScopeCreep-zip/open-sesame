//! SCTK + wayland-client overlay surface for the window switcher.
//!
//! Manages the full overlay lifecycle: layer-shell surface creation, keyboard
//! input capture, state machine integration, and tiny-skia rendering via the
//! `render` module. Runs on a dedicated thread with its own poll-based event
//! loop, communicating with the tokio event loop via std channels. The overlay
//! thread runs a manual poll loop using prepare_read() + rustix::event::poll()
//! for low-latency Wayland event dispatch with periodic command channel draining.

use crate::render::{self, HintRow, OverlayTheme};
use cosmic_text::{FontSystem, SwashCache};
use smithay_client_toolkit::{
    compositor::{CompositorHandler, CompositorState, Region},
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
    shm::{Shm, ShmHandler, slot::SlotPool},
};
use std::sync::mpsc;
use wayland_client::{
    Connection, QueueHandle,
    globals::registry_queue_init,
    protocol::{wl_keyboard, wl_output, wl_seat, wl_shm, wl_surface},
};

// ---------------------------------------------------------------------------
// Channel types — main event loop <-> overlay thread
// ---------------------------------------------------------------------------

/// Commands sent from the tokio event loop to the overlay thread.
#[derive(Debug)]
pub enum OverlayCmd {
    /// Show the border-only phase.
    ShowBorder,
    /// Show the full overlay with window list.
    ShowFull {
        windows: Vec<WindowInfo>,
        hints: Vec<String>,
    },
    /// Update input buffer and selection for redraw.
    UpdateInput { input: String, selection: usize },
    /// Hide the overlay and return to idle.
    Hide,
    /// Hide the overlay, flush the Wayland unmap to the compositor via a
    /// display sync, then send `OverlayEvent::SurfaceUnmapped` as
    /// acknowledgment. Use this before activating a different window so the
    /// compositor no longer sees our exclusive-keyboard layer-shell surface.
    HideAndSync,
    /// Show "Launching..." status.
    ShowLaunching,
    /// Show staged launch intent (waiting for Alt release to confirm).
    ShowLaunchStaged { command: String },
    /// Show launch error with message.
    ShowLaunchError { message: String },
    /// Show vault unlock password prompt with dot-masked field.
    /// Defense in depth: only the character count is sent, never password bytes.
    ShowUnlockPrompt {
        profile: String,
        password_len: usize,
        error: Option<String>,
    },
    /// Show unlock progress indicator (auto-unlock, verifying, etc.).
    ShowUnlockProgress { profile: String, message: String },
    /// Reset the modifier-poll grace timer. Proves Alt is still held
    /// (an IPC re-activation wouldn't fire otherwise).
    ResetGrace,
    /// Confirm that keyboard input is working via IPC. Stops the stale
    /// activation timeout and `KeyboardInteractivity::Exclusive` hammering by
    /// setting `received_key_event = true` on the overlay thread.
    ConfirmKeyboardInput,
    /// Update theme from config.
    UpdateTheme(Box<OverlayTheme>),
    /// Shut down the overlay thread.
    Quit,
}

/// Events sent from the overlay thread back to the tokio event loop.
#[derive(Debug, Clone)]
pub enum OverlayEvent {
    /// Character typed (for state machine routing).
    KeyChar(char),
    /// Backspace pressed.
    Backspace,
    /// Selection moved down (Tab / Down arrow).
    SelectionDown,
    /// Selection moved up (Shift+Tab / Up arrow).
    SelectionUp,
    /// Enter pressed to confirm selection.
    Confirm,
    /// Escape pressed.
    Escape,
    /// Modifier (Alt) released.
    ModifierReleased,
    /// Stale activation — dismiss without activating.
    Dismiss,
    /// Acknowledgment: the layer-shell surface has been unmapped and the
    /// compositor has confirmed via display sync. Safe to activate a window.
    SurfaceUnmapped,
}

/// Minimal window info passed to the overlay for display.
#[derive(Debug, Clone)]
pub struct WindowInfo {
    pub app_id: String,
    pub title: String,
}

// ---------------------------------------------------------------------------
// Overlay phase tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayPhase {
    Hidden,
    BorderOnly,
    Full,
    Launching,
    LaunchError,
    /// Vault unlock password entry — dot-masked field with profile name.
    UnlockPrompt,
    /// Vault unlock progress — status message (authenticating, verifying).
    UnlockProgress,
}

// ---------------------------------------------------------------------------
// Internal overlay state
// ---------------------------------------------------------------------------

/// Grace period (ms) after activation before modifier polling begins.
/// Gives the compositor time to forward modifier state to our surface.
const MODIFIER_POLL_GRACE_MS: u128 = 150;

/// Stale activation timeout (ms). If the overlay has been visible this long
/// without any keyboard event, assume the user released Alt before we got
/// keyboard focus and dismiss. Prevents the overlay getting permanently stuck.
const STALE_ACTIVATION_TIMEOUT_MS: u128 = 3000;

/// IPC idle timeout (ms). When the overlay is proactively told that IPC
/// keyboard input is available (zero-window launcher mode) but no real user
/// input ever arrives, dismiss after this period. This is the safety net for
/// daemon-input being down or the IPC bus being broken while the overlay is
/// open with `ipc_keyboard_active = true`. Generous (30s) because this is an
/// operational failure, not a normal user flow.
const IPC_IDLE_TIMEOUT_MS: u128 = 30_000;

/// Modifier poll interval in milliseconds, equivalent to the GTK4 timeout.
const POLL_INTERVAL_MS: u64 = 4;

// ---------------------------------------------------------------------------
// SCTK application state
// ---------------------------------------------------------------------------

struct OverlayApp {
    // -- Wayland state --
    registry_state: RegistryState,
    /// Retained to keep the compositor global alive for the connection lifetime.
    #[allow(dead_code)]
    compositor_state: CompositorState,
    output_state: OutputState,
    seat_state: SeatState,
    shm: Shm,
    /// Retained to keep the layer-shell global alive for the connection lifetime.
    #[allow(dead_code)]
    layer_shell: LayerShell,

    // -- Surface --
    layer_surface: Option<LayerSurface>,
    slot_pool: Option<SlotPool>,
    configured_size: (u32, u32),

    // -- Rendering --
    font_system: FontSystem,
    swash_cache: SwashCache,

    // -- Overlay state --
    phase: OverlayPhase,
    windows: Vec<WindowInfo>,
    hints: Vec<String>,
    input_buffer: String,
    selection: usize,
    theme: OverlayTheme,
    show_app_id: bool,
    show_title: bool,
    activated_at: Option<std::time::Instant>,
    received_key_event: bool,
    ipc_keyboard_active: bool,
    last_real_input_at: Option<std::time::Instant>,
    error_message: String,
    staged_launch: Option<String>,
    unlock_profile: String,
    unlock_password_len: usize,
    unlock_message: String,

    // -- Modifier tracking --
    alt_held: bool,
    modifier_released_sent: bool,

    // -- Communication --
    event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,

    // -- Lifecycle --
    running: bool,
    needs_redraw: bool,

    // -- Sync callback tracking --
    pending_sync: bool,

    // -- HiDPI --
    output_scale: f32,

    // -- Input region --
    /// Empty region used to make the surface click-through when hidden.
    empty_input_region: Region,
}

impl OverlayApp {
    fn send_event(&self, event: OverlayEvent) {
        let _ = self.event_tx.blocking_send(event);
    }

    fn hide_common(&mut self) {
        self.phase = OverlayPhase::Hidden;
        self.pending_sync = false;
        self.input_buffer.clear();
        self.selection = 0;
        self.windows.clear();
        self.hints.clear();
        self.activated_at = None;
        self.received_key_event = false;
        self.ipc_keyboard_active = false;
        self.last_real_input_at = None;
        self.staged_launch = None;
        self.needs_redraw = true;
        self.set_keyboard_interactivity(KeyboardInteractivity::None);
        // Set empty input region so pointer events pass through the transparent overlay.
        if let Some(ref surface) = self.layer_surface {
            surface
                .wl_surface()
                .set_input_region(Some(self.empty_input_region.wl_region()));
        }
    }

    fn set_keyboard_interactivity(&self, mode: KeyboardInteractivity) {
        if let Some(ref surface) = self.layer_surface {
            surface.set_keyboard_interactivity(mode);
            // Restore full input region when becoming interactive, so the overlay
            // receives pointer events. When hiding, hide_common sets the empty region.
            if mode == KeyboardInteractivity::Exclusive {
                surface.wl_surface().set_input_region(None);
            }
            surface.commit();
        }
    }

    fn render_frame(&mut self, _qh: &QueueHandle<Self>) {
        self.needs_redraw = false;

        let (logical_w, logical_h) = self.configured_size;
        if logical_w == 0 || logical_h == 0 {
            return;
        }

        let pool = match self.slot_pool.as_mut() {
            Some(p) => p,
            None => return,
        };

        // Scale buffer dimensions for HiDPI.
        let scale = self.output_scale;
        let width = (logical_w as f32 * scale) as u32;
        let height = (logical_h as f32 * scale) as u32;

        let stride = width as i32 * 4;

        let (buffer, canvas) = match pool.create_buffer(
            width as i32,
            height as i32,
            stride,
            wl_shm::Format::Argb8888,
        ) {
            Ok((buf, canvas)) => (buf, canvas),
            Err(e) => {
                tracing::warn!("failed to create shm buffer: {e}");
                return;
            }
        };

        // Render into a tiny-skia pixmap, then convert RGBA -> ARGB8888.
        let w = width;
        let h = height;
        let wf = w as f32;
        let hf = h as f32;

        if let Some(mut pixmap) = tiny_skia::Pixmap::new(w, h) {
            match self.phase {
                OverlayPhase::Hidden => {
                    pixmap.fill(tiny_skia::Color::TRANSPARENT);
                }
                OverlayPhase::BorderOnly => {
                    render::draw_border_only(&mut pixmap, wf, hf, scale, &self.theme);
                }
                OverlayPhase::Full => {
                    let rows: Vec<HintRow<'_>> = self
                        .windows
                        .iter()
                        .zip(self.hints.iter())
                        .map(|(w, h)| HintRow {
                            hint: h.as_str(),
                            app_id: &w.app_id,
                            title: &w.title,
                        })
                        .collect();
                    render::draw_full_overlay(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &rows,
                        &self.input_buffer,
                        self.selection,
                        &self.hints,
                        &self.theme,
                        self.show_app_id,
                        self.show_title,
                        self.staged_launch.as_deref(),
                    );
                }
                OverlayPhase::Launching => {
                    render::draw_status_toast(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        "Launching\u{2026}",
                        &self.theme,
                    );
                }
                OverlayPhase::LaunchError => {
                    render::draw_error_toast(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &self.error_message,
                        &self.theme,
                    );
                }
                OverlayPhase::UnlockPrompt => {
                    let error = if self.error_message.is_empty() {
                        None
                    } else {
                        Some(self.error_message.as_str())
                    };
                    render::draw_unlock_prompt(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &self.unlock_profile,
                        self.unlock_password_len,
                        error,
                        &self.theme,
                    );
                }
                OverlayPhase::UnlockProgress => {
                    render::draw_status_toast(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &self.unlock_message,
                        &self.theme,
                    );
                }
            }

            // Convert RGBA -> ARGB8888 (swap R and B channels).
            let mut pixel_data = pixmap.take();
            render::convert_rgba_to_argb8888(&mut pixel_data);

            // Copy rendered pixels into the wl_shm canvas.
            let len = canvas.len().min(pixel_data.len());
            canvas[..len].copy_from_slice(&pixel_data[..len]);
        } else {
            // Pixmap creation failed — fill with transparent.
            canvas.fill(0);
        }

        // Attach buffer to surface and commit.
        if let Some(ref surface) = self.layer_surface {
            let wl_surface = surface.wl_surface();
            buffer
                .attach_to(wl_surface)
                .expect("failed to attach buffer");
            // Inform the compositor about the buffer scale for HiDPI.
            // Ceil the fractional scale so the buffer is slightly oversampled
            // rather than undersized. The compositor downscales to the correct
            // logical size. TODO: use wp_fractional_scale_v1 + wp_viewport for
            // pixel-perfect fractional scaling.
            wl_surface.set_buffer_scale(scale.ceil() as i32);
            wl_surface.damage_buffer(0, 0, width as i32, height as i32);
            wl_surface.commit();
        }
    }

    fn process_command(&mut self, cmd: OverlayCmd, qh: &QueueHandle<Self>) {
        match cmd {
            OverlayCmd::ShowBorder => {
                self.phase = OverlayPhase::BorderOnly;
                self.input_buffer.clear();
                self.selection = 0;
                self.activated_at = Some(std::time::Instant::now());
                self.received_key_event = false;
                self.ipc_keyboard_active = false;
                self.last_real_input_at = None;
                self.staged_launch = None;
                self.modifier_released_sent = false;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowFull { windows, hints } => {
                self.phase = OverlayPhase::Full;
                self.windows = windows;
                self.hints = hints;
                if self.activated_at.is_none() {
                    self.activated_at = Some(std::time::Instant::now());
                    self.received_key_event = false;
                    self.ipc_keyboard_active = false;
                    self.last_real_input_at = None;
                }
                self.modifier_released_sent = false;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::UpdateInput { input, selection } => {
                self.input_buffer = input;
                self.staged_launch = None;
                self.selection = selection;
                self.last_real_input_at = Some(std::time::Instant::now());
                self.needs_redraw = true;
            }
            OverlayCmd::Hide => {
                self.hide_common();
                // Immediately render transparent frame.
                self.render_frame(qh);
            }
            OverlayCmd::HideAndSync => {
                self.hide_common();
                // Render transparent frame immediately.
                self.render_frame(qh);
                // Request a display sync — when the callback fires we know the
                // compositor has processed our transparent buffer and keyboard
                // interactivity change.
                self.pending_sync = true;
                // Send SurfaceUnmapped immediately — the transparent frame has
                // been committed and flushed. The compositor will process it
                // before our next request because Wayland is ordered.
                self.send_event(OverlayEvent::SurfaceUnmapped);
                self.pending_sync = false;
            }
            OverlayCmd::ShowLaunchStaged { command } => {
                self.staged_launch = Some(command);
                self.last_real_input_at = Some(std::time::Instant::now());
                self.needs_redraw = true;
            }
            OverlayCmd::ShowLaunching => {
                self.phase = OverlayPhase::Launching;
                self.error_message.clear();
                self.last_real_input_at = Some(std::time::Instant::now());
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowLaunchError { message } => {
                self.phase = OverlayPhase::LaunchError;
                self.error_message = message;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowUnlockPrompt {
                profile,
                password_len,
                error,
            } => {
                self.phase = OverlayPhase::UnlockPrompt;
                self.unlock_profile = profile;
                self.unlock_password_len = password_len;
                if let Some(err) = error {
                    self.error_message = err;
                } else {
                    self.error_message.clear();
                }
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowUnlockProgress { profile, message } => {
                self.phase = OverlayPhase::UnlockProgress;
                self.unlock_profile = profile;
                self.unlock_message = message;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ResetGrace => {
                self.activated_at = Some(std::time::Instant::now());
                self.received_key_event = false;
                self.ipc_keyboard_active = false;
                self.last_real_input_at = None;
                self.modifier_released_sent = false;
            }
            OverlayCmd::ConfirmKeyboardInput => {
                self.received_key_event = true;
                self.ipc_keyboard_active = true;
            }
            OverlayCmd::UpdateTheme(theme) => {
                self.theme = *theme;
                self.needs_redraw = true;
            }
            OverlayCmd::Quit => {
                self.running = false;
            }
        }
    }

    fn poll_modifiers(&mut self) {
        let phase = self.phase;
        if phase == OverlayPhase::Hidden {
            self.modifier_released_sent = false;
            return;
        }

        let elapsed_ms = self
            .activated_at
            .map(|t| t.elapsed().as_millis())
            .unwrap_or(0);
        let within_grace = elapsed_ms < MODIFIER_POLL_GRACE_MS;

        // Hammer keyboard exclusivity until we get a key event.
        if !self.received_key_event {
            self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
        }

        // Stale activation timeout: no input path confirmed at all.
        if !self.received_key_event
            && elapsed_ms >= STALE_ACTIVATION_TIMEOUT_MS
            && !self.modifier_released_sent
        {
            self.modifier_released_sent = true;
            self.send_event(OverlayEvent::Dismiss);
            return;
        }

        // IPC idle timeout: proactive confirmation was sent (zero-window launcher)
        // but no real user input has arrived. daemon-input may be down.
        if self.ipc_keyboard_active
            && self.last_real_input_at.is_none()
            && elapsed_ms >= IPC_IDLE_TIMEOUT_MS
            && !self.modifier_released_sent
        {
            tracing::warn!(
                "IPC keyboard confirmed but no input received after {IPC_IDLE_TIMEOUT_MS}ms, dismissing"
            );
            self.modifier_released_sent = true;
            self.send_event(OverlayEvent::Dismiss);
            return;
        }

        // Normal modifier poll: only when keyboard focus IS confirmed
        // AND IPC keyboard routing is NOT active.
        if !within_grace && self.received_key_event && !self.ipc_keyboard_active && !self.alt_held {
            if !self.modifier_released_sent {
                self.modifier_released_sent = true;
                self.send_event(OverlayEvent::ModifierReleased);
            }
        } else if self.alt_held {
            self.modifier_released_sent = false;
        }
    }
}

// ---------------------------------------------------------------------------
// SCTK delegate implementations
// ---------------------------------------------------------------------------

impl CompositorHandler for OverlayApp {
    fn scale_factor_changed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        // This callback only provides integer scale. Fractional scaling
        // requires wp_fractional_scale_v1 which is deferred to a future release.
        self.output_scale = new_factor as f32;
        self.needs_redraw = true;
    }

    fn transform_changed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _new_transform: wl_output::Transform,
    ) {
        // No action needed for transform changes.
    }

    fn frame(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _time: u32,
    ) {
        if self.needs_redraw {
            self.render_frame(qh);
        }
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

impl OutputHandler for OverlayApp {
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

impl ShmHandler for OverlayApp {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

impl SeatHandler for OverlayApp {
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
        if capability == Capability::Keyboard {
            let _ = self.seat_state.get_keyboard(qh, &seat, None);
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

impl KeyboardHandler for OverlayApp {
    fn enter(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _surface: &wl_surface::WlSurface,
        _serial: u32,
        _raw: &[u32],
        _keysyms: &[Keysym],
    ) {
        self.received_key_event = true;
        // The overlay only receives keyboard focus when it requests
        // KeyboardInteractivity::Exclusive, which happens during Alt+Tab
        // or Alt+Space activation. Defensively assume Alt is held so that
        // the Tab key handler suppresses SelectionDown — otherwise a Tab
        // press_key can fire before update_modifiers sets alt_held, causing
        // double-advancement (once from the SCTK Tab and once from the IPC
        // re-activation that the compositor sends for Alt+Tab).
        // update_modifiers will correct alt_held to false if Alt was released.
        self.alt_held = true;
    }

    fn leave(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _surface: &wl_surface::WlSurface,
        _serial: u32,
    ) {
    }

    fn press_key(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _serial: u32,
        event: KeyEvent,
    ) {
        self.received_key_event = true;

        let event = match event.keysym {
            Keysym::Escape => Some(OverlayEvent::Escape),
            Keysym::Return | Keysym::KP_Enter => Some(OverlayEvent::Confirm),
            Keysym::Tab => {
                // Tab-based cycling is entirely handled by IPC re-activation
                // (WmActivateOverlay). The compositor intercepts Alt+Tab and
                // spawns a new sesame process which sends the IPC message.
                // Suppress Tab here unconditionally to prevent double-advancement.
                // Use Down/Up arrow keys for non-Alt navigation (launcher mode).
                None
            }
            Keysym::ISO_Left_Tab => {
                // Same as Tab — backward cycling handled by IPC re-activation
                // (WmActivateOverlayBackward). Use Up arrow for non-Alt nav.
                None
            }
            Keysym::Down => Some(OverlayEvent::SelectionDown),
            Keysym::Up => Some(OverlayEvent::SelectionUp),
            Keysym::BackSpace => Some(OverlayEvent::Backspace),
            Keysym::space => Some(OverlayEvent::KeyChar(' ')),
            _ => event
                .utf8
                .as_ref()
                .and_then(|s| {
                    let mut chars = s.chars();
                    let c = chars.next()?;
                    if chars.next().is_none() && c.is_ascii_graphic() {
                        Some(c)
                    } else {
                        None
                    }
                })
                .map(OverlayEvent::KeyChar),
        };

        if let Some(ev) = event {
            self.send_event(ev);
        }
    }

    fn release_key(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _serial: u32,
        event: KeyEvent,
    ) {
        self.received_key_event = true;
        if matches!(
            event.keysym,
            Keysym::Alt_L | Keysym::Alt_R | Keysym::Meta_L | Keysym::Meta_R
        ) {
            self.send_event(OverlayEvent::ModifierReleased);
        }
    }

    fn update_modifiers(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _keyboard: &wl_keyboard::WlKeyboard,
        _serial: u32,
        modifiers: Modifiers,
        _raw_modifiers: RawModifiers,
        _layout: u32,
    ) {
        self.alt_held = modifiers.alt;
    }

    fn repeat_key(
        &mut self,
        conn: &Connection,
        qh: &QueueHandle<Self>,
        keyboard: &wl_keyboard::WlKeyboard,
        serial: u32,
        event: KeyEvent,
    ) {
        // Treat key repeats the same as key presses for navigation.
        self.press_key(conn, qh, keyboard, serial, event);
    }
}

impl LayerShellHandler for OverlayApp {
    fn closed(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _layer: &LayerSurface) {
        self.running = false;
    }

    fn configure(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        _layer: &LayerSurface,
        configure: LayerSurfaceConfigure,
        _serial: u32,
    ) {
        let (width, height) = if configure.new_size.0 > 0 && configure.new_size.1 > 0 {
            (configure.new_size.0, configure.new_size.1)
        } else {
            // Fallback if compositor gives (0,0) — use a reasonable default.
            // This shouldn't happen with anchored fullscreen surfaces.
            (1920, 1080)
        };

        self.configured_size = (width, height);

        // Create or resize the slot pool (account for HiDPI buffer scaling).
        let scale = self.output_scale;
        let phys_w = (width as f32 * scale) as u32;
        let phys_h = (height as f32 * scale) as u32;
        let buf_size = (phys_w * phys_h * 4) as usize;
        if self.slot_pool.is_none() {
            if let Ok(pool) = SlotPool::new(buf_size, &self.shm) {
                self.slot_pool = Some(pool);
            }
        } else if let Some(ref mut pool) = self.slot_pool {
            // Ensure pool is large enough.
            if let Err(e) = pool.resize(buf_size) {
                tracing::warn!("failed to resize slot pool: {e}");
            }
        }

        self.needs_redraw = true;
        self.render_frame(qh);
    }
}

impl ProvidesRegistryState for OverlayApp {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }

    registry_handlers![OutputState, SeatState];
}

delegate_compositor!(OverlayApp);
delegate_output!(OverlayApp);
delegate_shm!(OverlayApp);
delegate_seat!(OverlayApp);
delegate_keyboard!(OverlayApp);
delegate_layer!(OverlayApp);
delegate_registry!(OverlayApp);

// ---------------------------------------------------------------------------
// Public API: spawn the overlay thread
// ---------------------------------------------------------------------------

/// Spawn the SCTK overlay on a dedicated thread.
///
/// Returns channels for bidirectional communication:
/// - `cmd_tx`: send commands to the overlay (show, hide, update)
/// - `event_rx`: receive user interaction events (key presses)
///
/// The overlay thread runs its own poll-based event loop and blocks until `Quit`.
pub fn spawn_overlay(
    theme: OverlayTheme,
    show_app_id: bool,
    show_title: bool,
) -> (
    mpsc::Sender<OverlayCmd>,
    tokio::sync::mpsc::Receiver<OverlayEvent>,
) {
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<OverlayEvent>(64);
    let (cmd_tx, cmd_rx) = mpsc::channel::<OverlayCmd>();

    std::thread::Builder::new()
        .name("overlay-sctk".into())
        .spawn(move || {
            run_sctk_overlay(cmd_rx, event_tx, theme, show_app_id, show_title);
        })
        .expect("failed to spawn overlay thread");

    (cmd_tx, event_rx)
}

// ---------------------------------------------------------------------------
// SCTK overlay main loop (runs on dedicated thread)
// ---------------------------------------------------------------------------

fn run_sctk_overlay(
    cmd_rx: mpsc::Receiver<OverlayCmd>,
    event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,
    theme: OverlayTheme,
    show_app_id: bool,
    show_title: bool,
) {
    // Connect to the Wayland display.
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

    // Initialize SCTK state objects.
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
            tracing::warn!(
                "failed to bind zwlr_layer_shell_v1: {e}. \
                 Overlay disabled — layer-shell protocol is required. \
                 Supported compositors: COSMIC, Sway, Hyprland, niri, KWin 6+, Wayfire."
            );
            run_stub_loop(cmd_rx, event_tx);
            return;
        }
    };

    // Create an empty wl_region for click-through when the overlay is hidden.
    let empty_input_region = match Region::new(&compositor_state) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("failed to create wl_region for input passthrough: {e}");
            tracing::error!("overlay disabled — falling back to stub loop");
            run_stub_loop(cmd_rx, event_tx);
            return;
        }
    };

    // Create the layer surface — fullscreen, overlay layer.
    let surface = compositor_state.create_surface(&qh);
    let layer_surface = layer_shell.create_layer_surface(
        &qh,
        surface,
        Layer::Overlay,
        Some("sesame"),
        None, // all outputs
    );
    layer_surface.set_anchor(Anchor::TOP | Anchor::BOTTOM | Anchor::LEFT | Anchor::RIGHT);
    layer_surface.set_exclusive_zone(-1);
    layer_surface.set_keyboard_interactivity(KeyboardInteractivity::None);
    layer_surface.commit();

    let font_system = {
        let mut db = cosmic_text::fontdb::Database::new();
        db.load_system_fonts();
        FontSystem::new_with_locale_and_db("en-US".to_string(), db)
    };
    let swash_cache = SwashCache::new();

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
        font_system,
        swash_cache,
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
        empty_input_region,
    };

    // Run the event loop. We use a simple poll loop with blocking_dispatch
    // and non-blocking command channel reads, similar to the GTK4 GLib timeout
    // pattern but using Wayland's own dispatch mechanism.
    //
    // The loop:
    // 1. Dispatch Wayland events (blocking with timeout for ~4ms latency)
    // 2. Drain all pending commands from the std::sync::mpsc channel
    // 3. Poll modifier state for stale activation detection
    // 4. Render if needed
    while app.running {
        // Flush outgoing requests.
        if let Err(e) = conn.flush() {
            tracing::error!("Wayland connection flush failed: {e}");
            // Best-effort: unblock main loop if a HideAndSync is pending.
            if app.pending_sync {
                app.send_event(OverlayEvent::SurfaceUnmapped);
            }
            break;
        }

        // Prepare to read events. This ensures we have the read intent before
        // blocking on the fd.
        let read_guard = match event_queue.prepare_read() {
            Some(g) => g,
            None => {
                // Events are pending in the internal queue — dispatch them.
                if let Err(e) = event_queue.dispatch_pending(&mut app) {
                    tracing::error!("Wayland dispatch error: {e}");
                    if app.pending_sync {
                        app.send_event(OverlayEvent::SurfaceUnmapped);
                    }
                    break;
                }
                // Drain commands and poll after dispatching.
                drain_commands(&mut app, &qh, &cmd_rx);
                app.poll_modifiers();
                if app.needs_redraw {
                    app.render_frame(&qh);
                }
                continue;
            }
        };

        // Wait for Wayland events with a timeout so we can poll commands.
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

        // Read any available events.
        match read_guard.read() {
            Ok(_) => {}
            Err(wayland_client::backend::WaylandError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                tracing::error!("Wayland read error: {e}");
                if app.pending_sync {
                    app.send_event(OverlayEvent::SurfaceUnmapped);
                }
                break;
            }
        }

        // Dispatch any events that were read.
        if let Err(e) = event_queue.dispatch_pending(&mut app) {
            tracing::error!("Wayland dispatch error: {e}");
            if app.pending_sync {
                app.send_event(OverlayEvent::SurfaceUnmapped);
            }
            break;
        }

        // Drain commands from the tokio side.
        drain_commands(&mut app, &qh, &cmd_rx);

        // Poll modifier state.
        app.poll_modifiers();

        // Render if needed.
        if app.needs_redraw {
            app.render_frame(&qh);
        }
    }

    tracing::info!("overlay thread exiting");
}

/// Stub event loop for compositors without layer-shell support (e.g. GNOME/Mutter).
/// Drains commands and responds to `HideAndSync` with `SurfaceUnmapped` so the
/// main event loop never deadlocks waiting for an acknowledgment.
fn run_stub_loop(
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
                        "overlay not available: this compositor does not support \
                         wlr-layer-shell. The window switcher requires COSMIC, \
                         Sway, Hyprland, niri, or KWin 6+. GNOME/Mutter is not \
                         supported."
                    );
                    warned = true;
                }
                // Immediately dismiss so the controller doesn't hang for
                // the full stale activation timeout (3 seconds).
                let _ = event_tx.blocking_send(OverlayEvent::Dismiss);
            }
            Ok(_) => {}      // Ignore other commands.
            Err(_) => break, // Sender dropped — main loop exited.
        }
    }
    tracing::info!("overlay stub loop exiting");
}

fn drain_commands(
    app: &mut OverlayApp,
    qh: &QueueHandle<OverlayApp>,
    cmd_rx: &mpsc::Receiver<OverlayCmd>,
) {
    while let Ok(cmd) = cmd_rx.try_recv() {
        app.process_command(cmd, qh);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_phase_transitions() {
        assert_ne!(OverlayPhase::Hidden, OverlayPhase::BorderOnly);
        assert_ne!(OverlayPhase::BorderOnly, OverlayPhase::Full);
    }

    #[test]
    fn window_info_clone() {
        let info = WindowInfo {
            app_id: "com.mitchellh.ghostty".into(),
            title: "Terminal".into(),
        };
        let cloned = info.clone();
        assert_eq!(cloned.app_id, "com.mitchellh.ghostty");
    }

    #[test]
    fn overlay_cmd_debug() {
        let cmd = OverlayCmd::ShowBorder;
        assert!(format!("{cmd:?}").contains("ShowBorder"));
    }

    #[test]
    fn overlay_event_debug() {
        let ev = OverlayEvent::KeyChar('a');
        assert!(format!("{ev:?}").contains("KeyChar"));
    }
}
