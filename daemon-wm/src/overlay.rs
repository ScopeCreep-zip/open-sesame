//! GTK4 layer-shell overlay window for the window switcher.
//!
//! Manages the full overlay lifecycle: layer-shell surface creation, keyboard
//! input capture, state machine integration, and Cairo rendering via the
//! `render` module. Runs on a dedicated thread with its own GLib main loop,
//! communicating with the tokio event loop via std channels polled by a
//! GLib timeout source.

use crate::render::{self, HintRow, OverlayTheme};
use gtk4::gdk;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4_layer_shell::{Edge, KeyboardMode, Layer, LayerShell};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;

// ---------------------------------------------------------------------------
// Channel types — main event loop <-> GTK4 overlay thread
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
    UpdateInput {
        input: String,
        selection: usize,
    },
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
    ShowLaunchStaged {
        command: String,
    },
    /// Show launch error with message.
    ShowLaunchError {
        message: String,
    },
    /// Reset the modifier-poll grace timer. Proves Alt is still held
    /// (an IPC re-activation wouldn't fire otherwise).
    ResetGrace,
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
}

// ---------------------------------------------------------------------------
// Internal overlay state (lives on the GTK4 thread, Rc<RefCell<>>)
// ---------------------------------------------------------------------------

struct OverlayState {
    phase: OverlayPhase,
    windows: Vec<WindowInfo>,
    hints: Vec<String>,
    input_buffer: String,
    selection: usize,
    theme: OverlayTheme,
    show_app_id: bool,
    show_title: bool,
    /// When the overlay was last activated. Used to skip modifier polling
    /// during a grace period while the compositor establishes keyboard focus.
    activated_at: Option<std::time::Instant>,
    /// Set to true once any keyboard event is received for this activation
    /// cycle. When true, modifier polling is skipped because keyboard focus
    /// is confirmed working — the real key-release handler will fire.
    received_key_event: bool,
    /// Error message to display in LaunchError phase.
    error_message: String,
    /// Staged launch command — shown in picker instead of "no matches".
    staged_launch: Option<String>,
}

/// Grace period (ms) after activation before modifier polling begins.
/// Gives the compositor time to forward modifier state to our surface.
const MODIFIER_POLL_GRACE_MS: u128 = 150;

impl OverlayState {
    fn new(theme: OverlayTheme, show_app_id: bool, show_title: bool) -> Self {
        Self {
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
            error_message: String::new(),
            staged_launch: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API: spawn the overlay thread
// ---------------------------------------------------------------------------

/// Spawn the GTK4 overlay on a dedicated thread.
///
/// Returns channels for bidirectional communication:
/// - `cmd_tx`: send commands to the overlay (show, hide, update)
/// - `event_rx`: receive user interaction events (key presses)
///
/// The overlay thread runs its own GLib main loop and blocks until `Quit`.
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
        .name("overlay-gtk4".into())
        .spawn(move || {
            run_gtk4_overlay(cmd_rx, event_tx, theme, show_app_id, show_title);
        })
        .expect("failed to spawn overlay thread");

    (cmd_tx, event_rx)
}

// ---------------------------------------------------------------------------
// GTK4 overlay main loop (runs on dedicated thread)
// ---------------------------------------------------------------------------

fn run_gtk4_overlay(
    cmd_rx: mpsc::Receiver<OverlayCmd>,
    event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,
    theme: OverlayTheme,
    show_app_id: bool,
    show_title: bool,
) {
    gtk4::init().expect("failed to initialize GTK4");

    let state = Rc::new(RefCell::new(OverlayState::new(theme, show_app_id, show_title)));

    // Create the window.
    let window = gtk4::Window::new();
    window.set_title(Some("sesame"));
    window.set_decorated(false);

    // Layer-shell setup — must happen before realize/show.
    window.init_layer_shell();
    window.set_layer(Layer::Overlay);
    window.set_namespace(Some("sesame"));
    window.set_anchor(Edge::Top, true);
    window.set_anchor(Edge::Bottom, true);
    window.set_anchor(Edge::Left, true);
    window.set_anchor(Edge::Right, true);
    window.set_exclusive_zone(-1);
    window.set_keyboard_mode(KeyboardMode::None);

    // Transparent background via CSS.
    let css_provider = gtk4::CssProvider::new();
    css_provider.load_from_string("window { background: transparent; }");
    gtk4::style_context_add_provider_for_display(
        &gdk::Display::default().expect("no display"),
        &css_provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Drawing area fills the entire layer surface.
    let drawing_area = gtk4::DrawingArea::new();
    drawing_area.set_hexpand(true);
    drawing_area.set_vexpand(true);
    window.set_child(Some(&drawing_area));

    // Connect draw function.
    let state_draw = Rc::clone(&state);
    drawing_area.set_draw_func(move |_da, cr, width, height| {
        let st = state_draw.borrow();
        match st.phase {
            OverlayPhase::Hidden => {
                cr.set_operator(gtk4::cairo::Operator::Source);
                cr.set_source_rgba(0.0, 0.0, 0.0, 0.0);
                let _ = cr.paint();
            }
            OverlayPhase::BorderOnly => {
                render::draw_border_only(cr, width as f64, height as f64, &st.theme);
            }
            OverlayPhase::Full => {
                let rows: Vec<HintRow<'_>> = st
                    .windows
                    .iter()
                    .zip(st.hints.iter())
                    .map(|(w, h)| HintRow {
                        hint: h.as_str(),
                        app_id: &w.app_id,
                        title: &w.title,
                    })
                    .collect();
                render::draw_full_overlay(
                    cr,
                    width as f64,
                    height as f64,
                    &rows,
                    &st.input_buffer,
                    st.selection,
                    &st.hints,
                    &st.theme,
                    st.show_app_id,
                    st.show_title,
                    st.staged_launch.as_deref(),
                );
            }
            OverlayPhase::Launching => {
                render::draw_status_toast(
                    cr, width as f64, height as f64,
                    "Launching\u{2026}", &st.theme,
                );
            }
            OverlayPhase::LaunchError => {
                render::draw_error_toast(
                    cr, width as f64, height as f64,
                    &st.error_message, &st.theme,
                );
            }
        }
    });

    // Keyboard input controller.
    let key_controller = gtk4::EventControllerKey::new();
    let event_tx_press = event_tx.clone();
    let state_key = Rc::clone(&state);
    key_controller.connect_key_pressed(move |_ctrl, keyval, _keycode, modifiers| {
        // Mark that keyboard focus is confirmed working.
        state_key.borrow_mut().received_key_event = true;
        let event = match keyval {
            gdk::Key::Escape => Some(OverlayEvent::Escape),
            gdk::Key::Return | gdk::Key::KP_Enter => Some(OverlayEvent::Confirm),
            gdk::Key::Tab => {
                if modifiers.contains(gdk::ModifierType::SHIFT_MASK) {
                    Some(OverlayEvent::SelectionUp)
                } else {
                    Some(OverlayEvent::SelectionDown)
                }
            }
            gdk::Key::Down => Some(OverlayEvent::SelectionDown),
            gdk::Key::Up => Some(OverlayEvent::SelectionUp),
            gdk::Key::BackSpace => Some(OverlayEvent::Backspace),
            gdk::Key::space => None, // inert — activation key, not navigation
            _ => {
                if let Some(ch) = keyval.to_unicode() {
                    if ch.is_alphanumeric() {
                        Some(OverlayEvent::KeyChar(ch))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if let Some(ev) = event {
            let _ = event_tx_press.blocking_send(ev);
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });

    // Detect Alt key release for quick-switch.
    let event_tx_cmd = event_tx.clone();
    let event_tx_poll = event_tx.clone();
    let event_tx_release = event_tx;
    let state_release = Rc::clone(&state);
    key_controller.connect_key_released(move |_ctrl, keyval, _keycode, _modifiers| {
        state_release.borrow_mut().received_key_event = true;
        if matches!(
            keyval,
            gdk::Key::Alt_L | gdk::Key::Alt_R | gdk::Key::Meta_L | gdk::Key::Meta_R
        ) {
            let _ = event_tx_release.blocking_send(OverlayEvent::ModifierReleased);
        }
    });

    window.add_controller(key_controller);

    // Show the window immediately so the layer surface is created once and
    // never destroyed. "Hiding" is done by drawing fully transparent and
    // setting KeyboardMode::None — this avoids the layer surface
    // destroy/recreate cycle that causes cosmic-comp to kill our connection.
    window.set_visible(true);

    // Start with an empty input region so the transparent surface doesn't
    // steal pointer events. On show we restore to None (full surface).
    if let Some(surface) = window.surface() {
        let empty = gtk4::cairo::Region::create();
        surface.set_input_region(&empty);
    }

    // Poll the command channel from the GLib main loop via a timeout source.
    // 4ms interval (~250Hz) balances latency and CPU. Commands are non-blocking
    // try_recv so the GLib loop stays responsive.
    let state_cmd = Rc::clone(&state);
    let state_poll = Rc::clone(&state);
    let window_cmd = window.clone();
    let window_poll = window.clone();
    let da_cmd = drawing_area.clone();
    let main_loop = glib::MainLoop::new(None, false);
    let main_loop_quit = main_loop.clone();

    // Track whether we already sent a polled ModifierReleased this cycle
    // to avoid duplicate events.
    let modifier_released_sent = Rc::new(RefCell::new(false));
    let modifier_released_flag = Rc::clone(&modifier_released_sent);

    glib::timeout_add_local(std::time::Duration::from_millis(4), move || {
        // Drain all pending commands per tick.
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                OverlayCmd::ShowBorder => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::BorderOnly;
                        st.input_buffer.clear();
                        st.selection = 0;
                        st.activated_at = Some(std::time::Instant::now());
                        st.received_key_event = false;
                        st.staged_launch = None;
                    }
                    // Reset modifier poll flag for this activation cycle.
                    *modifier_released_sent.borrow_mut() = false;
                    // Restore full input region so overlay captures input.
                    if let Some(surface) = window_cmd.surface() {
                        surface.set_input_region(&gtk4::cairo::Region::create_rectangle(
                            &gtk4::cairo::RectangleInt::new(0, 0, i32::MAX, i32::MAX),
                        ));
                    }
                    window_cmd.set_keyboard_mode(KeyboardMode::Exclusive);
                    da_cmd.queue_draw();
                }
                OverlayCmd::ShowFull { windows, hints } => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::Full;
                        st.windows = windows;
                        st.hints = hints;
                        if st.activated_at.is_none() {
                            st.activated_at = Some(std::time::Instant::now());
                            st.received_key_event = false;
                        }
                    }
                    // Reset modifier poll flag for this activation cycle.
                    *modifier_released_sent.borrow_mut() = false;
                    // Restore full input region so overlay captures input.
                    if let Some(surface) = window_cmd.surface() {
                        surface.set_input_region(&gtk4::cairo::Region::create_rectangle(
                            &gtk4::cairo::RectangleInt::new(0, 0, i32::MAX, i32::MAX),
                        ));
                    }
                    window_cmd.set_keyboard_mode(KeyboardMode::Exclusive);
                    da_cmd.queue_draw();
                }
                OverlayCmd::UpdateInput { input, selection } => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.input_buffer = input;
                        // Clear staged launch — if still staged, ShowLaunchStaged
                        // will arrive after this in the same command batch.
                        st.staged_launch = None;
                        st.selection = selection;
                    }
                    da_cmd.queue_draw();
                }
                OverlayCmd::Hide => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::Hidden;
                        st.input_buffer.clear();
                        st.selection = 0;
                        st.windows.clear();
                        st.hints.clear();
                        st.activated_at = None;
                        st.received_key_event = false;
                        st.staged_launch = None;
                    }
                    // Release keyboard grab and commit transparent frame.
                    // Surface stays mapped to avoid layer surface destroy.
                    window_cmd.set_keyboard_mode(KeyboardMode::None);
                    // Empty input region so pointer events pass through.
                    if let Some(surface) = window_cmd.surface() {
                        surface.set_input_region(&gtk4::cairo::Region::create());
                    }
                    da_cmd.queue_draw();
                    // Pump GLib to flush the transparent frame to the
                    // compositor before returning. Without this, the last
                    // visible frame stays on screen indefinitely because the
                    // compositor stops sending frame callbacks to unfocused
                    // surfaces.
                    while glib::MainContext::default().iteration(false) {}
                }
                OverlayCmd::HideAndSync => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::Hidden;
                        st.input_buffer.clear();
                        st.selection = 0;
                        st.windows.clear();
                        st.hints.clear();
                        st.activated_at = None;
                        st.received_key_event = false;
                        st.staged_launch = None;
                    }
                    // Release keyboard grab and commit transparent frame.
                    window_cmd.set_keyboard_mode(KeyboardMode::None);
                    // Empty input region so pointer events pass through.
                    if let Some(surface) = window_cmd.surface() {
                        surface.set_input_region(&gtk4::cairo::Region::create());
                    }
                    da_cmd.queue_draw();
                    // Pump GLib to flush the transparent frame before the
                    // display sync — ensures the compositor receives the
                    // new buffer, not the stale window-list frame.
                    while glib::MainContext::default().iteration(false) {}
                    // Flush keyboard interactivity change + transparent
                    // buffer to compositor before caller activates window.
                    if let Some(display) = gdk::Display::default() {
                        display.sync();
                        display.flush();
                    }
                    let _ = event_tx_cmd.blocking_send(OverlayEvent::SurfaceUnmapped);
                }
                OverlayCmd::ShowLaunchStaged { command } => {
                    // Picker stays visible — update the staged launch indicator
                    // so the renderer shows "Launch <command>" instead of
                    // "No matches". The picker provides trust and context.
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.staged_launch = Some(command);
                    }
                    da_cmd.queue_draw();
                }
                OverlayCmd::ShowLaunching => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::Launching;
                        st.error_message.clear();
                    }
                    // Keep keyboard exclusive so Escape works.
                    window_cmd.set_keyboard_mode(KeyboardMode::Exclusive);
                    if let Some(surface) = window_cmd.surface() {
                        surface.set_input_region(&gtk4::cairo::Region::create_rectangle(
                            &gtk4::cairo::RectangleInt::new(0, 0, i32::MAX, i32::MAX),
                        ));
                    }
                    da_cmd.queue_draw();
                }
                OverlayCmd::ShowLaunchError { message } => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::LaunchError;
                        st.error_message = message;
                    }
                    window_cmd.set_keyboard_mode(KeyboardMode::Exclusive);
                    if let Some(surface) = window_cmd.surface() {
                        surface.set_input_region(&gtk4::cairo::Region::create_rectangle(
                            &gtk4::cairo::RectangleInt::new(0, 0, i32::MAX, i32::MAX),
                        ));
                    }
                    da_cmd.queue_draw();
                }
                OverlayCmd::ResetGrace => {
                    // An IPC re-activation proves Alt is still held.
                    // Reset the grace timer and poll flag so the modifier
                    // poll safety net doesn't fire prematurely.
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.activated_at = Some(std::time::Instant::now());
                        st.received_key_event = false;
                    }
                    *modifier_released_sent.borrow_mut() = false;
                }
                OverlayCmd::UpdateTheme(theme) => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.theme = *theme;
                    }
                    da_cmd.queue_draw();
                }
                OverlayCmd::Quit => {
                    window_cmd.close();
                    main_loop_quit.quit();
                    return glib::ControlFlow::Break;
                }
            }
        }

        // -- Modifier polling safety net --
        // When activated via COSMIC's system_actions, the compositor may
        // intercept the Alt key before our surface acquires keyboard
        // exclusivity. If Alt is released during that race window, we
        // never see the key-release event and get stuck. Poll the
        // current modifier state and synthesize ModifierReleased if
        // Alt/Meta is no longer held.
        let st = state_poll.borrow();
        let phase = st.phase;
        let within_grace = st.activated_at
            .map(|t| t.elapsed().as_millis() < MODIFIER_POLL_GRACE_MS)
            .unwrap_or(false);
        let keyboard_confirmed = st.received_key_event;
        drop(st);

        // Only poll modifier state as a safety net when keyboard focus IS
        // confirmed (at least one key event received). Before that, the
        // modifier state is unreliable — IPC activations (e.g. COSMIC
        // system actions) consume the Alt press, so the overlay's keyboard
        // device never sees it and modifier_state() won't include ALT_MASK
        // even when Alt is physically held. The key-release handler is the
        // primary commit mechanism; this poll is a backup for missed releases.
        if phase != OverlayPhase::Hidden && !within_grace && keyboard_confirmed {
            let alt_held = window_poll.surface()
                .and_then(|surface| surface.display().default_seat())
                .and_then(|seat| seat.keyboard())
                .map(|keyboard| {
                    let mods = keyboard.modifier_state();
                    mods.contains(gdk::ModifierType::ALT_MASK)
                })
                .unwrap_or(true); // assume held if we can't query

            if !alt_held {
                if !*modifier_released_flag.borrow() {
                    *modifier_released_flag.borrow_mut() = true;
                    let _ = event_tx_poll.blocking_send(OverlayEvent::ModifierReleased);
                }
            } else {
                // Alt is held — reset the flag so we detect future releases.
                *modifier_released_flag.borrow_mut() = false;
            }
        } else {
            // Reset flag when hidden.
            *modifier_released_flag.borrow_mut() = false;
        }

        glib::ControlFlow::Continue
    });

    // Run the GLib main loop. Blocks until Quit command is received.
    main_loop.run();
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
