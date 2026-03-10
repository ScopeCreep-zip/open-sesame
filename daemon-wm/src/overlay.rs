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
}

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
    window.set_keyboard_mode(KeyboardMode::Exclusive);

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
                );
            }
        }
    });

    // Keyboard input controller.
    let key_controller = gtk4::EventControllerKey::new();
    let event_tx_press = event_tx.clone();
    key_controller.connect_key_pressed(move |_ctrl, keyval, _keycode, modifiers| {
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
    let event_tx_release = event_tx;
    key_controller.connect_key_released(move |_ctrl, keyval, _keycode, _modifiers| {
        if matches!(
            keyval,
            gdk::Key::Alt_L | gdk::Key::Alt_R | gdk::Key::Meta_L | gdk::Key::Meta_R
        ) {
            let _ = event_tx_release.blocking_send(OverlayEvent::ModifierReleased);
        }
    });

    window.add_controller(key_controller);

    // Start hidden.
    window.set_visible(false);

    // Poll the command channel from the GLib main loop via a timeout source.
    // 4ms interval (~250Hz) balances latency and CPU. Commands are non-blocking
    // try_recv so the GLib loop stays responsive.
    let state_cmd = Rc::clone(&state);
    let window_cmd = window.clone();
    let da_cmd = drawing_area.clone();
    let main_loop = glib::MainLoop::new(None, false);
    let main_loop_quit = main_loop.clone();

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
                    }
                    window_cmd.set_visible(true);
                    da_cmd.queue_draw();
                }
                OverlayCmd::ShowFull { windows, hints } => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::Full;
                        st.windows = windows;
                        st.hints = hints;
                    }
                    window_cmd.set_visible(true);
                    da_cmd.queue_draw();
                }
                OverlayCmd::UpdateInput { input, selection } => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.input_buffer = input;
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
                    }
                    window_cmd.set_visible(false);
                }
                OverlayCmd::HideAndSync => {
                    {
                        let mut st = state_cmd.borrow_mut();
                        st.phase = OverlayPhase::Hidden;
                        st.input_buffer.clear();
                        st.selection = 0;
                        st.windows.clear();
                        st.hints.clear();
                    }
                    window_cmd.set_visible(false);
                    // Flush the unmap to the compositor and wait for
                    // confirmation so the exclusive layer surface is gone
                    // before the caller activates a different window.
                    if let Some(display) = gdk::Display::default() {
                        display.sync();
                        display.flush();
                    }
                    let _ = event_tx_cmd.blocking_send(OverlayEvent::SurfaceUnmapped);
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
