//! SCTK + wayland-client overlay surface for the window switcher.
//!
//! Manages the full overlay lifecycle: layer-shell surface creation, keyboard
//! input capture, blur protocol binding, and rendering dispatch. Runs on a
//! dedicated thread with its own poll-based event loop.

pub mod app;
pub mod blur;
pub mod commands;
pub mod compositor;
pub mod event_loop;
pub mod keyboard;
pub mod poll;
pub mod render_frame;

use std::sync::mpsc;

// ---------------------------------------------------------------------------
// Channel types — main event loop <-> overlay thread
// ---------------------------------------------------------------------------

/// Commands sent from the tokio event loop to the overlay thread.
#[derive(Debug)]
pub enum OverlayCmd {
    ShowBorder,
    ShowFull {
        windows: Vec<WindowInfo>,
        hints: Vec<String>,
    },
    UpdateInput {
        input: String,
        selection: usize,
    },
    Hide,
    HideAndSync,
    ShowLaunching,
    ShowLaunchStaged {
        command: String,
    },
    ShowLaunchError {
        message: String,
    },
    ShowUnlockPrompt {
        profile: String,
        password_len: usize,
        error: Option<String>,
    },
    ShowUnlockProgress {
        profile: String,
        message: String,
    },
    ResetGrace,
    ConfirmKeyboardInput,
    UpdateTheme(Box<crate::render::OverlayTheme>),
    Quit,
}

/// Events sent from the overlay thread back to the tokio event loop.
#[derive(Debug, Clone)]
pub enum OverlayEvent {
    KeyChar(char),
    Backspace,
    SelectionDown,
    SelectionUp,
    Confirm,
    Escape,
    ModifierReleased,
    Dismiss,
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
pub(crate) enum OverlayPhase {
    Hidden,
    BorderOnly,
    Full,
    Launching,
    LaunchError,
    UnlockPrompt,
    UnlockProgress,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Spawn the SCTK overlay on a dedicated thread.
pub fn spawn_overlay(
    theme: crate::render::OverlayTheme,
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
            event_loop::run_sctk_overlay(cmd_rx, event_tx, theme, show_app_id, show_title);
        })
        .expect("failed to spawn overlay thread");

    (cmd_tx, event_rx)
}
