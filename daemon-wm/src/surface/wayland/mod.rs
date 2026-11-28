//! SCTK + wayland-client overlay surface for the window switcher.
//!
//! Manages the full overlay lifecycle: layer-shell surface creation, keyboard
//! input capture, background blur (SCTK `background_effect`), and rendering
//! dispatch. Runs on a dedicated thread with its own poll-based event loop;
//! the daemon drives it with [`OverlayCmd`] and hears from it through
//! [`OverlayEvent`].

pub mod app;
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
    /// Unlock progress; the message names the profile.
    ShowUnlockProgress {
        message: String,
    },
    ResetGrace,
    ConfirmKeyboardInput,
    /// Replace every renderer-owned setting: a configuration application,
    /// acknowledged on `reply` once the renderer holds them, or a theme
    /// refresh from the desktop (`reply` `None`).
    Reconfigure {
        theme: Box<crate::render::OverlayTheme>,
        columns: crate::render::Columns,
        reply: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    },
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowInfo {
    pub app_id: String,
    pub title: String,
}

/// The overlay thread's command sender and event receiver.
pub type OverlayChannels = (
    mpsc::Sender<OverlayCmd>,
    tokio::sync::mpsc::Receiver<OverlayEvent>,
);

/// Spawn the SCTK overlay, themed and laid out by `config`, on a
/// dedicated thread.
///
/// # Errors
///
/// When the thread cannot be spawned.
pub fn spawn_overlay(config: &core_config::WmConfig) -> std::io::Result<OverlayChannels> {
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<OverlayEvent>(64);
    let (cmd_tx, cmd_rx) = mpsc::channel::<OverlayCmd>();
    let theme = crate::render::OverlayTheme::from_config(config);
    let columns = crate::render::Columns::of(config);
    std::thread::Builder::new()
        .name("overlay-sctk".into())
        .spawn(move || event_loop::run_sctk_overlay(&cmd_rx, &event_tx, theme, columns))?;
    Ok((cmd_tx, event_rx))
}
