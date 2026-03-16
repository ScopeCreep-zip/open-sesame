//! Platform abstraction layer
//!
//! Provides traits for window management that can be implemented
//! by different backends (Wayland, mock for testing).
//!
//! Includes COSMIC desktop integration for theming and fonts.

pub mod cosmic_keys;
pub mod cosmic_theme;
pub mod fonts;
pub mod wayland;

use crate::core::window::{Window, WindowId};
use crate::util::Result;

/// Trait for window management operations
///
/// Provides an abstraction layer over platform-specific window management,
/// enabling mocking in tests and potential support for multiple backends
/// (Wayland, X11, mock implementations).
///
/// # Contract
///
/// Implementations must guarantee:
/// - Window IDs returned by `list_windows()` are valid for `activate_window()`
/// - Window list is ordered by most-recently-used (MRU), with current window first
/// - Activation is idempotent (activating an already-focused window succeeds)
///
/// # Thread Safety
///
/// Implementations are not required to be `Send` or `Sync`. Callers should
/// assume window manager operations must happen on the main thread.
pub trait WindowManager {
    /// List all windows on the desktop
    ///
    /// Returns windows in most-recently-used (MRU) order, with the currently
    /// focused window at index 0. This ordering is critical for Alt+Tab behavior
    /// (cycling should start from the previous window, not the current one).
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - Unable to connect to the display server (Wayland/X11)
    /// - Required protocol extensions are unavailable
    /// - Display server communication times out
    /// - Insufficient permissions to enumerate windows
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let windows = wm.list_windows()?;
    /// assert!(!windows.is_empty());
    /// assert!(windows[0].is_focused); // First window should be focused
    /// ```
    fn list_windows(&self) -> Result<Vec<Window>>;

    /// Activate (focus) a window by its ID
    ///
    /// Raises and focuses the specified window. If the window is already focused,
    /// this operation succeeds without side effects (idempotent).
    ///
    /// # Parameters
    ///
    /// - `id`: Window ID obtained from `list_windows()`. Using an ID from a
    ///   different session or backend is undefined behavior.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - Window ID is invalid or window has been closed
    /// - Unable to communicate with the display server
    /// - Compositor denies activation (security policy)
    /// - Operation times out
    ///
    /// # Platform Notes
    ///
    /// **Wayland:** Uses `zcosmic_toplevel_manager_v1::activate()` which requires
    /// COSMIC desktop environment. On other compositors, may fall back to raise-only.
    ///
    /// **X11:** Uses `XRaiseWindow()` + `XSetInputFocus()` which may be subject to
    /// window manager policy (some WMs restrict focus stealing).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let windows = wm.list_windows()?;
    /// if let Some(prev) = windows.get(1) {
    ///     wm.activate_window(&prev.id)?;
    /// }
    /// ```
    fn activate_window(&self, id: &WindowId) -> Result<()>;
}

/// Wayland window management implementation
pub use wayland::{activate_window, enumerate_windows};

/// COSMIC keybinding management functions
pub use cosmic_keys::{keybinding_status, remove_keybinding, setup_keybinding};

/// COSMIC theme integration
pub use cosmic_theme::CosmicTheme;

/// Font resolution utilities
pub use fonts::{fontconfig_available, resolve_font, resolve_sans};
