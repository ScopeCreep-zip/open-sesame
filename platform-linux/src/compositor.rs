//! Compositor backend trait and detection for Linux Wayland compositors.
//!
//! The [`CompositorBackend`] trait abstracts the toplevel operations
//! daemon-wm performs over two Wayland protocol sets:
//! - `ext_foreign_toplevel_list_v1` + `zcosmic_toplevel_info_v1` +
//!   `zcosmic_toplevel_manager_v1` (COSMIC), in `backend_cosmic`;
//! - `wlr-foreign-toplevel-management-v1` (Hyprland, sway, niri, Wayfire),
//!   in `backend_wlr`.
//!
//! Focus tracking lives in `focus_monitor`.
//!
//! To add a new compositor backend:
//! 1. Create `backend_<name>.rs` implementing `CompositorBackend`.
//! 2. Add `pub(crate) mod backend_<name>;` to `lib.rs`.
//! 3. Add a match arm to `detect_compositor()` below.

use core_types::{Window, WindowId};

/// The toplevel operations every compositor backend provides.
///
/// Methods are synchronous: the window list is a snapshot a dispatch
/// thread maintains, and requests are Wayland round-trips that block the
/// calling thread. Async callers run requests on a blocking thread.
pub trait CompositorBackend: Send + Sync {
    /// The open toplevel windows.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the snapshot cannot be read.
    fn list_windows(&self) -> core_types::Result<Vec<Window>>;

    /// Bring window `id` to the foreground with input focus.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the window is unknown or the
    /// request cannot be delivered.
    fn activate_window(&self, id: &WindowId) -> core_types::Result<()>;

    /// Ask window `id` to close.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the window is unknown or the
    /// request cannot be delivered.
    fn close_window(&self, id: &WindowId) -> core_types::Result<()>;

    /// The backend's name for diagnostics (`cosmic`, `wlr`).
    fn name(&self) -> &'static str;
}

/// Detect and instantiate the compositor backend.
///
/// Detection order:
/// 1. COSMIC-specific protocols (with the `cosmic` feature);
/// 2. wlr-foreign-toplevel-management-v1 (Hyprland, sway, niri).
///
/// # Errors
///
/// `core_types::Error::Platform` when no backend can connect.
pub fn detect_compositor() -> core_types::Result<Box<dyn CompositorBackend>> {
    #[cfg(feature = "cosmic")]
    {
        match crate::backend_cosmic::CosmicBackend::connect() {
            Ok(backend) => {
                tracing::info!(
                    "compositor backend: cosmic (ext_foreign_toplevel + zcosmic_toplevel)"
                );
                return Ok(Box::new(backend));
            }
            Err(e) => {
                tracing::info!("cosmic backend unavailable, trying wlr: {e}");
            }
        }
    }

    match crate::backend_wlr::WlrBackend::connect() {
        Ok(backend) => {
            tracing::info!("compositor backend: wlr-foreign-toplevel-management-v1");
            Ok(Box::new(backend))
        }
        Err(e) => Err(core_types::Error::Platform(format!(
            "no supported compositor backend: {e}"
        ))),
    }
}
