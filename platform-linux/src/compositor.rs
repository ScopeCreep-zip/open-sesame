//! Compositor backend trait and detection for Linux Wayland compositors.
//!
//! The `CompositorBackend` trait abstracts window/workspace management over
//! multiple Wayland compositor protocol sets:
//! - `ext_foreign_toplevel_list_v1` + `zcosmic_toplevel_info_v1` +
//!   `zcosmic_toplevel_manager_v1` (COSMIC)
//! - `wlr-foreign-toplevel-management-v1` (Hyprland, sway, niri, Wayfire)
//!
//! Backend implementations live in dedicated modules:
//! - `backend_wlr` — wlr-foreign-toplevel-management-v1
//! - `backend_cosmic` — COSMIC toplevel-info/manager protocols
//!
//! Focus tracking lives in `focus_monitor`.
//!
//! To add a new compositor backend:
//! 1. Create `backend_<name>.rs` implementing `CompositorBackend`
//! 2. Add `pub(crate) mod backend_<name>;` to `lib.rs`
//! 3. Add a match arm to `detect_compositor()` below

use core_types::{CompositorWorkspaceId, Geometry, Window, WindowId};
use std::future::Future;
use std::pin::Pin;

// Re-export focus_monitor types at the compositor path for backward compatibility.
// Downstream crates use `platform_linux::compositor::{FocusEvent, focus_monitor}`.
pub use crate::focus_monitor::{FocusEvent, focus_monitor};

/// A Wayland workspace.
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: CompositorWorkspaceId,
    pub name: String,
    pub is_active: bool,
}

// Type alias for boxed async results used by CompositorBackend methods.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction over Wayland compositor protocols for window management.
///
/// Implementations:
/// - `CosmicBackend` — ext_foreign_toplevel + zcosmic_toplevel_{info,manager}
/// - `WlrBackend` — wlr-foreign-toplevel-management-v1
///
/// Uses `Pin<Box<dyn Future>>` return types for dyn-compatibility — required
/// because `detect_compositor()` returns `Box<dyn CompositorBackend>` for
/// runtime backend selection.
pub trait CompositorBackend: Send + Sync {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>>;
    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>>;
    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn set_window_geometry(
        &self,
        id: &WindowId,
        geom: &Geometry,
    ) -> BoxFuture<'_, core_types::Result<()>>;
    fn move_to_workspace(
        &self,
        id: &WindowId,
        ws: &CompositorWorkspaceId,
    ) -> BoxFuture<'_, core_types::Result<()>>;
    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;

    /// Human-readable backend name for diagnostics (e.g. "cosmic", "wlr", "sway-ipc").
    fn name(&self) -> &str;
}

/// Detect and instantiate the appropriate compositor backend.
///
/// Detection order:
/// 1. COSMIC-specific protocols (if `cosmic` feature enabled)
/// 2. wlr-foreign-toplevel-management-v1 (Hyprland, sway, niri)
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
