pub mod commands;
mod commands_unlock;
pub mod controller;
pub mod hints;
pub mod ipc_keys;
pub mod mru;
#[cfg(feature = "wayland")]
pub mod render;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(feature = "wayland")]
pub mod surface;

// Re-export surface types at the old path for main.rs compatibility.
#[cfg(feature = "wayland")]
pub mod overlay {
    pub use crate::surface::wayland::{OverlayCmd, OverlayEvent, WindowInfo, spawn_overlay};
}
