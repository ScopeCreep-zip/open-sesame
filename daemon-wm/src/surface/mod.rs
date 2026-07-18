//! Platform surface abstraction.
//!
//! Each platform implements the overlay surface lifecycle: create, show, hide,
//! set blur region, attach buffer, handle keyboard input. The main loop and
//! controller interact with surfaces only through the channel types defined
//! in the wayland module (OverlayCmd, OverlayEvent, WindowInfo).

#[cfg(feature = "wayland")]
pub mod wayland;
