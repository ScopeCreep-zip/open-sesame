//! daemon-wm: the Wayland overlay window switcher.
//!
//! [`controller::OverlayController`] owns every overlay decision;
//! [`commands::Runtime`] executes its commands and [`serve`] feeds it the
//! daemon's events. The overlay renders on its own thread
//! ([`surface::wayland`]).

pub mod commands;
mod commands_unlock;
pub mod controller;
pub mod hints;
pub mod ipc_keys;
pub mod mru;
pub mod render;
#[cfg(target_os = "linux")]
pub mod sandbox;
pub mod serve;
pub mod surface;
pub mod winlist;
