//! Wayland platform implementation
//!
//! Provides window enumeration and activation using COSMIC protocols.

mod protocols;

pub use protocols::{activate_window, enumerate_windows};
