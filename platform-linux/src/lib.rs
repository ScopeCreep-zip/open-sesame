//! Linux API wrappers for PDS daemons.
//!
//! Provides safe Rust abstractions over evdev (input capture), Wayland
//! toplevel protocols (window list, activation, focus monitoring), Wayland
//! clipboard capture (data-control), D-Bus (the `NetworkManager` SSID
//! monitor), the Secret Service credential store (`keyring`), systemd
//! notification, Landlock, and seccomp-bpf.
//!
//! Contains NO business logic. Consumed exclusively by daemon-* crates.
//!
//! # Feature flags
//!
//! - `desktop`: enables Wayland compositor integration, clipboard capture,
//!   and evdev input capture. Requires `wayland-client`,
//!   `wayland-protocols(-wlr)`, `wl-clipboard-rs`, `evdev`.
//! - `cosmic`: enables COSMIC-specific Wayland protocol support. Implies `desktop`.
//!   Pulls in GPL-3.0 dependencies (cosmic-client-toolkit, cosmic-protocols).
//!
//! Without any features, only headless-safe modules are available:
//! `sandbox`, `security`, `systemd`, `dbus`, `keyring`, `cosmic_keys`.

// -- Always available (headless-safe) --
#[cfg(target_os = "linux")]
pub mod cosmic_keys;
#[cfg(all(target_os = "linux", feature = "cosmic"))]
pub mod cosmic_theme;
#[cfg(target_os = "linux")]
pub mod dbus;
#[cfg(target_os = "linux")]
pub mod global_shortcuts;
#[cfg(target_os = "linux")]
pub mod keyring;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(target_os = "linux")]
pub mod security;
#[cfg(target_os = "linux")]
pub mod systemd;

// -- Desktop-only (requires `desktop` or `cosmic` feature) --
#[cfg(all(target_os = "linux", feature = "cosmic"))]
pub(crate) mod backend_cosmic;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub(crate) mod backend_wlr;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod clipboard;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod compositor;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod focus_monitor;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod input;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub(crate) mod wayland;
