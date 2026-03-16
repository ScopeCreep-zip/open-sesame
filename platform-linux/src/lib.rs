//! Linux API wrappers for PDS daemons.
//!
//! Provides safe Rust abstractions over evdev (input capture/injection),
//! Wayland protocols (toplevel management, layer-shell, data-control),
//! D-Bus (Secret Service, desktop portals), Landlock, and seccomp-bpf.
//!
//! Contains NO business logic. Consumed exclusively by daemon-* crates.
//!
//! # Feature flags
//!
//! - `desktop`: enables Wayland compositor integration, evdev input capture,
//!   and clipboard modules. Requires wayland-client, smithay-client-toolkit, evdev.
//! - `cosmic`: enables COSMIC-specific Wayland protocol support. Implies `desktop`.
//!   Pulls in GPL-3.0 dependencies (cosmic-client-toolkit, cosmic-protocols).
//!
//! Without any features, only headless-safe modules are available:
//! sandbox, security, systemd, dbus, cosmic_keys, cosmic_theme, clipboard (trait only).

// -- Always available (headless-safe) --
#[cfg(target_os = "linux")]
pub mod clipboard;
#[cfg(target_os = "linux")]
pub mod cosmic_keys;
#[cfg(target_os = "linux")]
pub mod cosmic_theme;
#[cfg(target_os = "linux")]
pub mod dbus;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(target_os = "linux")]
pub mod security;
#[cfg(target_os = "linux")]
pub mod systemd;

// -- Desktop-only (requires `desktop` or `cosmic` feature) --
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod compositor;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod input;
