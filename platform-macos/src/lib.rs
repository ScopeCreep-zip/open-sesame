//! macOS API wrappers for PDS daemons.
//!
//! Provides safe Rust abstractions over:
//! - Accessibility (AXUIElement) — window management
//! - CGEventTap — input monitoring (listen-only, Accessibility TCC)
//! - CGEventPost — input re-emission (Accessibility TCC)
//! - NSPasteboard — clipboard with sensitivity annotations
//! - security-framework (Keychain) — per-profile named keychains
//! - LaunchAgent — plist generation, launchctl lifecycle
//! - TCC introspection — permission state query before prompting
//!
//! Contains NO business logic. Consumed exclusively by daemon-* crates.
//!
//! Phase 1: module declarations only. macOS implementations deferred
//! until Linux platform is validated on Pop!_OS / COSMIC.

// All modules are cfg-gated to macOS. On other platforms this crate
// compiles as an empty library (no errors, no exports).

#[cfg(target_os = "macos")]
pub mod accessibility;
#[cfg(target_os = "macos")]
pub mod clipboard;
#[cfg(target_os = "macos")]
pub mod input;
#[cfg(target_os = "macos")]
pub mod keychain;
#[cfg(target_os = "macos")]
pub mod launch_agent;
#[cfg(target_os = "macos")]
pub mod tcc;
