//! macOS API wrappers for PDS daemons.
//!
//! Provides safe Rust abstractions over Accessibility (AXUIElement),
//! CGEventTap (input monitoring), NSPasteboard (clipboard),
//! security-framework (Keychain), and LaunchAgent (process lifecycle).
//!
//! Contains NO business logic. Consumed exclusively by daemon-* crates.
