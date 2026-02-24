//! Windows API wrappers for PDS daemons.
//!
//! Provides safe Rust abstractions over Win32 keyboard hooks,
//! UI Automation COM, VirtualDesktop, Credential Manager (DPAPI),
//! Group Policy registry, and Task Scheduler.
//!
//! Contains NO business logic. Consumed exclusively by daemon-* crates.
