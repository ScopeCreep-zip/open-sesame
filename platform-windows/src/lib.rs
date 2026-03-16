//! Windows API wrappers for PDS daemons.
//!
//! Provides safe Rust abstractions over:
//! - SetWindowsHookEx (WH_KEYBOARD_LL) — input capture with EDR disclosure
//! - RegisterHotKey / UnregisterHotKey — global hotkeys
//! - UI Automation COM — window management and enumeration
//! - SetWindowPos — window geometry manipulation
//! - VirtualDesktop COM — workspace management (undocumented, version-fragile)
//! - AddClipboardFormatListener — clipboard monitoring
//! - CryptProtectData / CredRead / CredWrite — DPAPI credential management
//! - Group Policy registry — enterprise policy reading
//! - Task Scheduler COM — daemon autostart at login
//! - Named Pipes — IPC bootstrap (Windows equivalent of Unix domain sockets)
//!
//! Contains NO business logic. Consumed exclusively by daemon-* crates.
//!
//! Phase 1: module declarations only. Windows implementations deferred
//! until Linux and macOS platforms are validated.

#[cfg(target_os = "windows")]
pub mod clipboard;
#[cfg(target_os = "windows")]
pub mod credential;
#[cfg(target_os = "windows")]
pub mod hotkey;
#[cfg(target_os = "windows")]
pub mod input_hook;
#[cfg(target_os = "windows")]
pub mod named_pipe;
#[cfg(target_os = "windows")]
pub mod policy;
#[cfg(target_os = "windows")]
pub mod task_scheduler;
#[cfg(target_os = "windows")]
pub mod ui_automation;
#[cfg(target_os = "windows")]
pub mod virtual_desktop;
