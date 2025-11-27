//! Open Sesame - Vimium-style Window Switcher for COSMIC Desktop
//!
//! A keyboard-driven window switcher that assigns letter hints to windows,
//! allowing rapid window switching with minimal keystrokes. Inspired by Vimium's
//! link-hinting interface, Open Sesame brings the same efficient navigation
//! paradigm to desktop window management on the COSMIC desktop environment.
//!
//! # Features
//!
//! - **Vimium-style hints**: Windows are assigned letter sequences (g, gg, ggg, etc.)
//!   based on their application type, making window selection predictable and fast
//! - **Focus-or-launch**: Press a key to focus a window or launch an app if not running,
//!   combining window switching and application launching into a single workflow
//! - **Configurable**: XDG-compliant configuration with system and user overrides,
//!   supporting per-application key bindings and launch commands
//! - **Fast**: Minimal latency with configurable activation delays for disambiguation
//!   and quick-switch support for Alt+Tab-style behavior
//! - **Visual overlay**: Full-screen overlay with window hints and card-based UI
//!   for visual navigation and selection
//!
//! # Quick Start
//!
//! ## Installation
//!
//! Install the `sesame` binary and configure a COSMIC keybinding:
//!
//! ```bash
//! # Setup keybinding (uses activation_key from config, default: alt+space)
//! sesame --setup-keybinding
//!
//! # Or specify a custom key combination
//! sesame --setup-keybinding alt+tab
//! ```
//!
//! ## Configuration
//!
//! Open Sesame uses XDG configuration paths. Generate a default config:
//!
//! ```bash
//! sesame --print-config > ~/.config/open-sesame/config.toml
//! ```
//!
//! Example configuration:
//!
//! ```toml
//! [settings]
//! activation_key = "alt+space"
//! activation_delay = 200
//! overlay_delay = 720
//! quick_switch_threshold = 250
//!
//! [keys.g]
//! apps = ["ghostty", "com.mitchellh.ghostty"]
//! launch = "ghostty"
//!
//! [keys.f]
//! apps = ["firefox", "org.mozilla.firefox"]
//! launch = "firefox"
//! ```
//!
//! # Architecture
//!
//! The crate is organized into several modules following clean architecture principles:
//!
//! - [`app`]: Application orchestration and Wayland event loop integration
//! - [`config`]: Configuration loading, validation, and XDG path resolution
//! - [`core`]: Domain types and business logic (window hints, matching, launching)
//! - [`input`]: Keyboard input processing and action conversion
//! - [`platform`]: Platform abstraction layer (Wayland protocols, COSMIC integration)
//! - [`render`]: Rendering pipeline with composable passes for overlay UI
//! - [`ui`]: UI components (overlay window, theming)
//! - [`util`]: Shared utilities (error handling, logging, IPC, MRU tracking)
//!
//! ## Data Flow
//!
//! 1. **Window Enumeration**: [`platform::enumerate_windows`] queries Wayland compositor
//!    for all toplevel windows via COSMIC protocols
//! 2. **Hint Assignment**: [`HintAssignment::assign`] assigns letter hints based on
//!    application IDs using configured key bindings from [`Config`]
//! 3. **User Input**: [`input`] module processes keyboard events and matches them
//!    against hint sequences
//! 4. **Rendering**: [`render`] module draws the overlay UI with window hints
//! 5. **Activation**: [`platform::activate_window`] focuses the selected window
//!
//! # Examples
//!
//! ## Programmatic Usage
//!
//! While Open Sesame is primarily a CLI application, the library exports types
//! for programmatic usage:
//!
//! ```no_run
//! use open_sesame::{Config, HintAssignment};
//!
//! # fn main() -> Result<(), open_sesame::Error> {
//! // Load configuration
//! let config = Config::load()?;
//! println!("Activation key: {}", config.settings.activation_key);
//!
//! // Enumerate windows and assign hints
//! # #[cfg(feature = "mock")]
//! # {
//! let windows = vec![]; // platform::enumerate_windows()?
//! let assignment = HintAssignment::assign(&windows, |app_id| {
//!     config.key_for_app(app_id.as_str())
//! });
//!
//! for hint in assignment.hints() {
//!     println!("[{}] {} - {}", hint.hint, hint.app_id, hint.title);
//! }
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuration Loading
//!
//! ```no_run
//! use open_sesame::Config;
//!
//! # fn main() -> Result<(), open_sesame::Error> {
//! // Load from default XDG paths
//! let config = Config::load()?;
//!
//! // Check if an app has a key binding
//! if let Some(key) = config.key_for_app("firefox") {
//!     println!("Firefox is bound to key: {}", key);
//! }
//!
//! // Get launch config for a key
//! if let Some(launch) = config.launch_config("g") {
//!     println!("'g' launches: {}", launch.command());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Platform Support
//!
//! Open Sesame requires:
//! - **COSMIC Desktop Environment**: Uses COSMIC-specific Wayland protocols
//!   (`zcosmic_toplevel_manager_v1`) for window enumeration and activation
//! - **Wayland Compositor**: Built on smithay-client-toolkit for Wayland integration
//! - **Fontconfig**: System font resolution for text rendering
//!
//! # Links
//!
//! - [Repository](https://github.com/ScopeCreep-zip/open-sesame)
//! - [Configuration Reference](https://github.com/ScopeCreep-zip/open-sesame#configuration)
//! - [COSMIC Desktop](https://system76.com/cosmic)

#![warn(missing_docs)]
#![warn(clippy::all)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod app;
pub mod config;
pub mod core;
pub mod input;
pub mod platform;
pub mod render;
pub mod ui;
pub mod util;

// Re-export commonly used types
pub use config::Config;
pub use core::{AppId, HintAssignment, HintMatcher, MatchResult, Window, WindowHint, WindowId};
pub use util::{Error, Result};
