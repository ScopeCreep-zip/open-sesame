//! Configuration schema, validation, hot-reload, and policy override for PDS.
//!
//! Handles TOML config loading with XDG inheritance (system -> user -> drop-in),
//! deep merge, semantic validation, and filesystem-watched hot-reload.
#![forbid(unsafe_code)]

mod schema;
mod loader;
mod validation;
mod watcher;

pub use schema::*;
pub use loader::{atomic_write, load_config, config_dir, resolve_config_paths, installation_path, load_installation, write_installation, load_workspace_config, save_workspace_config};
pub use validation::{validate, ConfigDiagnostic, DiagnosticSeverity};
pub use watcher::ConfigWatcher;
