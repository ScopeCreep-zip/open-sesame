//! Configuration schema, validation, hot-reload, and policy override for PDS.
//!
//! Handles TOML config loading with XDG inheritance (system -> user -> drop-in),
//! deep merge, semantic validation, and filesystem-watched hot-reload.
#![forbid(unsafe_code)]

mod loader;
mod loader_installation;
mod loader_workspace;
mod schema;
mod schema_agents;
mod schema_crypto;
mod schema_installation;
mod schema_peripheral;
mod schema_secrets;
mod schema_wm;
mod schema_workspace;
mod validation;
mod watcher;

pub use loader::{
    atomic_write, bootstrap_dirs, config_dir, installation_path, load_config, load_installation,
    load_workspace_config, resolve_config_paths, resolve_config_real_dirs, save_workspace_config,
    write_installation,
};
pub use schema::*;
pub use validation::{ConfigDiagnostic, DiagnosticSeverity, validate};
pub use watcher::ConfigWatcher;
