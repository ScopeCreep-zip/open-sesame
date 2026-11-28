//! Configuration schema, validation, hot-reload, and policy override for PDS.
//!
//! Handles TOML config loading with XDG inheritance (system -> user -> drop-in),
//! deep merge, semantic validation, and filesystem-watched hot-reload.
#![forbid(unsafe_code)]

pub mod edit;
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
mod transaction;
mod validation;
mod watcher;

pub use loader::{
    load_config, load_installation, load_workspace_config, read_machine_id, resolve_config_paths,
    source_revision, write_installation,
};
pub use schema::*;
pub use transaction::{RecoveryError, Transaction};
pub use validation::{ConfigDiagnostic, DiagnosticSeverity, validate};
pub use watcher::{
    ConfigSnapshot, ConfigState, ConfigWatcher, RECONCILE_INTERVAL, ReconcileTrigger,
};
