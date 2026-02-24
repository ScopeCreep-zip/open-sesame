//! Configuration schema, validation, hot-reload, and policy override for PDS.
//!
//! Handles TOML config loading with XDG inheritance (system -> user -> drop-in),
//! deep merge, semantic validation, and filesystem-watched hot-reload.
#![forbid(unsafe_code)]
