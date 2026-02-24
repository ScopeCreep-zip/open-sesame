//! Utility modules for Open Sesame
//!
//! Provides common utilities used across the application.

pub mod env;
pub mod error;
pub mod ipc;
pub mod lock;
pub mod log;
pub mod mru;
pub mod paths;
pub mod timeout;

pub use env::{expand_path, load_env_files, parse_env_file};
pub use error::{Error, Result};
pub use ipc::{IpcClient, IpcCommand, IpcServer};
pub use lock::InstanceLock;
pub use mru::{
    MruState, get_previous_window, load_mru_state, reorder_for_mru, save_activated_window,
};
pub use paths::{cache_dir, config_dir, lock_file, log_file, mru_file};
pub use timeout::TimeoutTracker;
