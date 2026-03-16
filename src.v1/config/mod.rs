//! Configuration module for Open Sesame
//!
//! Provides configuration loading, validation, and merging with XDG inheritance.

mod loader;
mod schema;

pub use loader::{load_config, load_config_from_paths};
pub use schema::{Color, Config, KeyBinding, LaunchConfig, Settings};

// Re-export validator module and its public types
pub mod validator;
pub use validator::{ConfigValidator, Severity, ValidationIssue};

// Re-export commonly used config paths
pub use loader::{user_config_dir, user_config_path};
