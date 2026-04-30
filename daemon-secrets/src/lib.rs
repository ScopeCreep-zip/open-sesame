//! daemon-secrets library crate.
//!
//! All domain modules live here so integration tests in `tests/` can
//! exercise the public API. The binary crate (`main.rs`) re-exports
//! from this library via `use daemon_secrets::*`.

#[cfg(target_os = "linux")]
pub mod key_locker_linux;

pub mod acl;
pub mod crud;
pub mod dispatch;
pub mod keyring;
pub mod network_identity;
pub mod rate_limit;
pub mod sandbox;
pub mod unlock;
pub mod vault;
pub mod vault_log;
