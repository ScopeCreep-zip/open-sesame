//! Workspace directory convention, git operations, and discovery for Open Sesame.
//!
//! Provides deterministic workspace paths derived from git remote URLs:
//! `{ROOT}/{USER}/{GIT_SERVER}/{ORG}/{REPO}`
//!
//! Git operations use `gix` (pure Rust) for most tasks and `git2` (bundled
//! libgit2) for init-around-existing-directory and pull --ff-only.
//! No git CLI dependency. No shell interpolation. No secret material on disk.
#![forbid(unsafe_code)]

pub mod config;
pub mod convention;
pub mod discover;
pub mod forge;
pub mod git;
pub mod platform;

pub use config::{ConfigProvenance, EffectiveWorkspaceConfig, resolve_workspace_profile};
pub use convention::{CloneTarget, WorkspaceConvention};
pub use discover::DiscoveredWorkspace;

/// Errors from workspace operations.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    /// The git URL could not be parsed into convention components.
    #[error("invalid git URL: {0}")]
    InvalidUrl(String),

    /// The workspace root directory does not exist.
    #[error("workspace root does not exist: {0}")]
    RootNotFound(std::path::PathBuf),

    /// The path is not inside the workspace root.
    #[error("path is not inside workspace root: {0}")]
    NotInWorkspace(std::path::PathBuf),

    /// A git command failed.
    #[error("git command failed: {0}")]
    GitError(String),

    /// Configuration error.
    #[error("config error: {0}")]
    ConfigError(String),

    /// I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The requested profile was not found.
    #[error("profile not found: {0}")]
    ProfileNotFound(String),

    /// The current platform is not supported for this operation.
    #[error("platform not supported: {0}")]
    PlatformNotSupported(String),

    /// Path validation failed (traversal, symlink, null bytes).
    #[error("path validation failed: {0}")]
    PathValidation(String),
}
