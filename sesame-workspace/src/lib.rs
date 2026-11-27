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
mod env;
pub mod forge;
pub mod format;
pub mod git;
pub mod inspection;
mod layout;
pub mod net;
pub mod normalize;
pub mod platform;
pub mod pool;
pub mod progress;
pub mod project;

pub use config::{
    ConfigProvenance, EffectiveWorkspaceConfig, WorkspaceLayout, resolve_workspace_profile,
};
pub use convention::{CloneInput, ParsedPath, RemoteRef, RemoteTarget};
pub use discover::{DiscoveredWorkspace, Discovery, DiscoveryIssue};
pub use inspection::{
    AheadBehind, DiskUsage, Field, FieldState, InspectionFailure, InspectionFailureKind,
    InspectionRequest, InspectionResult, RepoStatus, format_bytes, format_relative_time,
    parse_stale_duration,
};
pub use layout::Skipped;

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

    /// Fetching a repository for a clone failed. `kind` is classified
    /// from gix's typed handshake and transport errors.
    #[error("git clone failed: {message}")]
    CloneFailed {
        kind: CloneFailureKind,
        message: String,
    },

    /// Configuration error detected by this crate (`.sesame.toml`, proxy
    /// and credential variables).
    #[error("config error: {0}")]
    ConfigError(String),

    /// A PDS configuration file could not be read, parsed, or written
    /// (`core_config`).
    #[error(transparent)]
    Config(#[from] core_types::Error),

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

    /// A directory inside the workspace layout is not in canonical
    /// (lowercase) form. Resolve with `sesame workspace normalize`.
    #[error(
        "non-canonical workspace directory {path}: {source}\n\
         resolve with: sesame workspace normalize --apply"
    )]
    NonCanonical {
        path: std::path::PathBuf,
        #[source]
        source: core_workspace_types::ValidationError,
    },

    /// A repository with a different remote identity occupies the
    /// placement of the requested remote. Placement is lowercase, so
    /// remotes differing only in case share one directory.
    #[error(
        "placement conflict at {path}:\n\
         existing origin:  {existing}\n\
         requested remote: {requested}\n\
         both place at the same lowercase directory; remove or move the \
         existing repository to clone the requested one"
    )]
    PlacementConflict {
        path: std::path::PathBuf,
        existing: String,
        requested: String,
    },

    /// A canonical path is requested but a directory differing only in
    /// case already exists at that level of the layout.
    #[error(
        "case conflict: {requested} is requested but {existing} exists\n\
         resolve with: sesame workspace normalize --apply"
    )]
    CaseConflict {
        requested: std::path::PathBuf,
        existing: std::path::PathBuf,
    },
}

/// An I/O failure on a path (`WorkspaceError::io_at`).
#[derive(Debug, thiserror::Error)]
#[error("{}: {source}", path.display())]
struct IoAtPath {
    path: std::path::PathBuf,
    #[source]
    source: std::io::Error,
}

/// The cause class of a `WorkspaceError::CloneFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneFailureKind {
    /// The remote required credentials that were missing, refused, or
    /// not accepted (HTTP 401 included). Private repositories fail this
    /// way when no credential is configured.
    Authentication,
    /// Any other failure.
    Other,
}

impl WorkspaceError {
    /// A stable machine-readable name for the error's variant, used in
    /// structured output (`sesame workspace list --format json` issues).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidUrl(_) => "invalid-url",
            Self::RootNotFound(_) => "root-not-found",
            Self::NotInWorkspace(_) => "not-in-workspace",
            Self::GitError(_) => "git",
            Self::CloneFailed { .. } => "clone-failed",
            Self::ConfigError(_) | Self::Config(_) => "config",
            Self::Io(_) => "io",
            Self::ProfileNotFound(_) => "profile-not-found",
            Self::PlatformNotSupported(_) => "platform-not-supported",
            Self::PathValidation(_) => "invalid-path",
            Self::NonCanonical { .. } => "non-canonical",
            Self::PlacementConflict { .. } => "placement-conflict",
            Self::CaseConflict { .. } => "case-conflict",
        }
    }

    /// An I/O failure on `path`, with the path in the message. Keeps the
    /// error's `io::ErrorKind`, and the error itself as the source.
    #[must_use]
    pub fn io_at(path: &std::path::Path, error: std::io::Error) -> Self {
        Self::Io(std::io::Error::new(
            error.kind(),
            IoAtPath {
                path: path.to_path_buf(),
                source: error,
            },
        ))
    }

    /// Whether `sesame workspace normalize` resolves this error.
    #[must_use]
    pub fn is_normalizable(&self) -> bool {
        matches!(self, Self::NonCanonical { .. } | Self::CaseConflict { .. })
    }

    /// Classify a placement validation failure for a directory in the
    /// layout: a case problem is `NonCanonical` (fixable by normalize);
    /// anything else is `PathValidation`.
    pub(crate) fn placement(
        path: &std::path::Path,
        source: core_workspace_types::ValidationError,
    ) -> Self {
        match source {
            core_workspace_types::ValidationError::NonCanonicalCase { .. } => Self::NonCanonical {
                path: path.to_path_buf(),
                source,
            },
            other => Self::PathValidation(format!("{}: {other}", path.display())),
        }
    }
}
