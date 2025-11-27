//! Error types for Open Sesame
//!
//! Uses thiserror for typed errors instead of anyhow for better error handling.

use std::path::PathBuf;

/// Main error type for Open Sesame
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to establish connection to Wayland compositor
    #[error("Failed to connect to Wayland compositor")]
    WaylandConnection(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Required Wayland protocol extension is not available
    #[error("Required Wayland protocol not available: {protocol}")]
    MissingProtocol {
        /// Name of the missing protocol
        protocol: &'static str,
    },

    /// Window with specified identifier was not found
    #[error("Window not found: {identifier}")]
    WindowNotFound {
        /// The identifier that was searched for
        identifier: String,
    },

    /// Failed to activate the target window
    #[error("Failed to activate window: {0}")]
    ActivationFailed(String),

    /// Failed to parse TOML configuration file
    #[error("Failed to parse configuration: {0}")]
    ConfigParse(#[from] toml::de::Error),

    /// Failed to read configuration file from disk
    #[error("Failed to read configuration file: {path}")]
    ConfigRead {
        /// Path to the configuration file
        path: PathBuf,
        /// The underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// Configuration validation failed
    #[error("Invalid configuration: {message}")]
    ConfigValidation {
        /// Description of the validation error
        message: String,
    },

    /// Invalid color format in configuration
    #[error("Invalid color format: {value}")]
    InvalidColor {
        /// The invalid color value
        value: String,
    },

    /// Failed to create rendering surface
    #[error("Failed to create rendering surface")]
    SurfaceCreation,

    /// Surface dimensions are invalid (zero or too large)
    #[error("Invalid surface dimensions: {width}x{height}")]
    InvalidDimensions {
        /// The invalid width
        width: u32,
        /// The invalid height
        height: u32,
    },

    /// No suitable font could be found on the system
    #[error("Font not available")]
    FontNotFound,

    /// Generic I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to launch an external application
    #[error("Failed to launch application: {command}")]
    LaunchFailed {
        /// The command that failed to execute
        command: String,
        /// The underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// Generic error for wrapping external error types
    #[error("{0}")]
    Other(String),
}

/// Result type alias using our Error
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Creates an error from any error type.
    pub fn other<E: std::fmt::Display>(error: E) -> Self {
        Self::Other(error.to_string())
    }

    /// Returns whether this error is recoverable.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::WindowNotFound { .. }
                | Error::ConfigValidation { .. }
                | Error::InvalidColor { .. }
        )
    }
}

// Conversion from anyhow for compatibility during migration
impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Other(err.to_string())
    }
}
