/// Error type for the core-types crate and downstream consumers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("IPC error: {0}")]
    Ipc(String),

    /// An operation received no answer within its deadline.
    #[error("{operation} timed out after {}ms", after.as_millis())]
    Timeout {
        operation: String,
        after: std::time::Duration,
    },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("profile error: {0}")]
    Profile(String),

    #[error("secrets error: {0}")]
    Secrets(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("platform error: {0}")]
    Platform(String),

    #[error("extension error: {0}")]
    Extension(String),

    #[error("policy locked: {key} is controlled by {policy_source}")]
    PolicyLocked { key: String, policy_source: String },

    #[error("capability denied: {capability} not declared in extension manifest")]
    CapabilityDenied { capability: String },

    #[error("profile isolation: access to {resource} denied by isolation contract")]
    IsolationDenied { resource: String },

    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

// ============================================================================
// Secret Key Validation
// ============================================================================

/// Validate a secret key name.
///
/// Rejects keys that are empty, contain path traversal patterns, path
/// separators, or exceed 256 characters. Applied at both the CLI trust
/// boundary and in daemon-secrets as defense-in-depth.
///
/// # Errors
///
/// Returns `Error::Validation` if the key is empty, too long, contains
/// path traversal (`..`), or path separators (`/`, `\`).
pub fn validate_secret_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::Validation("secret key must not be empty".into()));
    }
    if key.len() > 256 {
        return Err(Error::Validation(format!(
            "secret key exceeds 256 characters (got {})",
            key.len()
        )));
    }
    if key.contains("..") {
        return Err(Error::Validation(
            "secret key must not contain '..' (path traversal)".into(),
        ));
    }
    if key.contains('/') || key.contains('\\') {
        return Err(Error::Validation(
            "secret key must not contain path separators ('/' or '\\')".into(),
        ));
    }
    if key.contains('\0') {
        return Err(Error::Validation(
            "secret key must not contain null bytes".into(),
        ));
    }
    Ok(())
}
