//! Validation errors for workspace identity types.

/// Errors produced when constructing validated workspace types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The value is empty.
    #[error("{kind} is empty")]
    Empty { kind: &'static str },

    /// The value contains a path traversal sequence.
    #[error("{kind} contains path traversal: {value}")]
    PathTraversal { kind: &'static str, value: String },

    /// The value contains a path separator.
    #[error("{kind} contains path separator: {value}")]
    PathSeparator { kind: &'static str, value: String },

    /// The value contains a null byte.
    #[error("{kind} contains null byte")]
    NullByte { kind: &'static str },

    /// The value starts with a dot.
    #[error("{kind} starts with dot: {value}")]
    LeadingDot { kind: &'static str, value: String },

    /// The value exceeds the filesystem component length limit.
    #[error("{kind} exceeds 255 bytes: {len}")]
    TooLong { kind: &'static str, len: usize },

    /// The value has leading or trailing whitespace.
    #[error("{kind} has leading or trailing whitespace: '{value}'")]
    Whitespace { kind: &'static str, value: String },

    /// The namespace path has no segments.
    #[error("namespace path has no segments")]
    EmptyNamespace,

    /// A port number is invalid.
    #[error("invalid port number: {value}")]
    InvalidPort { value: String },

    /// The authority hostname is empty or invalid.
    #[error("invalid hostname: {value}")]
    InvalidHostname { value: String },
}

/// Validate a single filesystem-safe component.
///
/// Rejects empty values, path traversal, separators, null bytes,
/// leading dots, length over 255 bytes, and leading/trailing whitespace.
pub(crate) fn validate_component(kind: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { kind });
    }
    // Only the literal path components "." and ".." constitute traversal.
    // Embedded ".." inside a name like "foo..bar" is a valid identifier
    // and must not be rejected.
    if value == "." || value == ".." {
        return Err(ValidationError::PathTraversal {
            kind,
            value: value.into(),
        });
    }
    if value.starts_with('.') {
        return Err(ValidationError::LeadingDot {
            kind,
            value: value.into(),
        });
    }
    if value.contains('/') || value.contains('\\') {
        return Err(ValidationError::PathSeparator {
            kind,
            value: value.into(),
        });
    }
    if value.contains('\0') {
        return Err(ValidationError::NullByte { kind });
    }
    if value.len() > 255 {
        return Err(ValidationError::TooLong {
            kind,
            len: value.len(),
        });
    }
    if value != value.trim() {
        return Err(ValidationError::Whitespace {
            kind,
            value: value.into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            validate_component("test", ""),
            Err(ValidationError::Empty { .. })
        ));
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(matches!(
            validate_component("test", ".hidden"),
            Err(ValidationError::LeadingDot { .. })
        ));
    }

    #[test]
    fn accepts_embedded_dots() {
        assert!(validate_component("test", "a..b").is_ok());
    }

    #[test]
    fn rejects_bare_dotdot() {
        assert!(matches!(
            validate_component("test", ".."),
            Err(ValidationError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_bare_dot() {
        assert!(matches!(
            validate_component("test", "."),
            Err(ValidationError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_slash() {
        assert!(matches!(
            validate_component("test", "a/b"),
            Err(ValidationError::PathSeparator { .. })
        ));
    }

    #[test]
    fn rejects_null() {
        assert!(matches!(
            validate_component("test", "a\0b"),
            Err(ValidationError::NullByte { .. })
        ));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(256);
        assert!(matches!(
            validate_component("test", &long),
            Err(ValidationError::TooLong { .. })
        ));
    }

    #[test]
    fn rejects_whitespace() {
        assert!(matches!(
            validate_component("test", " padded "),
            Err(ValidationError::Whitespace { .. })
        ));
    }

    #[test]
    fn accepts_valid() {
        assert!(validate_component("test", "valid-name_123").is_ok());
    }

    #[test]
    fn accepts_255_bytes() {
        let name = "a".repeat(255);
        assert!(validate_component("test", &name).is_ok());
    }
}
