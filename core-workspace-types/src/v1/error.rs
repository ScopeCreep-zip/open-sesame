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

    /// The value names a directory that the workspace layout reserves.
    #[error("{kind} is reserved: {value}")]
    ReservedName { kind: &'static str, value: String },

    /// The value contains characters outside ASCII.
    #[error("{kind} contains non-ASCII characters: {value}")]
    NonAscii { kind: &'static str, value: String },

    /// A workspace directory name is not in canonical (lowercase) form.
    #[error("{kind} is not lowercase: {value} (canonical form: {canonical})")]
    NonCanonicalCase {
        kind: &'static str,
        value: String,
        canonical: String,
    },

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

/// Whether a component may begin with `.`.
///
/// Workspace users and namespace segments sit at layout levels where a
/// dot-prefixed directory is hidden and is never a forge identifier.
/// Repository names are forge identifiers (`.github`, `.dotfiles`) and
/// carry their own reserved-name check for `.git`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeadingDotPolicy {
    Reject,
    Allow,
}

/// Validate a single component that maps to one filesystem directory.
///
/// Rejects empty values, the traversal components `.` and `..`, a
/// leading dot (unless `leading_dot` allows it), path separators, null
/// bytes, non-ASCII characters, length over 255 bytes, and
/// leading/trailing whitespace. ASCII-only input makes lowercase
/// placement a total, length-preserving, collision-free mapping.
pub(crate) fn validate_component(
    kind: &'static str,
    value: &str,
    leading_dot: LeadingDotPolicy,
) -> Result<(), ValidationError> {
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
    if leading_dot == LeadingDotPolicy::Reject && value.starts_with('.') {
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
    if !value.is_ascii() {
        return Err(ValidationError::NonAscii {
            kind,
            value: value.into(),
        });
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

    const R: LeadingDotPolicy = LeadingDotPolicy::Reject;
    const A: LeadingDotPolicy = LeadingDotPolicy::Allow;

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            validate_component("test", "", R),
            Err(ValidationError::Empty { .. })
        ));
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(matches!(
            validate_component("test", ".hidden", R),
            Err(ValidationError::LeadingDot { .. })
        ));
    }

    #[test]
    fn allow_policy_accepts_leading_dot() {
        assert!(validate_component("test", ".hidden", A).is_ok());
    }

    #[test]
    fn allow_policy_still_rejects_traversal() {
        assert!(matches!(
            validate_component("test", "..", A),
            Err(ValidationError::PathTraversal { .. })
        ));
        assert!(matches!(
            validate_component("test", ".", A),
            Err(ValidationError::PathTraversal { .. })
        ));
    }

    #[test]
    fn allow_policy_still_rejects_separator() {
        assert!(matches!(
            validate_component("test", ".a/b", A),
            Err(ValidationError::PathSeparator { .. })
        ));
    }

    #[test]
    fn accepts_embedded_dots() {
        assert!(validate_component("test", "a..b", R).is_ok());
    }

    #[test]
    fn rejects_bare_dotdot() {
        assert!(matches!(
            validate_component("test", "..", R),
            Err(ValidationError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_bare_dot() {
        assert!(matches!(
            validate_component("test", ".", R),
            Err(ValidationError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_slash() {
        assert!(matches!(
            validate_component("test", "a/b", R),
            Err(ValidationError::PathSeparator { .. })
        ));
    }

    #[test]
    fn rejects_null() {
        assert!(matches!(
            validate_component("test", "a\0b", R),
            Err(ValidationError::NullByte { .. })
        ));
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(matches!(
            validate_component("test", "Ärger", R),
            Err(ValidationError::NonAscii { .. })
        ));
        // Kelvin sign lowercases to ASCII 'k' under Unicode rules.
        assert!(matches!(
            validate_component("test", "\u{212A}ube", R),
            Err(ValidationError::NonAscii { .. })
        ));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(256);
        assert!(matches!(
            validate_component("test", &long, R),
            Err(ValidationError::TooLong { .. })
        ));
    }

    #[test]
    fn rejects_whitespace() {
        assert!(matches!(
            validate_component("test", " padded ", R),
            Err(ValidationError::Whitespace { .. })
        ));
    }

    #[test]
    fn accepts_valid() {
        assert!(validate_component("test", "valid-name_123", R).is_ok());
    }

    #[test]
    fn accepts_255_bytes() {
        let name = "a".repeat(255);
        assert!(validate_component("test", &name, R).is_ok());
    }
}
