//! Validated workspace username for path construction.
//!
//! `WorkspaceUser` is a placement component: the `{user}` directory in
//! `{root}/{user}/{host}/...`. Its source is configuration and command
//! input, never a forge, so input is lowercased on construction and the
//! stored value is always the canonical directory name.

use std::fmt;

use serde::Serialize;

use crate::v1::error::{LeadingDotPolicy, ValidationError, validate_component};

/// A validated workspace username.
///
/// Used as a path component in the workspace directory layout:
/// `{root}/{user}/{server}/{namespace}/{repo}`. Validated on
/// construction to prevent directory traversal and path injection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(into = "String")]
pub struct WorkspaceUser {
    name: String,
}

impl From<WorkspaceUser> for String {
    fn from(u: WorkspaceUser) -> String {
        u.name
    }
}

impl<'de> serde::Deserialize<'de> for WorkspaceUser {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        WorkspaceUser::new(&s).map_err(serde::de::Error::custom)
    }
}

impl WorkspaceUser {
    /// Construct from a username string.
    ///
    /// Validates as a single ASCII path component (no slashes, no
    /// traversal, no null bytes, no leading dots, no leading or trailing
    /// whitespace), then lowercases.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` for empty, malformed, non-ASCII, or
    /// unsafe input.
    pub fn new(input: &str) -> Result<Self, ValidationError> {
        validate_component("workspace user", input, LeadingDotPolicy::Reject)?;
        Ok(Self {
            name: input.to_ascii_lowercase(),
        })
    }

    /// The canonical username directory name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for WorkspaceUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl AsRef<str> for WorkspaceUser {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_user() {
        let u = WorkspaceUser::new("alice").unwrap();
        assert_eq!(u.as_str(), "alice");
    }

    #[test]
    fn normalizes_to_lowercase() {
        let u = WorkspaceUser::new("Alice").unwrap();
        assert_eq!(u.as_str(), "alice");
        assert_eq!(u, WorkspaceUser::new("alice").unwrap());
    }

    #[test]
    fn serde_normalizes_to_lowercase() {
        let parsed: WorkspaceUser = serde_json::from_str("\"Alice\"").unwrap();
        assert_eq!(parsed.as_str(), "alice");
    }

    #[test]
    fn rejects_empty() {
        assert!(WorkspaceUser::new("").is_err());
    }

    #[test]
    fn rejects_traversal() {
        assert!(WorkspaceUser::new("..").is_err());
    }

    #[test]
    fn rejects_slash() {
        assert!(WorkspaceUser::new("user/escape").is_err());
    }

    #[test]
    fn rejects_absolute() {
        assert!(WorkspaceUser::new("/root").is_err());
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(WorkspaceUser::new(".hidden").is_err());
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(matches!(
            WorkspaceUser::new("kätzchen"),
            Err(ValidationError::NonAscii { .. })
        ));
    }

    #[test]
    fn serde_roundtrip() {
        let original = WorkspaceUser::new("alice").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"alice\"");
        let parsed: WorkspaceUser = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<WorkspaceUser, _> = serde_json::from_str("\"..\"");
        assert!(result.is_err());
    }
}
