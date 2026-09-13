//! Validated workspace username for path construction.
//!
//! Ensures the username is a single filesystem-safe component that
//! cannot escape the workspace root directory via traversal or
//! absolute path injection through `Path::join`.

use std::fmt;

use serde::Serialize;

use crate::v1::error::{ValidationError, validate_component};

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
    /// Validates as a single filesystem-safe component: no slashes,
    /// no traversal, no null bytes, no leading dots, no whitespace.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` for empty, malformed, or unsafe input.
    pub fn new(input: &str) -> Result<Self, ValidationError> {
        validate_component("workspace user", input)?;
        Ok(Self {
            name: input.to_string(),
        })
    }

    /// The validated username string.
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
        let u = WorkspaceUser::new("usrbinkat").unwrap();
        assert_eq!(u.as_str(), "usrbinkat");
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
    fn serde_roundtrip() {
        let original = WorkspaceUser::new("usrbinkat").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"usrbinkat\"");
        let parsed: WorkspaceUser = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<WorkspaceUser, _> = serde_json::from_str("\"..\"");
        assert!(result.is_err());
    }
}
