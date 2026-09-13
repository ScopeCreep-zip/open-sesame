//! Validated repository name.
//!
//! Strips `.git` suffix on construction. Validated as a filesystem-safe
//! component. Repository identity is separate from workspace repository
//! detection, which is a command/config concern.

use std::fmt;

use serde::Serialize;

use crate::v1::error::{ValidationError, validate_component};

/// A validated repository name.
///
/// Construction strips a trailing `.git` suffix and validates the
/// result as filesystem-safe. The original suffix state is not
/// preserved because repository identity does not depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(into = "String")]
pub struct RepositoryName {
    name: String,
}

impl From<RepositoryName> for String {
    fn from(r: RepositoryName) -> String {
        r.name
    }
}

impl<'de> serde::Deserialize<'de> for RepositoryName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RepositoryName::new(&s).map_err(serde::de::Error::custom)
    }
}

impl RepositoryName {
    /// Construct from a repository name string.
    ///
    /// Strips a trailing `.git` suffix before validation.
    pub fn new(input: &str) -> Result<Self, ValidationError> {
        let name = input
            .strip_suffix(".git")
            .unwrap_or(input)
            .to_string();

        validate_component("repository name", &name)?;

        Ok(Self { name })
    }

    /// The validated repository name without `.git` suffix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RepositoryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl AsRef<str> for RepositoryName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_name() {
        let r = RepositoryName::new("konductor").unwrap();
        assert_eq!(r.as_str(), "konductor");
        assert_eq!(r.to_string(), "konductor");
    }

    #[test]
    fn strips_git_suffix() {
        let r = RepositoryName::new("konductor.git").unwrap();
        assert_eq!(r.as_str(), "konductor");
    }

    #[test]
    fn preserves_non_git_dots() {
        let r = RepositoryName::new("my.project").unwrap();
        assert_eq!(r.as_str(), "my.project");
    }

    #[test]
    fn does_not_double_strip() {
        let r = RepositoryName::new("repo.git.git").unwrap();
        assert_eq!(r.as_str(), "repo.git");
    }

    #[test]
    fn preserves_casing() {
        let r = RepositoryName::new("OpenSesame").unwrap();
        assert_eq!(r.as_str(), "OpenSesame");
    }

    #[test]
    fn rejects_empty() {
        assert!(RepositoryName::new("").is_err());
    }

    #[test]
    fn rejects_only_git_suffix() {
        // ".git" after stripping leaves empty string
        assert!(RepositoryName::new(".git").is_err());
    }

    #[test]
    fn rejects_traversal() {
        assert!(RepositoryName::new("../escape").is_err());
    }

    #[test]
    fn rejects_null() {
        assert!(RepositoryName::new("repo\0name").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = format!("{}.git", "a".repeat(256));
        assert!(RepositoryName::new(&long).is_err());
    }

    #[test]
    fn equality_by_normalized_name() {
        let a = RepositoryName::new("repo").unwrap();
        let b = RepositoryName::new("repo.git").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn accepts_embedded_dots() {
        let r = RepositoryName::new("foo..bar").unwrap();
        assert_eq!(r.as_str(), "foo..bar");
    }

    #[test]
    fn serde_roundtrip() {
        let original = RepositoryName::new("konductor").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"konductor\"");
        let parsed: RepositoryName = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn serde_strips_git_suffix() {
        let parsed: RepositoryName = serde_json::from_str("\"repo.git\"").unwrap();
        assert_eq!(parsed.as_str(), "repo");
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<RepositoryName, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }
}
