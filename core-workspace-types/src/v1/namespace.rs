//! Namespace path: one or more validated segments representing the
//! organizational hierarchy between server and repository.
//!
//! Supports both flat namespaces (GitHub: one segment) and nested
//! namespaces (GitLab: multiple segments). Each segment is validated
//! as a filesystem-safe component on construction. Malformed input
//! such as empty segments, leading/trailing slashes, and untrimmed
//! whitespace is rejected, not silently repaired.

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use crate::v1::error::{ValidationError, validate_component};

/// A validated namespace path of one or more segments.
///
/// Represents the organizational hierarchy between server and
/// repository. GitHub uses a single segment (organization or user).
/// GitLab uses one or more segments (group/subgroup/...).
///
/// Segments preserve original casing. Deserialization goes through the
/// validating constructor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(into = "String")]
pub struct NamespacePath {
    segments: Vec<String>,
}

impl From<NamespacePath> for String {
    fn from(ns: NamespacePath) -> String {
        ns.to_string()
    }
}

impl<'de> serde::Deserialize<'de> for NamespacePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        NamespacePath::new(&s).map_err(serde::de::Error::custom)
    }
}

impl NamespacePath {
    /// Construct from a slash-separated path string.
    ///
    /// Each segment is validated as a filesystem-safe component.
    /// At least one segment is required. Empty segments, leading
    /// slashes, trailing slashes, and whitespace-padded segments
    /// are rejected.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` for empty, malformed, or unsafe input.
    pub fn new(input: &str) -> Result<Self, ValidationError> {
        if input.is_empty() {
            return Err(ValidationError::EmptyNamespace);
        }

        let segments: Vec<&str> = input.split('/').collect();

        // Reject empty segments from leading, trailing, or double slashes.
        for seg in &segments {
            if seg.is_empty() {
                return Err(ValidationError::EmptyNamespace);
            }
            // Reject segments with leading/trailing whitespace.
            if *seg != seg.trim() {
                return Err(ValidationError::Whitespace {
                    kind: "namespace segment",
                    value: seg.to_string(),
                });
            }
        }

        let owned: Vec<String> = segments.iter().map(|s| s.to_string()).collect();

        for seg in &owned {
            validate_component("namespace segment", seg)?;
        }

        Ok(Self { segments: owned })
    }

    /// Construct from pre-validated segments.
    ///
    /// Each segment is still validated. Use this when segments come
    /// from parsed URL components rather than a slash-separated string.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` for empty or invalid segments.
    pub fn from_segments(segments: Vec<String>) -> Result<Self, ValidationError> {
        if segments.is_empty() {
            return Err(ValidationError::EmptyNamespace);
        }
        for seg in &segments {
            if seg.is_empty() {
                return Err(ValidationError::EmptyNamespace);
            }
            validate_component("namespace segment", seg)?;
        }
        Ok(Self { segments })
    }

    /// The individual segments of this namespace path.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// The first segment, which is the top-level organization or user.
    #[must_use]
    pub fn root_segment(&self) -> &str {
        &self.segments[0]
    }

    /// The number of segments in the namespace.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// Convert to a relative filesystem path.
    ///
    /// Each segment becomes a directory component.
    #[must_use]
    pub fn as_path(&self) -> PathBuf {
        self.segments.iter().collect()
    }
}

impl fmt::Display for NamespacePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_segment() {
        let ns = NamespacePath::new("braincraftio").unwrap();
        assert_eq!(ns.segments(), &["braincraftio"]);
        assert_eq!(ns.depth(), 1);
        assert_eq!(ns.root_segment(), "braincraftio");
        assert_eq!(ns.to_string(), "braincraftio");
        assert_eq!(ns.as_path(), PathBuf::from("braincraftio"));
    }

    #[test]
    fn nested_segments() {
        let ns = NamespacePath::new("group/subgroup").unwrap();
        assert_eq!(ns.segments(), &["group", "subgroup"]);
        assert_eq!(ns.depth(), 2);
        assert_eq!(ns.root_segment(), "group");
        assert_eq!(ns.to_string(), "group/subgroup");
        assert_eq!(ns.as_path(), PathBuf::from("group/subgroup"));
    }

    #[test]
    fn deeply_nested() {
        let ns = NamespacePath::new("a/b/c/d").unwrap();
        assert_eq!(ns.depth(), 4);
        assert_eq!(ns.to_string(), "a/b/c/d");
    }

    #[test]
    fn rejects_whitespace_padded_segments() {
        assert!(NamespacePath::new(" org / sub ").is_err());
    }

    #[test]
    fn rejects_empty_segments_from_double_slash() {
        assert!(NamespacePath::new("org//sub").is_err());
    }

    #[test]
    fn rejects_leading_slash() {
        assert!(NamespacePath::new("/org/sub").is_err());
    }

    #[test]
    fn rejects_trailing_slash() {
        assert!(NamespacePath::new("org/sub/").is_err());
    }

    #[test]
    fn rejects_empty_string() {
        assert!(matches!(
            NamespacePath::new(""),
            Err(ValidationError::EmptyNamespace)
        ));
    }

    #[test]
    fn rejects_only_slashes() {
        assert!(NamespacePath::new("///").is_err());
    }

    #[test]
    fn rejects_leading_dot_segment() {
        assert!(matches!(
            NamespacePath::new(".hidden/sub"),
            Err(ValidationError::LeadingDot { .. })
        ));
    }

    #[test]
    fn rejects_traversal_segment() {
        assert!(matches!(
            NamespacePath::new("../escape"),
            Err(ValidationError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_null_in_segment() {
        assert!(matches!(
            NamespacePath::new("org\0evil"),
            Err(ValidationError::NullByte { .. })
        ));
    }

    #[test]
    fn from_segments_valid() {
        let ns = NamespacePath::from_segments(vec!["a".into(), "b".into()]).unwrap();
        assert_eq!(ns.depth(), 2);
    }

    #[test]
    fn from_segments_empty_rejected() {
        assert!(NamespacePath::from_segments(vec![]).is_err());
    }

    #[test]
    fn from_segments_invalid_segment_rejected() {
        assert!(NamespacePath::from_segments(vec!["..".into()]).is_err());
    }

    #[test]
    fn from_segments_empty_segment_rejected() {
        assert!(NamespacePath::from_segments(vec!["".into()]).is_err());
    }

    #[test]
    fn preserves_casing() {
        let ns = NamespacePath::new("ScopeCreep-zip").unwrap();
        assert_eq!(ns.root_segment(), "ScopeCreep-zip");
    }

    #[test]
    fn accepts_embedded_dots_in_segment() {
        let ns = NamespacePath::new("foo..bar").unwrap();
        assert_eq!(ns.root_segment(), "foo..bar");
    }

    #[test]
    fn serde_roundtrip() {
        let original = NamespacePath::new("group/subgroup").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"group/subgroup\"");
        let parsed: NamespacePath = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<NamespacePath, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_double_slash() {
        let result: Result<NamespacePath, _> = serde_json::from_str("\"org//sub\"");
        assert!(result.is_err());
    }
}
