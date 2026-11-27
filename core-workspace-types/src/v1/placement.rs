//! Filesystem placement components.
//!
//! Placement types name directories under `{root}/{user}/{host}/`.
//! Every placement component is lowercase ASCII by construction, so one
//! remote resolves to exactly one directory on case-sensitive and
//! case-insensitive filesystems alike, whatever spelling the remote was
//! given in.
//!
//! Two constructors exist per type, and only two:
//! - `from_remote`: the total mapping from a validated remote identifier
//!   (`NamespacePath`, `RepositoryName`). Remote identifiers are ASCII,
//!   so lowercasing is length-preserving and collision-free.
//! - `parse`: strict parsing of a directory name read from disk. A name
//!   that is not already canonical is an error carrying the canonical
//!   form; it is never normalized silently, because a non-canonical
//!   directory on disk is a layout conflict the operator must resolve.
//!
//! No conversion from placement back to remote exists. Remote spelling
//! cannot be recovered from a directory name.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::v1::error::{LeadingDotPolicy, ValidationError, validate_component};
use crate::v1::repository::GIT_DIR_NAME;
use crate::v1::{NamespacePath, RepositoryName};

/// Validate a directory component read from disk and require canonical case.
fn parse_canonical(
    kind: &'static str,
    value: &str,
    leading_dot: LeadingDotPolicy,
) -> Result<String, ValidationError> {
    validate_component(kind, value, leading_dot)?;
    let canonical = value.to_ascii_lowercase();
    if canonical != value {
        return Err(ValidationError::NonCanonicalCase {
            kind,
            value: value.to_string(),
            canonical,
        });
    }
    Ok(canonical)
}

/// Namespace directory segments: `{namespace...}` in the workspace layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NamespaceDir {
    segments: Vec<String>,
}

impl NamespaceDir {
    /// Map a remote namespace to its placement.
    #[must_use]
    pub fn from_remote(namespace: &NamespacePath) -> Self {
        Self {
            segments: namespace
                .segments()
                .iter()
                .map(|seg| seg.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Parse namespace directory names read from disk.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::EmptyNamespace` for no segments,
    /// `ValidationError::NonCanonicalCase` for a segment that is not
    /// lowercase, and any component validation error.
    pub fn parse<S: AsRef<str>>(segments: &[S]) -> Result<Self, ValidationError> {
        if segments.is_empty() {
            return Err(ValidationError::EmptyNamespace);
        }
        let segments = segments
            .iter()
            .map(|seg| {
                parse_canonical(
                    "namespace directory",
                    seg.as_ref(),
                    LeadingDotPolicy::Reject,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { segments })
    }

    /// The directory segments.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// The first segment: the top-level organization or user directory.
    #[must_use]
    pub fn root_segment(&self) -> &str {
        &self.segments[0]
    }

    /// The relative filesystem path of the namespace directory.
    #[must_use]
    pub fn as_path(&self) -> PathBuf {
        self.segments.iter().collect()
    }
}

impl fmt::Display for NamespaceDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.segments.join("/"))
    }
}

impl From<NamespaceDir> for String {
    fn from(ns: NamespaceDir) -> String {
        ns.to_string()
    }
}

impl TryFrom<String> for NamespaceDir {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let segments: Vec<&str> = value.split('/').collect();
        Self::parse(&segments)
    }
}

/// Repository directory: `{repo}` in the workspace layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepoDir {
    name: String,
}

impl RepoDir {
    /// Map a remote repository name to its placement.
    #[must_use]
    pub fn from_remote(name: &RepositoryName) -> Self {
        Self {
            name: name.as_str().to_ascii_lowercase(),
        }
    }

    /// Parse a repository directory name read from disk.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::NonCanonicalCase` for a name that is not
    /// lowercase, `ValidationError::ReservedName` for `.git`, and any
    /// component validation error.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        const KIND: &str = "repository directory";
        let name = parse_canonical(KIND, value, LeadingDotPolicy::Allow)?;
        if name == GIT_DIR_NAME {
            return Err(ValidationError::ReservedName {
                kind: KIND,
                value: name,
            });
        }
        Ok(Self { name })
    }

    /// The directory name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RepoDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<RepoDir> for String {
    fn from(r: RepoDir) -> String {
        r.name
    }
}

impl TryFrom<String> for RepoDir {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_from_remote_lowercases() {
        let ns = NamespacePath::new("NixOS/Infra").unwrap();
        let dir = NamespaceDir::from_remote(&ns);
        assert_eq!(dir.segments(), &["nixos", "infra"]);
        assert_eq!(dir.as_path(), PathBuf::from("nixos/infra"));
        assert_eq!(dir.to_string(), "nixos/infra");
    }

    #[test]
    fn namespace_spellings_share_one_placement() {
        let a = NamespaceDir::from_remote(&NamespacePath::new("ScopeCreep-zip").unwrap());
        let b = NamespaceDir::from_remote(&NamespacePath::new("scopecreep-zip").unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn namespace_parse_accepts_canonical() {
        let dir = NamespaceDir::parse(&["group", "subgroup"]).unwrap();
        assert_eq!(dir.to_string(), "group/subgroup");
    }

    #[test]
    fn namespace_parse_rejects_non_canonical() {
        assert_eq!(
            NamespaceDir::parse(&["ScopeCreep-zip"]),
            Err(ValidationError::NonCanonicalCase {
                kind: "namespace directory",
                value: "ScopeCreep-zip".into(),
                canonical: "scopecreep-zip".into(),
            })
        );
    }

    #[test]
    fn namespace_parse_rejects_empty_and_invalid() {
        let none: [&str; 0] = [];
        assert_eq!(
            NamespaceDir::parse(&none),
            Err(ValidationError::EmptyNamespace)
        );
        assert!(matches!(
            NamespaceDir::parse(&[".hidden"]),
            Err(ValidationError::LeadingDot { .. })
        ));
        assert!(matches!(
            NamespaceDir::parse(&[".."]),
            Err(ValidationError::PathTraversal { .. })
        ));
    }

    #[test]
    fn repo_from_remote_lowercases() {
        let name = RepositoryName::new("NixPkgs").unwrap();
        assert_eq!(RepoDir::from_remote(&name).as_str(), "nixpkgs");
    }

    #[test]
    fn repo_from_remote_keeps_leading_dot() {
        let name = RepositoryName::new(".GitHub").unwrap();
        assert_eq!(RepoDir::from_remote(&name).as_str(), ".github");
    }

    #[test]
    fn repo_parse_accepts_canonical_leading_dot() {
        assert_eq!(RepoDir::parse(".github").unwrap().as_str(), ".github");
    }

    #[test]
    fn repo_parse_rejects_non_canonical() {
        assert!(matches!(
            RepoDir::parse("NixPkgs"),
            Err(ValidationError::NonCanonicalCase { .. })
        ));
    }

    #[test]
    fn repo_parse_rejects_git_dir() {
        assert!(matches!(
            RepoDir::parse(".git"),
            Err(ValidationError::ReservedName { .. })
        ));
    }

    #[test]
    fn serde_roundtrip_and_strictness() {
        let dir = NamespaceDir::parse(&["group", "sub"]).unwrap();
        let json = serde_json::to_string(&dir).unwrap();
        assert_eq!(json, "\"group/sub\"");
        assert_eq!(serde_json::from_str::<NamespaceDir>(&json).unwrap(), dir);
        assert!(serde_json::from_str::<NamespaceDir>("\"Group\"").is_err());
        assert!(serde_json::from_str::<RepoDir>("\"Repo\"").is_err());
    }
}
