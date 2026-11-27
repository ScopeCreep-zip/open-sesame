//! Validated repository name as the forge spells it.
//!
//! `RepositoryName` is a remote identifier. It preserves case exactly as
//! the user or forge supplied it, because URL rendering must reproduce
//! the remote's spelling: case-sensitive git servers (`git daemon`,
//! `git-http-backend`, bare repositories over SSH) resolve `Repo` and
//! `repo` to different repositories. Filesystem placement is derived
//! from it through `RepoDir`, which is lowercase by construction.
//!
//! Leading dots are permitted: forges host repositories such as
//! `.github` and `.dotfiles`. A name whose placement would be `.git`
//! is rejected, because a repository directory sits inside an org
//! directory whose own `.git` is the workspace.git repository.

use std::fmt;

use serde::Serialize;

use crate::v1::error::{LeadingDotPolicy, ValidationError, validate_component};

/// Directory name git uses for repository metadata.
pub(crate) const GIT_DIR_NAME: &str = ".git";

/// Suffix git URLs conventionally append to repository paths.
const GIT_URL_SUFFIX: &str = ".git";

/// A validated repository name in its remote spelling.
///
/// Construction strips one trailing `.git` URL suffix and validates the
/// result as a single ASCII path component. Equality is exact: two names
/// that differ only in case are different remote spellings. Use
/// `RepoDir::from_remote` to compare placements.
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
    /// Strips one trailing `.git` URL suffix in any ASCII case, then
    /// validates. Leading dots are accepted. A name equal to `.git` in
    /// any ASCII case, before or after suffix stripping, is reserved.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` for empty, malformed, non-ASCII,
    /// unsafe, or reserved input.
    pub fn new(input: &str) -> Result<Self, ValidationError> {
        const KIND: &str = "repository name";

        let name = if input.eq_ignore_ascii_case(GIT_DIR_NAME) {
            input
        } else {
            strip_git_suffix(input)
        };

        validate_component(KIND, name, LeadingDotPolicy::Allow)?;

        if name.eq_ignore_ascii_case(GIT_DIR_NAME) {
            return Err(ValidationError::ReservedName {
                kind: KIND,
                value: name.to_string(),
            });
        }

        Ok(Self {
            name: name.to_string(),
        })
    }

    /// The repository name in its remote spelling, without `.git` suffix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

/// Strip one trailing `.git` URL suffix, matched in any ASCII case.
fn strip_git_suffix(input: &str) -> &str {
    let split = input.len().saturating_sub(GIT_URL_SUFFIX.len());
    match input.get(split..) {
        Some(tail) if split > 0 && tail.eq_ignore_ascii_case(GIT_URL_SUFFIX) => &input[..split],
        _ => input,
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
    fn strips_git_suffix_in_any_case() {
        for input in ["Repo.git", "Repo.GIT", "Repo.Git"] {
            assert_eq!(
                RepositoryName::new(input).unwrap().as_str(),
                "Repo",
                "{input}"
            );
        }
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
    fn preserves_remote_casing() {
        let r = RepositoryName::new("NixPkgs").unwrap();
        assert_eq!(r.as_str(), "NixPkgs");
        assert_ne!(r, RepositoryName::new("nixpkgs").unwrap());
    }

    #[test]
    fn accepts_leading_dot() {
        let r = RepositoryName::new(".github").unwrap();
        assert_eq!(r.as_str(), ".github");
    }

    #[test]
    fn strips_git_suffix_from_leading_dot_name() {
        let r = RepositoryName::new(".github.git").unwrap();
        assert_eq!(r.as_str(), ".github");
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            RepositoryName::new(""),
            Err(ValidationError::Empty { .. })
        ));
    }

    #[test]
    fn rejects_git_dir_name() {
        for input in [".git", ".GIT", ".Git", ".git.git", ".GIT.git"] {
            assert!(
                matches!(
                    RepositoryName::new(input),
                    Err(ValidationError::ReservedName { .. })
                ),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_bare_dot_and_dotdot() {
        for input in [".", "..", "...git"] {
            assert!(
                matches!(
                    RepositoryName::new(input),
                    Err(ValidationError::PathTraversal { .. })
                ),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(matches!(
            RepositoryName::new("Ärger"),
            Err(ValidationError::NonAscii { .. })
        ));
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
    fn equality_by_suffix_normalized_name() {
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
    fn serde_roundtrip_preserves_case() {
        let original = RepositoryName::new("NixPkgs").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"NixPkgs\"");
        let parsed: RepositoryName = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn serde_strips_git_suffix() {
        let parsed: RepositoryName = serde_json::from_str("\"repo.git\"").unwrap();
        assert_eq!(parsed.as_str(), "repo");
    }

    #[test]
    fn serde_accepts_leading_dot() {
        let parsed: RepositoryName = serde_json::from_str("\".github\"").unwrap();
        assert_eq!(parsed.as_str(), ".github");
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<RepositoryName, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }
}
