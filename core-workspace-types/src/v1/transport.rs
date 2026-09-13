//! Git transport preference.
//!
//! Determines which protocol to use when constructing clone URLs
//! from shorthand input. Explicit URLs are never rewritten.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The preferred transport protocol for git clone operations.
///
/// Controls how shorthand inputs like `org/repo` are expanded into
/// full URLs. Explicit URLs with a scheme or SCP syntax are never
/// modified regardless of this setting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitTransport {
    /// Use HTTPS URLs: `https://server/namespace/repo`
    #[default]
    Https,
    /// Use SSH URLs: `git@server:namespace/repo.git`
    ///
    /// SCP-style syntax is used for standard port 22. For nonstandard
    /// ports, `ssh://git@server:port/namespace/repo` is generated
    /// instead because SCP syntax does not support port specification.
    Ssh,
}

impl fmt::Display for GitTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Https => write!(f, "https"),
            Self::Ssh => write!(f, "ssh"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_https() {
        assert_eq!(GitTransport::default(), GitTransport::Https);
    }

    #[test]
    fn display_https() {
        assert_eq!(GitTransport::Https.to_string(), "https");
    }

    #[test]
    fn display_ssh() {
        assert_eq!(GitTransport::Ssh.to_string(), "ssh");
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&GitTransport::Ssh).unwrap();
        assert_eq!(json, "\"ssh\"");
        let parsed: GitTransport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, GitTransport::Ssh);
    }
}
