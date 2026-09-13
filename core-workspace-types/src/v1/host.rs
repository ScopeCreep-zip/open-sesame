//! Git server host identity for workspace filesystem placement.
//!
//! A GitHost identifies a git service by hostname or IP address.
//! Ports are not part of host identity because one hostname serves
//! one git service regardless of port. Ports belong in RemoteEndpoint.
//!
//! The filesystem encoding is bidirectional:
//!   FQDN  -> lowercase hostname
//!   IPv4  -> canonical dotted decimal
//!   IPv6  -> "_ipv6_" prefix + canonical address with ":" replaced by "-"

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::v1::error::ValidationError;

/// Characters invalid in DNS hostnames. Rejected to prevent injection
/// into URL rendering or filesystem paths.
const INVALID_HOST_CHARS: &[char] = &[
    '@', '?', '#', '%', '/', '\\', '\0', ' ', '\t', '\n', '\r', ':',
];

/// A validated git server host identity.
///
/// Represents the server component of workspace filesystem placement.
/// Does not carry port, transport, or user information. Those belong
/// in RemoteEndpoint.
///
/// Equality is case-insensitive for FQDNs and canonical for IP
/// addresses. Deserialization validates through the constructor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GitHost {
    /// A DNS hostname, stored lowercase.
    Fqdn(String),
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address, stored in canonical form.
    Ipv6(Ipv6Addr),
}

impl GitHost {
    /// Parse a host string into a GitHost.
    ///
    /// Accepts DNS hostnames, dotted-decimal IPv4, and bracketed or
    /// bare IPv6 addresses. Rejects empty input, interior whitespace,
    /// and URI-significant characters.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::InvalidHostname` for unparseable or
    /// unsafe input.
    pub fn new(input: &str) -> Result<Self, ValidationError> {
        let input = input.trim();

        if input.is_empty() {
            return Err(ValidationError::InvalidHostname {
                value: input.into(),
            });
        }

        // Bracketed IPv6: [::1] or [2001:db8::25]
        if input.starts_with('[') {
            let close = input.find(']').ok_or_else(|| ValidationError::InvalidHostname {
                value: input.into(),
            })?;
            // Nothing should follow the closing bracket in a host-only context.
            if close + 1 != input.len() {
                return Err(ValidationError::InvalidHostname {
                    value: input.into(),
                });
            }
            let addr_str = &input[1..close];
            let addr: Ipv6Addr = addr_str.parse().map_err(|_| ValidationError::InvalidHostname {
                value: input.into(),
            })?;
            return Ok(Self::Ipv6(addr));
        }

        // Try IPv4 first (before FQDN check, since dotted decimal contains dots).
        if let Ok(addr) = input.parse::<Ipv4Addr>() {
            return Ok(Self::Ipv4(addr));
        }

        // Try bare IPv6 (contains multiple colons without brackets).
        if input.contains(':') {
            if let Ok(addr) = input.parse::<Ipv6Addr>() {
                return Ok(Self::Ipv6(addr));
            }
            // Contains colons but is not valid IPv6.
            return Err(ValidationError::InvalidHostname {
                value: input.into(),
            });
        }

        // FQDN: reject invalid characters, normalize to lowercase.
        if input.contains(INVALID_HOST_CHARS) {
            return Err(ValidationError::InvalidHostname {
                value: input.into(),
            });
        }

        if input.len() > 253 {
            return Err(ValidationError::InvalidHostname {
                value: input.into(),
            });
        }

        Ok(Self::Fqdn(input.to_ascii_lowercase()))
    }

    /// The hostname string for display and URL construction.
    ///
    /// FQDNs return the lowercase hostname. IPv4 returns dotted
    /// decimal. IPv6 returns the canonical text representation
    /// without brackets (brackets are added by URL renderers).
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Fqdn(s) => s.clone(),
            Self::Ipv4(addr) => addr.to_string(),
            Self::Ipv6(addr) => addr.to_string(),
        }
    }

    /// The filesystem directory name for this host.
    ///
    /// FQDNs and IPv4 addresses are their own directory names.
    /// IPv6 addresses are encoded as `_ipv6_` followed by the
    /// canonical address with colons replaced by dashes. The
    /// encoding is invertible via `from_dir_name`.
    #[must_use]
    pub fn as_dir_name(&self) -> String {
        match self {
            Self::Fqdn(s) => s.clone(),
            Self::Ipv4(addr) => addr.to_string(),
            Self::Ipv6(addr) => {
                format!("_ipv6_{}", addr.to_string().replace(':', "-"))
            }
        }
    }

    /// Decode a filesystem directory name back into a GitHost.
    ///
    /// Reverses `as_dir_name`. Returns None if the input does not
    /// correspond to a valid encoded host.
    #[must_use]
    pub fn from_dir_name(name: &str) -> Option<Self> {
        if let Some(rest) = name.strip_prefix("_ipv6_") {
            let addr_str = rest.replace('-', ":");
            let addr: Ipv6Addr = addr_str.parse().ok()?;
            return Some(Self::Ipv6(addr));
        }
        if let Ok(addr) = name.parse::<Ipv4Addr>() {
            return Some(Self::Ipv4(addr));
        }
        if name.is_empty() || name.contains(INVALID_HOST_CHARS) {
            return None;
        }
        Some(Self::Fqdn(name.to_ascii_lowercase()))
    }

    /// Whether this host contains a dot, indicating a fully qualified
    /// domain name. Used by shorthand resolution to distinguish
    /// `server/org/repo` from `ns/ns/repo`.
    #[must_use]
    pub fn has_dot(&self) -> bool {
        match self {
            Self::Fqdn(s) => s.contains('.'),
            Self::Ipv4(_) | Self::Ipv6(_) => false,
        }
    }
}

impl fmt::Display for GitHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for GitHost {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for GitHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        GitHost::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn() {
        let h = GitHost::new("github.com").unwrap();
        assert!(matches!(h, GitHost::Fqdn(_)));
        assert_eq!(h.as_str(), "github.com");
        assert_eq!(h.as_dir_name(), "github.com");
        assert!(h.has_dot());
    }

    #[test]
    fn fqdn_uppercase_normalized() {
        let h = GitHost::new("GITHUB.COM").unwrap();
        assert_eq!(h.as_str(), "github.com");
    }

    #[test]
    fn fqdn_dotless() {
        let h = GitHost::new("localhost").unwrap();
        assert_eq!(h.as_str(), "localhost");
        assert!(!h.has_dot());
    }

    #[test]
    fn ipv4() {
        let h = GitHost::new("192.0.2.40").unwrap();
        assert!(matches!(h, GitHost::Ipv4(_)));
        assert_eq!(h.as_str(), "192.0.2.40");
        assert_eq!(h.as_dir_name(), "192.0.2.40");
    }

    #[test]
    fn ipv6_bracketed() {
        let h = GitHost::new("[2001:db8::25]").unwrap();
        assert!(matches!(h, GitHost::Ipv6(_)));
        assert_eq!(h.as_str(), "2001:db8::25");
        assert_eq!(h.as_dir_name(), "_ipv6_2001-db8--25");
    }

    #[test]
    fn ipv6_bare() {
        let h = GitHost::new("::1").unwrap();
        assert!(matches!(h, GitHost::Ipv6(_)));
        assert_eq!(h.as_str(), "::1");
        assert_eq!(h.as_dir_name(), "_ipv6_--1");
    }

    #[test]
    fn ipv6_canonical_equivalence() {
        let a = GitHost::new("[2001:0DB8:0000:0000:0000:0000:0000:0025]").unwrap();
        let b = GitHost::new("[2001:db8::25]").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.as_dir_name(), b.as_dir_name());
    }

    #[test]
    fn dir_name_roundtrip_fqdn() {
        let h = GitHost::new("git.braincraft.io").unwrap();
        let decoded = GitHost::from_dir_name(&h.as_dir_name()).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn dir_name_roundtrip_ipv4() {
        let h = GitHost::new("192.0.2.40").unwrap();
        let decoded = GitHost::from_dir_name(&h.as_dir_name()).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn dir_name_roundtrip_ipv6() {
        let h = GitHost::new("[2001:db8::25]").unwrap();
        let encoded = h.as_dir_name();
        assert_eq!(encoded, "_ipv6_2001-db8--25");
        let decoded = GitHost::from_dir_name(&encoded).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn dir_name_roundtrip_ipv6_loopback() {
        let h = GitHost::new("::1").unwrap();
        let decoded = GitHost::from_dir_name(&h.as_dir_name()).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn rejects_empty() {
        assert!(GitHost::new("").is_err());
    }

    #[test]
    fn rejects_whitespace_only() {
        assert!(GitHost::new("   ").is_err());
    }

    #[test]
    fn rejects_at_sign() {
        assert!(GitHost::new("user@host").is_err());
    }

    #[test]
    fn rejects_question_mark() {
        assert!(GitHost::new("host?query").is_err());
    }

    #[test]
    fn rejects_hash() {
        assert!(GitHost::new("host#fragment").is_err());
    }

    #[test]
    fn rejects_percent() {
        assert!(GitHost::new("host%20name").is_err());
    }

    #[test]
    fn rejects_interior_space() {
        assert!(GitHost::new("host name").is_err());
    }

    #[test]
    fn rejects_slash() {
        assert!(GitHost::new("host/path").is_err());
    }

    #[test]
    fn rejects_unclosed_bracket() {
        assert!(GitHost::new("[::1").is_err());
    }

    #[test]
    fn rejects_bracket_with_trailing() {
        assert!(GitHost::new("[::1]:8080").is_err());
    }

    #[test]
    fn rejects_empty_bracket() {
        assert!(GitHost::new("[]").is_err());
    }

    #[test]
    fn rejects_invalid_ipv6() {
        assert!(GitHost::new("[not:valid:ipv6]").is_err());
    }

    #[test]
    fn equality_case_insensitive_fqdn() {
        let a = GitHost::new("GitHub.COM").unwrap();
        let b = GitHost::new("github.com").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn serde_roundtrip_fqdn() {
        let original = GitHost::new("github.com").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"github.com\"");
        let parsed: GitHost = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn serde_roundtrip_ipv6() {
        let original = GitHost::new("[2001:db8::25]").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        // Serializes as the canonical text without brackets.
        assert_eq!(json, "\"2001:db8::25\"");
        let parsed: GitHost = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<GitHost, _> = serde_json::from_str("\"user@host\"");
        assert!(result.is_err());
    }

    #[test]
    fn from_dir_name_rejects_empty() {
        assert!(GitHost::from_dir_name("").is_none());
    }

    #[test]
    fn from_dir_name_rejects_invalid_ipv6() {
        assert!(GitHost::from_dir_name("_ipv6_not-valid").is_none());
    }

    #[test]
    fn multi_subdomain() {
        let h = GitHost::new("git.braincraft.io").unwrap();
        assert_eq!(h.as_str(), "git.braincraft.io");
        assert!(h.has_dot());
    }
}
