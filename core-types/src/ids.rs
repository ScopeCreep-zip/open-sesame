use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ============================================================================
// Identity Types
// ============================================================================

macro_rules! define_id {
    ($name:ident, $prefix:expr) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-{}", $prefix, self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_id!(ProfileId, "prof");
define_id!(WindowId, "win");
define_id!(CompositorWorkspaceId, "ws");
define_id!(MonitorId, "mon");
define_id!(ClipboardEntryId, "clip");
define_id!(DaemonId, "dmon");
define_id!(ExtensionId, "ext");
define_id!(AgentId, "agent");
define_id!(SessionId, "sess");

// ============================================================================
// AppId
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(String);

impl AppId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Extract the last segment of a reverse-DNS app ID.
    /// `"com.mitchellh.ghostty"` -> `"ghostty"`
    /// `"firefox"` -> `"firefox"`
    #[must_use]
    pub fn last_segment(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Case-insensitive match against another `AppId` or fragment.
    #[must_use]
    pub fn matches(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
            || self.last_segment().eq_ignore_ascii_case(other)
            || other
                .rsplit('.')
                .next()
                .is_some_and(|seg| self.last_segment().eq_ignore_ascii_case(seg))
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
