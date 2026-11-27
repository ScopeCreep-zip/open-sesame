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

impl ProfileId {
    /// The installation-scoped identity of profile `name`: UUID v5 of
    /// `profile:<name>` in `installation_namespace`
    /// (`InstallationConfig::namespace`), stable across restarts and
    /// distinct between installations.
    #[must_use]
    pub fn of_profile(installation_namespace: &Uuid, name: &str) -> Self {
        Self(Uuid::new_v5(
            installation_namespace,
            format!("profile:{name}").as_bytes(),
        ))
    }
}

define_id!(WindowId, "win");
define_id!(CompositorWorkspaceId, "ws");
define_id!(MonitorId, "mon");
define_id!(ClipboardEntryId, "clip");
define_id!(DaemonId, "dmon");
define_id!(ExtensionId, "ext");
define_id!(AgentId, "agent");

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

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> Uuid {
        Uuid::new_v5(&Uuid::NAMESPACE_OID, b"installation")
    }

    #[test]
    fn profile_ids_are_installation_scoped_and_stable() {
        assert_eq!(
            ProfileId::of_profile(&ns(), "work"),
            ProfileId::of_profile(&ns(), "work")
        );
        assert_ne!(
            ProfileId::of_profile(&ns(), "work"),
            ProfileId::of_profile(&ns(), "home")
        );
        let other = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"other");
        assert_ne!(
            ProfileId::of_profile(&ns(), "work"),
            ProfileId::of_profile(&other, "work")
        );
        // The persisted derivation: audit entries and clipboard rows carry it.
        assert_eq!(
            *ProfileId::of_profile(&ns(), "work").as_uuid(),
            Uuid::new_v5(&ns(), b"profile:work")
        );
    }
}
