use serde::{Deserialize, Serialize};

use crate::profile::TrustProfileName;

/// Why an unlock request was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockRejectedReason {
    /// System is already unlocked. Distinct from wrong password.
    AlreadyUnlocked,
}

/// Why a secret operation was denied (typed denial, replaces ambiguous empty responses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretDenialReason {
    Locked,
    ProfileNotActive,
    AccessDenied,
    RateLimited,
    NotFound,
    VaultError(String),
    /// No accepted, applicable authorization policy is available at admission.
    PolicyUnavailable(String),
}

/// Why a launch was denied. Machine-readable so the WM can take action
/// (e.g. prompt for vault unlock when `VaultsLocked`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LaunchDenial {
    /// One or more required vaults are locked. The WM can offer inline unlock.
    VaultsLocked {
        locked_profiles: Vec<TrustProfileName>,
    },
    /// Required secrets were not found (configuration error, not lock state).
    /// Count is opaque to avoid revealing which secrets exist.
    SecretNotFound { missing_count: u32 },
    /// Rate limiting on secret access.
    RateLimited,
    /// A trust profile referenced by a tag does not exist in config.
    ProfileNotFound { profile: String },
    /// A launch profile referenced by a tag does not exist.
    LaunchProfileNotFound {
        profile: String,
        launch_profile: String,
    },
    /// Desktop entry not found in the launcher cache.
    EntryNotFound,
    /// The requested id matches no entry exactly and more than one entry
    /// loosely (case-insensitive id or last dot-separated segment).
    /// `candidates` lists the matching entry ids, sorted.
    EntryAmbiguous { candidates: Vec<String> },
    /// A launch profile secret maps to an environment variable no secret
    /// may set (`secret_env::is_protected_env_var`).
    ProtectedVariable { variable: String },
}

impl std::fmt::Display for LaunchDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VaultsLocked { locked_profiles } if locked_profiles.is_empty() => {
                f.write_str("vault locked")
            }
            Self::VaultsLocked { locked_profiles } => {
                f.write_str("vault locked: ")?;
                for (i, profile) in locked_profiles.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{profile}")?;
                }
                Ok(())
            }
            Self::SecretNotFound { missing_count } => {
                write!(f, "{missing_count} required secret(s) not found")
            }
            Self::RateLimited => f.write_str("secret access rate limited"),
            Self::ProfileNotFound { profile } => write!(f, "profile '{profile}' not found"),
            Self::LaunchProfileNotFound {
                profile,
                launch_profile,
            } => write!(
                f,
                "launch profile '{launch_profile}' not found in '{profile}'"
            ),
            Self::EntryNotFound => f.write_str("application not found"),
            Self::EntryAmbiguous { candidates } => {
                write!(f, "ambiguous application: {}", candidates.join(", "))
            }
            Self::ProtectedVariable { variable } => {
                write!(f, "a secret maps to protected variable {variable}")
            }
        }
    }
}

/// The outcome of a `LaunchExecute` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LaunchOutcome {
    /// The application was spawned.
    Launched { pid: u32 },
    /// The launch was refused for a reason the caller can act on.
    Denied(LaunchDenial),
    /// The launch failed (spawn error, unreadable secret, configuration
    /// state); `reason` describes it.
    Failed { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_denials_name_what_was_refused() {
        let work = TrustProfileName::try_from("work").unwrap();
        let ops = TrustProfileName::try_from("ops").unwrap();
        for (denial, text) in [
            (
                LaunchDenial::VaultsLocked {
                    locked_profiles: vec![work, ops],
                },
                "vault locked: work, ops",
            ),
            (
                LaunchDenial::VaultsLocked {
                    locked_profiles: vec![],
                },
                "vault locked",
            ),
            (
                LaunchDenial::EntryAmbiguous {
                    candidates: vec!["a.b".into(), "c.b".into()],
                },
                "ambiguous application: a.b, c.b",
            ),
            (
                LaunchDenial::ProtectedVariable {
                    variable: "LD_PRELOAD".into(),
                },
                "a secret maps to protected variable LD_PRELOAD",
            ),
        ] {
            assert_eq!(denial.to_string(), text);
        }
    }
}
