//! Authentication and secrets configuration types.
//!
//! Config sections for vault unlock policy and per-profile secret storage.

use core_types::SecretRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Authentication policy configuration for a profile's vault.
///
/// Determines how enrolled authentication factors combine to unlock the
/// vault. Stored in `[profiles.<name>.auth]` in `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// How factors combine: "any", "all", or "policy".
    pub mode: String,
    /// For mode="policy": factors always required (e.g., `["password", "ssh-agent"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// For mode="policy": how many additional enrolled factors beyond `required` must succeed.
    #[serde(default)]
    pub additional_required: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: "any".into(),
            required: Vec::new(),
            additional_required: 0,
        }
    }
}

impl AuthConfig {
    /// Convert to the validated typed representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the mode or any factor name is unrecognized.
    pub fn to_typed(&self) -> core_types::Result<core_types::AuthCombineMode> {
        match self.mode.as_str() {
            "any" => Ok(core_types::AuthCombineMode::Any),
            "all" => Ok(core_types::AuthCombineMode::All),
            "policy" => {
                let mut required = Vec::with_capacity(self.required.len());
                for name in &self.required {
                    let factor = core_types::AuthFactorId::from_config_str(name)?;
                    required.push(factor);
                }
                Ok(core_types::AuthCombineMode::Policy(
                    core_types::AuthPolicy {
                        required,
                        additional_required: self.additional_required,
                    },
                ))
            }
            other => Err(core_types::Error::Config(format!(
                "unknown auth mode: {other}"
            ))),
        }
    }
}

/// Secrets configuration for a profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsConfig {
    /// Default secret provider for this profile.
    pub provider: Option<String>,
    /// Pre-resolved secrets for this profile.
    pub secrets: BTreeMap<String, SecretRef>,
    /// Per-daemon access control for secrets in this profile.
    ///
    /// Maps daemon names to lists of allowed secret key names.
    /// - Present with empty list: no access.
    /// - Present with keys: access only to listed keys.
    /// - Absent: unrestricted access (backward compatible default).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub access: BTreeMap<String, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_config_default_is_any() {
        let ac = AuthConfig::default();
        assert_eq!(ac.mode, "any");
        assert!(ac.required.is_empty());
        assert_eq!(ac.additional_required, 0);
    }

    #[test]
    fn auth_config_to_typed_any() {
        let ac = AuthConfig::default();
        let typed = ac.to_typed().unwrap();
        assert_eq!(typed, core_types::AuthCombineMode::Any);
    }

    #[test]
    fn auth_config_to_typed_all() {
        let ac = AuthConfig {
            mode: "all".into(),
            required: Vec::new(),
            additional_required: 0,
        };
        assert_eq!(ac.to_typed().unwrap(), core_types::AuthCombineMode::All);
    }

    #[test]
    fn auth_config_to_typed_policy() {
        let ac = AuthConfig {
            mode: "policy".into(),
            required: vec!["password".into(), "ssh-agent".into()],
            additional_required: 1,
        };
        let typed = ac.to_typed().unwrap();
        match typed {
            core_types::AuthCombineMode::Policy(p) => {
                assert_eq!(p.required.len(), 2);
                assert!(p.required.contains(&core_types::AuthFactorId::Password));
                assert!(p.required.contains(&core_types::AuthFactorId::SshAgent));
                assert_eq!(p.additional_required, 1);
            }
            other => panic!("expected Policy, got {other:?}"),
        }
    }

    #[test]
    fn auth_config_to_typed_unknown_mode_errors() {
        let ac = AuthConfig {
            mode: "bogus".into(),
            required: Vec::new(),
            additional_required: 0,
        };
        assert!(ac.to_typed().is_err());
    }

    #[test]
    fn auth_config_to_typed_unknown_factor_errors() {
        let ac = AuthConfig {
            mode: "policy".into(),
            required: vec!["unknown-factor".into()],
            additional_required: 0,
        };
        assert!(ac.to_typed().is_err());
    }

    #[test]
    fn auth_config_roundtrips_toml() {
        let ac = AuthConfig {
            mode: "policy".into(),
            required: vec!["password".into(), "ssh-agent".into()],
            additional_required: 2,
        };
        let toml_str = toml::to_string_pretty(&ac).unwrap();
        let parsed: AuthConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.mode, "policy");
        assert_eq!(parsed.required, vec!["password", "ssh-agent"]);
        assert_eq!(parsed.additional_required, 2);
    }
}
