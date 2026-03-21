//! Configuration schema types.
//!
//! Root configuration struct and global settings live here. Domain-specific
//! types are defined in `schema_*` sibling modules and re-exported below
//! so that downstream crates can continue using `core_config::TypeName`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Re-export domain schema modules for stable downstream paths.
pub use crate::schema_agents::{
    AgentConfig, AgentsConfig, ExtensionsConfig, ExtensionsPolicyConfig,
};
pub use crate::schema_crypto::CryptoConfigToml;
pub use crate::schema_installation::{InstallationConfig, MachineBindingConfig, OrgConfig};
pub use crate::schema_peripheral::{AuditConfig, ClipboardConfig, InputConfig, LauncherConfig};
pub use crate::schema_secrets::{AuthConfig, SecretsConfig};
pub use crate::schema_wm::{LaunchProfile, WmConfig, WmKeyBinding};
pub use crate::schema_workspace::{LocalSesameConfig, WorkspaceConfig, WorkspaceSettings};

/// Top-level PDS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Schema version for forward migration.
    pub config_version: u32,

    /// Global settings that apply across all profiles.
    pub global: GlobalConfig,

    /// Named profiles (key is profile name).
    pub profiles: BTreeMap<String, ProfileConfig>,

    /// Cryptographic algorithm configuration.
    pub crypto: CryptoConfigToml,

    /// Agent identity and authorization configuration.
    pub agents: AgentsConfig,

    /// Extension policy configuration.
    pub extensions: ExtensionsConfig,

    /// System policy overrides (read-only at runtime).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<PolicyOverride>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: 3,
            global: GlobalConfig::default(),
            profiles: BTreeMap::new(),
            crypto: CryptoConfigToml::default(),
            agents: AgentsConfig::default(),
            extensions: ExtensionsConfig::default(),
            policy: Vec::new(),
        }
    }
}

/// Global settings that apply across all profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    /// Default trust profile on startup.
    pub default_profile: core_types::TrustProfileName,

    /// IPC bus configuration.
    pub ipc: IpcConfig,

    /// Logging configuration.
    pub logging: LogConfig,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            default_profile: core_types::TrustProfileName::try_from(
                core_types::DEFAULT_PROFILE_NAME,
            )
            .expect("hardcoded valid name"),
            ipc: IpcConfig::default(),
            logging: LogConfig::default(),
        }
    }
}

/// IPC bus configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpcConfig {
    /// Custom socket path override. `None` uses platform default.
    pub socket_path: Option<String>,

    /// Channel capacity per subscriber.
    pub channel_capacity: usize,

    /// Grace period (ms) before disconnecting slow subscribers.
    pub slow_subscriber_timeout_ms: u64,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            channel_capacity: 1024,
            slow_subscriber_timeout_ms: 5000,
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Default log level.
    pub level: String,

    /// Enable JSON-structured output.
    pub json: bool,

    /// Enable journald integration (Linux only).
    pub journald: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
            journald: true,
        }
    }
}

/// Per-profile configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileConfig {
    pub name: core_types::TrustProfileName,
    pub extends: Option<core_types::TrustProfileName>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub activation: ActivationConfig,
    pub auth: AuthConfig,
    pub secrets: SecretsConfig,
    pub clipboard: ClipboardConfig,
    pub input: InputConfig,
    pub wm: WmConfig,
    pub launcher: LauncherConfig,
    pub audit: AuditConfig,

    /// Named launch profiles for composable app environment injection.
    #[serde(default)]
    pub launch_profiles: BTreeMap<String, LaunchProfile>,

    /// Platform-specific overrides.
    #[serde(default)]
    pub platform: PlatformOverrides,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            name: core_types::TrustProfileName::try_from(core_types::DEFAULT_PROFILE_NAME)
                .expect("hardcoded valid name"),
            extends: None,
            color: None,
            icon: None,
            activation: ActivationConfig::default(),
            auth: AuthConfig::default(),
            secrets: SecretsConfig::default(),
            clipboard: ClipboardConfig::default(),
            input: InputConfig::default(),
            wm: WmConfig::default(),
            launcher: LauncherConfig::default(),
            audit: AuditConfig::default(),
            launch_profiles: BTreeMap::new(),
            platform: PlatformOverrides::default(),
        }
    }
}

/// Profile activation rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivationConfig {
    /// `WiFi` SSID triggers.
    pub wifi_ssids: Vec<String>,
    /// USB device triggers (vendor:product pairs).
    pub usb_devices: Vec<String>,
    /// Time-of-day rules (cron-like expressions).
    pub time_rules: Vec<String>,
    /// Hardware security key presence.
    pub require_security_key: bool,
}

/// Platform-specific configuration overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<toml::Value>,
}

/// A system policy override that locks a configuration key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOverride {
    /// Dotted key path (e.g. "`clipboard.max_history`").
    pub key: String,
    /// The enforced value.
    pub value: toml::Value,
    /// Source of the policy (e.g. "enterprise-mdm", "/etc/pds/policy.toml").
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_config_without_launch_profiles_defaults_empty() {
        let pc = ProfileConfig::default();
        assert!(pc.launch_profiles.is_empty());
    }

    #[test]
    fn profile_config_includes_auth() {
        let toml_str = r#"
            [auth]
            mode = "all"

            [secrets]
            [clipboard]
            [input]
            [wm]
            [launcher]
            [audit]
        "#;
        let pc: ProfileConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(pc.auth.mode, "all");
    }
}
