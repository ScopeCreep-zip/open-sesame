//! Configuration schema types.

use core_types::SecretRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

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
            default_profile: core_types::TrustProfileName::try_from("default").expect("hardcoded valid name"),
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
            name: core_types::TrustProfileName::try_from("default").expect("hardcoded valid name"),
            extends: None,
            color: None,
            icon: None,
            activation: ActivationConfig::default(),
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

/// Clipboard configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClipboardConfig {
    /// Maximum history entries.
    pub max_history: usize,
    /// TTL for sensitive entries (seconds).
    pub sensitive_ttl_s: u64,
    /// Enable sensitivity detection.
    pub detect_sensitive: bool,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            max_history: 1000,
            sensitive_ttl_s: 30,
            detect_sensitive: true,
        }
    }
}

/// Input remapping configuration for a profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InputConfig {
    /// Key binding layers.
    pub layers: BTreeMap<String, BTreeMap<String, String>>,
}

/// Per-key app binding for hint assignment and launch-or-focus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmKeyBinding {
    /// App ID patterns that match this key.
    #[serde(default)]
    pub apps: Vec<String>,
    /// Command to launch if no matching window exists (launch-or-focus).
    #[serde(default)]
    pub launch: Option<String>,
    /// Launch profile tags to compose at launch time.
    /// Supports qualified cross-profile references: `"work:corp"`.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A named, composable launch profile for environment injection.
///
/// Defines environment variables, secrets, and optional Nix devshell
/// to inject when launching applications tagged with this profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LaunchProfile {
    /// Static environment variables to inject.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Secret names to fetch from the vault and inject as env vars.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Nix flake devshell reference (e.g., "/workspace/project#rust").
    #[serde(default)]
    pub devshell: Option<String>,
}

/// Window manager overlay configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WmConfig {
    /// Characters used for Vimium-style window hints (each char = one hint key).
    pub hint_keys: String,
    /// Delay (ms) before transitioning from border-only to full overlay.
    pub overlay_delay_ms: u32,
    /// Delay (ms) after activation before dismissing the overlay.
    pub activation_delay_ms: u32,
    /// Border width (px) for the focused window indicator.
    pub border_width: f32,
    /// Border color as hex (e.g., "#89b4fa").
    pub border_color: String,
    /// Background overlay color (hex, with optional alpha: "#RRGGBBAA").
    pub background_color: String,
    /// Card background color (hex).
    pub card_color: String,
    /// Primary text color (hex).
    pub text_color: String,
    /// Hint badge color (hex).
    pub hint_color: String,
    /// Matched hint badge color (hex).
    pub hint_matched_color: String,
    /// Quick-switch threshold in ms -- Alt+Tab released within this time
    /// activates the previous window instantly (v1 default: 250ms).
    pub quick_switch_threshold_ms: u32,
    /// Per-key app bindings for hint assignment and launch-or-focus.
    #[serde(default)]
    pub key_bindings: BTreeMap<String, WmKeyBinding>,
    /// Show window titles in the overlay.
    pub show_title: bool,
    /// Show app IDs in the overlay.
    pub show_app_id: bool,
    /// Maximum windows visible in the overlay list.
    pub max_visible_windows: u32,
}

impl Default for WmConfig {
    fn default() -> Self {
        Self {
            hint_keys: "asdfghjkl".into(),
            overlay_delay_ms: 150,
            activation_delay_ms: 200,
            border_width: 4.0,
            border_color: "#89b4fa".into(),
            background_color: "#000000c8".into(),
            card_color: "#1e1e1ef0".into(),
            text_color: "#ffffff".into(),
            hint_color: "#646464".into(),
            hint_matched_color: "#4caf50".into(),
            quick_switch_threshold_ms: 250,
            key_bindings: [
                ("g", vec!["ghostty", "com.mitchellh.ghostty"], Some("ghostty")),
                ("f", vec!["firefox", "org.mozilla.firefox"], Some("firefox")),
                ("e", vec!["microsoft-edge"], Some("microsoft-edge")),
                ("c", vec!["chromium", "google-chrome"], None),
                ("v", vec!["code", "Code", "cursor", "Cursor"], Some("code")),
                ("n", vec!["nautilus", "org.gnome.Nautilus"], Some("nautilus")),
                ("s", vec!["slack", "Slack"], Some("slack")),
                ("d", vec!["discord", "Discord"], Some("discord")),
                ("m", vec!["spotify"], Some("spotify")),
                ("t", vec!["thunderbird"], Some("thunderbird")),
            ]
            .into_iter()
            .map(|(k, apps, launch)| {
                (
                    k.to_string(),
                    WmKeyBinding {
                        apps: apps.into_iter().map(String::from).collect(),
                        launch: launch.map(String::from),
                        tags: Vec::new(),
                    },
                )
            })
            .collect(),
            show_title: true,
            show_app_id: false,
            max_visible_windows: 20,
        }
    }
}

/// Launcher configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LauncherConfig {
    /// Maximum results to display.
    pub max_results: usize,
    /// Enable frecency-based ranking.
    pub frecency: bool,
}

impl Default for LauncherConfig {
    fn default() -> Self {
        Self {
            max_results: 20,
            frecency: true,
        }
    }
}

/// Audit log configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging for this profile.
    pub enabled: bool,
    /// Retention period (days).
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 90,
        }
    }
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

// ============================================================================
// Cryptographic Algorithm Configuration
// ============================================================================

/// TOML-level cryptographic algorithm configuration.
///
/// String-based for human-readable config files. Use `to_typed()` to convert
/// to the validated `core_types::CryptoConfig` with enum variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CryptoConfigToml {
    /// Key derivation function: "argon2id" or "pbkdf2-sha256".
    pub kdf: String,
    /// HKDF algorithm: "blake3" or "hkdf-sha256".
    pub hkdf: String,
    /// Noise cipher: "chacha-poly" or "aes-gcm".
    pub noise_cipher: String,
    /// Noise hash: "blake2s" or "sha256".
    pub noise_hash: String,
    /// Audit hash: "blake3" or "sha256".
    pub audit_hash: String,
    /// Minimum crypto profile accepted from peers: "leading-edge", "governance-compatible", "custom".
    pub minimum_peer_profile: String,
}

impl Default for CryptoConfigToml {
    fn default() -> Self {
        Self {
            kdf: "argon2id".into(),
            hkdf: "blake3".into(),
            noise_cipher: "chacha-poly".into(),
            noise_hash: "blake2s".into(),
            audit_hash: "blake3".into(),
            minimum_peer_profile: "leading-edge".into(),
        }
    }
}

impl CryptoConfigToml {
    /// Convert to the validated typed representation.
    ///
    /// # Errors
    ///
    /// Returns an error if any algorithm name is unrecognized.
    pub fn to_typed(&self) -> core_types::Result<core_types::CryptoConfig> {
        let kdf = match self.kdf.as_str() {
            "argon2id" => core_types::KdfAlgorithm::Argon2id,
            "pbkdf2-sha256" => core_types::KdfAlgorithm::Pbkdf2Sha256,
            other => return Err(core_types::Error::Config(format!("unknown kdf: {other}"))),
        };
        let hkdf = match self.hkdf.as_str() {
            "blake3" => core_types::HkdfAlgorithm::Blake3,
            "hkdf-sha256" => core_types::HkdfAlgorithm::HkdfSha256,
            other => return Err(core_types::Error::Config(format!("unknown hkdf: {other}"))),
        };
        let noise_cipher = match self.noise_cipher.as_str() {
            "chacha-poly" => core_types::NoiseCipher::ChaChaPoly,
            "aes-gcm" => core_types::NoiseCipher::AesGcm,
            other => return Err(core_types::Error::Config(format!("unknown noise_cipher: {other}"))),
        };
        let noise_hash = match self.noise_hash.as_str() {
            "blake2s" => core_types::NoiseHash::Blake2s,
            "sha256" => core_types::NoiseHash::Sha256,
            other => return Err(core_types::Error::Config(format!("unknown noise_hash: {other}"))),
        };
        let audit_hash = match self.audit_hash.as_str() {
            "blake3" => core_types::AuditHash::Blake3,
            "sha256" => core_types::AuditHash::Sha256,
            other => return Err(core_types::Error::Config(format!("unknown audit_hash: {other}"))),
        };
        let minimum_peer_profile = match self.minimum_peer_profile.as_str() {
            "leading-edge" => core_types::CryptoProfile::LeadingEdge,
            "governance-compatible" => core_types::CryptoProfile::GovernanceCompatible,
            "custom" => core_types::CryptoProfile::Custom,
            other => return Err(core_types::Error::Config(format!("unknown crypto profile: {other}"))),
        };
        Ok(core_types::CryptoConfig {
            kdf,
            hkdf,
            noise_cipher,
            noise_hash,
            audit_hash,
            minimum_peer_profile,
        })
    }
}

// ============================================================================
// Agent Configuration
// ============================================================================

/// Agent identity and authorization configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentsConfig {
    /// Default agent configuration applied when no specific agent matches.
    pub default: AgentConfig,
    /// Named agent configurations keyed by agent name.
    #[serde(default)]
    pub agents: BTreeMap<String, AgentConfig>,
}

/// Configuration for a single agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Agent type: "human", "ai", "service", "extension".
    pub agent_type: String,
    /// Default capabilities granted to this agent.
    pub default_capabilities: Vec<String>,
    /// Whether master password verification is required.
    pub require_master_password: bool,
    /// Unix UID constraint (process attestation).
    pub uid: Option<u32>,
    /// AI model family (for `agent_type` = "ai").
    pub model_family: Option<String>,
    /// Maximum delegation chain depth this agent can create.
    pub max_delegation_depth: Option<u8>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_type: "human".into(),
            default_capabilities: vec!["admin".into()],
            require_master_password: true,
            uid: None,
            model_family: None,
            max_delegation_depth: None,
        }
    }
}

// ============================================================================
// Installation Configuration
// ============================================================================

/// Installation identity stored in `installation.toml`.
///
/// Generated once at `sesame init` and never modified unless the user
/// explicitly re-initializes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationConfig {
    /// Unique installation identifier (UUID v4).
    pub id: Uuid,
    /// Derived namespace for deterministic ID generation.
    pub namespace: Uuid,
    /// Optional organizational namespace for enterprise deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgConfig>,
    /// Optional machine binding for hardware attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_binding: Option<MachineBindingConfig>,
}

/// Organizational namespace configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgConfig {
    /// Organization domain (e.g., "braincraft.io").
    pub domain: String,
    /// Deterministic namespace derived from domain.
    pub namespace: Uuid,
}

/// Machine binding configuration (serialized as hex strings in TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineBindingConfig {
    /// Hex-encoded hash of machine identity material.
    pub binding_hash: String,
    /// Binding method: "machine-id" or "tpm-bound".
    pub binding_type: String,
}

// ============================================================================
// Extensions Configuration
// ============================================================================

/// Extension system configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionsConfig {
    /// Extension security policy.
    pub policy: ExtensionsPolicyConfig,
}

/// Security policy for extension installation and execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionsPolicyConfig {
    /// Allowed OCI registries for extension installation.
    pub allowed_registries: Vec<String>,
    /// Blocked namespaces (deny list).
    pub blocked_namespaces: Vec<String>,
    /// Require cryptographic signature on extension manifests.
    pub require_signature: bool,
    /// Trusted signer public keys (hex-encoded).
    pub trusted_signers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_profile_deserializes_from_toml() {
        let toml_str = r#"
            env = { RUST_LOG = "debug", CARGO_HOME = "/workspace/.cargo" }
            secrets = ["github-token", "crates-io-token"]
            devshell = "/workspace/myproject#rust"
        "#;
        let lp: LaunchProfile = toml::from_str(toml_str).unwrap();
        assert_eq!(lp.env["RUST_LOG"], "debug");
        assert_eq!(lp.secrets, vec!["github-token", "crates-io-token"]);
        assert_eq!(lp.devshell.as_deref(), Some("/workspace/myproject#rust"));
    }

    #[test]
    fn launch_profile_defaults_empty() {
        let lp = LaunchProfile::default();
        assert!(lp.env.is_empty());
        assert!(lp.secrets.is_empty());
        assert!(lp.devshell.is_none());
    }

    #[test]
    fn wm_key_binding_with_tags() {
        let toml_str = r#"
            apps = ["ghostty"]
            launch = "ghostty"
            tags = ["dev-rust", "ai-tools"]
        "#;
        let kb: WmKeyBinding = toml::from_str(toml_str).unwrap();
        assert_eq!(kb.tags, vec!["dev-rust", "ai-tools"]);
    }

    #[test]
    fn wm_key_binding_without_tags_defaults_empty() {
        let toml_str = r#"
            apps = ["firefox"]
            launch = "firefox"
        "#;
        let kb: WmKeyBinding = toml::from_str(toml_str).unwrap();
        assert!(kb.tags.is_empty());
    }

    #[test]
    fn profile_config_without_launch_profiles_defaults_empty() {
        let pc = ProfileConfig::default();
        assert!(pc.launch_profiles.is_empty());
    }
}
