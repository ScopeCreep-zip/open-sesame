//! Configuration schema types.

use core_types::SecretRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

    /// System policy overrides (read-only at runtime).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<PolicyOverride>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: 2,
            global: GlobalConfig::default(),
            profiles: BTreeMap::new(),
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
