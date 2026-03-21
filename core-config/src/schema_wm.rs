//! Window manager overlay and launch profile configuration types.
//!
//! Consumed by daemon-wm and daemon-launcher.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// Additional CLI arguments to pass to the launched command.
    #[serde(default)]
    pub launch_args: Vec<String>,
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
    /// Working directory for the launched process. If multiple tags specify `cwd`,
    /// the last tag wins (same merge semantics as `devshell`).
    #[serde(default)]
    pub cwd: Option<String>,
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
                (
                    "g",
                    vec!["ghostty", "com.mitchellh.ghostty"],
                    Some("ghostty"),
                ),
                ("f", vec!["firefox", "org.mozilla.firefox"], Some("firefox")),
                ("e", vec!["microsoft-edge"], Some("microsoft-edge")),
                ("c", vec!["chromium", "google-chrome"], None),
                ("v", vec!["code", "Code", "cursor", "Cursor"], Some("code")),
                (
                    "n",
                    vec!["nautilus", "org.gnome.Nautilus"],
                    Some("nautilus"),
                ),
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
                        launch_args: Vec::new(),
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
    fn wm_key_binding_with_launch_args() {
        let toml_str = r#"
            apps = ["ghostty"]
            launch = "ghostty"
            launch_args = ["--working-directory=/workspace/user/github.com/org/repo"]
        "#;
        let kb: WmKeyBinding = toml::from_str(toml_str).unwrap();
        assert_eq!(
            kb.launch_args,
            vec!["--working-directory=/workspace/user/github.com/org/repo"]
        );
    }

    #[test]
    fn launch_profile_with_cwd() {
        let toml_str = r#"
            env = { RUST_LOG = "debug" }
            secrets = ["github-token"]
            cwd = "/workspace/usrbinkat/github.com/org/repo"
        "#;
        let lp: LaunchProfile = toml::from_str(toml_str).unwrap();
        assert_eq!(
            lp.cwd.as_deref(),
            Some("/workspace/usrbinkat/github.com/org/repo")
        );
    }
}
