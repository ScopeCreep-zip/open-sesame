//! Configuration schema types
//!
//! Pure data types with no business logic.

use crate::core::LaunchCommand;
use crate::util::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

/// RGBA color with hex string serialization
///
/// Supports parsing from hex strings ("#RRGGBB" or "#RRGGBBAA") and serialization back to hex.
///
/// # Examples
///
/// ```
/// use open_sesame::config::Color;
///
/// // Parse from hex string
/// let color = Color::from_hex("#ff0000").unwrap();
/// assert_eq!(color.r, 255);
/// assert_eq!(color.g, 0);
/// assert_eq!(color.b, 0);
/// assert_eq!(color.a, 255);
///
/// // Create from components
/// let purple = Color::new(180, 160, 255, 180);
/// assert_eq!(purple.to_hex(), "#b4a0ffb4");
///
/// // Parse with alpha
/// let translucent = Color::from_hex("#00ff00b4").unwrap();
/// assert_eq!(translucent.a, 180);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Color {
    /// Red channel (0-255)
    pub r: u8,
    /// Green channel (0-255)
    pub g: u8,
    /// Blue channel (0-255)
    pub b: u8,
    /// Alpha channel (0-255, where 255 is fully opaque)
    pub a: u8,
}

impl Color {
    /// Create a new color from RGBA components
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Parses a color from hex string: "#RRGGBB" or "#RRGGBBAA".
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim_start_matches('#');
        match s.len() {
            6 => {
                let r = u8::from_str_radix(&s[0..2], 16).map_err(|_| Error::InvalidColor {
                    value: s.to_string(),
                })?;
                let g = u8::from_str_radix(&s[2..4], 16).map_err(|_| Error::InvalidColor {
                    value: s.to_string(),
                })?;
                let b = u8::from_str_radix(&s[4..6], 16).map_err(|_| Error::InvalidColor {
                    value: s.to_string(),
                })?;
                Ok(Self { r, g, b, a: 255 })
            }
            8 => {
                let r = u8::from_str_radix(&s[0..2], 16).map_err(|_| Error::InvalidColor {
                    value: s.to_string(),
                })?;
                let g = u8::from_str_radix(&s[2..4], 16).map_err(|_| Error::InvalidColor {
                    value: s.to_string(),
                })?;
                let b = u8::from_str_radix(&s[4..6], 16).map_err(|_| Error::InvalidColor {
                    value: s.to_string(),
                })?;
                let a = u8::from_str_radix(&s[6..8], 16).map_err(|_| Error::InvalidColor {
                    value: s.to_string(),
                })?;
                Ok(Self { r, g, b, a })
            }
            _ => Err(Error::InvalidColor {
                value: s.to_string(),
            }),
        }
    }

    /// Converts the color to a hex string with alpha channel.
    pub fn to_hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}{:02x}", self.r, self.g, self.b, self.a)
    }
}

impl Default for Color {
    fn default() -> Self {
        // Soft lavender-purple with ~70% opacity
        Self::new(180, 160, 255, 180) // #b4a0ffb4
    }
}

impl Serialize for Color {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&(*self).to_hex())
    }
}

impl<'de> Deserialize<'de> for Color {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Global settings for timing and appearance
///
/// Controls activation delays, UI appearance, and global environment variables.
///
/// # Examples
///
/// ```
/// use open_sesame::config::Settings;
///
/// let settings = Settings::default();
/// assert_eq!(settings.activation_delay, 200);
/// assert_eq!(settings.overlay_delay, 720);
/// assert_eq!(settings.quick_switch_threshold, 250);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Activation key combo for launching sesame (e.g., "super+space", "alt+tab")
    /// Used by --setup-keybinding to configure COSMIC shortcuts
    pub activation_key: String,

    /// Delay in ms before activating a match (allows typing gg, ggg)
    pub activation_delay: u64,

    /// Delay in ms before showing full overlay (0 = immediate)
    pub overlay_delay: u64,

    /// Quick switch threshold in ms - Alt+Tab released within this time = instant switch to previous window
    pub quick_switch_threshold: u64,

    /// Border width in pixels for focus indicator
    pub border_width: f32,

    /// Border color for focus indicator (hex: "#RRGGBB" or "#RRGGBBAA")
    pub border_color: Color,

    /// Background overlay color
    pub background_color: Color,

    /// Card background color
    pub card_color: Color,

    /// Text color
    pub text_color: Color,

    /// Hint badge color
    pub hint_color: Color,

    /// Matched hint color
    pub hint_matched_color: Color,

    /// Global env files loaded for all launches (direnv .env style)
    #[serde(default)]
    pub env_files: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            activation_key: "alt+space".to_string(),
            activation_delay: 200,
            overlay_delay: 720,
            quick_switch_threshold: 250,
            border_width: 3.0,
            border_color: Color::default(),
            background_color: Color::new(0, 0, 0, 200),
            card_color: Color::new(30, 30, 30, 240),
            text_color: Color::new(255, 255, 255, 255),
            hint_color: Color::new(100, 100, 100, 255),
            hint_matched_color: Color::new(76, 175, 80, 255),
            env_files: Vec::new(),
        }
    }
}

/// Launch configuration - supports simple command string or advanced config
///
/// Provides two forms: simple (just a command string) and advanced (with args, env files, and env vars).
///
/// # Examples
///
/// ## Simple Launch
///
/// ```
/// use open_sesame::config::LaunchConfig;
///
/// let simple = LaunchConfig::Simple("firefox".to_string());
/// assert_eq!(simple.command(), "firefox");
/// assert!(simple.args().is_empty());
/// ```
///
/// ## Advanced Launch
///
/// ```
/// use open_sesame::config::LaunchConfig;
/// use std::collections::HashMap;
///
/// let mut env = HashMap::new();
/// env.insert("EDITOR".to_string(), "vim".to_string());
///
/// let advanced = LaunchConfig::Advanced {
///     command: "ghostty".to_string(),
///     args: vec!["--config".to_string(), "custom.toml".to_string()],
///     env_files: vec!["~/.config/ghostty/.env".to_string()],
///     env,
/// };
///
/// assert_eq!(advanced.command(), "ghostty");
/// assert_eq!(advanced.args().len(), 2);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LaunchConfig {
    /// Simple command: `launch = "ghostty"`
    Simple(String),
    /// Advanced config with args and env
    Advanced {
        /// Command to run (binary name or full path)
        command: String,
        /// Arguments to pass to the command
        #[serde(default)]
        args: Vec<String>,
        /// Env files to load (direnv .env style, paths expanded)
        #[serde(default)]
        env_files: Vec<String>,
        /// Environment variables to set for the process
        #[serde(default)]
        env: HashMap<String, String>,
    },
}

impl LaunchConfig {
    /// Returns the command to execute.
    pub fn command(&self) -> &str {
        match self {
            LaunchConfig::Simple(cmd) => cmd,
            LaunchConfig::Advanced { command, .. } => command,
        }
    }

    /// Returns command arguments (empty for simple config).
    pub fn args(&self) -> &[String] {
        match self {
            LaunchConfig::Simple(_) => &[],
            LaunchConfig::Advanced { args, .. } => args,
        }
    }

    /// Returns environment files to load (empty for simple config).
    pub fn env_files(&self) -> &[String] {
        match self {
            LaunchConfig::Simple(_) => &[],
            LaunchConfig::Advanced { env_files, .. } => env_files,
        }
    }

    /// Returns explicit environment variables.
    pub fn env(&self) -> HashMap<String, String> {
        match self {
            LaunchConfig::Simple(_) => HashMap::new(),
            LaunchConfig::Advanced { env, .. } => env.clone(),
        }
    }

    /// Converts to a LaunchCommand for execution.
    pub fn to_launch_command(&self) -> LaunchCommand {
        match self {
            LaunchConfig::Simple(cmd) => LaunchCommand::simple(cmd),
            LaunchConfig::Advanced {
                command,
                args,
                env_files,
                env,
            } => LaunchCommand::advanced(command, args.clone(), env_files.clone(), env.clone()),
        }
    }
}

/// Configuration for a single key binding
///
/// Associates a key with application IDs and an optional launch command.
///
/// # Examples
///
/// ```
/// use open_sesame::config::{KeyBinding, LaunchConfig};
///
/// let binding = KeyBinding {
///     apps: vec!["firefox".to_string(), "org.mozilla.firefox".to_string()],
///     launch: Some(LaunchConfig::Simple("firefox".to_string())),
/// };
///
/// assert_eq!(binding.apps.len(), 2);
/// assert!(binding.launch.is_some());
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyBinding {
    /// App IDs that match this key
    #[serde(default)]
    pub apps: Vec<String>,

    /// Launch config if no matching window exists
    #[serde(default)]
    pub launch: Option<LaunchConfig>,
}

/// Main configuration structure
///
/// Provides global settings and per-key bindings for application focus/launch behavior.
///
/// # Examples
///
/// ```no_run
/// use open_sesame::Config;
///
/// # fn main() -> Result<(), open_sesame::Error> {
/// // Load from default XDG paths
/// let config = Config::load()?;
/// println!("Activation key: {}", config.settings.activation_key);
///
/// // Check key binding for an application
/// if let Some(key) = config.key_for_app("firefox") {
///     println!("Firefox is bound to: {}", key);
/// }
///
/// // Get launch command for a key
/// if let Some(launch) = config.launch_config("g") {
///     println!("Key 'g' launches: {}", launch.command());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Global settings
    pub settings: Settings,

    /// Key bindings: letter -> binding config
    #[serde(default)]
    pub keys: HashMap<String, KeyBinding>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            keys: default_keys(),
        }
    }
}

impl Config {
    /// Returns the key binding character for an app_id.
    pub fn key_for_app(&self, app_id: &str) -> Option<char> {
        let app_lower = app_id.to_lowercase();
        let app_last_segment = app_id.split('.').next_back().map(|s| s.to_lowercase());

        for (key, binding) in &self.keys {
            for pattern in &binding.apps {
                // Exact match
                if pattern == app_id {
                    return key.chars().next();
                }
                // Case-insensitive match
                if pattern.to_lowercase() == app_lower {
                    return key.chars().next();
                }
                // Last segment match (e.g., "ghostty" matches "com.mitchellh.ghostty")
                if let Some(ref last) = app_last_segment
                    && pattern.to_lowercase() == *last
                {
                    return key.chars().next();
                }
            }
        }
        None
    }

    /// Returns the launch config for a key.
    pub fn launch_config(&self, key: &str) -> Option<&LaunchConfig> {
        self.keys.get(key).and_then(|b| b.launch.as_ref())
    }

    /// Serializes configuration to TOML string.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Other(e.to_string()))
    }

    /// Generates default TOML configuration string.
    pub fn default_toml() -> String {
        let default = Config::default();
        toml::to_string_pretty(&default).unwrap_or_default()
    }

    /// Loads configuration from default XDG paths.
    pub fn load() -> Result<Self> {
        crate::config::load_config()
    }
}

/// Generates default key bindings.
fn default_keys() -> HashMap<String, KeyBinding> {
    [
        (
            "g",
            &["ghostty", "com.mitchellh.ghostty"][..],
            Some("ghostty"),
        ),
        (
            "f",
            &["firefox", "org.mozilla.firefox"][..],
            Some("firefox"),
        ),
        ("e", &["microsoft-edge"][..], Some("microsoft-edge")),
        ("c", &["chromium", "google-chrome"][..], None),
        ("v", &["code", "Code", "cursor", "Cursor"][..], Some("code")),
        (
            "n",
            &["nautilus", "org.gnome.Nautilus"][..],
            Some("nautilus"),
        ),
        ("s", &["slack", "Slack"][..], Some("slack")),
        ("d", &["discord", "Discord"][..], Some("discord")),
        ("m", &["spotify"][..], Some("spotify")),
        ("t", &["thunderbird"][..], Some("thunderbird")),
    ]
    .into_iter()
    .map(|(key, apps, launch)| {
        (
            key.to_string(),
            KeyBinding {
                apps: apps.iter().map(|s| s.to_string()).collect(),
                launch: launch.map(|cmd| LaunchConfig::Simple(cmd.to_string())),
            },
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_hex_parse() {
        let c = Color::from_hex("#ff0000").unwrap();
        assert_eq!(c, Color::new(255, 0, 0, 255));

        let c = Color::from_hex("#00ff00ff").unwrap();
        assert_eq!(c, Color::new(0, 255, 0, 255));

        let c = Color::from_hex("63a4ffb4").unwrap();
        assert_eq!(c, Color::new(99, 164, 255, 180));
    }

    #[test]
    fn test_color_hex_roundtrip() {
        let c = Color::new(99, 164, 255, 180);
        assert_eq!(c.to_hex(), "#63a4ffb4");
        assert_eq!(Color::from_hex(&c.to_hex()).unwrap(), c);
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.keys.is_empty());
        assert_eq!(config.settings.activation_delay, 200);
    }

    #[test]
    fn test_key_for_app() {
        let config = Config::default();
        assert_eq!(config.key_for_app("ghostty"), Some('g'));
        assert_eq!(config.key_for_app("com.mitchellh.ghostty"), Some('g'));
        assert_eq!(config.key_for_app("Ghostty"), Some('g'));
        assert_eq!(config.key_for_app("unknown-app"), None);
    }

    #[test]
    fn test_launch_config_simple() {
        let config = Config::default();
        let launch = config.launch_config("g").unwrap();
        assert_eq!(launch.command(), "ghostty");
        assert!(launch.args().is_empty());
    }
}
