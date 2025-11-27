//! Configuration loading with XDG inheritance
//!
//! Loads configuration from multiple sources with proper merging.

use crate::config::schema::Config;
use crate::util::{Error, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Returns the XDG config home directory.
///
/// Falls back to $HOME/.config if XDG_CONFIG_HOME is not set.
/// Returns None if neither XDG_CONFIG_HOME nor HOME is available.
fn xdg_config_home() -> Option<PathBuf> {
    dirs::config_dir().or_else(|| {
        // Falls back to $HOME/.config (properly expanded, not literal "~")
        dirs::home_dir().map(|h| h.join(".config"))
    })
}

/// Returns the system config directory.
fn system_config_dir() -> PathBuf {
    PathBuf::from("/etc/open-sesame")
}

/// Returns the user config directory.
///
/// Returns None if HOME is not set (unusual but possible in containers).
pub fn user_config_dir() -> Option<PathBuf> {
    xdg_config_home().map(|c| c.join("open-sesame"))
}

/// Returns the user config file path.
///
/// Returns None if HOME is not set.
pub fn user_config_path() -> Option<PathBuf> {
    user_config_dir().map(|d| d.join("config.toml"))
}

/// Returns the user config.d directory path.
fn user_config_d_path() -> Option<PathBuf> {
    user_config_dir().map(|d| d.join("config.d"))
}

/// Performs deep merge of overlay config into base config.
fn deep_merge(base: &mut Config, overlay: Config) {
    let defaults = Config::default();

    // Merges settings (overriding if different from defaults)
    if overlay.settings.activation_key != defaults.settings.activation_key {
        base.settings.activation_key = overlay.settings.activation_key;
    }
    if overlay.settings.activation_delay != defaults.settings.activation_delay {
        base.settings.activation_delay = overlay.settings.activation_delay;
    }
    if overlay.settings.overlay_delay != defaults.settings.overlay_delay {
        base.settings.overlay_delay = overlay.settings.overlay_delay;
    }
    if overlay.settings.quick_switch_threshold != defaults.settings.quick_switch_threshold {
        base.settings.quick_switch_threshold = overlay.settings.quick_switch_threshold;
    }
    if overlay.settings.border_width != defaults.settings.border_width {
        base.settings.border_width = overlay.settings.border_width;
    }
    if overlay.settings.border_color != defaults.settings.border_color {
        base.settings.border_color = overlay.settings.border_color;
    }
    if overlay.settings.background_color != defaults.settings.background_color {
        base.settings.background_color = overlay.settings.background_color;
    }
    if overlay.settings.card_color != defaults.settings.card_color {
        base.settings.card_color = overlay.settings.card_color;
    }
    if overlay.settings.text_color != defaults.settings.text_color {
        base.settings.text_color = overlay.settings.text_color;
    }
    if overlay.settings.hint_color != defaults.settings.hint_color {
        base.settings.hint_color = overlay.settings.hint_color;
    }
    if overlay.settings.hint_matched_color != defaults.settings.hint_matched_color {
        base.settings.hint_matched_color = overlay.settings.hint_matched_color;
    }
    if !overlay.settings.env_files.is_empty() {
        base.settings.env_files = overlay.settings.env_files;
    }

    // Merges keys additively (overlay keys override or add to base)
    for (key, binding) in overlay.keys {
        base.keys.insert(key, binding);
    }
}

/// Merges config from TOML content string.
fn merge_from_content(base: &mut Config, content: &str, source: &str) -> Result<()> {
    let overlay: Config = toml::from_str(content)?;
    deep_merge(base, overlay);
    tracing::debug!("Merged config from {}", source);
    Ok(())
}

/// Merges config from file if it exists.
fn merge_config_file(base: &mut Config, path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(path).map_err(|source| Error::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;

    merge_from_content(base, &content, &path.display().to_string())?;
    Ok(true)
}

/// Reads config from stdin.
fn read_stdin() -> Result<String> {
    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;
    Ok(content)
}

/// Loads config from explicit paths (for --config flag).
///
/// Paths are canonicalized to resolve symlinks and relative components.
/// Only regular files are accepted (not directories or special files).
pub fn load_config_from_paths(paths: &[String]) -> Result<Config> {
    let mut config = Config::default();

    for path in paths {
        if path == "-" {
            let content = read_stdin()?;
            merge_from_content(&mut config, &content, "stdin")?;
            tracing::info!("Loaded config from stdin");
        } else {
            let path = PathBuf::from(path);
            if !path.exists() {
                return Err(Error::ConfigRead {
                    path: path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Config file not found",
                    ),
                });
            }

            // Canonicalizes path to resolve symlinks and relative components
            let canonical = path.canonicalize().map_err(|source| Error::ConfigRead {
                path: path.clone(),
                source,
            })?;

            // Ensures path is a regular file, not a directory or special file
            if !canonical.is_file() {
                return Err(Error::ConfigRead {
                    path: canonical,
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Path is not a regular file",
                    ),
                });
            }

            if merge_config_file(&mut config, &canonical)? {
                tracing::info!("Loaded config from {:?}", canonical);
            }
        }
    }

    Ok(config)
}

/// Loads configuration with XDG inheritance.
///
/// Load order (later overrides earlier):
/// 1. /etc/open-sesame/config.toml (system defaults)
/// 2. ~/.config/open-sesame/config.toml (user config)
/// 3. ~/.config/open-sesame/config.d/*.toml (user overrides, alphabetical)
pub fn load_config() -> Result<Config> {
    let mut config = Config::default();
    let mut loaded_any = false;

    // 1. System config
    let system_path = system_config_dir().join("config.toml");
    if merge_config_file(&mut config, &system_path)? {
        loaded_any = true;
        tracing::info!("Loaded system config: {:?}", system_path);
    }

    // 2. User config
    if let Some(user_path) = user_config_path()
        && merge_config_file(&mut config, &user_path)?
    {
        loaded_any = true;
        tracing::info!("Loaded user config: {:?}", user_path);
    }

    // 3. User config.d directory
    if let Some(config_d) = user_config_d_path()
        && config_d.exists()
        && config_d.is_dir()
    {
        let mut entries: Vec<_> = std::fs::read_dir(&config_d)
            .map_err(|source| Error::ConfigRead {
                path: config_d.clone(),
                source,
            })?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "toml")
                    .unwrap_or(false)
            })
            .collect();

        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            if merge_config_file(&mut config, &path)? {
                loaded_any = true;
                tracing::info!("Loaded config.d: {:?}", path);
            }
        }
    }

    if !loaded_any {
        tracing::debug!("No config files found, using defaults");
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_default_config() {
        // Should not fail even with no config files
        let config = load_config().unwrap();
        assert!(!config.keys.is_empty());
    }

    #[test]
    fn test_user_config_paths() {
        // These may return None in unusual environments (no HOME set)
        if let Some(dir) = user_config_dir() {
            assert!(dir.to_string_lossy().contains("open-sesame"));
        }

        if let Some(path) = user_config_path() {
            assert!(path.to_string_lossy().contains("config.toml"));
        }
    }
}
