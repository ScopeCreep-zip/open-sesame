//! Workspace configuration file I/O.
//!
//! Handles reading and writing `~/.config/pds/workspaces.toml` with
//! drop-in fragment merging from `~/.config/pds/workspaces.d/*.toml`.

use crate::loader::{atomic_write, config_dir};

/// Load workspace configuration from `~/.config/pds/workspaces.toml`.
///
/// Merges drop-in fragments from `~/.config/pds/workspaces.d/*.toml`
/// (alphabetical order). Fragment links extend/override base links.
///
/// Returns a default config if the file does not exist.
///
/// # Errors
///
/// Returns an error string if the file exists but cannot be read or parsed.
pub fn load_workspace_config() -> Result<crate::schema::WorkspaceConfig, String> {
    let path = config_dir().join("workspaces.toml");
    let mut config = if path.exists() {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        toml::from_str(&contents).map_err(|e| format!("failed to parse {}: {e}", path.display()))?
    } else {
        crate::schema::WorkspaceConfig::default()
    };

    // Merge drop-in fragments from workspaces.d/
    let dropin_dir = config_dir().join("workspaces.d");
    if dropin_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&dropin_dir)
    {
        let mut fragments: Vec<std::path::PathBuf> = entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        fragments.sort();
        for frag_path in fragments {
            let contents = std::fs::read_to_string(&frag_path)
                .map_err(|e| format!("failed to read {}: {e}", frag_path.display()))?;
            let fragment: crate::schema::WorkspaceConfig = toml::from_str(&contents)
                .map_err(|e| format!("failed to parse {}: {e}", frag_path.display()))?;
            config.links.extend(fragment.links);
            let defaults = crate::schema::WorkspaceSettings::default();
            if fragment.settings.root != defaults.root {
                config.settings.root = fragment.settings.root;
            }
            if fragment.settings.user != defaults.user {
                config.settings.user = fragment.settings.user;
            }
        }
    }

    Ok(config)
}

/// Save workspace configuration atomically to `~/.config/pds/workspaces.toml`.
///
/// # Errors
///
/// Returns an error string if serialization or file I/O fails.
pub fn save_workspace_config(config: &crate::schema::WorkspaceConfig) -> Result<(), String> {
    let path = config_dir().join("workspaces.toml");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let contents = toml::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize workspace config: {e}"))?;
    atomic_write(&path, contents.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}
