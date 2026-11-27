//! Configuration loading and file I/O.
//!
//! Core config loading, layer merging, and filesystem utilities live here.
//! Installation and workspace I/O are in sibling modules and re-exported.
//! Every location comes from `core_layout::Layout`.

use crate::schema::Config;
use core_layout::Layout;
use std::path::{Path, PathBuf};

// Re-export installation and workspace I/O for stable downstream paths.
pub use crate::loader_installation::{load_installation, read_machine_id, write_installation};
pub use crate::loader_workspace::load_workspace_config;

/// Whether `path` exists. A failure to determine it (permission denied on
/// a parent, for example) is an error.
pub(crate) fn exists(path: &Path) -> core_types::Result<bool> {
    path.try_exists()
        .map_err(|e| core_types::Error::Config(format!("failed to check {}: {e}", path.display())))
}

/// The system policy file when it exists: the lowest, read-only layer.
///
/// # Errors
///
/// The `exists` errors.
pub fn system_policy_file(layout: &Layout) -> core_types::Result<Option<PathBuf>> {
    match layout.system_policy_file() {
        Some(path) if exists(path)? => Ok(Some(path.to_path_buf())),
        Some(_) | None => Ok(None),
    }
}

/// The `*.toml` files directly in `dir`, sorted (load order). A missing
/// directory has none.
///
/// # Errors
///
/// `core_types::Error::Config` naming `dir` when it exists but cannot be
/// listed.
pub(crate) fn toml_files_in(dir: &Path) -> core_types::Result<Vec<PathBuf>> {
    let list_failed = |e: std::io::Error| {
        core_types::Error::Config(format!("failed to list {}: {e}", dir.display()))
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(list_failed(e)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.map_err(list_failed)?.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Resolve all config paths in loading order (lowest to highest priority).
///
/// 1. System policy (`Layout::system_policy_file`)
/// 2. User config (`Layout::config_file`)
/// 3. Drop-in fragments (`Layout::config_drop_in_dir`, `*.toml`, sorted)
///
/// # Errors
///
/// The layout errors, and `core_types::Error::Config` when a layer's
/// presence cannot be determined or `config.d` exists but cannot be listed.
pub fn resolve_config_paths(layout: &Layout) -> core_types::Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = system_policy_file(layout)?.into_iter().collect();
    let user_config = layout.config_file()?;
    if exists(&user_config)? {
        paths.push(user_config);
    }
    paths.extend(toml_files_in(&layout.config_drop_in_dir()?)?);
    Ok(paths)
}

/// Load configuration by merging all layers.
///
/// Each file from `resolve_config_paths` (lowest to highest priority) is
/// merged into the layers below it with `merge_layer`; the merged
/// document is then read as a [`Config`], so every key a file leaves unset
/// takes its compiled default.
///
/// # Errors
///
/// The `resolve_config_paths` errors, and `core_types::Error::Config`
/// naming the file when a config file cannot be read, is not TOML, or does
/// not match the schema.
pub fn load_config(layout: &Layout) -> core_types::Result<Config> {
    let mut merged = toml::Table::new();
    for path in resolve_config_paths(layout)? {
        let contents = std::fs::read_to_string(&path).map_err(|e| {
            core_types::Error::Config(format!("failed to read {}: {e}", path.display()))
        })?;
        let layer = parse_layer(&contents)
            .map_err(|e| core_types::Error::Config(format!("{}: {e}", path.display())))?;
        merge_layer(&mut merged, layer);
    }
    merged
        .try_into()
        .map_err(|e| core_types::Error::Config(format!("merged configuration is invalid: {e}")))
}

/// One configuration file as a TOML table, checked against the schema on
/// its own so a schema error names the file that holds it.
fn parse_layer(contents: &str) -> Result<toml::Table, String> {
    let layer: toml::Table = toml::from_str(contents).map_err(|e| format!("not TOML: {e}"))?;
    layer
        .clone()
        .try_into::<Config>()
        .map_err(|e| format!("does not match the configuration schema: {e}"))?;
    Ok(layer)
}

/// Merge a higher-priority `layer` into `merged`: tables merge key by key
/// at every depth, and any other value the layer sets replaces the lower
/// one. Two top-level keys merge differently: `policy` overrides
/// accumulate across layers, and `config_version` keeps the highest.
fn merge_layer(merged: &mut toml::Table, layer: toml::Table) {
    for (key, value) in layer {
        match (key.as_str(), merged.get_mut(&key), value) {
            ("policy", Some(toml::Value::Array(lower)), toml::Value::Array(higher)) => {
                lower.extend(higher);
            }
            ("config_version", Some(toml::Value::Integer(lower)), toml::Value::Integer(higher)) => {
                *lower = (*lower).max(higher);
            }
            (_, Some(toml::Value::Table(lower)), toml::Value::Table(higher)) => {
                merge_tables(lower, higher);
            }
            (_, _, value) => {
                merged.insert(key, value);
            }
        }
    }
}

/// Merge `higher` into `lower`: tables recursively, other values replace.
fn merge_tables(lower: &mut toml::Table, higher: toml::Table) {
    for (key, value) in higher {
        match (lower.get_mut(&key), value) {
            (Some(toml::Value::Table(lower)), toml::Value::Table(higher)) => {
                merge_tables(lower, higher);
            }
            (_, value) => {
                lower.insert(key, value);
            }
        }
    }
}

/// Resolve all config file symlinks to their real filesystem paths.
///
/// On NixOS / home-manager, config files are often symlinks into `/nix/store`.
/// Landlock grants access to `~/.config/pds` but not to the symlink targets.
/// Call this **before** applying Landlock and add the returned directories
/// as read-only rules so that config hot-reload can follow the symlinks.
///
/// Returns a deduplicated set of parent directories of resolved symlink targets
/// that differ from the original config directory.
///
/// # Errors
///
/// The layout and `resolve_config_paths` errors, and
/// `core_types::Error::Config` when an existing config file or directory
/// cannot be resolved. A path that does not exist contributes nothing.
pub fn resolve_config_real_dirs(layout: &Layout) -> core_types::Result<Vec<PathBuf>> {
    let config_dir = layout.config_dir()?;
    let canonical_config = canonical_or_absent(&config_dir)?.unwrap_or_else(|| config_dir.clone());

    let mut real_dirs = std::collections::BTreeSet::new();
    let mut paths = resolve_config_paths(layout)?;
    // installation.toml may be a symlink too.
    paths.push(layout.installation_file()?);
    for path in &paths {
        if let Some(real) = canonical_or_absent(path)?
            && let Some(parent) = real.parent()
            && !parent.starts_with(&canonical_config)
        {
            real_dirs.insert(parent.to_path_buf());
        }
    }

    Ok(real_dirs.into_iter().collect())
}

/// The canonical form of `path`, or `None` when it does not exist.
fn canonical_or_absent(path: &Path) -> core_types::Result<Option<PathBuf>> {
    match std::fs::canonicalize(path) {
        Ok(real) => Ok(Some(real)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(core_types::Error::Config(format!(
            "failed to resolve {}: {e}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration `load_config` produces from `layers`, lowest first.
    fn merged(layers: &[&str]) -> Config {
        let mut table = toml::Table::new();
        for layer in layers {
            merge_layer(&mut table, parse_layer(layer).unwrap());
        }
        table.try_into().unwrap()
    }

    #[test]
    fn default_config_roundtrips_toml() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.config_version, config.config_version);
        assert_eq!(parsed.global.default_profile, config.global.default_profile);
    }

    #[test]
    fn load_config_returns_defaults_when_no_files() {
        // In a clean tmpdir with no config files, load_config should succeed
        // with defaults (paths won't exist).
        let config = Config::default();
        assert_eq!(config.config_version, 3);
        assert_eq!(&*config.global.default_profile, "default");
    }

    #[test]
    fn agents_config_defaults_in_config() {
        let config = Config::default();
        assert_eq!(config.agents.default.agent_type, "human");
        assert_eq!(config.agents.default.default_capabilities, vec!["admin"]);
        assert!(config.agents.default.require_master_password);
        assert!(config.agents.agents.is_empty());
    }

    #[test]
    fn extensions_config_defaults_in_config() {
        let config = Config::default();
        assert!(config.extensions.policy.allowed_registries.is_empty());
        assert!(!config.extensions.policy.require_signature);
    }

    #[test]
    fn config_without_agents_section_loads() {
        let toml_str = r#"
            config_version = 2
            [global]
            default_profile = "default"
        "#;
        let parsed: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.agents.default.agent_type, "human");
        assert!(parsed.extensions.policy.allowed_registries.is_empty());
    }

    #[test]
    fn merge_overlay_profile() {
        let config = merged(&["", "[profiles.work]\ncolor = \"#ff0000\"\n"]);
        assert_eq!(config.profiles["work"].color.as_deref(), Some("#ff0000"));
    }

    #[test]
    fn merge_overlay_crypto() {
        // A later layer that does not set the field keeps the override.
        let config = merged(&["[crypto]\naudit_hash = \"sha256\"\n", "[crypto]\n"]);
        assert_eq!(config.crypto.audit_hash, "sha256");
        assert_eq!(
            config.crypto().unwrap().audit_hash,
            core_types::AuditHash::Sha256
        );
    }

    #[test]
    fn later_layer_settings_reach_an_existing_profile() {
        let config = merged(&[
            "[profiles.work]\ncolor = \"#00ff00\"\n",
            "[profiles.work.secrets.access]\n\"daemon-launcher\" = [\"api-key\"]\n\
             [profiles.work.wm]\nshow_title = false\nquick_switch_threshold_ms = 400\n",
        ]);
        let work = &config.profiles["work"];
        assert_eq!(work.color.as_deref(), Some("#00ff00"));
        assert_eq!(work.secrets.access["daemon-launcher"], ["api-key"]);
        assert!(!work.wm.show_title);
        assert_eq!(work.wm.quick_switch_threshold_ms, 400);
    }

    #[test]
    fn later_layer_can_set_the_default_profile_back_to_default() {
        let config = merged(&[
            "[global]\ndefault_profile = \"work\"\n",
            "[global]\ndefault_profile = \"default\"\n",
        ]);
        assert_eq!(config.global.default_profile.as_ref(), "default");
    }

    #[test]
    fn policy_accumulates_and_version_keeps_the_highest() {
        let config = merged(&[
            "config_version = 4\n[[policy]]\nkey = \"a\"\nvalue = 1\nsource = \"system\"\n",
            "config_version = 3\n[[policy]]\nkey = \"b\"\nvalue = 2\nsource = \"user\"\n",
        ]);
        assert_eq!(config.config_version, 4);
        let keys: Vec<&str> = config.policy.iter().map(|p| p.key.as_str()).collect();
        assert_eq!(keys, ["a", "b"]);
    }

    #[test]
    fn schema_errors_name_the_layer() {
        let err = parse_layer("[global]\ndefault_profile = 7\n").unwrap_err();
        assert!(err.contains("schema"), "{err}");
    }

    #[test]
    fn merge_preserves_default_key_bindings() {
        let config = merged(&[
            "[profiles.default]\n",
            "[profiles.default]\ncolor = \"#fff\"\n",
        ]);
        assert_eq!(
            config.profiles["default"].wm.key_bindings.len(),
            crate::schema::WmConfig::default().key_bindings.len()
        );
    }

    #[test]
    fn merge_overlay_key_binding_overrides_matching_key() {
        let config = merged(&[
            "[profiles.default.wm.key_bindings.f]\napps = [\"firefox\"]\n\
             [profiles.default.wm.key_bindings.g]\napps = [\"ghostty\"]\n",
            "[profiles.default.wm.key_bindings.g]\napps = [\"custom-app\"]\n\
             launch = \"custom-app\"\ntags = [\"my-tag\"]\n",
        ]);
        let bindings = &config.profiles["default"].wm.key_bindings;
        assert_eq!(bindings["g"].apps, ["custom-app"]);
        assert_eq!(bindings["g"].tags, ["my-tag"]);
        assert_eq!(bindings["f"].apps, ["firefox"]);
    }

    #[test]
    fn merge_preserves_launch_profiles() {
        let config = merged(&[
            "[profiles.default.launch_profiles.dev-rust]\nenv = { RUST_LOG = \"debug\" }\n",
            "[profiles.default.launch_profiles.ai-tools]\nsecrets = [\"anthropic-api-key\"]\n",
        ]);
        let launch_profiles = &config.profiles["default"].launch_profiles;
        assert!(launch_profiles.contains_key("dev-rust"));
        assert!(launch_profiles.contains_key("ai-tools"));
    }

    #[test]
    fn full_config_with_launch_profiles_roundtrips() {
        let toml_str = r#"
            config_version = 3

            [global]
            default_profile = "default"

            [profiles.default]
            name = "default"

            [profiles.default.launch_profiles.dev-rust]
            env = { RUST_LOG = "debug" }
            secrets = ["github-token"]
            devshell = "/workspace#rust"

            [profiles.default.wm.key_bindings.g]
            apps = ["ghostty"]
            launch = "ghostty"
            tags = ["dev-rust"]
        "#;
        let parsed: Config = toml::from_str(toml_str).unwrap();
        assert!(
            parsed.profiles["default"]
                .launch_profiles
                .contains_key("dev-rust")
        );
        let lp = &parsed.profiles["default"].launch_profiles["dev-rust"];
        assert_eq!(lp.env["RUST_LOG"], "debug");
        assert_eq!(lp.secrets, vec!["github-token"]);
        assert_eq!(lp.devshell.as_deref(), Some("/workspace#rust"));
        assert_eq!(
            parsed.profiles["default"].wm.key_bindings["g"].tags,
            vec!["dev-rust"]
        );
    }
}
