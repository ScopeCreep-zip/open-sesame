//! Configuration loading and file I/O.
//!
//! Core config loading, layer merging, and filesystem utilities live here.
//! Installation and workspace I/O are in sibling modules and re-exported.

use crate::schema::Config;
use std::path::{Path, PathBuf};

// Re-export installation and workspace I/O for stable downstream paths.
pub use crate::loader_installation::{installation_path, load_installation, write_installation};
pub use crate::loader_workspace::{load_workspace_config, save_workspace_config};

/// Return the platform-appropriate PDS config directory.
#[must_use]
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("pds")
}

/// Resolve all config paths in loading order (lowest to highest priority).
///
/// 1. System policy (`/etc/pds/policy.toml` on Linux)
/// 2. User config (`~/.config/pds/config.toml`)
/// 3. Drop-in fragments (`~/.config/pds/config.d/*.toml`, alphabetical)
/// 4. Profile overrides (`~/.config/pds/profiles/{name}/config.toml`)
#[must_use]
pub fn resolve_config_paths(profile_name: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // System policy (Linux only for now)
    #[cfg(target_os = "linux")]
    {
        let system = PathBuf::from("/etc/pds/policy.toml");
        if system.exists() {
            paths.push(system);
        }
    }

    let base = config_dir();

    // User config
    let user_config = base.join("config.toml");
    if user_config.exists() {
        paths.push(user_config);
    }

    // Drop-in fragments (sorted alphabetically)
    let dropin_dir = base.join("config.d");
    if dropin_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&dropin_dir)
    {
        let mut fragments: Vec<PathBuf> = entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        fragments.sort();
        paths.extend(fragments);
    }

    // Profile overrides
    if let Some(name) = profile_name {
        let profile_config = base.join("profiles").join(name).join("config.toml");
        if profile_config.exists() {
            paths.push(profile_config);
        }
    }

    paths
}

/// Load configuration by merging all layers.
///
/// Layers are applied in order: compiled defaults, then each file from
/// `resolve_config_paths` (lowest to highest priority). Higher-priority
/// values override lower-priority ones via TOML deep merge.
///
/// # Errors
///
/// Returns an error if any config file contains invalid TOML or fails
/// schema validation.
pub fn load_config(profile_name: Option<&str>) -> core_types::Result<Config> {
    let mut config = Config::default();
    let paths = resolve_config_paths(profile_name);

    for path in &paths {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            core_types::Error::Config(format!("failed to read {}: {e}", path.display()))
        })?;
        let layer: Config = toml::from_str(&contents).map_err(|e| {
            core_types::Error::Config(format!("failed to parse {}: {e}", path.display()))
        })?;
        merge_config(&mut config, &layer);
    }

    Ok(config)
}

/// Deep merge `overlay` into `base`. Non-default overlay values override base.
fn merge_config(base: &mut Config, overlay: &Config) {
    // Schema version: always take the higher
    if overlay.config_version > base.config_version {
        base.config_version = overlay.config_version;
    }

    // Global settings
    if overlay.global.default_profile.as_ref() != GlobalConfigDefaults::DEFAULT_PROFILE {
        base.global.default_profile = overlay.global.default_profile.clone();
    }

    // Profiles: overlay profiles merge into base by name
    for (name, profile) in &overlay.profiles {
        base.profiles
            .entry(name.clone())
            .and_modify(|existing| merge_profile(existing, profile))
            .or_insert_with(|| profile.clone());
    }

    // Policy: append (policies are additive)
    base.policy.extend(overlay.policy.iter().cloned());
}

fn merge_profile(base: &mut crate::schema::ProfileConfig, overlay: &crate::schema::ProfileConfig) {
    if overlay.extends.is_some() {
        base.extends.clone_from(&overlay.extends);
    }
    if overlay.color.is_some() {
        base.color.clone_from(&overlay.color);
    }
    if overlay.icon.is_some() {
        base.icon.clone_from(&overlay.icon);
    }
    // Sub-configs: merge non-default values
    if overlay.clipboard.max_history != crate::schema::ClipboardConfig::default().max_history {
        base.clipboard.max_history = overlay.clipboard.max_history;
    }
    if overlay.wm.hint_keys != crate::schema::WmConfig::default().hint_keys {
        base.wm.hint_keys.clone_from(&overlay.wm.hint_keys);
    }
    if overlay.wm.overlay_delay_ms != crate::schema::WmConfig::default().overlay_delay_ms {
        base.wm.overlay_delay_ms = overlay.wm.overlay_delay_ms;
    }
    if overlay.wm.max_visible_windows != crate::schema::WmConfig::default().max_visible_windows {
        base.wm.max_visible_windows = overlay.wm.max_visible_windows;
    }

    // Key bindings: overlay entries override matching keys, base entries preserved.
    for (key, binding) in &overlay.wm.key_bindings {
        base.wm.key_bindings.insert(key.clone(), binding.clone());
    }

    // Launch profiles: overlay entries override matching names, base entries preserved.
    for (name, lp) in &overlay.launch_profiles {
        base.launch_profiles.insert(name.clone(), lp.clone());
    }
}

/// Helpers for detecting default values.
struct GlobalConfigDefaults;
impl GlobalConfigDefaults {
    const DEFAULT_PROFILE: &str = core_types::DEFAULT_PROFILE_NAME;
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
#[must_use]
pub fn resolve_config_real_dirs(profile_name: Option<&str>) -> Vec<PathBuf> {
    let config_dir = config_dir();
    let canonical_config =
        std::fs::canonicalize(&config_dir).unwrap_or_else(|_| config_dir.clone());

    let mut real_dirs = std::collections::BTreeSet::new();

    // Resolve config file symlinks.
    let paths = resolve_config_paths(profile_name);
    for path in &paths {
        if let Ok(real) = std::fs::canonicalize(path)
            && let Some(parent) = real.parent()
        {
            let parent_path = parent.to_path_buf();
            if !parent_path.starts_with(&canonical_config) {
                real_dirs.insert(parent_path);
            }
        }
    }

    // Also resolve installation.toml in case it's a symlink.
    let install_path = installation_path();
    if let Ok(real) = std::fs::canonicalize(&install_path)
        && let Some(parent) = real.parent()
    {
        let parent_path = parent.to_path_buf();
        if !parent_path.starts_with(&canonical_config) {
            real_dirs.insert(parent_path);
        }
    }

    real_dirs.into_iter().collect()
}

/// Bootstrap required directories for PDS daemons.
///
/// Creates the config dir, runtime dir, and cache dir if they don't exist.
/// This makes directory creation application-owned rather than solely relying
/// on systemd tmpfiles.d or other init-system-specific mechanisms.
///
/// Should be called early in daemon startup, before config loading.
pub fn bootstrap_dirs() {
    let config = config_dir();
    let cache = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("~/.cache"))
        .join("open-sesame");

    for dir in [&config, &cache] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::warn!(path = %dir.display(), error = %e, "failed to create directory");
        }
    }

    // Runtime dir (%t/pds) — only on Linux where XDG_RUNTIME_DIR is set.
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let pds_runtime = PathBuf::from(runtime).join("pds");
        if let Err(e) = std::fs::create_dir_all(&pds_runtime) {
            tracing::warn!(path = %pds_runtime.display(), error = %e, "failed to create runtime directory");
        }
    }
}

/// Atomically write contents to a file using the POSIX rename pattern.
///
/// Writes to a temporary file in the same directory, calls `fsync`, then
/// atomically renames over the target. On failure, the original file is
/// untouched.
///
/// # Errors
///
/// Returns an I/O error if the write, sync, or rename fails.
pub fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        atomic_write(&path, b"hello = true\n").unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "hello = true\n");
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(&path, b"old").unwrap();
        atomic_write(&path, b"new").unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "new");
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
        let mut base = Config::default();
        let mut overlay = Config::default();
        overlay.profiles.insert(
            "work".into(),
            crate::schema::ProfileConfig {
                name: core_types::TrustProfileName::try_from("work").unwrap(),
                color: Some("#ff0000".into()),
                ..Default::default()
            },
        );
        merge_config(&mut base, &overlay);
        assert!(base.profiles.contains_key("work"));
        assert_eq!(base.profiles["work"].color.as_deref(), Some("#ff0000"));
    }

    #[test]
    fn merge_preserves_default_key_bindings() {
        let mut base = Config::default();
        base.profiles
            .insert("default".into(), crate::schema::ProfileConfig::default());
        let overlay = Config::default();
        merge_config(&mut base, &overlay);
        let default_wm = crate::schema::WmConfig::default();
        assert_eq!(
            base.profiles["default"].wm.key_bindings.len(),
            default_wm.key_bindings.len()
        );
    }

    #[test]
    fn merge_overlay_key_binding_overrides_default() {
        let mut base = Config::default();
        base.profiles
            .insert("default".into(), crate::schema::ProfileConfig::default());
        let mut overlay = Config::default();
        let mut overlay_profile = crate::schema::ProfileConfig::default();
        overlay_profile.wm.key_bindings.insert(
            "g".into(),
            crate::schema::WmKeyBinding {
                apps: vec!["custom-app".into()],
                launch: Some("custom-app".into()),
                tags: vec!["my-tag".into()],
                launch_args: Vec::new(),
            },
        );
        overlay.profiles.insert("default".into(), overlay_profile);
        merge_config(&mut base, &overlay);
        let binding = &base.profiles["default"].wm.key_bindings["g"];
        assert_eq!(binding.apps, vec!["custom-app"]);
        assert_eq!(binding.tags, vec!["my-tag"]);
    }

    #[test]
    fn merge_preserves_launch_profiles() {
        let mut base = Config::default();
        let mut base_profile = crate::schema::ProfileConfig::default();
        base_profile.launch_profiles.insert(
            "dev-rust".into(),
            crate::schema::LaunchProfile {
                env: [("RUST_LOG".into(), "debug".into())].into(),
                ..Default::default()
            },
        );
        base.profiles.insert("default".into(), base_profile);

        let mut overlay = Config::default();
        let mut overlay_profile = crate::schema::ProfileConfig::default();
        overlay_profile.launch_profiles.insert(
            "ai-tools".into(),
            crate::schema::LaunchProfile {
                secrets: vec!["anthropic-api-key".into()],
                ..Default::default()
            },
        );
        overlay.profiles.insert("default".into(), overlay_profile);

        merge_config(&mut base, &overlay);
        assert!(
            base.profiles["default"]
                .launch_profiles
                .contains_key("dev-rust")
        );
        assert!(
            base.profiles["default"]
                .launch_profiles
                .contains_key("ai-tools")
        );
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
