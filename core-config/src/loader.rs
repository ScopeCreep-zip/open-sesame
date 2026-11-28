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

/// The configuration error of `path`: `<path>: <detail>`. Every
/// configuration file error is built here, so each names its file the same
/// way.
pub(crate) fn path_error(path: &Path, detail: impl std::fmt::Display) -> core_types::Error {
    core_types::Error::Config(format!("{}: {detail}", path.display()))
}

/// Whether `path` exists. A failure to determine it (permission denied on
/// a parent, for example) is an error.
pub(crate) fn exists(path: &Path) -> core_types::Result<bool> {
    path.try_exists()
        .map_err(|e| path_error(path, format!("cannot check: {e}")))
}

/// The bytes of `path`, `None` when it does not exist; a file that exists
/// but cannot be read is an error, never absent.
pub(crate) fn read_optional(path: &Path) -> core_types::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(path_error(path, format!("cannot read: {e}"))),
    }
}

/// `bytes`, read from `path`, as UTF-8 text.
pub(crate) fn utf8<'b>(path: &Path, bytes: &'b [u8]) -> core_types::Result<&'b str> {
    std::str::from_utf8(bytes).map_err(|e| path_error(path, format!("not UTF-8: {e}")))
}

/// The entries directly in `dir`, sorted. A missing directory has none.
///
/// # Errors
///
/// `core_types::Error::Config` naming `dir` when it exists but cannot be
/// listed.
pub(crate) fn entries(dir: &Path) -> core_types::Result<Vec<PathBuf>> {
    let list_failed = |e: std::io::Error| path_error(dir, format!("cannot list: {e}"));
    let listing = match std::fs::read_dir(dir) {
        Ok(listing) => listing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(list_failed(e)),
    };
    let mut paths = listing
        .map(|entry| entry.map(|entry| entry.path()).map_err(list_failed))
        .collect::<core_types::Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

/// The `*.toml` files directly in `dir`, sorted (load order).
///
/// # Errors
///
/// The [`entries`] errors.
pub(crate) fn toml_files_in(dir: &Path) -> core_types::Result<Vec<PathBuf>> {
    Ok(entries(dir)?
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect())
}

/// The configuration layers of a layout, whether or not each exists yet:
/// the one definition the loader, the editor (`crate::edit`), and the
/// watcher (`crate::watcher`) derive their layer sets from.
pub(crate) struct LayerSpec {
    layout: Layout,
    /// The system policy file, the lowest and read-only layer; `None` on
    /// platforms without one.
    pub(crate) policy: Option<PathBuf>,
    /// The user configuration file.
    pub(crate) user: PathBuf,
    /// The drop-in directory: its `*.toml` files, sorted, load last.
    pub(crate) drop_in_dir: PathBuf,
    profiles_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layer {
    pub(crate) path: PathBuf,
    pub(crate) writable: bool,
    /// An override is confined to this profile; it cannot change globals.
    profile: Option<core_types::TrustProfileName>,
}

impl LayerSpec {
    /// The layers of `layout`.
    ///
    /// # Errors
    ///
    /// The layout errors.
    pub(crate) fn of(layout: &Layout) -> core_types::Result<Self> {
        Ok(Self {
            layout: layout.clone(),
            policy: layout.system_policy_file().map(Path::to_path_buf),
            user: layout.config_file()?,
            drop_in_dir: layout.config_drop_in_dir()?,
            profiles_dir: Some(layout.profiles_dir()?),
        })
    }

    pub(crate) fn workspace(layout: &Layout) -> core_types::Result<Self> {
        Ok(Self {
            layout: layout.clone(),
            policy: None,
            user: layout.workspaces_file()?,
            drop_in_dir: layout.workspaces_drop_in_dir()?,
            profiles_dir: None,
        })
    }

    fn profiles(&self) -> core_types::Result<Vec<(core_types::TrustProfileName, PathBuf)>> {
        let Some(dir) = &self.profiles_dir else {
            return Ok(Vec::new());
        };
        entries(dir)?
            .into_iter()
            .map(|path| {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| core_types::TrustProfileName::try_from(n).ok())
                    .ok_or_else(|| path_error(&path, "not a valid profile name"))?;
                Ok((name, path))
            })
            .collect()
    }

    /// Candidate base files plus discovered fragments and scoped overrides.
    pub(crate) fn layers(&self) -> core_types::Result<Vec<Layer>> {
        let mut layers = Vec::new();
        if let Some(path) = &self.policy {
            layers.push(Layer {
                path: path.clone(),
                writable: false,
                profile: None,
            });
        }
        layers.push(Layer {
            path: self.user.clone(),
            writable: true,
            profile: None,
        });
        layers.extend(
            toml_files_in(&self.drop_in_dir)?
                .into_iter()
                .map(|path| Layer {
                    path,
                    writable: true,
                    profile: None,
                }),
        );
        for (profile, _) in self.profiles()? {
            layers.push(Layer {
                path: self.layout.profile_config_file(&profile)?,
                writable: true,
                profile: Some(profile),
            });
        }
        Ok(layers)
    }

    /// The directories whose entries are layers: the policy file's and the
    /// user file's directories, and the drop-in directory.
    pub(crate) fn directories(&self) -> core_types::Result<Vec<PathBuf>> {
        let mut dirs: Vec<PathBuf> = self
            .policy
            .iter()
            .chain(std::iter::once(&self.user))
            .filter_map(|file| file.parent().map(Path::to_path_buf))
            .collect();
        dirs.push(self.drop_in_dir.clone());
        if let Some(dir) = &self.profiles_dir {
            dirs.push(dir.clone());
            dirs.extend(self.profiles()?.into_iter().map(|(_, path)| path));
        }
        dirs.sort();
        dirs.dedup();
        Ok(dirs)
    }
}

/// Resolve all config paths in loading order (lowest to highest priority).
///
/// 1. System policy (`Layout::system_policy_file`)
/// 2. User config (`Layout::config_file`)
/// 3. Drop-in fragments (`Layout::config_drop_in_dir`, `*.toml`, sorted)
/// 4. Scoped profile overrides (`Layout::profile_config_file`, sorted by profile)
///
/// Only layers that exist are returned.
///
/// # Errors
///
/// The layout errors, and `core_types::Error::Config` when a layer's
/// presence cannot be determined or `config.d` exists but cannot be listed.
pub fn resolve_config_paths(layout: &Layout) -> core_types::Result<Vec<PathBuf>> {
    let spec = LayerSpec::of(layout)?;
    let mut paths = Vec::new();
    for layer in spec.layers()? {
        if exists(&layer.path)? {
            paths.push(layer.path);
        }
    }
    Ok(paths)
}

/// The bytes of every configuration layer present, in loading order, read
/// once: what a configuration is parsed from and what a change is detected
/// by, so the two are the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Capture {
    layers: Vec<(Layer, Vec<u8>)>,
    installation: (PathBuf, Option<Vec<u8>>),
}

impl Capture {
    /// Hash framed source names and bytes, independent of watcher lifetime.
    pub(crate) fn revision(&self) -> core_types::ConfigRevision {
        let mut hash = blake3::Hasher::new();
        hash.update(b"open-sesame/config-capture/v1\0");
        let mut field = |bytes: &[u8]| {
            hash.update(&(bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        };
        for (layer, bytes) in &self.layers {
            field(layer.path.as_os_str().as_encoded_bytes());
            field(bytes);
        }
        field(self.installation.0.as_os_str().as_encoded_bytes());
        match &self.installation.1 {
            Some(bytes) => {
                field(b"present");
                field(bytes);
            }
            None => field(b"absent"),
        }
        core_types::ConfigRevision(*hash.finalize().as_bytes())
    }

    /// The layers of `layout` as they are now, read outside any
    /// cooperating writer's transaction (`crate::transaction::consistent`),
    /// so a capture never holds half of one. A layer removed between
    /// listing and reading is absent from the capture.
    ///
    /// # Errors
    ///
    /// The `resolve_config_paths` errors, `core_types::Error::Config`
    /// naming a layer that cannot be read, and the `consistent` errors.
    pub(crate) fn of(layout: &Layout) -> core_types::Result<Self> {
        crate::transaction::consistent(layout, || {
            let mut layers = Vec::new();
            for layer in LayerSpec::of(layout)?.layers()? {
                if let Some(bytes) = read_optional(&layer.path)? {
                    layers.push((layer, bytes));
                }
            }
            let path = layout.installation_file()?;
            let bytes = read_optional(&path)?;
            Ok(Self {
                layers,
                installation: (path, bytes),
            })
        })
    }

    pub(crate) fn installation(&self) -> core_types::Result<Option<crate::InstallationConfig>> {
        self.installation
            .1
            .as_deref()
            .map(|bytes| {
                crate::loader_installation::parse_installation(&self.installation.0, bytes)
            })
            .transpose()
    }

    /// The configuration these layers make: each merged into the layers
    /// below it with `merge_layer`, the merged document read as a
    /// [`Config`], so every key a layer leaves unset takes its compiled
    /// default.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Config` naming the layer that is not UTF-8, not
    /// TOML, or does not match the schema, or naming the merged
    /// configuration when it does not.
    pub(crate) fn config(&self) -> core_types::Result<Config> {
        let mut merged = toml::Table::new();
        for (source, bytes) in &self.layers {
            let path = &source.path;
            let layer = parse_layer(utf8(path, bytes)?).map_err(|e| path_error(path, e))?;
            if let Some(profile) = &source.profile {
                let confined = layer.len() == 1
                    && layer
                        .get("profiles")
                        .and_then(toml::Value::as_table)
                        .is_some_and(|profiles| {
                            profiles.len() == 1 && profiles.contains_key(profile.as_ref())
                        });
                if !confined {
                    return Err(path_error(
                        path,
                        format!("profile override may define only [profiles.{profile}]"),
                    ));
                }
            }
            merge_layer(&mut merged, layer);
        }
        let config: Config = merged.try_into().map_err(|e| {
            core_types::Error::Config(format!("merged configuration is invalid: {e}"))
        })?;
        let errors: Vec<String> = crate::validate(&config)
            .into_iter()
            .filter(|d| d.severity == crate::DiagnosticSeverity::Error)
            .map(|d| d.message)
            .collect();
        if !errors.is_empty() {
            return Err(core_types::Error::Config(errors.join("; ")));
        }
        Ok(config)
    }
}

/// Load configuration by merging all layers as they are now: each layer
/// from `resolve_config_paths` (lowest to highest priority) is merged into
/// the layers below it, and the merged document is read as a [`Config`],
/// so every key a layer leaves unset takes its compiled default.
///
/// # Errors
///
/// The `resolve_config_paths` errors, and `core_types::Error::Config`
/// naming the layer that cannot be read, is not UTF-8, is not TOML, or
/// does not match the schema, or naming the merged configuration when it
/// does not.
pub fn load_config(layout: &Layout) -> core_types::Result<Config> {
    Capture::of(layout)?.config()
}

/// The content identity of `layout`'s configuration sources as they are
/// now: the revision a watcher of the same sources accepts. Comparing a
/// daemon's accepted revision with it shows whether the daemon runs the
/// sources on disk.
///
/// # Errors
///
/// The `Capture::of` errors.
pub fn source_revision(layout: &Layout) -> core_types::Result<core_types::ConfigRevision> {
    Ok(Capture::of(layout)?.revision())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_override_is_loaded_and_confined_to_its_owner() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let name = core_types::TrustProfileName::try_from("work").unwrap();
        let path = layout.profile_config_file(&name).unwrap();
        core_layout::file::write(
            &path,
            b"[profiles.work]\ncolor = \"#123456\"\n",
            core_layout::file::Mode::OwnerOnly,
        )
        .unwrap();
        assert_eq!(
            load_config(&layout).unwrap().profiles["work"]
                .color
                .as_deref(),
            Some("#123456")
        );
        core_layout::file::write(
            &path,
            b"[profiles.other]\n",
            core_layout::file::Mode::OwnerOnly,
        )
        .unwrap();
        assert!(
            load_config(&layout)
                .unwrap_err()
                .to_string()
                .contains("only [profiles.work]")
        );
    }

    #[test]
    fn startup_uses_the_same_semantic_acceptance_as_reload() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        core_layout::file::write(
            &layout.config_file().unwrap(),
            b"[profiles.work]\nextends = \"missing\"\n",
            core_layout::file::Mode::OwnerOnly,
        )
        .unwrap();
        assert!(
            load_config(&layout)
                .unwrap_err()
                .to_string()
                .contains("not defined")
        );
    }

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
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let config = load_config(&layout).unwrap();
        assert_eq!(config.config_version, 3);
        assert_eq!(&*config.global.default_profile, "default");
        assert!(config.profiles.is_empty());
    }

    #[test]
    fn a_capture_holds_every_present_layer_in_loading_order() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let policy = layout.system_policy_file().unwrap().to_path_buf();
        let user = layout.config_file().unwrap();
        let drop_in = layout.config_drop_in_dir().unwrap().join("10-local.toml");
        for (path, contents) in [
            (&policy, "[profiles.a]\n"),
            (&user, "[profiles.b]\n"),
            (&drop_in, "[profiles.c]\n"),
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        let capture = Capture::of(&layout).unwrap();
        let paths: Vec<&PathBuf> = capture
            .layers
            .iter()
            .map(|(layer, _)| &layer.path)
            .collect();
        assert_eq!(paths, [&policy, &user, &drop_in]);
        let config = capture.config().unwrap();
        assert_eq!(config.profiles.keys().collect::<Vec<_>>(), ["a", "b", "c"]);
    }

    #[test]
    fn the_layer_directories_include_the_drop_in_directory() {
        let layout = Layout::under(Path::new("/r"));
        assert_eq!(
            LayerSpec::of(&layout).unwrap().directories().unwrap(),
            [
                PathBuf::from("/r/config/pds"),
                PathBuf::from("/r/config/pds/config.d"),
                PathBuf::from("/r/config/pds/profiles"),
                PathBuf::from("/r/etc/pds"),
            ]
        );
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
