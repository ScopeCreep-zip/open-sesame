//! Workspace configuration loading.
//!
//! Reads `Layout::workspaces_file` and merges drop-in fragments from
//! `Layout::workspaces_drop_in_dir`. Fragments use
//! `WorkspaceConfigFragment` with `Option` fields so only explicitly present
//! values override the base configuration.
//!
//! The merged `WorkspaceConfig` is a read model. Writes go through
//! `crate::edit`, which edits the single file that defines each key.

use std::path::{Path, PathBuf};

use core_layout::Layout;
use core_types::Error;

use crate::loader::toml_files_in;
use crate::schema::{WorkspaceConfig, WorkspaceConfigFragment};

/// The workspace config files: `workspaces.toml`, then `workspaces.d/*.toml`
/// fragments in load order.
///
/// # Errors
///
/// The layout errors when the config directory cannot be placed, and
/// `Error::Config` when `workspaces.d` exists but cannot be listed.
pub(crate) fn workspace_config_files(layout: &Layout) -> core_types::Result<Vec<PathBuf>> {
    let mut files = vec![layout.workspaces_file()?];
    files.extend(toml_files_in(&layout.workspaces_drop_in_dir()?)?);
    Ok(files)
}

/// `contents` of `path` parsed as `T`.
fn parse<T: serde::de::DeserializeOwned>(path: &Path, contents: &str) -> core_types::Result<T> {
    toml::from_str(contents)
        .map_err(|e| Error::Config(format!("failed to parse {}: {e}", path.display())))
}

/// Load workspace configuration from `workspaces.toml`.
///
/// Merges drop-in fragments from `workspaces.d/*.toml` in alphabetical
/// order. Fragment links are additive. Fragment settings override only
/// explicitly present fields.
///
/// Returns a default config if no file exists.
///
/// # Errors
///
/// The layout errors when the config directory cannot be placed, and
/// `Error::Config` naming the file when one exists but cannot be read or
/// parsed, or `workspaces.d` cannot be listed.
pub fn load_workspace_config(layout: &Layout) -> core_types::Result<WorkspaceConfig> {
    let base = layout.workspaces_file()?;
    let mut config = match std::fs::read_to_string(&base) {
        Ok(contents) => parse(&base, &contents)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => WorkspaceConfig::default(),
        Err(e) => {
            return Err(Error::Config(format!(
                "failed to read {}: {e}",
                base.display()
            )));
        }
    };

    for frag_path in toml_files_in(&layout.workspaces_drop_in_dir()?)? {
        let contents = std::fs::read_to_string(&frag_path)
            .map_err(|e| Error::Config(format!("failed to read {}: {e}", frag_path.display())))?;
        let fragment: WorkspaceConfigFragment = parse(&frag_path, &contents)?;
        config.settings.apply_override(&fragment.settings);
        config.links.extend(fragment.links);
    }

    Ok(config)
}
