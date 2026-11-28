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

use crate::loader::{LayerSpec, path_error, read_optional, utf8};
use crate::schema::{WorkspaceConfig, WorkspaceConfigFragment};

/// The workspace config files: `workspaces.toml`, then `workspaces.d/*.toml`
/// fragments in load order.
///
/// # Errors
///
/// The layout errors when the config directory cannot be placed, and
/// `Error::Config` when `workspaces.d` exists but cannot be listed.
pub(crate) fn workspace_config_files(layout: &Layout) -> core_types::Result<Vec<PathBuf>> {
    Ok(LayerSpec::workspace(layout)?
        .layers()?
        .into_iter()
        .map(|layer| layer.path)
        .collect())
}

/// The `T` that `path` holds; `None` when it does not exist.
fn parse<T: serde::de::DeserializeOwned>(path: &Path) -> core_types::Result<Option<T>> {
    read_optional(path)?
        .map(|bytes| {
            toml::from_str(utf8(path, &bytes)?)
                .map_err(|e| path_error(path, format!("cannot parse: {e}")))
        })
        .transpose()
}

/// Load workspace configuration from `workspaces.toml`.
///
/// Merges drop-in fragments from `workspaces.d/*.toml` in alphabetical
/// order. Fragment links are additive. Fragment settings override only
/// explicitly present fields.
///
/// Returns a default config if no file exists. The files are read outside
/// any cooperating writer's transaction, so the result never holds half of
/// one. A fragment removed between listing and reading is absent.
///
/// # Errors
///
/// The layout errors when the config directory cannot be placed, and
/// `Error::Config` naming the file when one exists but cannot be read or
/// parsed, or `workspaces.d` cannot be listed, or when every read
/// overlapped a transaction.
pub fn load_workspace_config(layout: &Layout) -> core_types::Result<WorkspaceConfig> {
    crate::transaction::consistent(layout, || read_workspace_config(layout))
}

/// [`load_workspace_config`]'s read, outside the transaction check.
fn read_workspace_config(layout: &Layout) -> core_types::Result<WorkspaceConfig> {
    let files = workspace_config_files(layout)?;
    let Some((base, fragments)) = files.split_first() else {
        return Ok(WorkspaceConfig::default());
    };
    let mut config: WorkspaceConfig = parse(base)?.unwrap_or_default();
    for path in fragments {
        let Some(fragment) = parse::<WorkspaceConfigFragment>(path)? else {
            continue;
        };
        config.settings.apply_override(&fragment.settings);
        config.links.extend(fragment.links);
    }
    Ok(config)
}
