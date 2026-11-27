//! Configuration hot-reload.

use std::sync::{Arc, RwLock};

use anyhow::Context;
use core_config::{Config, ConfigWatcher};
use core_layout::Layout;
use tokio::sync::mpsc;

/// A running configuration watch.
pub struct ConfigWatch {
    /// The live configuration; replaced on each valid reload.
    pub state: Arc<RwLock<Config>>,
    /// One message per reload. A message still queued covers every later
    /// reload, so the watcher thread never blocks on a slow event loop.
    pub reloads: mpsc::Receiver<()>,
    _watcher: ConfigWatcher,
}

/// Watch the configuration files of `layout`, starting from `initial`.
///
/// # Errors
///
/// When the configuration files cannot be resolved or the filesystem
/// watcher cannot be started.
pub fn watch_config(layout: &Layout, initial: Config) -> anyhow::Result<ConfigWatch> {
    let paths =
        core_config::resolve_config_paths(layout).context("failed to resolve config paths")?;
    let (tx, reloads) = mpsc::channel::<()>(1);
    let notify = move || match tx.try_send(()) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
        Err(mpsc::error::TrySendError::Closed(())) => {
            tracing::warn!("config reload channel closed, reload dropped");
        }
    };
    let (watcher, state) =
        ConfigWatcher::with_callback(layout.clone(), &paths, initial, Some(Box::new(notify)))
            .context("failed to start config watcher")?;
    Ok(ConfigWatch {
        state,
        reloads,
        _watcher: watcher,
    })
}
