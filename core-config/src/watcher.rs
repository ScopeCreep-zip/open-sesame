//! Filesystem-based config hot-reload using the `notify` crate.

use core_layout::Layout;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{error, info, warn};

use crate::schema::Config;

/// The canonical form of a watched path; a path that does not exist is
/// matched by its spelling.
fn watch_key(path: &PathBuf) -> core_types::Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(canonical) => Ok(canonical),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(path.clone()),
        Err(e) => Err(core_types::Error::Config(format!(
            "failed to resolve watched config file {}: {e}",
            path.display()
        ))),
    }
}

/// Decides which filesystem events reload the configuration.
///
/// The watcher watches whole parent directories, which also hold
/// audit.jsonl, vault DBs, and salt files. Reloading on every write there
/// is a feedback loop (write → reload → IPC publish → more writes) that
/// pins a CPU, so only events on config files reload.
struct ChangeFilter {
    /// Canonical watched config paths (`watch_key`).
    files: HashSet<PathBuf>,
    /// Extensions of the watched files: a new drop-in fragment matches.
    extensions: Vec<String>,
}

impl ChangeFilter {
    /// Whether `event` reloads: a rescan (the kernel queue overflowed and
    /// events were lost, possibly without paths), or a create or modify of
    /// a config file.
    fn is_config_change(&self, event: &notify::Event) -> bool {
        if event.need_rescan() {
            return true;
        }
        if !(event.kind.is_modify() || event.kind.is_create()) {
            return false;
        }
        event.paths.iter().any(|p| {
            if self.files.contains(p) {
                return true;
            }
            if let Ok(canon) = std::fs::canonicalize(p)
                && self.files.contains(&canon)
            {
                return true;
            }
            p.extension().is_some_and(|ext| {
                let ext = ext.to_string_lossy();
                self.extensions.iter().any(|we| *we == ext)
            })
        })
    }
}

/// Watches config file paths for changes and triggers reload + validation.
pub struct ConfigWatcher {
    watcher: RecommendedWatcher,
    current: Arc<RwLock<Config>>,
}

impl ConfigWatcher {
    /// Create a new config watcher monitoring the given paths.
    ///
    /// Returns the watcher and a clone of the shared config state.
    /// The config is reloaded (with validation) whenever a watched file changes.
    ///
    /// # Errors
    ///
    /// Returns an error if a watched path cannot be resolved or the
    /// filesystem watcher cannot be initialized.
    pub fn new(
        layout: Layout,
        config_paths: &[PathBuf],
        initial_config: Config,
    ) -> core_types::Result<(Self, Arc<RwLock<Config>>)> {
        Self::with_callback(layout, config_paths, initial_config, None)
    }

    /// Create a new config watcher with an optional reload notification callback.
    ///
    /// Reloads read the configuration from `layout`. The callback is invoked
    /// on the notify thread after a successful config reload. Use this to
    /// bridge into async runtimes (e.g. send on a channel).
    ///
    /// # Errors
    ///
    /// Returns an error if a watched path cannot be resolved or the
    /// filesystem watcher cannot be initialized.
    pub fn with_callback(
        layout: Layout,
        config_paths: &[PathBuf],
        initial_config: Config,
        on_reload: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> core_types::Result<(Self, Arc<RwLock<Config>>)> {
        let current = Arc::new(RwLock::new(initial_config));
        let current_clone = Arc::clone(&current);

        let filter = ChangeFilter {
            files: config_paths
                .iter()
                .map(watch_key)
                .collect::<core_types::Result<_>>()?,
            // Also match by extension for drop-in directories where new files may appear.
            extensions: config_paths
                .iter()
                .filter_map(|p| p.extension().map(|e| e.to_string_lossy().into_owned()))
                .collect(),
        };

        let watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        if filter.is_config_change(&event) {
                            info!(?event, "config file changed, reloading");
                            match crate::loader::load_config(&layout) {
                                Ok(new_config) => {
                                    let diags = crate::validation::validate(&new_config);
                                    let has_errors = diags.iter().any(|d| {
                                        d.severity == crate::validation::DiagnosticSeverity::Error
                                    });
                                    if has_errors {
                                        warn!("config reload rejected: validation errors");
                                        for d in &diags {
                                            warn!(message = %d.message, "config diagnostic");
                                        }
                                    } else {
                                        match current_clone.write() {
                                            Ok(mut guard) => {
                                                *guard = new_config;
                                                info!("config reloaded successfully");
                                                if let Some(ref cb) = on_reload {
                                                    cb();
                                                }
                                            }
                                            // A reader panicked holding the lock: the
                                            // daemon keeps serving its previous config.
                                            Err(e) => error!(
                                                error = %e,
                                                "config state lock poisoned, reload dropped"
                                            ),
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "config reload failed");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "filesystem watcher error");
                    }
                }
            })
            .map_err(|e| core_types::Error::Config(format!("failed to create watcher: {e}")))?;

        let mut w = Self {
            watcher,
            current: Arc::clone(&current),
        };

        for path in config_paths {
            if let Some(parent) = path.parent()
                && parent.exists()
                && let Err(e) = w.watcher.watch(parent, RecursiveMode::NonRecursive)
            {
                warn!(path = %parent.display(), error = %e, "failed to watch config directory");
            }
        }

        Ok((w, current))
    }

    /// Get a read handle to the current configuration.
    #[must_use]
    pub fn current(&self) -> Arc<RwLock<Config>> {
        Arc::clone(&self.current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, DataChange, Flag, ModifyKind, RemoveKind, RenameMode};
    use notify::{Event, EventKind};

    fn filter() -> ChangeFilter {
        ChangeFilter {
            files: HashSet::from([PathBuf::from("/cfg/config.toml")]),
            extensions: vec!["toml".into()],
        }
    }

    fn modify_data() -> EventKind {
        EventKind::Modify(ModifyKind::Data(DataChange::Content))
    }

    #[test]
    fn a_rescan_without_paths_reloads() {
        let event = Event::new(EventKind::Other).set_flag(Flag::Rescan);
        assert!(filter().is_config_change(&event));
    }

    #[test]
    fn writes_and_renames_onto_config_files_reload() {
        let f = filter();
        let write = Event::new(modify_data()).add_path("/cfg/config.toml".into());
        let rename = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To)))
            .add_path("/cfg/config.toml".into());
        let drop_in = Event::new(EventKind::Create(CreateKind::File))
            .add_path("/cfg/config.d/10-local.toml".into());
        assert!(f.is_config_change(&write));
        assert!(f.is_config_change(&rename));
        assert!(f.is_config_change(&drop_in));
    }

    #[test]
    fn unrelated_files_and_removals_do_not_reload() {
        let f = filter();
        let audit = Event::new(modify_data()).add_path("/cfg/audit.jsonl".into());
        let removal =
            Event::new(EventKind::Remove(RemoveKind::File)).add_path("/cfg/config.toml".into());
        assert!(!f.is_config_change(&audit));
        assert!(!f.is_config_change(&removal));
    }
}
