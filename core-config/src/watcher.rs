//! Filesystem-based config hot-reload using the `notify` crate.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::schema::Config;

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
    /// Returns an error if the filesystem watcher cannot be initialized.
    pub fn new(
        config_paths: &[PathBuf],
        initial_config: Config,
    ) -> core_types::Result<(Self, Arc<RwLock<Config>>)> {
        Self::with_callback(config_paths, initial_config, None)
    }

    /// Create a new config watcher with an optional reload notification callback.
    ///
    /// The callback is invoked on the notify thread after a successful config
    /// reload. Use this to bridge into async runtimes (e.g. send on a channel).
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem watcher cannot be initialized.
    pub fn with_callback(
        config_paths: &[PathBuf],
        initial_config: Config,
        on_reload: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> core_types::Result<(Self, Arc<RwLock<Config>>)> {
        let current = Arc::new(RwLock::new(initial_config));
        let current_clone = Arc::clone(&current);

        // Collect watched config file paths so the callback can filter out
        // unrelated changes in the same parent directory (e.g. audit.jsonl,
        // vault DBs, salt files). Without this filter, ANY write to
        // ~/.config/pds/ triggers a config reload cascade that causes 100%
        // CPU via feedback loop: write → reload → IPC publish → more writes.
        let watched_files: std::collections::HashSet<PathBuf> = config_paths
            .iter()
            .filter_map(|p| std::fs::canonicalize(p).ok().or_else(|| Some(p.clone())))
            .collect();
        // Also match by filename for drop-in directories where new files may appear.
        let watched_extensions: Vec<String> = config_paths
            .iter()
            .filter_map(|p| p.extension().map(|e| e.to_string_lossy().to_string()))
            .collect();

        let watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        if event.kind.is_modify() || event.kind.is_create() {
                            // Filter: only react to changes in actual config files.
                            let is_config_file = event.paths.iter().any(|p| {
                                // Exact match against known config paths.
                                if let Ok(canon) = std::fs::canonicalize(p)
                                    && watched_files.contains(&canon)
                                {
                                    return true;
                                }
                                if watched_files.contains(p) {
                                    return true;
                                }
                                // Extension match for drop-in fragments.
                                if let Some(ext) = p.extension() {
                                    let ext_str = ext.to_string_lossy();
                                    return watched_extensions
                                        .iter()
                                        .any(|we| we == ext_str.as_ref());
                                }
                                false
                            });
                            if !is_config_file {
                                return;
                            }
                            info!(?event, "config file changed, reloading");
                            match crate::loader::load_config(None) {
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
                                    } else if let Ok(mut guard) = current_clone.write() {
                                        *guard = new_config;
                                        info!("config reloaded successfully");
                                        if let Some(ref cb) = on_reload {
                                            cb();
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
