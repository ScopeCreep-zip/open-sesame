//! Configuration hot-reload.

use anyhow::Context;
use core_config::{Config, ConfigWatcher};
use core_layout::Layout;
use tokio::sync::mpsc;

/// A running configuration watch. Consumers read configuration only
/// through its application state (`crate::ConfigApplicationState`): what
/// they applied, never the raw accepted observation.
pub struct ConfigWatch {
    /// One message per reload. A message still queued covers every later
    /// reload, so the watcher thread never blocks on a slow event loop.
    reloads: mpsc::Receiver<()>,
    application: crate::ConfigApplicationState,
    watcher: ConfigWatcher,
    retry: tokio::time::Interval,
}

impl ConfigWatch {
    /// Application state owned by this watch's consumer.
    #[must_use]
    pub fn application(&self) -> &crate::ConfigApplicationState {
        &self.application
    }

    /// Acquire the current candidate for explicit startup adoption.
    ///
    /// # Errors
    ///
    /// The current observation is rejected or unreadable.
    pub fn candidate(&mut self) -> anyhow::Result<crate::Reload> {
        while self.reloads.try_recv().is_ok() {}
        self.application.begin()
    }

    /// Await a candidate through the same path for bus clients and the bus host.
    ///
    /// # Errors
    ///
    /// The channel closes or the latest observation is rejected or unreadable.
    pub async fn reload(&mut self) -> anyhow::Result<crate::Reload> {
        loop {
            tokio::select! {
                notification = self.reloads.recv() => {
                    if notification.is_none() {
                        anyhow::bail!("configuration reload channel closed");
                    }
                    return self.candidate();
                }
                _ = self.retry.tick() => {
                    if self.application.needs_retry()? {
                        return self.application.begin();
                    }
                }
            }
        }
    }
    /// Request and await the same reconciliation used by events and the timer.
    ///
    /// # Errors
    ///
    /// The reconciliation task stops or the on-disk configuration is rejected.
    pub async fn reconcile(&self) -> anyhow::Result<()> {
        let trigger = self.watcher.trigger();
        tokio::task::spawn_blocking(move || trigger.reconcile())
            .await
            .context("configuration reconciliation task failed")??;
        Ok(())
    }
}

/// Watch the configuration layers of `layout`, starting from `initial`
/// (`core_config::ConfigWatcher`): the running configuration is reconciled
/// with the layers once after the watches are armed, on every change to
/// the layers' directories, and every `core_config::RECONCILE_INTERVAL`.
///
/// # Errors
///
/// When the reconciliation thread cannot be started, or the startup
/// observation is not accepted. Native watcher failure is reported in the
/// application status and leaves periodic reconciliation.
pub fn watch_config(layout: &Layout, initial: Config) -> anyhow::Result<ConfigWatch> {
    let startup = initial.clone();
    let (tx, reloads) = mpsc::channel::<()>(1);
    let notify = move || match tx.try_send(()) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
        Err(mpsc::error::TrySendError::Closed(())) => {
            tracing::warn!("config reload channel closed, reload dropped");
        }
    };
    let (watcher, state) =
        ConfigWatcher::with_callback(layout.clone(), initial, Some(Box::new(notify)))
            .context("failed to start config watcher")?;
    Ok(ConfigWatch {
        application: crate::ConfigApplicationState::new(state, startup),
        reloads,
        watcher,
        retry: tokio::time::interval(core_config::RECONCILE_INTERVAL),
    })
}
