//! The event loop every bus client daemon runs: systemd watchdog pings,
//! bus messages from others, configuration reloads, termination, and the
//! daemon's own event source.

use std::future::Future;
use std::time::Duration;

use anyhow::Context;
use core_ipc::{BusClient, Message};
use core_types::EventKind;

use crate::{ConfigWatch, Shutdown, ShutdownSignal};

/// How often the systemd watchdog is pinged: half of `WatchdogSec=30`.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(15);

/// What a daemon handles next.
#[derive(Debug)]
pub enum Wake<T> {
    /// A bus message from another daemon or a client.
    Message(Message<EventKind>),
    /// A configuration candidate to apply and acknowledge
    /// (`crate::Reload`).
    ConfigReloaded(crate::Reload),
    /// The daemon's own event source produced a value.
    Own(T),
    /// A termination signal: the daemon stops.
    Shutdown(ShutdownSignal),
}

/// The loop a bus client daemon waits in.
pub struct EventLoop {
    daemon: core_types::Daemon,
    shutdown: Shutdown,
    config: ConfigWatch,
    watchdog: tokio::time::Interval,
}

impl EventLoop {
    /// The loop over `shutdown`'s signals and `config`'s reloads.
    #[must_use]
    pub fn new(daemon: core_types::Daemon, shutdown: Shutdown, config: ConfigWatch) -> Self {
        Self {
            daemon,
            shutdown,
            config,
            watchdog: tokio::time::interval(WATCHDOG_INTERVAL),
        }
    }

    /// The consumer's committed configuration and application status.
    #[must_use]
    pub fn application(&self) -> &crate::ConfigApplicationState {
        self.config.application()
    }

    /// Acquire the startup candidate before initializing resources.
    ///
    /// # Errors
    ///
    /// The current observation failed.
    pub fn candidate(&mut self) -> anyhow::Result<crate::Reload> {
        self.config.candidate()
    }

    /// Wait for what the daemon handles next: a message from another
    /// sender on `client`, a configuration reload, a termination signal, or
    /// the value of `own`. Watchdog pings are sent while waiting, and the
    /// daemon's own published messages (the bus delivers them back) are
    /// skipped.
    ///
    /// # Errors
    ///
    /// When the bus connection is lost, the configuration state lock is
    /// poisoned (the watcher panicked), or the termination listener fails.
    /// The daemon stops with the error, so systemd restarts it.
    pub async fn next<T>(
        &mut self,
        client: &mut BusClient,
        own: impl Future<Output = T>,
    ) -> anyhow::Result<Wake<T>> {
        let mut own = std::pin::pin!(own);
        loop {
            tokio::select! {
                _ = self.watchdog.tick() => {
                    #[cfg(target_os = "linux")]
                    platform_linux::systemd::notify_watchdog();
                }
                msg = client.recv() => {
                    let msg = msg.context("the IPC bus connection was lost")?;
                    if let EventKind::ConfigStatusRequest { daemon } = &msg.payload {
                        if *daemon == self.daemon {
                            crate::reply(client, &msg, EventKind::ConfigStatusResponse {
                                daemon: self.daemon,
                                status: self.config.application().status()?,
                            }).await;
                        }
                        continue;
                    }
                    if msg.sender != client.daemon_id() {
                        return Ok(Wake::Message(msg));
                    }
                }
                reload = self.config.reload() => {
                    match reload {
                        Ok(reload) => return Ok(Wake::ConfigReloaded(reload)),
                        Err(error) => tracing::warn!(%error, "configuration observation unavailable"),
                    }
                }
                signal = self.shutdown.wait() => {
                    let signal = signal.context("the termination signal listener failed")?;
                    tracing::info!(?signal, "shutting down");
                    return Ok(Wake::Shutdown(signal));
                }
                value = &mut own => return Ok(Wake::Own(value)),
            }
        }
    }
}
