//! Daemon lifecycle shared by every PDS daemon.
//!
//! - [`startup`]: the process layout, its directories, and the loaded
//!   configuration.
//! - [`init_logging`]: the tracing subscriber for a [`LogFormat`];
//!   [`init_cli_logging`] for the `sesame` CLI.
//! - [`Shutdown`]: SIGINT and SIGTERM.
//! - [`watch_config`]: configuration hot-reload with a coalescing reload
//!   channel.
//! - [`EventLoop`]: the loop every bus client daemon waits in (watchdog,
//!   bus messages, reloads, termination, its own events).
//! - [`DaemonIdentity`], [`connect_bus`], [`announce_started`],
//!   [`announce_stopped`], [`reply`]: the bus connection, lifecycle
//!   announcements, and correlated responses.
//! - [`sandbox`] (Linux): Landlock grants derived from the layout, and the
//!   seccomp allowlists.
//! - [`credential_store`]: the platform's credential store, connected.
#![forbid(unsafe_code)]

mod bus;
mod config_watch;
mod event_loop;
mod logging;
#[cfg(target_os = "linux")]
pub mod sandbox;
mod signals;

pub use bus::{
    DaemonIdentity, announce_config_reloaded, announce_started, announce_stopped, connect_bus,
    reply,
};
pub use config_watch::{ConfigWatch, watch_config};
pub use event_loop::{EventLoop, Wake};
pub use logging::{LogFormat, init_cli_logging, init_logging};
pub use signals::{Shutdown, ShutdownSignal};

use anyhow::Context;
use core_layout::Layout;
use core_types::{BoxFuture, CredentialStore};
use std::sync::Arc;

/// The platform's credential store, connected: the Secret Service (or,
/// sandboxed, the Secret portal) on Linux. `None` when the platform has no
/// implementation yet or the store cannot be reached; the reason is
/// logged, and the platform keyring factor has no backend.
///
/// The connection future is boxed: the Secret Service handshake is a deep
/// state machine, and inlined into a caller's future (daemon-wm's event
/// loop) it exceeds the compiler's layout query depth.
#[must_use]
pub fn credential_store() -> BoxFuture<'static, Option<Arc<dyn CredentialStore>>> {
    Box::pin(async {
        #[cfg(target_os = "linux")]
        {
            match platform_linux::keyring::SecretServiceStore::connect().await {
                Ok(store) => Some(Arc::new(store) as Arc<dyn CredentialStore>),
                Err(e) => {
                    tracing::info!(error = %e, "platform credential store unavailable");
                    None
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            tracing::info!("this platform has no credential store implementation");
            None
        }
    })
}

/// The process layout with its configuration, cache, and runtime
/// directories created, and the configuration loaded from it.
///
/// # Errors
///
/// When a directory cannot be placed or created, or the configuration
/// cannot be loaded.
pub fn startup() -> anyhow::Result<(Layout, core_config::Config)> {
    let layout = Layout::from_process();
    layout
        .bootstrap()
        .context("failed to bootstrap directories")?;
    let config = core_config::load_config(&layout).context("failed to load config")?;
    Ok((layout, config))
}
