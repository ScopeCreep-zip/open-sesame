//! Termination signals.

/// The signal that ended the event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// SIGINT (Ctrl-C).
    Interrupt,
    /// SIGTERM (systemd stop).
    Terminate,
}

/// SIGINT and SIGTERM, registered once at startup.
pub struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl Shutdown {
    /// Register the handlers.
    ///
    /// # Errors
    ///
    /// When the SIGTERM handler cannot be registered.
    pub fn register() -> std::io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    /// Wait for the next termination signal.
    ///
    /// # Errors
    ///
    /// When the SIGINT listener fails.
    pub async fn wait(&mut self) -> std::io::Result<ShutdownSignal> {
        #[cfg(unix)]
        {
            tokio::select! {
                result = tokio::signal::ctrl_c() => result.map(|()| ShutdownSignal::Interrupt),
                Some(()) = self.terminate.recv() => Ok(ShutdownSignal::Terminate),
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .map(|()| ShutdownSignal::Interrupt)
        }
    }
}
