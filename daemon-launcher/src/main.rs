//! daemon-launcher: Application launcher daemon.
//!
//! Scans XDG desktop entries, builds a nucleo fuzzy index with frecency
//! ranking, and serves `LaunchQuery`/`LaunchExecute` requests over the IPC
//! bus.
//!
//! Unsandboxed: seccomp and Landlock are inherited across fork+exec and
//! would confine every application it launches. Its security boundary is
//! IPC bus authentication (Noise IK).
//!
//! Being outside a sandbox, it is also the broker of daemon-wm's platform
//! keyring factor (`KeyringUnlockRequest`): the credential store is on the
//! session D-Bus bus, which daemon-wm's sandbox does not grant because the
//! bus also reaches the user's service manager.
//!
//! For the same reason it holds the `GlobalShortcuts` portal session that
//! binds the overlay shortcuts where the desktop's portal implements it
//! (`platform_linux::global_shortcuts`): each activation is published as
//! the overlay request daemon-wm serves.

use anyhow::Context;
use clap::Parser;
use core_daemon::{DaemonIdentity, EventLoop, LogFormat, Shutdown, Wake};
use core_fuzzy::{FrecencyDb, FuzzyMatcher, SearchEngine, inject_items};
use core_ipc::{BusClient, Message};
use core_layout::Layout;
use core_types::{
    EventKind, KeyCombo, LaunchOutcome, OverlayRequest, SecurityLevel, TrustProfileName,
};
use std::collections::HashMap;
use std::sync::Arc;

mod launch;
mod scanner;

/// How long daemon-secrets may take to verify a submitted factor (vault
/// open with the derived key).
const FACTOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether `payload` is daemon-secrets' answer to a `FactorSubmit`, which
/// a `KeyringUnlockRequest` relays as it is.
fn is_factor_answer(payload: &EventKind) -> bool {
    matches!(
        payload,
        EventKind::FactorResponse { .. } | EventKind::UnlockRejected { .. }
    )
}

/// Why a `KeyringUnlockRequest` from `sender` (the bus-verified name) is
/// refused; `None` for daemon-wm, the one daemon it is brokered for. The
/// request unlocks a vault without the user, so it is not offered to every
/// bus client.
fn keyring_unlock_refusal(sender: Option<&str>) -> Option<String> {
    (sender != Some(core_types::Daemon::Wm.name())).then(|| {
        format!(
            "keyring unlocks are brokered for {} only, not for {}",
            core_types::Daemon::Wm,
            sender.unwrap_or("an unverified sender")
        )
    })
}

const IDENTITY: DaemonIdentity = DaemonIdentity {
    daemon: core_types::Daemon::Launcher,
    version: env!("CARGO_PKG_VERSION"),
    capabilities: &["launcher", "fuzzy-search"],
};

#[derive(Parser)]
#[command(name = IDENTITY.daemon.name(), about = "Application launcher daemon")]
struct Cli {
    /// Profile whose frecency ranks results until a query names another.
    #[arg(long, default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = parse_profile)]
    profile: TrustProfileName,

    /// Log format.
    #[arg(long, value_enum, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: LogFormat,
}

fn parse_profile(name: &str) -> Result<TrustProfileName, String> {
    TrustProfileName::try_from(name).map_err(|e| e.to_string())
}

/// `profile`'s frecency database, its directory created first.
fn open_frecency(layout: &Layout, profile: &TrustProfileName) -> anyhow::Result<FrecencyDb> {
    let path = layout.frecency_db(profile)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    FrecencyDb::open(&path)
        .with_context(|| format!("failed to open frecency database {}", path.display()))
}

/// The overlay shortcuts bound through the `GlobalShortcuts` portal.
#[cfg(target_os = "linux")]
struct PortalBinding {
    /// The session bus connection the portal session lives on: dropping
    /// it ends the session.
    _connection: zbus::Connection,
    _shortcuts: platform_linux::global_shortcuts::PortalShortcuts,
    activations: std::pin::Pin<Box<dyn futures_util::Stream<Item = OverlayRequest>>>,
    /// The launcher key the session was bound with.
    launcher: KeyCombo,
}

/// Bind the overlay shortcuts with `launcher` through this session's
/// `GlobalShortcuts` portal; `None` (logged) without a session bus or a
/// portal implementing it. Binding and activation-stream failures are errors.
#[cfg(target_os = "linux")]
async fn bind_portal(launcher: &KeyCombo) -> anyhow::Result<Option<PortalBinding>> {
    use platform_linux::global_shortcuts::{PortalShortcuts, available};
    let connection = match zbus::Connection::session().await {
        Ok(connection) => connection,
        Err(e) => {
            tracing::info!(error = %e, "no session bus: overlay shortcuts are not bound through a portal");
            return Ok(None);
        }
    };
    if !available(&connection).await {
        tracing::info!(
            "the desktop portal does not implement GlobalShortcuts: the overlay shortcuts are the desktop's own bindings"
        );
        return Ok(None);
    }
    let shortcuts = match PortalShortcuts::bind(&connection, launcher).await {
        Ok(shortcuts) => shortcuts,
        Err(e) => {
            tracing::warn!(error = %e, "overlay shortcuts not bound through the portal");
            return Err(e.into());
        }
    };
    match shortcuts.activations().await {
        Ok(activations) => Ok(Some(PortalBinding {
            _connection: connection,
            _shortcuts: shortcuts,
            activations: Box::pin(activations),
            launcher: launcher.clone(),
        })),
        Err(e) => {
            tracing::warn!(error = %e, "portal shortcut activations unavailable");
            Err(e.into())
        }
    }
}

/// The next shortcut activation, or `None` when an established binding is lost.
/// Without a binding, reconciliation owns recovery.
#[cfg(target_os = "linux")]
async fn next_activation(portal: &mut Option<PortalBinding>) -> Option<OverlayRequest> {
    use futures_util::StreamExt;
    match portal {
        Some(binding) => binding.activations.next().await,
        None => std::future::pending().await,
    }
}

/// What request handling draws on.
struct Daemon {
    layout: Layout,
    engine: SearchEngine,
    launcher: launch::Launcher,
    client: BusClient,
    #[cfg(target_os = "linux")]
    portal: Option<PortalBinding>,
    /// Once adopted, portal shortcuts remain required across resource loss.
    #[cfg(target_os = "linux")]
    portal_required: bool,
}

impl Daemon {
    /// The `LaunchQueryResponse`: the best matches of `query`, ranked by
    /// `profile`'s frecency when one is named (a failed switch keeps the
    /// current profile).
    fn query(
        &mut self,
        query: &str,
        max_results: u32,
        profile: Option<&TrustProfileName>,
    ) -> EventKind {
        if let Some(p) = profile
            && p != self.engine.profile()
            && let Err(e) = open_frecency(&self.layout, p)
                .and_then(|db| Ok(self.engine.switch_profile(p.clone(), db)?))
        {
            tracing::warn!(profile = %p, error = %format!("{e:#}"), "frecency profile switch failed");
        }
        let results = self.engine.query(query, max_results);
        tracing::info!(%query, result_count = results.len(), "LaunchQuery complete");
        EventKind::LaunchQueryResponse { results }
    }

    /// The `LaunchExecuteResponse`: `entry_id` launched (its launch
    /// recorded for frecency), denied, or failed.
    async fn execute(
        &mut self,
        entry_id: &str,
        profile: Option<&TrustProfileName>,
        tags: &[String],
        launch_args: &[String],
    ) -> EventKind {
        if let Err(e) = self.engine.record_launch(entry_id) {
            tracing::warn!(entry_id, error = %e, "frecency record failed");
        }
        let profile = profile.map(AsRef::as_ref);
        let outcome = match launch::launch_entry(
            &self.launcher,
            &self.client,
            entry_id,
            profile,
            tags,
            launch_args,
        )
        .await
        {
            Ok(pid) => LaunchOutcome::Launched { pid },
            Err(launch::LaunchError::Denial(denial)) => {
                tracing::error!(entry_id, ?denial, "launch denied");
                LaunchOutcome::Denied(denial)
            }
            Err(launch::LaunchError::Other(e)) => {
                tracing::error!(entry_id, error = %format!("{e:#}"), "launch failed");
                LaunchOutcome::Failed {
                    reason: format!("{e:#}"),
                }
            }
        };
        EventKind::LaunchExecuteResponse { outcome }
    }

    /// The answer to `sender`'s `KeyringUnlockRequest` for `profile`:
    /// daemon-secrets' answer to the platform keyring factor, read and
    /// submitted here, or `KeyringUnlockFailed` naming why the factor could
    /// not be submitted (a sender other than daemon-wm among the reasons,
    /// [`keyring_unlock_refusal`]).
    async fn keyring_unlock(&self, sender: Option<&str>, profile: &TrustProfileName) -> EventKind {
        let failed = |reason: String| {
            tracing::warn!(%profile, audit = "unlock-flow", %reason, "keyring unlock not submitted");
            EventKind::KeyringUnlockFailed {
                profile: profile.clone(),
                reason,
            }
        };
        if let Some(refusal) = keyring_unlock_refusal(sender) {
            return failed(refusal);
        }
        let Some(store) = core_daemon::credential_store().await else {
            return failed("no platform credential store is reachable".into());
        };
        let keying = match core_auth::VaultMetadata::load_keying(&self.layout, profile) {
            Ok((_, keying)) => keying,
            Err(e) => return failed(format!("vault is unreadable: {e}")),
        };
        let outcome = match core_auth::VaultAuthBackend::unlock(
            &core_auth::PlatformKeyringBackend::new(store),
            profile,
            &self.layout,
            &keying,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(e) => return failed(e.to_string()),
        };
        match self
            .client
            .request(
                outcome.into_factor_submit(profile),
                SecurityLevel::Internal,
                FACTOR_TIMEOUT,
            )
            .await
        {
            Ok(reply) if is_factor_answer(&reply.payload) => {
                tracing::info!(%profile, audit = "unlock-flow", answer = ?reply.payload, "keyring factor submitted");
                reply.payload
            }
            Ok(reply) => failed(format!(
                "daemon-secrets answered the factor with {:?}",
                reply.payload
            )),
            Err(e) => failed(format!("factor submission failed: {e}")),
        }
    }

    /// Answer `msg` when it is a launcher request, correlated to it.
    async fn handle(&mut self, msg: &Message<EventKind>) {
        let response = match &msg.payload {
            EventKind::LaunchQuery {
                query,
                max_results,
                profile,
            } => self.query(query, *max_results, profile.as_ref()),
            EventKind::LaunchExecute {
                entry_id,
                profile,
                tags,
                launch_args,
            } => {
                self.execute(entry_id, profile.as_ref(), tags, launch_args)
                    .await
            }
            EventKind::KeyringUnlockRequest { profile } => {
                self.keyring_unlock(msg.verified_sender_name.as_deref(), profile)
                    .await
            }
            _ => return,
        };
        core_daemon::reply(&self.client, msg, response).await;
    }

    /// Serve requests until a shutdown signal.
    ///
    /// # Errors
    ///
    /// The [`EventLoop::next`] errors (a lost bus among them).
    async fn serve(&mut self, events: &mut EventLoop) -> anyhow::Result<()> {
        loop {
            #[cfg(target_os = "linux")]
            let own = next_activation(&mut self.portal);
            #[cfg(not(target_os = "linux"))]
            let own = std::future::pending::<Option<OverlayRequest>>();
            match events.next(&mut self.client, own).await? {
                Wake::Message(msg) => self.handle(&msg).await,
                Wake::ConfigReloaded(reload) => {
                    #[cfg(target_os = "linux")]
                    if let Err(error) = self
                        .rebind_if_changed(&reload.snapshot.config.global.launcher_key)
                        .await
                    {
                        reload.reject(error.to_string());
                        continue;
                    }
                    reload.applied(&self.client).await;
                }
                Wake::Own(Some(request)) => {
                    tracing::info!(request = request.id(), "overlay shortcut activated");
                    self.client
                        .publish_or_log("overlay request", request.event(), SecurityLevel::Internal)
                        .await;
                }
                Wake::Own(None) => {
                    #[cfg(target_os = "linux")]
                    {
                        self.portal = None;
                        events
                            .application()
                            .resource_lost("shortcut portal activation stream ended".into());
                    }
                }
                Wake::Shutdown(_) => return Ok(()),
            }
        }
    }

    /// Bind the portal shortcuts again when the reloaded `launcher` key
    /// differs from the bound one or the binding was lost. Prepare the
    /// replacement before releasing an existing session.
    #[cfg(target_os = "linux")]
    async fn rebind_if_changed(&mut self, launcher: &KeyCombo) -> anyhow::Result<()> {
        if self
            .portal
            .as_ref()
            .is_none_or(|binding| binding.launcher != *launcher)
        {
            tracing::info!(%launcher, "launcher key changed: rebinding the portal shortcuts");
            let replacement = bind_portal(launcher).await?;
            anyhow::ensure!(
                !self.portal_required || replacement.is_some(),
                "shortcut portal disappeared during reconfiguration"
            );
            self.portal_required |= replacement.is_some();
            self.portal = replacement;
        }
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    core_daemon::init_logging(cli.log_format)?;
    tracing::info!("daemon-launcher starting");

    #[cfg(target_os = "linux")]
    {
        platform_linux::security::harden_process();
        platform_linux::security::apply_resource_limits(
            &platform_linux::security::ResourceLimits {
                nofile: 4096,
                memlock_bytes: 0,
            },
        );
    }

    let shutdown = Shutdown::register()?;
    let (layout, config) = core_daemon::startup()?;
    let mut events = EventLoop::new(
        IDENTITY.daemon,
        shutdown,
        core_daemon::watch_config(&layout, config)?,
    );
    let initial = events.candidate()?;
    #[cfg(target_os = "linux")]
    let launcher_key = initial.snapshot.config.global.launcher_key.clone();

    // Desktop entries are scanned once (blocking I/O); launches use the
    // cached Exec lines.
    let (items, entry_cache) = tokio::task::spawn_blocking(|| {
        let (items, cached) = scanner::scan_all();
        let cache: HashMap<String, scanner::CachedEntry> =
            cached.into_iter().map(|e| (e.id.clone(), e)).collect();
        (items, cache)
    })
    .await
    .context("desktop entry scan task failed")?;
    let matcher = FuzzyMatcher::new(Arc::new(|| {}));
    let item_count = items.len();
    inject_items(&matcher.injector(), items);
    tracing::info!(item_count, "desktop entries indexed");

    let frecency = open_frecency(&layout, &cli.profile)?;
    let engine = SearchEngine::new(matcher, cli.profile, frecency)
        .context("failed to read frecency scores")?;
    let client = core_daemon::connect_bus(&layout, &IDENTITY).await?;
    let launcher = launch::Launcher {
        cache: entry_cache,
        config_state: events.application().clone(),
        bus_socket: layout.bus_socket()?,
    };

    // Secure memory before any ProtectedAlloc use (fetched secrets).
    core_types::init_secure_memory();
    #[cfg(target_os = "linux")]
    let portal = bind_portal(&launcher_key).await?;
    let mut daemon = Daemon {
        layout,
        engine,
        launcher,
        client,
        #[cfg(target_os = "linux")]
        portal_required: portal.is_some(),
        #[cfg(target_os = "linux")]
        portal,
    };
    initial.applied(&daemon.client).await;
    core_daemon::announce_started(&daemon.client, &IDENTITY).await;
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
    tracing::info!("daemon-launcher ready, entering event loop");
    daemon.serve(&mut events).await?;

    core_daemon::announce_stopped(&daemon.client).await;
    tracing::info!("daemon-launcher shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_unlocks_are_brokered_for_daemon_wm_only() {
        assert_eq!(keyring_unlock_refusal(Some("daemon-wm")), None);
        let other = keyring_unlock_refusal(Some("daemon-clipboard")).expect("refused");
        assert!(other.contains("daemon-clipboard"), "{other}");
        let unverified = keyring_unlock_refusal(None).expect("refused");
        assert!(unverified.contains("unverified"), "{unverified}");
    }

    #[test]
    fn only_daemon_secrets_factor_answers_are_relayed() {
        let profile = TrustProfileName::try_from("work").unwrap();
        assert!(is_factor_answer(&EventKind::FactorResponse {
            accepted: true,
            unlock_complete: true,
            remaining_factors: vec![],
            remaining_additional: 0,
            profile: profile.clone(),
            error: None,
        }));
        assert!(is_factor_answer(&EventKind::UnlockRejected {
            reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
            profile: Some(profile.clone()),
        }));
        assert!(!is_factor_answer(&EventKind::AccessDenied {
            reason: "denied".into()
        }));
        assert!(!is_factor_answer(&EventKind::KeyringUnlockFailed {
            profile,
            reason: "locked".into()
        }));
    }
}
