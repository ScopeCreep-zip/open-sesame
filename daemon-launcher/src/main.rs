//! daemon-launcher: Application launcher daemon.
//!
//! Scans XDG desktop entries, builds a nucleo fuzzy index with frecency
//! ranking, and serves LaunchQuery/LaunchExecute requests over the IPC bus.

use anyhow::Context;
use clap::Parser;
use core_fuzzy::{FrecencyDb, FuzzyMatcher, SearchEngine, inject_items};
use core_ipc::{BusClient, Message};
use core_types::{
    DaemonId, EventKind, LaunchDenial, LaunchResult, SecurityLevel, TrustProfileName,
};
use std::collections::HashMap;
use std::sync::Arc;

mod launch;
mod scanner;

#[derive(Parser)]
#[command(name = "daemon-launcher")]
struct Cli {
    /// Profile to scope the launcher to.
    #[arg(long, default_value = core_types::DEFAULT_PROFILE_NAME)]
    profile: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Validate profile name at CLI boundary (fail-fast).
    let profile: TrustProfileName = TrustProfileName::try_from(cli.profile.clone())
        .map_err(|e| anyhow::anyhow!("invalid trust profile name '{}': {e}", cli.profile))?;

    // Logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("daemon-launcher starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 4096,
        memlock_bytes: 0,
    });

    // -- Directory bootstrap --
    core_config::bootstrap_dirs();

    // Config hot-reload.
    let config = core_config::load_config(None).context("failed to load config")?;
    let config_paths = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, _config_state) = core_config::ConfigWatcher::with_callback(
        &config_paths,
        config,
        Some(Box::new(move || {
            let _ = reload_tx.blocking_send(());
        })),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Frecency DB: per-profile, plaintext SQLite (not secrets).
    let data_dir = core_config::config_dir().join("launcher");
    std::fs::create_dir_all(&data_dir).context("failed to create launcher data directory")?;
    let frecency_path = data_dir.join(format!("{}.frecency.db", &*profile));
    let frecency = FrecencyDb::open(&frecency_path).context("failed to open frecency database")?;

    // Fuzzy matcher.
    let matcher = FuzzyMatcher::new(Arc::new(|| {}));

    // Scan desktop entries (blocking I/O) — cache Exec lines before sandbox.
    let (items, entry_cache) = tokio::task::spawn_blocking(|| {
        let (items, cached) = scanner::scan_all();
        let cache: HashMap<String, scanner::CachedEntry> =
            cached.into_iter().map(|e| (e.id.clone(), e)).collect();
        (items, cache)
    })
    .await
    .context("desktop entry scan task failed")?;
    let item_count = items.len();

    // Inject items into the matcher.
    let injector = matcher.injector();
    inject_items(&injector, items);
    tracing::info!(item_count, "desktop entries indexed");

    // Search engine: fuzzy + frecency.
    let mut engine = SearchEngine::new(matcher, frecency, profile.clone());
    engine.refresh_frecency().ok(); // Non-fatal if DB is empty.

    // Connect to IPC bus: read keypair BEFORE sandbox.
    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key()
        .await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);

    // Connect with keypair retry (daemon-profile may regenerate on crash-restart).
    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-launcher",
        daemon_id,
        &socket_path,
        &server_pub,
        5,
        std::time::Duration::from_millis(500),
    )
    .await
    .context("failed to connect to IPC bus")?;
    // No sandbox: seccomp/Landlock inherit across fork+exec and would kill
    // every child process. Security boundary is IPC bus auth (Noise IK).

    // Announce startup.
    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["launcher".into(), "fuzzy-search".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    // Platform readiness.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-launcher ready, entering event loop");

    // Watchdog timer: half the WatchdogSec=30 interval.
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // Event loop.
    let mut watchdog_count: u64 = 0;
    let mut loop_count: u64 = 0;
    loop {
        loop_count += 1;
        if loop_count <= 5 || loop_count.is_multiple_of(500) {
            tracing::debug!(loop_count, "select loop top");
        }
        tokio::select! {
            _ = watchdog.tick() => {
                watchdog_count += 1;
                tracing::info!(watchdog_count, loop_count, "watchdog tick");
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            msg_opt = client.recv() => {
                match msg_opt {
                    None => {
                        tracing::error!("IPC client.recv() returned None — server disconnected, exiting");
                        break;
                    }
                    Some(msg) => {
                        tracing::debug!(
                            sender = %msg.sender,
                            msg_id = %msg.msg_id,
                            "IPC message received"
                        );

                        // Skip self-published messages to prevent feedback loops.
                        if msg.sender == daemon_id {
                            tracing::trace!("skipping self-published message");
                            continue;
                        }

                        let response_event = match &msg.payload {
                            EventKind::LaunchQuery { query, max_results, profile } => {
                                tracing::info!(%query, max_results, "handling LaunchQuery");
                                // Switch frecency context if profile differs.
                                if let Some(p) = profile
                                    && p != engine.profile_id()
                                    && let Err(e) = engine.switch_profile(p.clone())
                                {
                                    tracing::warn!(profile = %p, error = %e, "frecency profile switch failed");
                                }
                                let results = engine.query(query, *max_results);
                                tracing::info!(result_count = results.len(), "LaunchQuery complete");
                                Some(EventKind::LaunchQueryResponse {
                                    results: results
                                        .into_iter()
                                        .map(|r| LaunchResult {
                                            entry_id: r.entry_id,
                                            name: r.name,
                                            icon: r.icon,
                                            score: r.score,
                                        })
                                        .collect(),
                                })
                            }

                            EventKind::LaunchExecute { entry_id, profile, tags, launch_args } => {
                                tracing::info!(%entry_id, ?profile, ?tags, ?launch_args, "handling LaunchExecute");
                                if let Err(e) = engine.record_launch(entry_id) {
                                    tracing::warn!(entry_id, error = %e, "frecency record failed");
                                }
                                match launch::launch_entry(entry_id, profile.as_ref().map(|p| p.as_ref()), tags, launch_args, &entry_cache, &client, &_config_state).await {
                                    Ok(pid) => {
                                        tracing::info!(%entry_id, pid, "launch succeeded");
                                        Some(EventKind::LaunchExecuteResponse { pid, error: None, denial: None })
                                    }
                                    Err(launch::LaunchError::Denial(denial)) => {
                                        let error_msg = format!("{denial:?}");
                                        tracing::error!(entry_id, ?denial, "launch denied");
                                        Some(EventKind::LaunchExecuteResponse { pid: 0, error: Some(error_msg), denial: Some(denial) })
                                    }
                                    Err(launch::LaunchError::Other(e)) => {
                                        tracing::error!(entry_id, error = %e, "launch failed");
                                        Some(EventKind::LaunchExecuteResponse {
                                            pid: 0,
                                            error: Some(e.to_string()),
                                            denial: Some(LaunchDenial::SpawnFailed { reason: e.to_string() }),
                                        })
                                    }
                                }
                            }

                            // Key rotation — reconnect with new keypair.
                            EventKind::KeyRotationPending { daemon_name, new_pubkey, grace_period_s }
                                if daemon_name == "daemon-launcher" =>
                            {
                                tracing::info!(grace_period_s, "key rotation pending, will reconnect with new keypair");
                                match BusClient::handle_key_rotation(
                                    "daemon-launcher", daemon_id, &socket_path, &server_pub, new_pubkey,
                                    vec!["launcher".into(), "fuzzy-search".into()], env!("CARGO_PKG_VERSION"),
                                ).await {
                                    Ok(new_client) => {
                                        client = new_client;
                                        tracing::info!("reconnected with rotated keypair");
                                    }
                                    Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
                                }
                                None
                            }

                            // Ignore events not addressed to us.
                            _ => None,
                        };

                        if let Some(event) = response_event {
                            let response = Message::new(
                                &msg_ctx,
                                event,
                                msg.security_level,
                                client.epoch(),
                            )
                            .with_correlation(msg.msg_id);
                            if let Err(e) = client.send(&response).await {
                                tracing::warn!(error = %e, "failed to send response");
                            }
                        }
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                tracing::info!("config reloaded");
                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["launcher".into()],
                    },
                    SecurityLevel::Internal,
                ).await.ok();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received, shutting down");
                break;
            }
            _ = sigterm() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
        }
    }

    // Best-effort shutdown announcement.
    client
        .publish(
            EventKind::DaemonStopped {
                daemon_id,
                reason: "shutdown".into(),
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    tracing::info!("daemon-launcher shutting down");
    Ok(())
}

/// Wait for SIGTERM (Unix) or block forever on non-Unix.
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        sig.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}
