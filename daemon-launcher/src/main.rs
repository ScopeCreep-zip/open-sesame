//! daemon-launcher: Application launcher daemon.
//!
//! Scans XDG desktop entries, builds a nucleo fuzzy index with frecency
//! ranking, and serves LaunchQuery/LaunchExecute requests over the IPC bus.
//!
//! GTK4 layer-shell UI is behind the `gtk` feature flag.

use anyhow::Context;
use clap::Parser;
use core_fuzzy::{FrecencyDb, FuzzyMatcher, SearchEngine, inject_items};
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, LaunchResult, SecurityLevel, TrustProfileName};
use std::sync::Arc;

mod scanner;

#[derive(Parser)]
#[command(name = "daemon-launcher")]
struct Cli {
    /// Profile to scope the launcher to.
    #[arg(long, default_value = "default")]
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

    // Config hot-reload.
    let config = core_config::load_config(None)
        .context("failed to load config")?;
    let config_paths = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, _config_state) = core_config::ConfigWatcher::with_callback(
        &config_paths,
        config,
        Some(Box::new(move || { let _ = reload_tx.blocking_send(()); })),
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Frecency DB: per-profile, plaintext SQLite (not secrets).
    let data_dir = core_config::config_dir().join("launcher");
    std::fs::create_dir_all(&data_dir)
        .context("failed to create launcher data directory")?;
    let frecency_path = data_dir.join(format!("{}.frecency.db", &*profile));
    let frecency = FrecencyDb::open(&frecency_path)
        .context("failed to open frecency database")?;

    // Fuzzy matcher.
    let matcher = FuzzyMatcher::new(Arc::new(|| {}));

    // Scan desktop entries (blocking I/O).
    let items = tokio::task::spawn_blocking(scanner::scan)
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
    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key().await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();

    // Connect with keypair retry (daemon-profile may regenerate on crash-restart).
    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-launcher", daemon_id, &socket_path, &server_pub, 5,
        std::time::Duration::from_millis(500),
    ).await.context("failed to connect to IPC bus")?;
    // ZeroizingKeypair: private key zeroized on drop (no manual zeroize needed).
    drop(_client_keypair);

    // Sandbox (Linux) — seccomp only; no Landlock because child processes inherit
    // Landlock rules, which would break arbitrary application launches.
    #[cfg(target_os = "linux")]
    apply_sandbox();

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
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            Some(msg) = client.recv() => {
                // Skip self-published messages to prevent feedback loops.
                if msg.sender == daemon_id {
                    continue;
                }

                let response_event = match &msg.payload {
                    EventKind::LaunchQuery { query, max_results, profile } => {
                        // Switch frecency context if profile differs.
                        if let Some(p) = profile
                            && p != engine.profile_id()
                            && let Err(e) = engine.switch_profile(p.clone())
                        {
                            tracing::warn!(profile = %p, error = %e, "frecency profile switch failed");
                        }
                        let results = engine.query(query, *max_results);
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

                    EventKind::LaunchExecute { entry_id, profile } => {
                        // Record the launch for frecency.
                        if let Err(e) = engine.record_launch(entry_id) {
                            tracing::warn!(entry_id, error = %e, "frecency record failed");
                        }

                        // Look up the Exec line from desktop entries and launch.
                        match launch_entry(entry_id, profile.as_ref().map(|p| p.as_ref())).await {
                            Ok(pid) => Some(EventKind::LaunchExecuteResponse { pid }),
                            Err(e) => {
                                tracing::error!(entry_id, error = %e, "launch failed");
                                Some(EventKind::LaunchExecuteResponse { pid: 0 })
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
                        daemon_id,
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
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        sig.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

/// Apply seccomp sandbox (Linux only).
///
/// daemon-launcher uses seccomp ONLY (no Landlock) because Landlock rules inherit
/// to child processes. Since daemon-launcher spawns arbitrary applications via
/// `LaunchExecute`, Landlock inheritance would restrict those applications to the
/// launcher's filesystem view, breaking them. seccomp is acceptable because
/// daemon-launcher has `Internal` clearance (not `SecretsOnly`) and does not
/// handle raw secret values.
#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{
        apply_sandbox, LandlockRule, SeccompProfile,
    };

    let seccomp = SeccompProfile {
        daemon_name: "daemon-launcher".into(),
        allowed_syscalls: vec![
            // I/O basics
            "read".into(), "write".into(), "close".into(),
            "openat".into(), "lseek".into(), "pread64".into(),
            "fstat".into(), "stat".into(), "newfstatat".into(),
            "statx".into(), "access".into(), "fcntl".into(),
            "flock".into(), "mkdir".into(), "getdents64".into(),
            "fdatasync".into(), "ioctl".into(),
            // Memory
            "mmap".into(), "mprotect".into(), "munmap".into(),
            "madvise".into(), "brk".into(),
            // Process / threading
            "futex".into(), "clone3".into(), "clone".into(),
            "set_robust_list".into(), "set_tid_address".into(),
            "rseq".into(), "sched_getaffinity".into(),
            "prlimit64".into(), "prctl".into(),
            "getpid".into(), "gettid".into(), "getuid".into(), "geteuid".into(),
            "kill".into(),
            // Epoll / event loop (tokio)
            "epoll_wait".into(), "epoll_ctl".into(),
            "epoll_create1".into(), "eventfd2".into(),
            "poll".into(), "ppoll".into(),
            // Timers (tokio runtime)
            "clock_gettime".into(), "timer_create".into(),
            "timer_settime".into(), "timer_delete".into(),
            // Networking / IPC
            "socket".into(), "connect".into(), "sendto".into(),
            "recvfrom".into(), "sendmsg".into(), "recvmsg".into(),
            "shutdown".into(), "getsockopt".into(),
            "socketpair".into(),
            // Signals
            "sigaltstack".into(), "rt_sigaction".into(),
            "rt_sigprocmask".into(), "rt_sigreturn".into(),
            "tgkill".into(),
            // Misc
            "exit_group".into(), "exit".into(), "getrandom".into(),
            "restart_syscall".into(),
            "pipe2".into(), "dup".into(),
            // Process spawning (LaunchExecute needs fork/exec).
            "execve".into(), "execveat".into(), "wait4".into(),
            "vfork".into(),
        ],
    };

    // No Landlock rules — seccomp only (see doc comment above).
    let rules: Vec<LandlockRule> = vec![];

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied (seccomp only, no Landlock)");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

/// Launch a desktop entry by its app ID.
///
/// Looks up the entry's Exec line, strips field codes, and spawns the process.
/// If `profile` is provided, `SESAME_PROFILE` is injected into the child environment
/// so the launched application (or sesame SDK) can request profile-scoped secrets.
async fn launch_entry(entry_id: &str, profile: Option<&str>) -> anyhow::Result<u32> {
    let entry_id = entry_id.to_owned();
    let profile = profile.map(|s| s.to_owned());
    let pid = tokio::task::spawn_blocking(move || -> anyhow::Result<u32> {
        let locales = freedesktop_desktop_entry::get_languages_from_env();
        let entries = freedesktop_desktop_entry::desktop_entries(&locales);

        let entry = entries
            .into_iter()
            .find(|e| e.id() == entry_id)
            .ok_or_else(|| anyhow::anyhow!("desktop entry '{entry_id}' not found"))?;

        let exec = entry
            .exec()
            .ok_or_else(|| anyhow::anyhow!("desktop entry '{entry_id}' has no Exec field"))?;

        let cmd = scanner::strip_field_codes(exec);
        let parts = scanner::tokenize_exec(&cmd);
        if parts.is_empty() {
            anyhow::bail!("empty Exec line for '{entry_id}'");
        }

        let mut cmd = std::process::Command::new(&parts[0]);
        cmd.args(&parts[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        if let Some(ref p) = profile {
            cmd.env("SESAME_PROFILE", p);
        }

        let child = cmd.spawn()
            .context("failed to spawn process")?;

        Ok(child.id())
    })
    .await
    .context("launch task panicked")??;

    Ok(pid)
}
