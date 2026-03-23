//! daemon-snippets: Snippet expansion daemon.
//!
//! Manages text snippet templates with variable substitution and secret
//! injection. Snippets are profile-scoped: each trust profile has its own
//! snippet namespace. Expansion requests arrive over the encrypted IPC bus
//! and are served from an in-memory cache backed by config-defined templates.
//!
//! Landlock: runtime dir (IPC), config dir (read-only).
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, SecurityLevel, SnippetInfo};
use std::collections::HashMap;

/// In-memory snippet store: (profile_name, trigger) -> template.
type SnippetMap = HashMap<(String, String), String>;

#[derive(Parser, Debug)]
#[command(name = "daemon-snippets", about = "Snippet expansion daemon")]
struct Cli {
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

/// Build snippet map from config. Config schema does not yet have a dedicated
/// snippets section, so snippets are managed in-memory via SnippetAdd RPC.
fn build_snippet_map(_config: &core_config::Config) -> SnippetMap {
    HashMap::new()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(&cli.log_format)?;

    tracing::info!("daemon-snippets starting");

    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 4096,
        memlock_bytes: 0,
    });

    // -- Directory bootstrap --
    core_config::bootstrap_dirs();

    let config = core_config::load_config(None).context("failed to load config")?;

    let mut snippets = build_snippet_map(&config);

    let config_paths = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, config_state) = core_config::ConfigWatcher::with_callback(
        &config_paths,
        config,
        Some(Box::new(move || {
            let _ = reload_tx.blocking_send(());
        })),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key()
        .await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);

    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-snippets",
        daemon_id,
        &socket_path,
        &server_pub,
        5,
        std::time::Duration::from_millis(500),
    )
    .await
    .context("failed to connect to IPC bus")?;
    drop(_client_keypair);

    core_types::init_secure_memory();

    #[cfg(target_os = "linux")]
    apply_sandbox();

    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["snippets".into(), "expansion".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-snippets ready, entering event loop");

    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));
    let mut watchdog_count: u64 = 0;

    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                watchdog_count += 1;
                if watchdog_count <= 3 || watchdog_count.is_multiple_of(20) {
                    tracing::info!(watchdog_count, "watchdog tick");
                }
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            Some(msg) = client.recv() => {
                // Skip self-published messages to prevent feedback loops.
                if msg.sender == daemon_id {
                    continue;
                }

                let response_event = match &msg.payload {
                    EventKind::KeyRotationPending { daemon_name, new_pubkey, grace_period_s }
                        if daemon_name == "daemon-snippets" =>
                    {
                        tracing::info!(grace_period_s, "key rotation pending");
                        match BusClient::handle_key_rotation(
                            "daemon-snippets", daemon_id, &socket_path, &server_pub, new_pubkey,
                            vec!["snippets".into(), "expansion".into()], env!("CARGO_PKG_VERSION"),
                        ).await {
                            Ok(new_client) => {
                                client = new_client;
                                tracing::info!("reconnected with rotated keypair");
                            }
                            Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
                        }
                        None
                    }

                    EventKind::SnippetList { profile } => {
                        let profile_str = profile.to_string();
                        let result: Vec<SnippetInfo> = snippets.iter()
                            .filter(|((p, _), _)| p == &profile_str)
                            .map(|((_, trigger), template)| SnippetInfo {
                                trigger: trigger.clone(),
                                template_preview: if template.len() > 80 {
                                    format!("{}...", &template[..77])
                                } else {
                                    template.clone()
                                },
                            })
                            .collect();
                        tracing::debug!(profile = %profile, count = result.len(), "SnippetList");
                        Some(EventKind::SnippetListResponse { snippets: result })
                    }

                    EventKind::SnippetExpand { profile, trigger } => {
                        let key = (profile.to_string(), trigger.clone());
                        let expanded = snippets.get(&key).cloned();
                        tracing::debug!(profile = %profile, trigger = %trigger, found = expanded.is_some(), "SnippetExpand");
                        Some(EventKind::SnippetExpandResponse { expanded })
                    }

                    EventKind::SnippetAdd { profile, trigger, template } => {
                        let key = (profile.to_string(), trigger.clone());
                        snippets.insert(key, template.clone());
                        tracing::info!(profile = %profile, trigger = %trigger, "snippet added");
                        Some(EventKind::SnippetAddResponse { success: true })
                    }

                    _ => None,
                };

                if let Some(event) = response_event {
                    let response = Message::new(
                        &msg_ctx, event, msg.security_level, client.epoch(),
                    ).with_correlation(msg.msg_id);
                    if let Err(e) = client.send(&response).await {
                        tracing::warn!(error = %e, "failed to send response");
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                if let Ok(cfg) = config_state.read() {
                    snippets = build_snippet_map(&cfg);
                }
                tracing::info!("config reloaded, snippet map refreshed");
                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["snippets".into()],
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

    tracing::info!("daemon-snippets shut down");
    Ok(())
}

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

#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{FsAccess, LandlockRule, SeccompProfile, apply_sandbox};

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());

    let pds_dir = std::path::PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    let config_dir = core_config::config_dir();

    // Resolve config symlink targets (e.g. /nix/store) before Landlock.
    let config_real_dirs = core_config::resolve_config_real_dirs(None);

    let mut rules = vec![
        LandlockRule {
            path: keys_dir.clone(),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: pds_dir.join("bus.pub"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: pds_dir.join("bus.sock"),
            access: FsAccess::ReadWriteFile,
        },
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadOnly,
        },
    ];

    // Config symlink targets (e.g. /nix/store paths) need read access
    // for config hot-reload to follow symlinks after Landlock is applied.
    for dir in &config_real_dirs {
        rules.push(LandlockRule {
            path: dir.clone(),
            access: FsAccess::ReadOnly,
        });
    }

    let seccomp = SeccompProfile {
        daemon_name: "daemon-snippets".into(),
        allowed_syscalls: vec![
            "read".into(),
            "write".into(),
            "close".into(),
            "openat".into(),
            "lseek".into(),
            "pread64".into(),
            "fstat".into(),
            "stat".into(),
            "newfstatat".into(),
            "statx".into(),
            "access".into(),
            "readlink".into(),
            "fcntl".into(),
            "mkdir".into(),
            "getdents64".into(),
            "ioctl".into(),
            "mmap".into(),
            "mprotect".into(),
            "munmap".into(),
            "madvise".into(),
            "brk".into(),
            "futex".into(),
            "clone3".into(),
            "clone".into(),
            "set_robust_list".into(),
            "set_tid_address".into(),
            "rseq".into(),
            "sched_getaffinity".into(),
            "prlimit64".into(),
            "prctl".into(),
            "getpid".into(),
            "gettid".into(),
            "getuid".into(),
            "geteuid".into(),
            "kill".into(),
            "epoll_wait".into(),
            "epoll_ctl".into(),
            "epoll_create1".into(),
            "eventfd2".into(),
            "poll".into(),
            "ppoll".into(),
            "clock_gettime".into(),
            "timer_create".into(),
            "timer_settime".into(),
            "timer_delete".into(),
            "socket".into(),
            "connect".into(),
            "sendto".into(),
            "recvfrom".into(),
            "recvmsg".into(),
            "sendmsg".into(),
            "getsockname".into(),
            "getpeername".into(),
            "setsockopt".into(),
            "socketpair".into(),
            "shutdown".into(),
            "getsockopt".into(),
            "sigaltstack".into(),
            "rt_sigaction".into(),
            "rt_sigprocmask".into(),
            "rt_sigreturn".into(),
            "tgkill".into(),
            // Config hot-reload (notify crate uses inotify)
            "inotify_init1".into(),
            "inotify_add_watch".into(),
            "inotify_rm_watch".into(),
            "exit_group".into(),
            "exit".into(),
            "getrandom".into(),
            "memfd_secret".into(),
            "ftruncate".into(),
            "restart_syscall".into(),
            "pipe2".into(),
            "dup".into(),
        ],
    };

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} -- refusing to run unsandboxed");
        }
    }
}

fn init_logging(format: &str) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_snippet_map_returns_empty() {
        let config = core_config::Config::default();
        let map = build_snippet_map(&config);
        assert!(map.is_empty());
    }

    #[test]
    fn snippet_crud() {
        let mut snippets: SnippetMap = HashMap::new();

        // Insert
        snippets.insert(("work".into(), "addr".into()), "123 Main St".into());
        snippets.insert(("personal".into(), "addr".into()), "456 Oak Ave".into());

        // Lookup
        assert_eq!(
            snippets.get(&("work".into(), "addr".into())),
            Some(&"123 Main St".into()),
        );

        // List by profile
        let work_snippets: Vec<_> = snippets.iter().filter(|((p, _), _)| p == "work").collect();
        assert_eq!(work_snippets.len(), 1);

        // Overwrite
        snippets.insert(("work".into(), "addr".into()), "789 Elm Blvd".into());
        assert_eq!(
            snippets.get(&("work".into(), "addr".into())),
            Some(&"789 Elm Blvd".into()),
        );
    }

    #[test]
    fn snippet_info_preview_truncation() {
        let long_template = "a".repeat(100);
        let preview = if long_template.len() > 80 {
            format!("{}...", &long_template[..77])
        } else {
            long_template.clone()
        };
        assert_eq!(preview.len(), 80);
        assert!(preview.ends_with("..."));
    }
}
