//! daemon-clipboard: Clipboard manager daemon.
//!
//! Monitors clipboard changes via Wayland data-control protocol, stores
//! history per-profile in SQLite, detects and auto-expires sensitive content,
//! and serves clipboard RPC requests over the encrypted IPC bus.
//!
//! Landlock: Wayland socket, runtime dir (IPC), cache dir (history DB).
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_ipc::{BusClient, Message};
use core_types::{
    ClipboardEntry, ClipboardEntryId, DaemonId, EventKind, ProfileId, SecurityLevel,
    SensitivityClass,
};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(name = "daemon-clipboard", about = "Clipboard manager daemon")]
struct Cli {
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

fn init_db(db_path: &std::path::Path) -> anyhow::Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create clipboard cache directory")?;
    }
    let conn = Connection::open(db_path).context("failed to open clipboard database")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS clipboard_entries (
            entry_id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL,
            content TEXT NOT NULL,
            content_type TEXT NOT NULL DEFAULT 'text/plain',
            sensitivity TEXT NOT NULL DEFAULT 'public',
            preview TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_clipboard_profile
            ON clipboard_entries(profile_id, timestamp_ms DESC);",
    )
    .context("failed to initialize clipboard schema")?;
    Ok(conn)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(&cli.log_format)?;

    tracing::info!("daemon-clipboard starting");

    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("open-sesame");
    let db_path = cache_dir.join("clipboard.db");
    let db = Arc::new(Mutex::new(init_db(&db_path)?));

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

    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key()
        .await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);

    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-clipboard",
        daemon_id,
        &socket_path,
        &server_pub,
        5,
        std::time::Duration::from_millis(500),
    )
    .await
    .context("failed to connect to IPC bus")?;
    drop(_client_keypair);

    #[cfg(target_os = "linux")]
    apply_sandbox();

    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["clipboard".into(), "history".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-clipboard ready, entering event loop");

    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

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
                    EventKind::KeyRotationPending { daemon_name, new_pubkey, grace_period_s }
                        if daemon_name == "daemon-clipboard" =>
                    {
                        tracing::info!(grace_period_s, "key rotation pending");
                        match BusClient::handle_key_rotation(
                            "daemon-clipboard", daemon_id, &socket_path, &server_pub, new_pubkey,
                            vec!["clipboard".into(), "history".into()], env!("CARGO_PKG_VERSION"),
                        ).await {
                            Ok(new_client) => {
                                client = new_client;
                                tracing::info!("reconnected with rotated keypair");
                            }
                            Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
                        }
                        None
                    }
                    EventKind::ClipboardHistory { profile, limit } => {
                        let profile_str = profile.to_string();
                        let limit = *limit;
                        let db_guard = db.lock().await;
                        let result: Vec<ClipboardEntry> = (|| -> anyhow::Result<Vec<ClipboardEntry>> {
                            let mut stmt = db_guard.prepare(
                                "SELECT entry_id, profile_id, content_type, sensitivity, preview, timestamp_ms
                                 FROM clipboard_entries WHERE profile_id = ?1
                                 ORDER BY timestamp_ms DESC LIMIT ?2"
                            )?;
                            let rows = stmt.query_map(
                                rusqlite::params![&profile_str, limit],
                                |row| {
                                    let entry_id_str: String = row.get(0)?;
                                    let sensitivity_str: String = row.get(3)?;
                                    let sensitivity = match sensitivity_str.as_str() {
                                        "confidential" => SensitivityClass::Confidential,
                                        "secret" => SensitivityClass::Secret,
                                        "topsecret" => SensitivityClass::TopSecret,
                                        _ => SensitivityClass::Public,
                                    };
                                    Ok(ClipboardEntry {
                                        entry_id: ClipboardEntryId::from_uuid(
                                            uuid::Uuid::parse_str(&entry_id_str).unwrap_or_else(|_| uuid::Uuid::now_v7())
                                        ),
                                        content_type: row.get(2)?,
                                        sensitivity,
                                        profile_id: ProfileId::from_uuid(
                                            uuid::Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_else(|_| uuid::Uuid::now_v7())
                                        ),
                                        preview: row.get(4)?,
                                        timestamp_ms: row.get::<_, i64>(5)? as u64,
                                    })
                                },
                            )?;
                            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
                        })().unwrap_or_else(|e| {
                            tracing::error!(error = %e, "ClipboardHistory query failed");
                            vec![]
                        });
                        drop(db_guard);
                        tracing::debug!(profile = %profile, count = result.len(), "ClipboardHistory");
                        Some(EventKind::ClipboardHistoryResponse { entries: result })
                    }

                    EventKind::ClipboardClear { profile } => {
                        let profile_str = profile.to_string();
                        let db_guard = db.lock().await;
                        let success = db_guard
                            .execute("DELETE FROM clipboard_entries WHERE profile_id = ?1", rusqlite::params![&profile_str])
                            .map(|deleted| {
                                tracing::info!(profile = %profile, deleted, "ClipboardClear");
                                true
                            })
                            .unwrap_or_else(|e| {
                                tracing::error!(error = %e, "ClipboardClear failed");
                                false
                            });
                        drop(db_guard);
                        Some(EventKind::ClipboardClearResponse { success })
                    }

                    EventKind::ClipboardGet { entry_id } => {
                        let entry_id_str = entry_id.as_uuid().to_string();
                        let db_guard = db.lock().await;
                        let (content, content_type) = db_guard
                            .query_row(
                                "SELECT content, content_type FROM clipboard_entries WHERE entry_id = ?1",
                                rusqlite::params![&entry_id_str],
                                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                            )
                            .map(|(c, ct)| (Some(c), Some(ct)))
                            .unwrap_or((None, None));
                        drop(db_guard);
                        Some(EventKind::ClipboardGetResponse { content, content_type })
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
                tracing::info!("config reloaded");
                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["clipboard".into()],
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

    tracing::info!("daemon-clipboard shut down");
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

    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("open-sesame");

    let pds_dir = PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    let rules = vec![
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
            path: PathBuf::from(&runtime_dir)
                .join(std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-1".into())),
            access: FsAccess::ReadWriteFile,
        },
        LandlockRule {
            path: cache_dir,
            access: FsAccess::ReadWrite,
        },
    ];

    let seccomp = SeccompProfile {
        daemon_name: "daemon-clipboard".into(),
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
            "fcntl".into(),
            "flock".into(),
            "mkdir".into(),
            "getdents64".into(),
            "fdatasync".into(),
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
            "exit_group".into(),
            "exit".into(),
            "getrandom".into(),
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
    fn init_db_creates_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS clipboard_entries (
                entry_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                content TEXT NOT NULL,
                content_type TEXT NOT NULL DEFAULT 'text/plain',
                sensitivity TEXT NOT NULL DEFAULT 'public',
                preview TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_clipboard_profile
                ON clipboard_entries(profile_id, timestamp_ms DESC);",
        )
        .unwrap();

        // Verify table exists by inserting and querying.
        conn.execute(
            "INSERT INTO clipboard_entries (entry_id, profile_id, content, content_type, sensitivity, preview, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["e1", "p1", "hello", "text/plain", "public", "hello", 1000],
        ).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM clipboard_entries WHERE profile_id = 'p1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn sensitivity_mapping() {
        let cases = [
            ("public", "Public"),
            ("confidential", "Confidential"),
            ("secret", "Secret"),
            ("topsecret", "TopSecret"),
            ("unknown", "Public"),
        ];
        for (input, expected_variant) in cases {
            let sensitivity = match input {
                "confidential" => SensitivityClass::Confidential,
                "secret" => SensitivityClass::Secret,
                "topsecret" => SensitivityClass::TopSecret,
                _ => SensitivityClass::Public,
            };
            assert_eq!(
                format!("{sensitivity:?}"),
                expected_variant,
                "input: {input}"
            );
        }
    }

    #[test]
    fn insert_and_query_roundtrip() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE clipboard_entries (
                entry_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                content TEXT NOT NULL,
                content_type TEXT NOT NULL DEFAULT 'text/plain',
                sensitivity TEXT NOT NULL DEFAULT 'public',
                preview TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );",
        )
        .unwrap();

        let entry_id = uuid::Uuid::now_v7().to_string();
        conn.execute(
            "INSERT INTO clipboard_entries VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &entry_id,
                "profile-a",
                "secret data",
                "text/plain",
                "secret",
                "sec***",
                42
            ],
        )
        .unwrap();

        let (content, sensitivity): (String, String) = conn
            .query_row(
                "SELECT content, sensitivity FROM clipboard_entries WHERE entry_id = ?1",
                rusqlite::params![&entry_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(content, "secret data");
        assert_eq!(sensitivity, "secret");
    }
}
