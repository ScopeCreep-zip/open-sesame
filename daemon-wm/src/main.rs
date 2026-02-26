//! daemon-wm: Wayland overlay window switcher daemon.
//!
//! Tracks open windows via wlr-foreign-toplevel-management-v1, maintains MRU
//! ordering, and serves WmListWindows/WmActivateWindow RPC requests over the
//! encrypted IPC bus. The overlay rendering pipeline (layer-shell surface,
//! hint labels, input handling) is initialized when compositor detection
//! succeeds.
//!
//! Landlock: Wayland socket, fontconfig, cache dir (MRU state).
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, SecurityLevel, Window};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Window manager daemon.
#[derive(Parser, Debug)]
#[command(name = "daemon-wm", about = "Window manager overlay daemon")]
struct Cli {
    /// Log format: "json" or "pretty".
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(&cli.log_format)?;

    tracing::info!("daemon-wm starting");

    // Load config.
    let config = core_config::load_config(None)
        .context("failed to load config")?;
    let _wm_config = config
        .profiles
        .values()
        .next()
        .map(|p| p.wm.clone())
        .unwrap_or_default();

    tracing::info!(
        hint_keys = %_wm_config.hint_keys,
        overlay_delay_ms = _wm_config.overlay_delay_ms,
        "wm config loaded"
    );

    // Sandbox (Linux).
    #[cfg(target_os = "linux")]
    apply_sandbox();

    // Connect to IPC bus.
    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key().await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();
    let mut client = BusClient::connect_encrypted(daemon_id, &socket_path, &server_pub)
        .await
        .context("failed to connect to IPC bus")?;

    // Announce startup.
    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["wm".into(), "window-switcher".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    // Window list — populated by compositor backend (when available).
    let windows: Arc<Mutex<Vec<Window>>> = Arc::new(Mutex::new(Vec::new()));

    // Compositor backend — try to detect, but continue without it.
    // The daemon still serves RPC requests with an empty window list.
    #[cfg(target_os = "linux")]
    {
        match platform_linux::compositor::detect_compositor() {
            Ok(backend) => {
                tracing::info!(backend = backend.name(), "compositor backend detected");
                // TODO: spawn toplevel monitor task when backend is implemented.
            }
            Err(e) => {
                tracing::warn!(error = %e, "compositor detection failed; window list will be empty until backend is implemented");
            }
        }
    }

    // Platform readiness.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-wm ready, entering event loop");

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
                let response_event = match &msg.payload {
                    EventKind::WmListWindows => {
                        let win_list = windows.lock().await.clone();
                        Some(EventKind::WmListWindowsResponse { windows: win_list })
                    }

                    EventKind::WmActivateWindow { window_id } => {
                        let win_list = windows.lock().await;
                        let found = win_list.iter().any(|w| {
                            w.id.to_string() == *window_id
                                || w.app_id.as_str() == window_id
                        });

                        if found {
                            // Record MRU state.
                            let origin = win_list.iter()
                                .find(|w| w.is_focused)
                                .map(|w| w.id.to_string());
                            daemon_wm::mru::save(origin.as_deref(), window_id);

                            tracing::info!(window_id, "window activation requested");
                            Some(EventKind::WmActivateWindowResponse { success: true })
                        } else {
                            tracing::warn!(window_id, "window not found for activation");
                            Some(EventKind::WmActivateWindowResponse { success: false })
                        }
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

    // Shutdown.
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

    tracing::info!("daemon-wm shut down");
    Ok(())
}

/// Wait for SIGTERM (Unix).
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

/// Apply Landlock + seccomp sandbox (Linux only).
#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{
        apply_sandbox, FsAccess, LandlockRule, SeccompProfile,
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| "/run/user/1000".into());

    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("open-sesame");

    let rules = vec![
        LandlockRule {
            path: std::path::PathBuf::from(&runtime_dir).join("pds"),
            access: FsAccess::ReadWrite,
        },
        // Wayland socket access (use $WAYLAND_DISPLAY, default wayland-1 for COSMIC).
        LandlockRule {
            path: std::path::PathBuf::from(&runtime_dir).join(
                std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-1".into()),
            ),
            access: FsAccess::ReadWrite,
        },
        // MRU state file.
        LandlockRule {
            path: cache_dir,
            access: FsAccess::ReadWrite,
        },
        // Fontconfig (read-only).
        LandlockRule {
            path: std::path::PathBuf::from("/etc/fonts"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: std::path::PathBuf::from("/usr/share/fonts"),
            access: FsAccess::ReadOnly,
        },
    ];

    let seccomp = SeccompProfile {
        daemon_name: "daemon-wm".into(),
        allowed_syscalls: vec![
            // I/O basics
            "read".into(), "write".into(), "close".into(),
            "openat".into(), "lseek".into(), "pread64".into(),
            "fstat".into(), "stat".into(), "newfstatat".into(),
            "statx".into(), "access".into(), "fcntl".into(),
            "flock".into(), "ftruncate".into(), "mkdir".into(),
            "rename".into(), "chmod".into(), "fchmod".into(),
            "fsync".into(), "fdatasync".into(), "ioctl".into(),
            "getdents64".into(),
            // Memory
            "mmap".into(), "mprotect".into(), "munmap".into(),
            "madvise".into(), "brk".into(),
            // Process / threading
            "futex".into(), "clone3".into(), "clone".into(),
            "set_robust_list".into(), "set_tid_address".into(),
            "rseq".into(), "sched_getaffinity".into(),
            "prlimit64".into(), "prctl".into(),
            "getpid".into(), "gettid".into(), "geteuid".into(),
            "kill".into(),
            // Epoll / event loop (tokio)
            "epoll_wait".into(), "epoll_ctl".into(),
            "epoll_create1".into(), "eventfd2".into(),
            "poll".into(), "ppoll".into(),
            // Timers (tokio runtime)
            "clock_gettime".into(), "timer_create".into(),
            "timer_settime".into(), "timer_delete".into(),
            // Networking / IPC (Wayland compositor protocol)
            "socket".into(), "connect".into(), "sendto".into(),
            "recvfrom".into(), "recvmsg".into(), "sendmsg".into(),
            "getsockname".into(), "getpeername".into(),
            "setsockopt".into(), "socketpair".into(),
            "shutdown".into(), "getsockopt".into(),
            // Signals
            "sigaltstack".into(), "rt_sigaction".into(),
            "rt_sigprocmask".into(), "rt_sigreturn".into(),
            "tgkill".into(),
            // Misc
            "exit_group".into(), "exit".into(), "getrandom".into(),
            "restart_syscall".into(),
            "pipe2".into(), "dup".into(), "ioctl".into(),
        ],
    };

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

fn init_logging(format: &str) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }

    Ok(())
}
