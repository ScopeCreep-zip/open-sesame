//! Process hardening: Landlock filesystem sandbox, seccomp syscall filter,
//! logging initialization, and signal handling.

use anyhow::Context;
use std::path::PathBuf;

/// Wait for SIGTERM (Unix).
pub(crate) async fn sigterm() {
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

/// Apply Landlock + seccomp sandbox (Linux only).
///
/// Ensures all Landlock target directories exist before opening PathFd handles.
/// After `sesame init --wipe-reset-destroy-all-data`, systemd may restart
/// daemon-profile before `sesame init` recreates the wiped directories
/// (`~/.config/pds/` and `$XDG_RUNTIME_DIR/pds/`). Landlock PathFd::new()
/// requires every path in the ruleset to exist.
#[cfg(target_os = "linux")]
pub(crate) fn apply_sandbox() -> anyhow::Result<()> {
    use platform_linux::sandbox::{FsAccess, LandlockRule, LandlockScope, SeccompProfile};

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());

    let config_dir = core_config::config_dir();
    let pds_runtime = PathBuf::from(&runtime_dir).join("pds");

    // Ensure Landlock target directories exist before PathFd::new().
    for dir in [&config_dir, &pds_runtime] {
        if !dir.exists() {
            std::fs::create_dir_all(dir).context(format!("failed to create {}", dir.display()))?;
        }
    }

    // Resolve config symlink targets (e.g. /nix/store) before Landlock.
    let config_real_dirs = core_config::resolve_config_real_dirs(None);

    let mut rules = vec![
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadWrite, // audit log writes here
        },
        LandlockRule {
            path: pds_runtime,
            access: FsAccess::ReadWrite,
        },
    ];

    // systemd notify socket: sd_notify(READY=1) and watchdog keepalives
    // need connect+sendto access to $NOTIFY_SOCKET after Landlock is applied.
    // Abstract sockets (prefixed '@') bypass Landlock AccessFs rules.
    if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET")
        && !notify_socket.starts_with('@')
    {
        let path = PathBuf::from(&notify_socket);
        if path.exists() {
            rules.push(LandlockRule {
                path,
                access: FsAccess::ReadWriteFile,
            });
        }
    }

    // SSH agent socket: daemon-profile hosts the auth dispatcher and needs
    // access to the SSH agent for auto-unlock (can_unlock + sign challenge).
    //
    // Forwarded SSH agent sockets rotate per-session (/tmp/ssh-XXXX/agent.PID).
    // On Konductor VMs, a profile.d script creates a stable symlink at
    // ~/.ssh/agent.sock. Landlock resolves symlinks to their target inodes,
    // so we must grant access to the symlink, its resolved target, and the
    // parent directory of the target for path traversal.
    {
        let mut seen = std::collections::HashSet::new();
        let add_path = |rules: &mut Vec<LandlockRule>,
                        path: PathBuf,
                        access: FsAccess,
                        seen: &mut std::collections::HashSet<PathBuf>| {
            if seen.insert(path.clone()) && (path.exists() || path.is_symlink()) {
                rules.push(LandlockRule { path, access });
            }
        };

        if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            let sock_path = PathBuf::from(&sock);
            add_path(
                &mut rules,
                sock_path.clone(),
                FsAccess::ReadWriteFile,
                &mut seen,
            );

            if let Ok(canonical) = std::fs::canonicalize(&sock_path) {
                add_path(
                    &mut rules,
                    canonical.clone(),
                    FsAccess::ReadWriteFile,
                    &mut seen,
                );
                if let Some(parent) = canonical.parent() {
                    add_path(
                        &mut rules,
                        parent.to_path_buf(),
                        FsAccess::ReadOnly,
                        &mut seen,
                    );
                }
            }
        }

        // Stable fallback: ~/.ssh/agent.sock (forwarded agent symlink)
        if let Some(home) = std::env::var_os("HOME") {
            let ssh_dir = PathBuf::from(&home).join(".ssh");
            let agent_sock = ssh_dir.join("agent.sock");

            add_path(&mut rules, ssh_dir, FsAccess::ReadOnly, &mut seen);
            add_path(
                &mut rules,
                agent_sock.clone(),
                FsAccess::ReadWriteFile,
                &mut seen,
            );

            if let Ok(canonical) = std::fs::canonicalize(&agent_sock) {
                add_path(
                    &mut rules,
                    canonical.clone(),
                    FsAccess::ReadWriteFile,
                    &mut seen,
                );
                if let Some(parent) = canonical.parent() {
                    add_path(
                        &mut rules,
                        parent.to_path_buf(),
                        FsAccess::ReadOnly,
                        &mut seen,
                    );
                }
            }
        }
    }

    // Config symlink targets (e.g. /nix/store paths) need read access
    // for config hot-reload to follow symlinks after Landlock is applied.
    for dir in &config_real_dirs {
        rules.push(LandlockRule {
            path: dir.clone(),
            access: FsAccess::ReadOnly,
        });
    }

    let seccomp = SeccompProfile {
        daemon_name: "daemon-profile".into(),
        allowed_syscalls: vec![
            // I/O basics
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
            "unlink".into(),
            "mkdir".into(),
            "rename".into(),
            "chmod".into(),
            "fchmod".into(),
            "fchown".into(),
            "fcntl".into(),
            "ioctl".into(),
            "fsync".into(),
            "fdatasync".into(),
            "getdents64".into(),
            // Memory
            "mmap".into(),
            "mprotect".into(),
            "munmap".into(),
            "madvise".into(),
            "brk".into(),
            // Process / threading
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
            // Epoll / event loop (tokio)
            "epoll_wait".into(),
            "epoll_ctl".into(),
            "epoll_create1".into(),
            "eventfd2".into(),
            "poll".into(),
            "ppoll".into(),
            // Timers (tokio runtime)
            "clock_gettime".into(),
            "timer_create".into(),
            "timer_settime".into(),
            "timer_delete".into(),
            // Networking / IPC (Unix domain sockets)
            "socket".into(),
            "bind".into(),
            "listen".into(),
            "accept4".into(),
            "connect".into(),
            "sendto".into(),
            "recvfrom".into(),
            "getsockname".into(),
            "getpeername".into(),
            "setsockopt".into(),
            "socketpair".into(),
            "sendmsg".into(),
            "recvmsg".into(),
            "shutdown".into(),
            "getsockopt".into(),
            // Signals
            "sigaltstack".into(),
            "rt_sigaction".into(),
            "rt_sigprocmask".into(),
            "rt_sigreturn".into(),
            "tgkill".into(),
            // D-Bus credential passing
            "getresuid".into(),
            "getresgid".into(),
            "getgid".into(),
            "getegid".into(),
            // D-Bus / Wayland I/O
            "writev".into(),
            "readv".into(),
            "readlink".into(),
            "readlinkat".into(),
            "uname".into(),
            "memfd_create".into(),
            "getcwd".into(),
            // Timers (D-Bus / Wayland event loops)
            "nanosleep".into(),
            "clock_nanosleep".into(),
            "sched_yield".into(),
            "timerfd_create".into(),
            "timerfd_settime".into(),
            "timerfd_gettime".into(),
            // Misc
            "exit_group".into(),
            "exit".into(),
            "getrandom".into(),
            "memfd_secret".into(),
            "ftruncate".into(),
            "restart_syscall".into(),
            "inotify_init1".into(),
            "inotify_add_watch".into(),
            "inotify_rm_watch".into(),
            "pipe2".into(),
            "dup".into(),
            "flock".into(),
        ],
    };

    match platform_linux::sandbox::apply_sandbox_with_scope(
        &rules,
        &seccomp,
        LandlockScope::SignalOnly,
    ) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

pub(crate) fn init_logging(format: &str) -> anyhow::Result<()> {
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
