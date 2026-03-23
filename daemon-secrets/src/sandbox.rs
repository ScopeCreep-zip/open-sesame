//! Landlock + seccomp sandbox application (Linux only).

use std::path::PathBuf;

/// Apply Landlock + seccomp sandbox (Linux only).
#[cfg(target_os = "linux")]
pub(crate) fn apply_sandbox() {
    use platform_linux::sandbox::{FsAccess, LandlockRule, SeccompProfile, apply_sandbox};

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());

    let config_dir = core_config::config_dir();

    let pds_dir = PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    // Resolve config symlink targets (e.g. /nix/store) before Landlock.
    // On NixOS, config.toml is a symlink into /nix/store — without this,
    // config hot-reload fails because Landlock blocks reading the target.
    let config_real_dirs = core_config::resolve_config_real_dirs(None);

    let mut rules = vec![
        // Config dir: vault DBs + salt stored here.
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadWrite,
        },
        LandlockRule {
            path: keys_dir.clone(),
            access: FsAccess::ReadOnly,
        },
        // Bus public key: needed if reconnect ever happens.
        LandlockRule {
            path: pds_dir.join("bus.pub"),
            access: FsAccess::ReadOnly,
        },
        // Bus socket: connect + read/write IPC traffic.
        LandlockRule {
            path: pds_dir.join("bus.sock"),
            access: FsAccess::ReadWriteFile,
        },
        // D-Bus socket — non-directory fd, use ReadWriteFile to avoid
        // PartiallyEnforced from directory-only landlock flags.
        LandlockRule {
            path: PathBuf::from(&runtime_dir).join("bus"),
            access: FsAccess::ReadWriteFile,
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

    // Config symlink targets (e.g. /nix/store paths) need read access
    // for config hot-reload to follow symlinks after Landlock is applied.
    for dir in &config_real_dirs {
        rules.push(LandlockRule {
            path: dir.clone(),
            access: FsAccess::ReadOnly,
        });
    }

    let seccomp = SeccompProfile {
        daemon_name: "daemon-secrets".into(),
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
            "fcntl".into(),
            "flock".into(),
            "pwrite64".into(),
            "ftruncate".into(),
            "fallocate".into(),
            "fsync".into(),
            "fdatasync".into(),
            "mkdir".into(),
            "getdents64".into(),
            "rename".into(),
            // Memory (secrets needs mlock/munlock/madvise for zeroization)
            "mmap".into(),
            "mprotect".into(),
            "munmap".into(),
            "mlock".into(),
            "munlock".into(),
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
            // Networking / IPC
            "socket".into(),
            "connect".into(),
            "sendto".into(),
            "recvfrom".into(),
            "socketpair".into(),
            "sendmsg".into(),
            "recvmsg".into(),
            "shutdown".into(),
            "getsockopt".into(),
            "getsockname".into(),
            "getpeername".into(),
            "setsockopt".into(),
            // D-Bus credential passing (KeyLocker / SecretService)
            "getresuid".into(),
            "getresgid".into(),
            "getgid".into(),
            "getegid".into(),
            // D-Bus / SSH agent I/O
            "writev".into(),
            "readv".into(),
            "readlink".into(),
            "readlinkat".into(),
            "uname".into(),
            "getcwd".into(),
            // Timing
            "nanosleep".into(),
            "clock_nanosleep".into(),
            // Signals
            "sigaltstack".into(),
            "rt_sigaction".into(),
            "rt_sigprocmask".into(),
            "rt_sigreturn".into(),
            "tgkill".into(),
            // Config hot-reload (notify crate uses inotify)
            "inotify_init1".into(),
            "inotify_add_watch".into(),
            "inotify_rm_watch".into(),
            // Misc
            "exit_group".into(),
            "exit".into(),
            "getrandom".into(),
            "memfd_secret".into(),
            "restart_syscall".into(),
            "pipe2".into(),
            "dup".into(),
            "ioctl".into(),
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
