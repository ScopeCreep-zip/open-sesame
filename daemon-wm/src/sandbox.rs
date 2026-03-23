//! Landlock + seccomp sandbox for daemon-wm (Linux only).

use platform_linux::sandbox::{
    FsAccess, LandlockRule, LandlockScope, SeccompProfile, apply_sandbox_with_scope,
};

/// Apply Landlock + seccomp sandbox (Linux only).
pub fn apply_sandbox() {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());

    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("open-sesame");

    let pds_dir = std::path::PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    // Resolve config symlink targets (e.g. /nix/store) before Landlock.
    let config_real_dirs = core_config::resolve_config_real_dirs(None);

    let mut rules = vec![
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
        // Wayland socket access (use $WAYLAND_DISPLAY, default wayland-1 for COSMIC).
        // ReadWriteFile because the socket is a non-directory fd — directory-only
        // landlock flags (ReadDir, MakeDir, etc.) cause PartiallyEnforced.
        LandlockRule {
            path: std::path::PathBuf::from(&runtime_dir)
                .join(std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-1".into())),
            access: FsAccess::ReadWriteFile,
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
        // COSMIC desktop theme (read-only, for native theme integration).
        LandlockRule {
            path: dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/nonexistent"))
                .join("cosmic"),
            access: FsAccess::ReadOnly,
        },
        // Nix store (read-only, shared libs, schemas, locale data, XKB).
        LandlockRule {
            path: std::path::PathBuf::from("/nix/store"),
            access: FsAccess::ReadOnly,
        },
        // /proc (read-only, xdg-desktop-portal needs /proc/PID/root for verification).
        LandlockRule {
            path: std::path::PathBuf::from("/proc"),
            access: FsAccess::ReadOnly,
        },
        // System shared data (fonts, icons, mime, locale).
        LandlockRule {
            path: std::path::PathBuf::from("/usr/share"),
            access: FsAccess::ReadOnly,
        },
        // XKB system rules (evdev on non-NixOS).
        LandlockRule {
            path: std::path::PathBuf::from("/usr/share/X11/xkb"),
            access: FsAccess::ReadOnly,
        },
        // User data directory (fonts, theme data).
        LandlockRule {
            path: dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from("/nonexistent")),
            access: FsAccess::ReadOnly,
        },
        // NOTE: DRI device access and sysfs GPU discovery rules intentionally
        // removed. daemon-wm uses wl_shm (CPU shared memory buffers) via
        // tiny-skia for all overlay rendering. No GPU/DRI access is required.
        // The Rust wayland-client crate does not dlopen Mesa or probe /dev/dri.
        //
        // PDS vaults directory: salt files and SSH enrollment blobs needed
        // for auto-unlock (SSH-agent backend reads salt + blob at unlock time).
        LandlockRule {
            path: core_config::config_dir().join("vaults"),
            access: FsAccess::ReadOnly,
        },
    ];

    // systemd notify socket: sd_notify(READY=1) and watchdog keepalives
    // need connect+sendto access to $NOTIFY_SOCKET after Landlock is applied.
    // Abstract sockets (prefixed '@') bypass Landlock AccessFs rules.
    if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET")
        && !notify_socket.starts_with('@')
    {
        let path = std::path::PathBuf::from(&notify_socket);
        if path.exists() {
            rules.push(LandlockRule {
                path,
                access: FsAccess::ReadWriteFile,
            });
        }
    }

    // SSH agent socket: needed for SSH-agent auto-unlock (can_unlock + sign).
    //
    // Forwarded SSH agent sockets live at random /tmp/ssh-XXXX/agent.PID
    // paths that change every session. On Konductor VMs, a profile.d script
    // creates a stable symlink at ~/.ssh/agent.sock pointing to the real
    // socket. Landlock resolves symlinks to their target inodes, so we must
    // grant access to:
    //   1. The path in $SSH_AUTH_SOCK (may be a symlink or direct path)
    //   2. The resolved (canonical) target if it differs (the real socket)
    //   3. The parent directory of the resolved target (for path traversal)
    //   4. The ~/.ssh/agent.sock fallback path (stable symlink convention)
    //   5. The ~/.ssh/ directory itself (for symlink traversal to target)
    {
        let mut ssh_paths_added = std::collections::HashSet::new();

        // Helper: add a path to Landlock rules if it exists and hasn't been added yet.
        let add_ssh_path =
            |rules: &mut Vec<LandlockRule>,
             path: std::path::PathBuf,
             access: FsAccess,
             seen: &mut std::collections::HashSet<std::path::PathBuf>| {
                if seen.insert(path.clone()) && (path.exists() || path.is_symlink()) {
                    rules.push(LandlockRule { path, access });
                }
            };

        if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            let sock_path = std::path::PathBuf::from(&sock);

            // Grant the literal $SSH_AUTH_SOCK path (symlink or direct).
            add_ssh_path(
                &mut rules,
                sock_path.clone(),
                FsAccess::ReadWriteFile,
                &mut ssh_paths_added,
            );

            // Resolve symlink to canonical target; grant target + parent dir.
            if let Ok(canonical) = std::fs::canonicalize(&sock_path) {
                add_ssh_path(
                    &mut rules,
                    canonical.clone(),
                    FsAccess::ReadWriteFile,
                    &mut ssh_paths_added,
                );
                if let Some(parent) = canonical.parent() {
                    add_ssh_path(
                        &mut rules,
                        parent.to_path_buf(),
                        FsAccess::ReadOnly,
                        &mut ssh_paths_added,
                    );
                }
            }
        }

        // Always grant the stable fallback path (~/.ssh/agent.sock) so
        // core-auth's connect_agent() fallback can reach forwarded agents
        // even if $SSH_AUTH_SOCK was not set when the daemon started.
        if let Some(home) = std::env::var_os("HOME") {
            let ssh_dir = std::path::PathBuf::from(&home).join(".ssh");
            let agent_sock = ssh_dir.join("agent.sock");

            add_ssh_path(
                &mut rules,
                ssh_dir,
                FsAccess::ReadOnly,
                &mut ssh_paths_added,
            );
            add_ssh_path(
                &mut rules,
                agent_sock.clone(),
                FsAccess::ReadWriteFile,
                &mut ssh_paths_added,
            );

            // If the fallback symlink exists, also resolve its target.
            if let Ok(canonical) = std::fs::canonicalize(&agent_sock) {
                add_ssh_path(
                    &mut rules,
                    canonical.clone(),
                    FsAccess::ReadWriteFile,
                    &mut ssh_paths_added,
                );
                if let Some(parent) = canonical.parent() {
                    add_ssh_path(
                        &mut rules,
                        parent.to_path_buf(),
                        FsAccess::ReadOnly,
                        &mut ssh_paths_added,
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
        daemon_name: "daemon-wm".into(),
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
            "fcntl".into(),
            "flock".into(),
            "ftruncate".into(),
            "mkdir".into(),
            "rename".into(),
            "chmod".into(),
            "fchmod".into(),
            "fsync".into(),
            "fdatasync".into(),
            "ioctl".into(),
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
            "getresuid".into(),
            "getresgid".into(),
            "getgid".into(),
            "getegid".into(),
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
            // Networking / IPC (Wayland compositor protocol)
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
            // Signals
            "sigaltstack".into(),
            "rt_sigaction".into(),
            "rt_sigprocmask".into(),
            "rt_sigreturn".into(),
            "tgkill".into(),
            // Wayland/SCTK runtime
            "inotify_init1".into(),
            "inotify_add_watch".into(),
            "inotify_rm_watch".into(),
            "statfs".into(),
            "fstatfs".into(),
            "memfd_create".into(),
            "writev".into(),
            "readv".into(),
            "readlink".into(),
            "readlinkat".into(),
            "uname".into(),
            "accept4".into(),
            "bind".into(),
            "listen".into(),
            "nanosleep".into(),
            "clock_nanosleep".into(),
            "sched_yield".into(),
            "timerfd_create".into(),
            "timerfd_settime".into(),
            "timerfd_gettime".into(),
            "mlock".into(),
            "mlock2".into(),
            "mremap".into(),
            "unlink".into(),
            "sched_get_priority_max".into(),
            "sysinfo".into(),
            // Misc
            "exit_group".into(),
            "exit".into(),
            "getrandom".into(),
            "memfd_secret".into(),
            "restart_syscall".into(),
            "getcwd".into(),
            "pipe2".into(),
            "dup".into(),
        ],
    };

    // daemon-wm uses Wayland sockets only (no D-Bus). SignalOnly scope blocks
    // cross-process signals while allowing abstract Unix sockets for Wayland.
    match apply_sandbox_with_scope(&rules, &seccomp, LandlockScope::SignalOnly) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}
