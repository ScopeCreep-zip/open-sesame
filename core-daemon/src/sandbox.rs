//! Landlock grants derived from the layout, and the seccomp allowlists.
//!
//! Each rule function returns the rules for one access need; a daemon's
//! rule set is the concatenation of the needs it has plus its own device
//! and system paths. Paths come only from `core_layout::Layout`, so the
//! granted set and the set the daemon opens are one derivation.
//!
//! Every daemon's seccomp allowlist is [`BASE_SYSCALLS`] plus the calls
//! its own work adds ([`seccomp_profile`]).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Context;
use core_layout::Layout;
use platform_linux::sandbox::{FsAccess, LandlockRule, SeccompProfile};

fn rule(path: PathBuf, access: FsAccess) -> LandlockRule {
    LandlockRule { path, access }
}

/// The system calls every daemon makes: file I/O, memory, threads, the
/// tokio event loop and timers, Unix domain sockets (the bus client),
/// signals, inotify (configuration hot-reload), and secure memory.
pub const BASE_SYSCALLS: &[&str] = &[
    // File I/O
    "read",
    "write",
    "close",
    "openat",
    "lseek",
    "pread64",
    "fstat",
    "stat",
    "newfstatat",
    "statx",
    "access",
    "readlink",
    "fcntl",
    "ioctl",
    "mkdir",
    "getdents64",
    "ftruncate",
    "pipe2",
    "dup",
    // Memory
    "mmap",
    "mprotect",
    "munmap",
    "madvise",
    "brk",
    "memfd_secret",
    // Locked memory: SQLCipher's private heap (mlock'd at the first
    // database use, munlock'd by its atexit shutdown) and the
    // `ProtectedAlloc` fallback without memfd_secret. A clean exit of a
    // daemon with a database runs munlock inside the sandbox.
    "mlock",
    "munlock",
    // Process and threads
    "futex",
    "clone3",
    "clone",
    "set_robust_list",
    "set_tid_address",
    "rseq",
    "sched_getaffinity",
    "prlimit64",
    "prctl",
    "getpid",
    "gettid",
    "getuid",
    "geteuid",
    "kill",
    "exit_group",
    "exit",
    "restart_syscall",
    "getrandom",
    // Event loop and timers (tokio)
    "epoll_wait",
    "epoll_ctl",
    "epoll_create1",
    "eventfd2",
    "poll",
    "ppoll",
    "clock_gettime",
    "timer_create",
    "timer_settime",
    "timer_delete",
    // Unix domain sockets (bus client)
    "socket",
    "connect",
    "sendto",
    "recvfrom",
    "recvmsg",
    "sendmsg",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "socketpair",
    "shutdown",
    // Signals
    "sigaltstack",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "tgkill",
    // Configuration hot-reload (inotify)
    "inotify_init1",
    "inotify_add_watch",
    "inotify_rm_watch",
    // Error reports: backtrace capture (`RUST_BACKTRACE`) reads the working
    // directory, so a daemon reporting an error is not killed doing it.
    "getcwd",
];

/// The seccomp profile of `daemon`: [`BASE_SYSCALLS`] and the `extra`
/// calls its own work makes, sorted and without repeats.
#[must_use]
pub fn seccomp_profile(daemon: core_types::Daemon, extra: &[&str]) -> SeccompProfile {
    let allowed: BTreeSet<&str> = BASE_SYSCALLS.iter().chain(extra).copied().collect();
    SeccompProfile {
        daemon_name: daemon.name().to_owned(),
        allowed_syscalls: allowed.into_iter().map(str::to_owned).collect(),
    }
}

/// The number of threads of this process (`<proc>/self/task`).
fn thread_count(layout: &Layout) -> anyhow::Result<usize> {
    let tasks = layout
        .proc_root()
        .context("this platform has no process filesystem")?
        .join("self")
        .join("task");
    Ok(std::fs::read_dir(&tasks)
        .with_context(|| format!("failed to list {}", tasks.display()))?
        .count())
}

/// Apply the daemon's sandbox: Landlock with `rules` and the floor of
/// `config` (`[global.sandbox] require`), then the `seccomp` filter.
///
/// Landlock restricts the calling thread and the threads it starts
/// afterwards, never a thread that already exists. This is called while
/// the process has exactly one thread (before the async runtime, the
/// configuration watcher, or any other thread starts), so every thread of
/// the daemon is sandboxed. A second thread is an error, not a partial
/// sandbox.
///
/// # Errors
///
/// When the threads cannot be counted, there is more than one, the kernel
/// does not enforce a protection of the floor, or either layer cannot be
/// applied: the daemon does not run below its floor or unsandboxed.
pub fn apply(
    layout: &Layout,
    config: &core_config::Config,
    rules: &[LandlockRule],
    seccomp: &SeccompProfile,
) -> anyhow::Result<()> {
    let threads = thread_count(layout)?;
    anyhow::ensure!(
        threads == 1,
        "{} has {threads} threads; the sandbox is applied while it has one, \
         so that no thread runs outside it",
        seccomp.daemon_name
    );
    let status =
        platform_linux::sandbox::apply_sandbox(rules, &config.global.sandbox.require, seccomp)
            .with_context(|| format!("{} refuses to start", seccomp.daemon_name))?;
    tracing::info!(?status, daemon = %seccomp.daemon_name, "sandbox applied");
    Ok(())
}

/// Whether `path` names a filesystem entry (a dangling symlink counts).
fn present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

/// Bus client access: the per-daemon keys (read), the bus endpoint
/// (read), and the bus socket (connect).
///
/// # Errors
///
/// When the runtime directory cannot be placed.
pub fn ipc_client_rules(layout: &Layout) -> anyhow::Result<Vec<LandlockRule>> {
    Ok(vec![
        rule(layout.keys_dir()?, FsAccess::ReadOnly),
        rule(layout.bus_endpoint_file()?, FsAccess::ReadOnly),
        rule(layout.bus_socket()?, FsAccess::ReadWriteFile),
    ])
}

/// Configuration access: the configuration directory with `access`, and
/// read access to the directories configuration symlinks resolve into
/// (for example `/nix/store`), so hot-reload can follow them.
///
/// # Errors
///
/// When the configuration directory cannot be placed or its symlinks
/// cannot be resolved.
pub fn config_rules(layout: &Layout, access: FsAccess) -> anyhow::Result<Vec<LandlockRule>> {
    let mut rules = vec![rule(layout.config_dir()?, access)];
    rules.extend(
        core_config::resolve_config_real_dirs(layout)
            .context("cannot resolve config symlink targets")?
            .into_iter()
            .map(|dir| rule(dir, FsAccess::ReadOnly)),
    );
    Ok(rules)
}

/// The systemd notification socket, when it is a filesystem socket that
/// exists: `READY=1` and watchdog pings connect to it after Landlock is
/// applied. Abstract sockets need no filesystem grant.
///
/// # Errors
///
/// When the socket's presence cannot be determined.
pub fn notify_rules(layout: &Layout) -> anyhow::Result<Vec<LandlockRule>> {
    match layout.notify_socket_path() {
        Some(path) if present(&path)? => Ok(vec![rule(path, FsAccess::ReadWriteFile)]),
        Some(_) | None => Ok(Vec::new()),
    }
}

/// SSH agent access for every agent socket candidate: the candidate and
/// its directory, and, when the candidate is a symlink (forwarded agents
/// rotate per session behind a stable link), its resolved target and the
/// target's directory. Landlock checks the resolved inode, so both ends of
/// the link are granted.
///
/// # Errors
///
/// When a candidate's presence or target cannot be determined.
pub fn ssh_agent_rules(layout: &Layout) -> anyhow::Result<Vec<LandlockRule>> {
    let mut seen = BTreeSet::new();
    let mut rules = Vec::new();
    let mut grant = |path: PathBuf, access: FsAccess| -> anyhow::Result<()> {
        if present(&path)? && seen.insert(path.clone()) {
            rules.push(rule(path, access));
        }
        Ok(())
    };
    for candidate in layout.ssh_agent_sockets() {
        if let Some(dir) = candidate.parent() {
            grant(dir.to_path_buf(), FsAccess::ReadOnly)?;
        }
        grant(candidate.clone(), FsAccess::ReadWriteFile)?;
        match std::fs::canonicalize(&candidate) {
            Ok(target) => {
                if let Some(dir) = target.parent() {
                    grant(dir.to_path_buf(), FsAccess::ReadOnly)?;
                }
                grant(target, FsAccess::ReadWriteFile)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to resolve {}", candidate.display()));
            }
        }
    }
    Ok(rules)
}

/// The Wayland compositor socket (connect).
///
/// # Errors
///
/// When `$WAYLAND_DISPLAY` or `$XDG_RUNTIME_DIR` is not set.
pub fn wayland_rules(layout: &Layout) -> anyhow::Result<Vec<LandlockRule>> {
    Ok(vec![rule(
        layout.wayland_socket()?,
        FsAccess::ReadWriteFile,
    )])
}

/// The system D-Bus socket (connect), the one `Layout::system_bus_socket`
/// names and system bus clients connect to.
///
/// No daemon is granted the session bus: a process on it can ask the
/// user's service manager (`org.freedesktop.systemd1`) to run any command
/// outside the sandbox.
///
/// # Errors
///
/// The `Layout::system_bus_socket` errors.
pub fn system_bus_rules(layout: &Layout) -> anyhow::Result<Vec<LandlockRule>> {
    Ok(vec![rule(
        layout.system_bus_socket()?,
        FsAccess::ReadWriteFile,
    )])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(rules: &[LandlockRule]) -> Vec<PathBuf> {
        rules.iter().map(|r| r.path.clone()).collect()
    }

    #[test]
    fn profiles_are_the_base_and_their_extras_once_each() {
        let base: BTreeSet<&str> = BASE_SYSCALLS.iter().copied().collect();
        assert_eq!(
            base.len(),
            BASE_SYSCALLS.len(),
            "BASE_SYSCALLS repeats a call"
        );
        let profile = seccomp_profile(core_types::Daemon::Snippets, &["flock", "read", "flock"]);
        assert_eq!(profile.daemon_name, "daemon-snippets");
        let mut expected: Vec<String> = base.iter().map(|s| (*s).to_owned()).collect();
        expected.push("flock".to_owned());
        expected.sort();
        assert_eq!(profile.allowed_syscalls, expected);
    }

    #[test]
    fn threads_are_counted_from_the_layouts_process_filesystem() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let tasks = layout.proc_root().unwrap().join("self/task");
        std::fs::create_dir_all(tasks.join("100")).unwrap();
        assert_eq!(thread_count(&layout).unwrap(), 1);
        std::fs::create_dir(tasks.join("101")).unwrap();
        assert_eq!(thread_count(&layout).unwrap(), 2);
    }

    #[test]
    fn a_second_thread_refuses_the_sandbox_before_applying_it() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let tasks = layout.proc_root().unwrap().join("self/task");
        std::fs::create_dir_all(tasks.join("100")).unwrap();
        std::fs::create_dir(tasks.join("101")).unwrap();
        let seccomp = SeccompProfile {
            daemon_name: "test-daemon".into(),
            allowed_syscalls: Vec::new(),
        };
        let err = apply(&layout, &core_config::Config::default(), &[], &seccomp)
            .unwrap_err()
            .to_string();
        assert!(err.contains("test-daemon has 2 threads"), "{err}");
    }

    #[test]
    fn ipc_client_rules_come_from_the_layout() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        assert_eq!(
            paths(&ipc_client_rules(&layout).unwrap()),
            [
                layout.keys_dir().unwrap(),
                layout.bus_endpoint_file().unwrap(),
                layout.bus_socket().unwrap(),
            ]
        );
    }

    #[test]
    fn config_rules_grant_the_config_dir() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        layout.bootstrap().unwrap();
        let rules = config_rules(&layout, FsAccess::ReadOnly).unwrap();
        assert_eq!(paths(&rules), [layout.config_dir().unwrap()]);
    }

    #[test]
    fn notify_rule_only_for_existing_filesystem_sockets() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("notify");
        let with = |value: &std::ffi::OsStr| {
            notify_rules(&Layout::new(core_layout::Environment {
                notify_socket: Some(value.to_owned()),
                ..core_layout::Environment::default()
            }))
            .unwrap()
        };
        assert!(with(std::ffi::OsStr::new("@/abstract")).is_empty());
        assert!(with(socket.as_os_str()).is_empty());
        std::fs::write(&socket, b"").unwrap();
        assert_eq!(paths(&with(socket.as_os_str())), vec![socket]);
    }

    #[test]
    fn ssh_agent_rules_grant_both_ends_of_a_link() {
        let root = tempfile::tempdir().unwrap();
        let target_dir = root.path().join("ssh-session");
        std::fs::create_dir(&target_dir).unwrap();
        let target = target_dir.join("agent.1");
        std::fs::write(&target, b"").unwrap();
        let home = root.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let link = home.join(".ssh/agent.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let layout = Layout::new(core_layout::Environment {
            home: Some(home.clone()),
            ..core_layout::Environment::default()
        });
        let granted = paths(&ssh_agent_rules(&layout).unwrap());
        let target = std::fs::canonicalize(&target).unwrap();
        for expected in [
            home.join(".ssh"),
            link,
            target.clone(),
            target.parent().unwrap().to_path_buf(),
        ] {
            assert!(
                granted.contains(&expected),
                "{expected:?} not in {granted:?}"
            );
        }
    }
}
