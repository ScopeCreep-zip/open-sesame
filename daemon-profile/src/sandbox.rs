//! Landlock filesystem sandbox, seccomp syscall filter, and the SIGHUP
//! handler `Type=notify-reload` requires.

/// Register a SIGHUP handler (required for `Type=notify-reload`).
///
/// systemd verifies a SIGHUP handler is installed before the first
/// `READY=1` notification; without it, systemd aborts startup with
/// `SERVICE_FAILURE_PROTOCOL`. The handler must be registered before
/// `notify_ready()` is called. The event loop reloads configuration on
/// each SIGHUP (`systemctl reload`).
///
/// # Errors
///
/// When the handler cannot be registered.
#[cfg(unix)]
pub(crate) fn register_sighup() -> std::io::Result<tokio::signal::unix::Signal> {
    use tokio::signal::unix::{SignalKind, signal};
    signal(SignalKind::hangup())
}

/// Apply Landlock + seccomp under `config`'s sandbox floor: configuration
/// (read-write: the audit log and installation identity live there), the
/// PDS runtime directory
/// (read-write: bus socket, endpoint, and keys), the systemd notification
/// socket, and with the `desktop` feature the system D-Bus socket (the
/// Wi-Fi monitor) and, in a Wayland session, the compositor socket (the
/// focus monitor).
///
/// Every granted directory exists: `core_daemon::startup` creates them
/// (after `sesame init --wipe-reset-destroy-all-data` systemd may restart
/// daemon-profile before `sesame init` recreates them), and Landlock opens
/// each ruleset path.
///
/// # Errors
///
/// When a granted location cannot be placed, the kernel is below the
/// floor, or the sandbox cannot be applied: the daemon does not run.
#[cfg(target_os = "linux")]
pub(crate) fn apply_sandbox(
    layout: &core_layout::Layout,
    config: &core_config::Config,
) -> anyhow::Result<()> {
    use core_daemon::sandbox::{config_rules, notify_rules, seccomp_profile};
    use platform_linux::sandbox::{FsAccess, LandlockRule};

    let mut rules = config_rules(layout, FsAccess::ReadWrite)?;
    rules.push(LandlockRule {
        path: layout.runtime_dir()?,
        access: FsAccess::ReadWrite,
    });
    rules.extend(notify_rules(layout)?);
    #[cfg(feature = "desktop")]
    {
        rules.extend(core_daemon::sandbox::system_bus_rules(layout)?);
        // The focus monitor runs only in a Wayland session.
        if layout.environment().wayland_display.is_some() {
            rules.extend(core_daemon::sandbox::wayland_rules(layout)?);
        }
    }

    let seccomp = seccomp_profile(
        core_types::Daemon::Profile,
        &[
            // The bus server.
            "bind",
            "listen",
            "accept4",
            // Audit log, keys, endpoint: owner-only files written atomically.
            "unlink",
            "rename",
            "chmod",
            "fchmod",
            "fchown",
            "flock",
            "fsync",
            "fdatasync",
            // D-Bus credential passing.
            "getresuid",
            "getresgid",
            "getgid",
            "getegid",
            // D-Bus I/O and event loops.
            "writev",
            "readv",
            "readlinkat",
            "uname",
            "memfd_create",
            "nanosleep",
            "clock_nanosleep",
            "sched_yield",
            "timerfd_create",
            "timerfd_settime",
            "timerfd_gettime",
        ],
    );
    core_daemon::sandbox::apply(layout, config, &rules, &seccomp)
}
