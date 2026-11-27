//! Landlock + seccomp sandbox application (Linux only).

/// Apply Landlock + seccomp: bus client, configuration (read-write: vault
/// databases, salts, and metadata live under it), and the systemd
/// notification socket.
///
/// # Errors
///
/// When a granted location cannot be placed or the sandbox cannot be
/// applied: the daemon does not run unsandboxed.
#[cfg(target_os = "linux")]
pub(crate) fn apply_sandbox(layout: &core_layout::Layout) -> anyhow::Result<()> {
    use core_daemon::sandbox::{config_rules, ipc_client_rules, notify_rules, seccomp_profile};
    use platform_linux::sandbox::FsAccess;

    let mut rules = ipc_client_rules(layout)?;
    rules.extend(config_rules(layout, FsAccess::ReadWrite)?);
    rules.extend(notify_rules(layout)?);

    let seccomp = seccomp_profile(
        crate::IDENTITY.daemon,
        &[
            // SQLCipher: page writes, preallocation, locks, durable commits,
            // journal rename and unlink.
            "pwrite64",
            "fallocate",
            "flock",
            "fsync",
            "fdatasync",
            "rename",
            "unlink",
            // Vectored socket I/O, sleeps, and runtime queries.
            "writev",
            "readv",
            "readlinkat",
            "uname",
            "nanosleep",
            "clock_nanosleep",
        ],
    );
    core_daemon::sandbox::apply(layout, &rules, &seccomp)
}
