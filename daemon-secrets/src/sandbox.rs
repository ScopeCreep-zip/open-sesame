//! Landlock + seccomp sandbox application (Linux only).

/// Apply Landlock + seccomp under `config`'s sandbox floor: bus client,
/// configuration (read-write: vault databases, salts, and metadata live
/// under it), and the systemd notification socket.
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
            // Vectored socket I/O and runtime queries.
            "writev",
            "readv",
            "readlinkat",
            "uname",
        ],
    );
    core_daemon::sandbox::apply(layout, config, &rules, &seccomp)
}
