//! Landlock + seccomp sandbox for daemon-wm (Linux only).

use anyhow::Context;
use core_daemon::sandbox::{
    config_rules, ipc_client_rules, notify_rules, seccomp_profile, ssh_agent_rules, wayland_rules,
};
use core_layout::Layout;
use platform_linux::sandbox::{FsAccess, LandlockRule};

/// Apply Landlock + seccomp under `config`'s sandbox floor: bus client,
/// Wayland compositor socket,
/// configuration (read: hot-reload, vault salts and enrollments for inline
/// unlock), SSH agent sockets, the systemd notification socket, the cache
/// directory (MRU stack), COSMIC theme configuration, user data, and the
/// system font, library, and XKB paths.
///
/// No D-Bus bus is granted: the platform keyring factor of an inline
/// unlock is read by daemon-launcher (`KeyringUnlockRequest`), outside
/// this sandbox.
///
/// # Errors
///
/// When a granted location cannot be placed, the kernel is below the
/// floor, or the sandbox cannot be applied: the daemon does not run.
pub fn apply_sandbox(layout: &Layout, config: &core_config::Config) -> anyhow::Result<()> {
    let mut rules = ipc_client_rules(layout)?;
    rules.extend(wayland_rules(layout)?);
    rules.extend(config_rules(layout, FsAccess::ReadOnly)?);
    rules.extend(ssh_agent_rules(layout)?);
    rules.extend(notify_rules(layout)?);
    rules.extend([
        // MRU state file.
        LandlockRule {
            path: layout.cache_dir()?,
            access: FsAccess::ReadWrite,
        },
        // COSMIC desktop theme (read: the theme is opened only where its
        // config directories exist, so nothing is created).
        LandlockRule {
            path: layout.cosmic_config_dir()?,
            access: FsAccess::ReadOnly,
        },
        // User data directory (fonts, theme data).
        LandlockRule {
            path: layout
                .user_data_base()
                .context("cannot place the user data directory")?
                .to_path_buf(),
            access: FsAccess::ReadOnly,
        },
    ]);
    rules.extend([
        // Fontconfig (read-only).
        LandlockRule {
            path: std::path::PathBuf::from("/etc/fonts"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: std::path::PathBuf::from("/usr/share/fonts"),
            access: FsAccess::ReadOnly,
        },
        // System shared libraries (read-only, for dlopen of libwayland-client,
        // libfontconfig, etc. when running patchelf'd binaries without RPATH).
        LandlockRule {
            path: std::path::PathBuf::from("/lib"),
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
        // No DRI or sysfs GPU grants: overlay rendering is wl_shm (CPU
        // shared memory) via tiny-skia, and wayland-client neither dlopens
        // Mesa nor probes /dev/dri.
    ]);

    let seccomp = seccomp_profile(
        core_types::Daemon::Wm,
        &[
            // MRU stack: locked, atomically replaced, durable.
            "flock",
            "rename",
            "unlink",
            "chmod",
            "fchmod",
            "fsync",
            "fdatasync",
            // Credential queries (Wayland, D-Bus).
            "getresuid",
            "getresgid",
            "getgid",
            "getegid",
            // Wayland/SCTK runtime: shared-memory buffers, vectored I/O,
            // the fast-path socket, frame timers.
            "statfs",
            "fstatfs",
            "memfd_create",
            "mlock2",
            "mremap",
            "writev",
            "readv",
            "readlinkat",
            "uname",
            "accept4",
            "bind",
            "listen",
            "sched_yield",
            "sched_get_priority_max",
            "timerfd_create",
            "timerfd_settime",
            "timerfd_gettime",
            "sysinfo",
        ],
    );

    core_daemon::sandbox::apply(layout, config, &rules, &seccomp)
}
