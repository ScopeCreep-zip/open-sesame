//! Landlock + seccomp sandbox for daemon-network (Linux only).
//!
//! Applied AFTER keypair read and IPC bus connection, BEFORE processing
//! any network traffic. Restricts filesystem access to only the paths
//! daemon-network needs: config (read), state (read/write for TOFU store
//! and audit log), runtime (IPC socket), and Nix store symlink targets.

use std::path::PathBuf;

/// Apply Landlock + seccomp sandbox (Linux only).
///
/// # Panics
///
/// Panics if sandbox application fails. daemon-network must not run
/// unsandboxed — a failure here is a hard stop.
#[cfg(target_os = "linux")]
pub fn apply_network_sandbox() {
    use platform_linux::sandbox::{FsAccess, LandlockRule, apply_sandbox};

    platform_linux::security::harden_process();

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());
    let config_dir = core_config::config_dir();
    let pds_dir = PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    // State directory: TOFU store (network-tofu.db) and audit log (network-audit.jsonl).
    let state_dir = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pds");

    // Resolve config symlink targets (e.g. /nix/store) before Landlock.
    let config_real_dirs = core_config::resolve_config_real_dirs(None);

    let mut rules = vec![
        // Config dir: read config.toml, installation.toml, bootstrap.json.
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadOnly,
        },
        // State dir: read/write TOFU store and audit log.
        LandlockRule {
            path: state_dir,
            access: FsAccess::ReadWrite,
        },
        // Keys dir: read Noise keypair material.
        LandlockRule {
            path: keys_dir,
            access: FsAccess::ReadOnly,
        },
        // Bus public key: needed for IPC reconnect.
        LandlockRule {
            path: pds_dir.join("bus.pub"),
            access: FsAccess::ReadOnly,
        },
        // Bus socket: IPC traffic to daemon-profile.
        LandlockRule {
            path: pds_dir.join("bus.sock"),
            access: FsAccess::ReadWriteFile,
        },
    ];

    // systemd notify socket for sd_notify(READY=1) and watchdog keepalives.
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

    // Config symlink targets (e.g. /nix/store paths).
    for dir in &config_real_dirs {
        rules.push(LandlockRule {
            path: dir.clone(),
            access: FsAccess::ReadOnly,
        });
    }

    let seccomp = platform_linux::sandbox::network_daemon_seccomp_profile();

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply_network_sandbox() {
    tracing::warn!("sandbox not available on this platform");
}
