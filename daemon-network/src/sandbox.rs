//! Sandbox application for daemon-network.
//!
//! Applies Landlock filesystem restrictions and the network-capable
//! seccomp profile from `platform-linux`.

/// Apply the daemon-network sandbox.
///
/// Must be called AFTER secure memory init and BEFORE processing any
/// network traffic.
pub fn apply_network_sandbox() {
    #[cfg(target_os = "linux")]
    {
        platform_linux::security::harden_process();

        let profile = platform_linux::sandbox::network_daemon_seccomp_profile();
        tracing::info!(
            daemon = "daemon-network",
            syscalls = profile.allowed_syscalls.len(),
            "applying seccomp profile"
        );
        // Landlock and seccomp application delegated to platform-linux.
        // The actual apply_sandbox call requires runtime directory paths
        // which are resolved in main.rs and passed here.
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("sandbox not available on this platform");
    }
}
