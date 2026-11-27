//! The protections of the daemons' kernel sandbox: what the running kernel
//! enforces of them is reported, and the configuration can require them
//! (`[global.sandbox] require`).

use serde::{Deserialize, Serialize};

/// A restriction of the daemons' Landlock sandbox, introduced by one
/// Landlock ABI. The configuration names it in kebab case
/// (`pathname-sockets`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxProtection {
    /// File system access control (Landlock ABI 1).
    Filesystem,
    /// Linking and renaming files across directories (`Refer`, ABI 2).
    Reparenting,
    /// Truncating files (`Truncate`, ABI 3).
    Truncation,
    /// TCP bind and connect (ABI 4).
    Tcp,
    /// Device `ioctl(2)` (`IoctlDev`, ABI 5).
    DeviceIoctl,
    /// Abstract Unix sockets and signals outside the sandbox (scopes,
    /// ABI 6).
    Scopes,
    /// Connecting to pathname Unix sockets (`ResolveUnix`, ABI 9).
    PathnameSockets,
    /// UDP bind, connect, and send (ABI 10).
    Udp,
}

impl SandboxProtection {
    /// Every protection, in the order of the ABIs that introduced them.
    pub const ALL: [Self; 8] = [
        Self::Filesystem,
        Self::Reparenting,
        Self::Truncation,
        Self::Tcp,
        Self::DeviceIoctl,
        Self::Scopes,
        Self::PathnameSockets,
        Self::Udp,
    ];

    /// Its name in the configuration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Reparenting => "reparenting",
            Self::Truncation => "truncation",
            Self::Tcp => "tcp",
            Self::DeviceIoctl => "device-ioctl",
            Self::Scopes => "scopes",
            Self::PathnameSockets => "pathname-sockets",
            Self::Udp => "udp",
        }
    }

    /// The first Linux release that enforces it.
    #[must_use]
    pub const fn since_linux(self) -> &'static str {
        match self {
            Self::Filesystem => "5.13",
            Self::Reparenting => "5.19",
            Self::Truncation => "6.2",
            Self::Tcp => "6.7",
            Self::DeviceIoctl => "6.10",
            Self::Scopes => "6.12",
            Self::PathnameSockets => "7.1",
            Self::Udp => "7.2",
        }
    }

    /// What a sandboxed process can do on a kernel that does not enforce
    /// it.
    #[must_use]
    pub const fn unenforced(self) -> &'static str {
        match self {
            Self::Filesystem => "Landlock is absent: every file, socket, and port is open",
            Self::Reparenting => "files can be linked or renamed across directories",
            Self::Truncation => "files can be truncated",
            Self::Tcp => "TCP ports can be bound and connected",
            Self::DeviceIoctl => "device ioctl commands are unrestricted",
            Self::Scopes => "abstract Unix sockets and processes outside the sandbox are reachable",
            Self::PathnameSockets => {
                "every pathname Unix socket is reachable, the session D-Bus bus (systemd \
                 StartTransientUnit runs commands outside the sandbox) among them"
            }
            Self::Udp => "UDP ports can be bound, connected, and sent to",
        }
    }

    /// `protections` as one line: each one's name, consequence, and the
    /// Linux release that enforces it.
    #[must_use]
    pub fn describe(protections: &[Self]) -> String {
        protections
            .iter()
            .map(|p| {
                format!(
                    "{} ({}; Linux {})",
                    p.name(),
                    p.unenforced(),
                    p.since_linux()
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl std::fmt::Display for SandboxProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One protection, as a configuration names it.
    #[derive(Debug, Deserialize)]
    struct One {
        p: SandboxProtection,
    }

    #[test]
    fn configuration_names_are_the_serde_names() {
        for protection in SandboxProtection::ALL {
            let toml = format!("p = \"{}\"", protection.name());
            let parsed: One = toml::from_str(&toml).unwrap();
            assert_eq!(parsed.p, protection);
        }
    }

    #[test]
    fn an_unknown_name_lists_the_accepted_ones() {
        let error = toml::from_str::<One>("p = \"sockets\"")
            .unwrap_err()
            .to_string();
        assert!(error.contains("pathname-sockets"), "{error}");
    }

    #[test]
    fn protections_are_in_abi_order() {
        let mut sorted = SandboxProtection::ALL;
        sorted.sort();
        assert_eq!(sorted, SandboxProtection::ALL);
    }
}
