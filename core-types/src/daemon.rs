//! The PDS daemons: the one definition of each daemon's name, which is
//! also its bus identity (its keypair name) and its seccomp profile name.

/// A PDS daemon.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Daemon {
    /// The bus server and profile orchestrator.
    Profile,
    /// The secrets broker.
    Secrets,
    /// The window switcher overlay.
    Wm,
    /// The application launcher.
    Launcher,
    /// The clipboard history.
    Clipboard,
    /// The keyboard capture.
    Input,
    /// The snippets.
    Snippets,
}

impl Daemon {
    /// The name without its `daemon-` prefix: the doctor's check names and
    /// the service unit's (every name carries the prefix; a test holds it).
    #[must_use]
    pub fn short_name(self) -> &'static str {
        let name = self.name();
        name.strip_prefix("daemon-").unwrap_or(name)
    }

    /// The systemd user service for this daemon.
    #[must_use]
    pub fn unit(self) -> String {
        format!("open-sesame-{}.service", self.short_name())
    }

    /// Whether this daemon belongs to the graphical-session desktop target.
    #[must_use]
    pub const fn desktop(self) -> bool {
        matches!(self, Self::Wm | Self::Clipboard | Self::Input)
    }

    /// Bus clearance assigned to this daemon's authenticated key.
    #[must_use]
    pub const fn clearance(self) -> crate::SecurityLevel {
        match self {
            Self::Secrets => crate::SecurityLevel::SecretsOnly,
            _ => crate::SecurityLevel::Internal,
        }
    }

    /// Every daemon.
    pub const ALL: [Self; 7] = [
        Self::Profile,
        Self::Secrets,
        Self::Wm,
        Self::Launcher,
        Self::Clipboard,
        Self::Input,
        Self::Snippets,
    ];

    /// The daemon's name: its executable, bus identity, and keypair name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Profile => "daemon-profile",
            Self::Secrets => "daemon-secrets",
            Self::Wm => "daemon-wm",
            Self::Launcher => "daemon-launcher",
            Self::Clipboard => "daemon-clipboard",
            Self::Input => "daemon-input",
            Self::Snippets => "daemon-snippets",
        }
    }

    /// The daemon named `name`, `None` for any other name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|daemon| daemon.name() == name)
    }
}

impl std::fmt::Display for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_distinct_and_resolve_back() {
        let mut names: Vec<&str> = Daemon::ALL.iter().map(|d| d.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Daemon::ALL.len());
        for daemon in Daemon::ALL {
            assert_eq!(Daemon::from_name(daemon.name()), Some(daemon));
            assert_eq!(daemon.to_string(), daemon.name());
        }
        assert_eq!(Daemon::from_name("daemon-unknown"), None);
    }

    #[test]
    fn every_name_has_the_daemon_prefix() {
        for daemon in Daemon::ALL {
            assert_eq!(
                format!("daemon-{}", daemon.short_name()),
                daemon.name(),
                "{daemon}"
            );
        }
    }

    /// The packages ship exactly one service unit per daemon, named after
    /// it (`contrib/systemd`): the registry and the units cannot diverge.
    #[test]
    fn the_shipped_service_units_are_the_daemons() {
        let units = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../contrib/systemd");
        let mut shipped: Vec<String> = std::fs::read_dir(&units)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".service"))
            .collect();
        shipped.sort();
        let mut expected: Vec<String> = Daemon::ALL.iter().map(|d| d.unit()).collect();
        expected.sort();
        assert_eq!(shipped, expected);
        for daemon in Daemon::ALL {
            let unit = std::fs::read_to_string(units.join(daemon.unit())).unwrap();
            let target = if daemon.desktop() {
                "desktop"
            } else {
                "headless"
            };
            assert!(
                unit.lines()
                    .any(|line| { line == format!("WantedBy=open-sesame-{target}.target") }),
                "{daemon} target membership differs from its shipped unit"
            );
        }
    }
}
