//! The PDS daemons: the one definition of each daemon's name, which is
//! also its bus identity (its keypair name) and its seccomp profile name.

/// A PDS daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}
