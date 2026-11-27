//! The overlay activations a user can request: the window switcher and the
//! launcher, each forward or backward. The single definition every
//! carrier derives from: the bus event daemon-wm serves, the shortcut id
//! (the resident fast-path datagram and the `GlobalShortcuts` portal id),
//! the description a shortcut is presented with, and the `sesame`
//! command a desktop binding runs.

use crate::{EventKind, KeyCombo};

/// One overlay activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OverlayRequest {
    /// The window switcher, next window first.
    Forward,
    /// The window switcher, previous window first.
    Backward,
    /// The launcher with the window list.
    Launcher,
    /// The launcher, previous window first.
    LauncherBackward,
}

impl OverlayRequest {
    /// Every activation, in presentation order.
    pub const ALL: [Self; 4] = [
        Self::Forward,
        Self::Backward,
        Self::Launcher,
        Self::LauncherBackward,
    ];

    /// The activation of `sesame wm overlay` with `--launcher` and
    /// `--backward` as given.
    #[must_use]
    pub const fn new(launcher: bool, backward: bool) -> Self {
        match (launcher, backward) {
            (true, true) => Self::LauncherBackward,
            (true, false) => Self::Launcher,
            (false, true) => Self::Backward,
            (false, false) => Self::Forward,
        }
    }

    /// Whether this is a launcher activation.
    #[must_use]
    pub const fn is_launcher(self) -> bool {
        matches!(self, Self::Launcher | Self::LauncherBackward)
    }

    /// Whether this activation starts from the previous window.
    #[must_use]
    pub const fn is_backward(self) -> bool {
        matches!(self, Self::Backward | Self::LauncherBackward)
    }

    /// The stable identifier: the resident fast-path datagram payload and
    /// the `GlobalShortcuts` portal shortcut id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Forward => "overlay",
            Self::Backward => "overlay-backward",
            Self::Launcher => "overlay-launcher",
            Self::LauncherBackward => "overlay-launcher-backward",
        }
    }

    /// The activation identified by `id`; any other text is `None`.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|request| request.id() == id)
    }

    /// The user-readable description a desktop presents the shortcut with.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Forward => "Switch to the next window",
            Self::Backward => "Switch to the previous window",
            Self::Launcher => "Open the launcher",
            Self::LauncherBackward => "Open the launcher at the previous window",
        }
    }

    /// The `sesame` arguments that request this activation:
    /// `wm overlay` with `--launcher` and `--backward` as it has them.
    #[must_use]
    pub const fn command_args(self) -> &'static [&'static str] {
        match self {
            Self::Forward => &["wm", "overlay"],
            Self::Backward => &["wm", "overlay", "--backward"],
            Self::Launcher => &["wm", "overlay", "--launcher"],
            Self::LauncherBackward => &["wm", "overlay", "--launcher", "--backward"],
        }
    }

    /// The shortcut this activation is bound to: Alt+Tab for the window
    /// switcher, `launcher` (`[global] launcher_key`) for the launcher, and
    /// each with Shift added backward.
    ///
    /// # Panics
    ///
    /// Never: `alt+Tab` is a valid combination.
    #[must_use]
    pub fn trigger(self, launcher: &KeyCombo) -> KeyCombo {
        let switcher: KeyCombo = "alt+Tab".parse().expect("alt+Tab is a valid key combo");
        match self {
            Self::Forward => switcher,
            Self::Backward => switcher.with_shift(),
            Self::Launcher => launcher.clone(),
            Self::LauncherBackward => launcher.with_shift(),
        }
    }

    /// The bus request daemon-wm serves for this activation.
    #[must_use]
    pub const fn event(self) -> EventKind {
        match self {
            Self::Forward => EventKind::WmActivateOverlay,
            Self::Backward => EventKind::WmActivateOverlayBackward,
            Self::Launcher => EventKind::WmActivateOverlayLauncher,
            Self::LauncherBackward => EventKind::WmActivateOverlayLauncherBackward,
        }
    }

    /// The activation `event` requests; `None` for any other event.
    #[must_use]
    pub const fn from_event(event: &EventKind) -> Option<Self> {
        match event {
            EventKind::WmActivateOverlay => Some(Self::Forward),
            EventKind::WmActivateOverlayBackward => Some(Self::Backward),
            EventKind::WmActivateOverlayLauncher => Some(Self::Launcher),
            EventKind::WmActivateOverlayLauncherBackward => Some(Self::LauncherBackward),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_carrier_round_trips_to_the_same_request() {
        for request in OverlayRequest::ALL {
            assert_eq!(OverlayRequest::from_id(request.id()), Some(request));
            assert_eq!(OverlayRequest::from_event(&request.event()), Some(request));
            assert_eq!(
                OverlayRequest::new(request.is_launcher(), request.is_backward()),
                request
            );
            let args = request.command_args();
            assert_eq!(&args[..2], ["wm", "overlay"]);
            assert_eq!(args.contains(&"--launcher"), request.is_launcher());
            assert_eq!(args.contains(&"--backward"), request.is_backward());
        }
    }

    #[test]
    fn ids_and_descriptions_are_distinct() {
        let ids: std::collections::BTreeSet<_> =
            OverlayRequest::ALL.iter().map(|r| r.id()).collect();
        let descriptions: std::collections::BTreeSet<_> = OverlayRequest::ALL
            .iter()
            .map(|r| r.description())
            .collect();
        assert_eq!(ids.len(), OverlayRequest::ALL.len());
        assert_eq!(descriptions.len(), OverlayRequest::ALL.len());
    }

    #[test]
    fn triggers_pair_each_request_with_its_backward_variant() {
        let launcher: KeyCombo = "super+space".parse().unwrap();
        assert_eq!(
            OverlayRequest::Forward.trigger(&launcher).xdg_trigger(),
            "ALT+Tab"
        );
        assert_eq!(
            OverlayRequest::Backward.trigger(&launcher).xdg_trigger(),
            "ALT+SHIFT+Tab"
        );
        assert_eq!(OverlayRequest::Launcher.trigger(&launcher), launcher);
        assert_eq!(
            OverlayRequest::LauncherBackward
                .trigger(&launcher)
                .xdg_trigger(),
            "LOGO+SHIFT+space"
        );
    }

    #[test]
    fn unknown_ids_and_events_are_none() {
        assert_eq!(OverlayRequest::from_id(""), None);
        assert_eq!(OverlayRequest::from_id("overlay-sideways"), None);
        assert_eq!(OverlayRequest::from_event(&EventKind::StatusRequest), None);
    }
}
