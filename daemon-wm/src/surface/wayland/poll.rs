//! Modifier polling and stale activation detection.

use std::time::{Duration, Instant};

use super::OverlayEvent;
use super::app::{OverlayApp, View};
use smithay_client_toolkit::shell::wlr_layer::KeyboardInteractivity;

/// Grace period after activation before a released modifier counts.
const MODIFIER_POLL_GRACE: Duration = Duration::from_millis(150);

/// How long an activation waits for any keyboard input before dismissing.
const STALE_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(3);

/// How long an IPC-confirmed activation waits for real input.
const IPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the overlay's keyboard input comes from this activation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum KeyboardInput {
    /// No key event yet: the compositor may not have granted focus.
    #[default]
    Unconfirmed,
    /// The compositor delivers key events to the overlay.
    Compositor,
    /// daemon-input forwards key events over IPC.
    Ipc,
}

/// One activation of the overlay: when it began, its keyboard source, the
/// last real input, and whether its end (release or dismissal) was
/// reported.
#[derive(Debug, Default)]
pub(crate) struct Activation {
    started: Option<Instant>,
    keyboard: KeyboardInput,
    last_input: Option<Instant>,
    ended: bool,
}

impl Activation {
    /// A fresh activation starting now.
    pub fn now() -> Self {
        Self {
            started: Some(Instant::now()),
            ..Self::default()
        }
    }

    /// Whether the activation has started.
    pub fn started(&self) -> bool {
        self.started.is_some()
    }

    /// Time since the activation started; zero before it has.
    fn elapsed(&self) -> Duration {
        self.started.map_or(Duration::ZERO, |t| t.elapsed())
    }

    /// The compositor delivered a key event; IPC confirmation stands.
    pub fn key_event(&mut self) {
        if self.keyboard == KeyboardInput::Unconfirmed {
            self.keyboard = KeyboardInput::Compositor;
        }
    }

    /// daemon-input confirmed it forwards the keyboard.
    pub fn confirm_ipc(&mut self) {
        self.keyboard = KeyboardInput::Ipc;
    }

    /// Real user input arrived.
    pub fn input(&mut self) {
        self.last_input = Some(Instant::now());
    }

    /// The end of the activation may be reported again (a new picker or
    /// modifier cycle).
    pub fn rearm(&mut self) {
        self.ended = false;
    }

    /// What the activation reports at `elapsed` with Alt held (`alt_held`),
    /// marking it ended when it reports anything:
    /// - no key event within [`STALE_ACTIVATION_TIMEOUT`]: dismiss;
    /// - IPC keyboard but no input within [`IPC_IDLE_TIMEOUT`]: dismiss;
    /// - compositor keyboard, past [`MODIFIER_POLL_GRACE`], Alt released:
    ///   the modifier release.
    ///
    /// Alt held again rearms the release.
    fn report(&mut self, elapsed: Duration, alt_held: bool) -> Option<OverlayEvent> {
        let event = match self.keyboard {
            _ if self.ended => None,
            KeyboardInput::Unconfirmed if elapsed >= STALE_ACTIVATION_TIMEOUT => {
                Some(OverlayEvent::Dismiss)
            }
            KeyboardInput::Ipc if self.last_input.is_none() && elapsed >= IPC_IDLE_TIMEOUT => {
                tracing::warn!(
                    timeout = ?IPC_IDLE_TIMEOUT,
                    "IPC keyboard confirmed but no input received, dismissing"
                );
                Some(OverlayEvent::Dismiss)
            }
            KeyboardInput::Compositor if elapsed >= MODIFIER_POLL_GRACE && !alt_held => {
                Some(OverlayEvent::ModifierReleased)
            }
            _ => None,
        };
        if event.is_some() {
            self.ended = true;
        } else if alt_held {
            self.ended = false;
        }
        event
    }
}

impl OverlayApp {
    /// Poll the activation: an unconfirmed keyboard re-requests exclusive
    /// focus each poll, and a stale activation or a released modifier is
    /// reported to the event loop.
    pub fn poll_modifiers(&mut self) {
        if matches!(self.view, View::Hidden) {
            self.activation.rearm();
            return;
        }
        if self.activation.keyboard == KeyboardInput::Unconfirmed {
            self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
        }
        let elapsed = self.activation.elapsed();
        if let Some(event) = self.activation.report(elapsed, self.alt_held) {
            self.send_event(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(activation: &mut Activation, ms: u64, alt_held: bool) -> Option<OverlayEvent> {
        activation.report(Duration::from_millis(ms), alt_held)
    }

    #[test]
    fn an_unconfirmed_keyboard_dismisses_once_after_the_stale_timeout() {
        let mut activation = Activation::now();
        assert!(report(&mut activation, 2_999, false).is_none());
        assert!(matches!(
            report(&mut activation, 3_000, false),
            Some(OverlayEvent::Dismiss)
        ));
        assert!(
            report(&mut activation, 4_000, false).is_none(),
            "reported once"
        );
    }

    #[test]
    fn a_compositor_release_counts_after_the_grace_period_and_rearms_on_hold() {
        let mut activation = Activation::now();
        activation.key_event();
        assert!(
            report(&mut activation, 100, false).is_none(),
            "within the grace period"
        );
        assert!(matches!(
            report(&mut activation, 200, false),
            Some(OverlayEvent::ModifierReleased)
        ));
        assert!(report(&mut activation, 250, false).is_none());
        assert!(
            report(&mut activation, 300, true).is_none(),
            "held again rearms"
        );
        assert!(matches!(
            report(&mut activation, 350, false),
            Some(OverlayEvent::ModifierReleased)
        ));
    }

    #[test]
    fn an_ipc_keyboard_dismisses_only_without_input() {
        let mut activation = Activation::now();
        activation.confirm_ipc();
        activation.key_event();
        assert!(
            report(&mut activation, 10_000, false).is_none(),
            "IPC releases come over IPC"
        );
        assert!(matches!(
            report(&mut activation, 30_000, false),
            Some(OverlayEvent::Dismiss)
        ));
        let mut active = Activation::now();
        active.confirm_ipc();
        active.input();
        assert!(report(&mut active, 30_000, false).is_none());
    }
}
