//! Modifier polling and stale activation detection.

use super::app::OverlayApp;
use super::{OverlayEvent, OverlayPhase};
use smithay_client_toolkit::shell::wlr_layer::KeyboardInteractivity;

/// Grace period (ms) after activation before modifier polling begins.
pub const MODIFIER_POLL_GRACE_MS: u128 = 150;

/// Stale activation timeout (ms).
pub const STALE_ACTIVATION_TIMEOUT_MS: u128 = 3000;

/// IPC idle timeout (ms).
pub const IPC_IDLE_TIMEOUT_MS: u128 = 30_000;

/// Modifier poll interval in milliseconds.
pub const POLL_INTERVAL_MS: u64 = 4;

impl OverlayApp {
    pub fn poll_modifiers(&mut self) {
        if self.phase == OverlayPhase::Hidden {
            self.modifier_released_sent = false;
            return;
        }

        let elapsed_ms = self
            .activated_at
            .map(|t| t.elapsed().as_millis())
            .unwrap_or(0);
        let within_grace = elapsed_ms < MODIFIER_POLL_GRACE_MS;

        if !self.received_key_event {
            self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
        }

        if !self.received_key_event
            && elapsed_ms >= STALE_ACTIVATION_TIMEOUT_MS
            && !self.modifier_released_sent
        {
            self.modifier_released_sent = true;
            self.send_event(OverlayEvent::Dismiss);
            return;
        }

        if self.ipc_keyboard_active
            && self.last_real_input_at.is_none()
            && elapsed_ms >= IPC_IDLE_TIMEOUT_MS
            && !self.modifier_released_sent
        {
            tracing::warn!(
                "IPC keyboard confirmed but no input received after {IPC_IDLE_TIMEOUT_MS}ms, dismissing"
            );
            self.modifier_released_sent = true;
            self.send_event(OverlayEvent::Dismiss);
            return;
        }

        if !within_grace && self.received_key_event && !self.ipc_keyboard_active && !self.alt_held {
            if !self.modifier_released_sent {
                self.modifier_released_sent = true;
                self.send_event(OverlayEvent::ModifierReleased);
            }
        } else if self.alt_held {
            self.modifier_released_sent = false;
        }
    }
}
