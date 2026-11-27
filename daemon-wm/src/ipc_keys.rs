//! IPC keyboard event deduplication and keysym mapping.

use crate::controller::Event;
use core_types::keysym;
use std::time::{Duration, Instant};

/// How recent an identical key event must be to count as the same
/// keystroke.
const DUPLICATE_WINDOW: Duration = Duration::from_millis(50);

/// How many recent key events are remembered.
const RECENT: usize = 8;

/// Tracks recently processed key events to deduplicate overlay and IPC sources.
///
/// When compositor keyboard focus is working, both the SCTK keyboard handler
/// and the IPC `InputKeyEvent` will fire for the same physical keystroke. This
/// ring buffer ensures only the first arrival is processed.
#[derive(Debug)]
pub struct KeyDeduplicator {
    recent: [(u32, bool, Instant); RECENT],
    next: usize,
}

impl Default for KeyDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDeduplicator {
    #[must_use]
    pub fn new() -> Self {
        // Entries start one window in the past, so none matches yet.
        let past = Instant::now()
            .checked_sub(DUPLICATE_WINDOW)
            .unwrap_or_else(Instant::now);
        Self {
            recent: [(0, false, past); RECENT],
            next: 0,
        }
    }

    /// Whether this event should be processed: no event with the same
    /// keysym and direction was processed within `DUPLICATE_WINDOW`.
    pub fn accept(&mut self, keyval: u32, pressed: bool) -> bool {
        let now = Instant::now();
        if self.recent.iter().any(|&(kv, pr, at)| {
            kv == keyval && pr == pressed && now.duration_since(at) < DUPLICATE_WINDOW
        }) {
            return false;
        }
        self.recent[self.next] = (keyval, pressed, now);
        self.next = (self.next + 1) % RECENT;
        true
    }
}

/// The controller event of an IPC key press (X11 keysym, identical to GDK
/// key constants), if the overlay handles it. Tab is not one: Tab cycling
/// is driven by IPC re-activation (`WmActivateOverlay` /
/// `WmActivateOverlayBackward`, sent when the compositor intercepts
/// Alt+Tab), and handling it here would advance twice. Modifiers, function
/// keys, and characters other than printable ASCII and space are not
/// handled either.
#[must_use]
pub fn map_ipc_key_to_event(keyval: u32, unicode: Option<char>) -> Option<Event> {
    match keyval {
        keysym::ESCAPE => Some(Event::Escape),
        keysym::RETURN | keysym::KP_ENTER => Some(Event::Confirm),
        keysym::TAB => None,
        keysym::DOWN => Some(Event::SelectionDown),
        keysym::UP => Some(Event::SelectionUp),
        keysym::BACKSPACE => Some(Event::Backspace),
        keysym::SPACE => Some(Event::Char(' ')),
        _ => unicode
            .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
            .map(Event::Char),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_keys_map_to_their_events() {
        assert!(matches!(
            map_ipc_key_to_event(keysym::ESCAPE, None),
            Some(Event::Escape)
        ));
        assert!(matches!(
            map_ipc_key_to_event(keysym::RETURN, None),
            Some(Event::Confirm)
        ));
        assert!(matches!(
            map_ipc_key_to_event(keysym::KP_ENTER, None),
            Some(Event::Confirm)
        ));
        assert!(matches!(
            map_ipc_key_to_event(keysym::DOWN, None),
            Some(Event::SelectionDown)
        ));
        assert!(matches!(
            map_ipc_key_to_event(keysym::UP, None),
            Some(Event::SelectionUp)
        ));
        assert!(matches!(
            map_ipc_key_to_event(keysym::BACKSPACE, None),
            Some(Event::Backspace)
        ));
    }

    #[test]
    fn tab_is_suppressed() {
        // Cycling is handled by IPC re-activation.
        assert!(map_ipc_key_to_event(keysym::TAB, None).is_none());
    }

    #[test]
    fn printable_characters_map_and_modifiers_do_not() {
        assert!(matches!(
            map_ipc_key_to_event(keysym::SPACE, Some(' ')),
            Some(Event::Char(' '))
        ));
        assert!(matches!(
            map_ipc_key_to_event(0x0067, Some('g')),
            Some(Event::Char('g'))
        ));
        assert!(matches!(
            map_ipc_key_to_event(0x002F, Some('/')),
            Some(Event::Char('/'))
        ));
        assert!(map_ipc_key_to_event(keysym::ALT_L, None).is_none());
        assert!(
            map_ipc_key_to_event(0x00E9, Some('é')).is_none(),
            "non-ASCII is not input"
        );
    }

    #[test]
    fn dedup_accepts_first() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_rejects_immediate_duplicate() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(!dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_accepts_different_key() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(dedup.accept(0x68, true));
    }

    #[test]
    fn dedup_accepts_same_key_different_direction() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(dedup.accept(0x67, false));
    }

    #[test]
    fn dedup_accepts_after_window_expires() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        std::thread::sleep(DUPLICATE_WINDOW + Duration::from_millis(10));
        assert!(dedup.accept(0x67, true));
    }

    #[test]
    fn a_fresh_deduplicator_accepts_keysym_zero() {
        // The empty slots must not read as a recent keysym-0 release.
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0, false));
    }

    #[test]
    fn dedup_ring_buffer_wraps() {
        let mut dedup = KeyDeduplicator::new();
        for keyval in 0..u32::try_from(RECENT).unwrap() {
            assert!(dedup.accept(keyval + 1, true));
        }
        // The oldest entry is overwritten; the newest still deduplicates.
        assert!(dedup.accept(100, true));
        assert!(!dedup.accept(u32::try_from(RECENT).unwrap(), true));
    }
}
