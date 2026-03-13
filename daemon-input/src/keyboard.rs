//! Keyboard event capture via evdev and XKB keysym translation.
//!
//! Provides:
//! - `XkbContext`: maintains xkbcommon state for keycode-to-keysym translation.
//! - `KeyboardEvent`: a processed keyboard event with keysym, unicode, and modifiers.
//! - `spawn_keyboard_readers()`: starts async tasks that read from all keyboard
//!   devices and funnel events through a single channel.

use evdev::EventSummary;
use tokio::sync::mpsc;

/// A processed keyboard event ready for IPC forwarding.
#[derive(Debug, Clone)]
pub struct KeyboardEvent {
    /// XKB keysym value (e.g., 0xFF1B for Escape).
    pub keyval: u32,
    /// Evdev keycode (hardware scan code).
    pub keycode: u32,
    /// true = key press, false = key release.
    pub pressed: bool,
    /// Active modifier bitmask (GDK-compatible bit positions).
    pub modifiers: u32,
    /// Unicode character, if applicable (only on key press).
    pub unicode: Option<char>,
}

/// XKB context for translating evdev keycodes to keysyms and unicode.
///
/// Maintains xkbcommon keymap and state. Must be called from a single thread
/// (xkb::State is not Send/Sync). Process events sequentially.
pub struct XkbContext {
    state: xkbcommon::xkb::State,
}

impl XkbContext {
    /// Create a new XKB context with the system's default keymap.
    ///
    /// Returns `None` if xkbcommon fails to initialize (missing XKB data files).
    pub fn new() -> Option<Self> {
        let context = xkbcommon::xkb::Context::new(xkbcommon::xkb::CONTEXT_NO_FLAGS);
        let keymap = xkbcommon::xkb::Keymap::new_from_names(
            &context,
            "",   // rules — empty = system default
            "",   // model
            "",   // layout
            "",   // variant
            None, // options
            xkbcommon::xkb::KEYMAP_COMPILE_NO_FLAGS,
        )?;
        let state = xkbcommon::xkb::State::new(&keymap);
        Some(Self { state })
    }

    /// Process an evdev key event and return the translated keysym, unicode, and modifiers.
    ///
    /// IMPORTANT: reads keysym and modifiers BEFORE updating state. This ensures
    /// that when the Alt key itself is pressed, the modifier mask does NOT yet
    /// include Alt — critical for correct Alt-release detection on the receiving end.
    pub fn process_key(&mut self, evdev_keycode: u32, pressed: bool) -> KeyboardEvent {
        // Evdev keycodes are offset by 8 from XKB keycodes.
        let xkb_keycode = evdev_keycode + 8;

        let direction = if pressed {
            xkbcommon::xkb::KeyDirection::Down
        } else {
            xkbcommon::xkb::KeyDirection::Up
        };

        // Read keysym and unicode BEFORE updating state.
        let keyval = self.state.key_get_one_sym(xkb_keycode.into()).raw();
        let utf32 = self.state.key_get_utf32(xkb_keycode.into());
        let unicode = if pressed && utf32 > 0 {
            char::from_u32(utf32)
        } else {
            None
        };
        let modifiers = self.active_modifiers();

        // Update state AFTER reading.
        self.state.update_key(xkb_keycode.into(), direction);

        KeyboardEvent {
            keyval,
            keycode: evdev_keycode,
            pressed,
            modifiers,
            unicode,
        }
    }

    /// Query whether Alt (Mod1) is currently active in the XKB state.
    ///
    /// Used for synthetic Alt-release check when a grab is first activated —
    /// if Alt is already released, daemon-input sends a synthetic release event.
    pub fn is_alt_active(&self) -> bool {
        self.state.mod_name_is_active(
            xkbcommon::xkb::MOD_NAME_ALT,
            xkbcommon::xkb::STATE_MODS_EFFECTIVE,
        )
    }

    /// Build a GDK-compatible modifier bitmask from the current XKB state.
    fn active_modifiers(&self) -> u32 {
        let mut mask = 0u32;
        if self.state.mod_name_is_active(
            xkbcommon::xkb::MOD_NAME_SHIFT,
            xkbcommon::xkb::STATE_MODS_EFFECTIVE,
        ) {
            mask |= 1 << 0; // GDK_SHIFT_MASK
        }
        if self.state.mod_name_is_active(
            xkbcommon::xkb::MOD_NAME_CTRL,
            xkbcommon::xkb::STATE_MODS_EFFECTIVE,
        ) {
            mask |= 1 << 2; // GDK_CONTROL_MASK
        }
        if self.state.mod_name_is_active(
            xkbcommon::xkb::MOD_NAME_ALT,
            xkbcommon::xkb::STATE_MODS_EFFECTIVE,
        ) {
            mask |= 1 << 3; // GDK_ALT_MASK
        }
        if self.state.mod_name_is_active(
            xkbcommon::xkb::MOD_NAME_LOGO,
            xkbcommon::xkb::STATE_MODS_EFFECTIVE,
        ) {
            mask |= 1 << 26; // GDK_SUPER_MASK
        }
        mask
    }
}

/// Spawn async reader tasks for all keyboard devices.
///
/// Enumerates `/dev/input/event*`, opens all keyboard devices as async
/// `EventStream`s, and spawns one tokio task per device. All tasks funnel
/// key events into the returned receiver channel.
///
/// If no keyboard devices are found (user not in `input` group, or no
/// keyboards attached), logs a warning and returns an empty receiver.
/// This is not fatal — daemon-wm falls back to GTK4-only keyboard input.
pub fn spawn_keyboard_readers() -> mpsc::Receiver<RawKeyEvent> {
    let (tx, rx) = mpsc::channel::<RawKeyEvent>(256);

    let devices = match platform_linux::input::enumerate_devices() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "failed to enumerate input devices — keyboard forwarding disabled");
            return rx;
        }
    };

    let keyboards: Vec<_> = devices.into_iter().filter(|d| d.is_keyboard).collect();

    if keyboards.is_empty() {
        tracing::warn!(
            "no keyboard devices found — ensure your user is in the 'input' group: \
             `sudo usermod -aG input $USER` (logout/login required)"
        );
        return rx;
    }

    for dev_info in keyboards {
        let tx = tx.clone();
        let path = dev_info.path.clone();
        tracing::info!(
            device = %dev_info.name,
            path = %dev_info.path.display(),
            "opening keyboard device for event capture"
        );

        tokio::spawn(async move {
            let mut stream = match platform_linux::input::open_keyboard_stream(&path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to open keyboard device — skipping"
                    );
                    return;
                }
            };

            loop {
                match stream.next_event().await {
                    Ok(event) => {
                        if let EventSummary::Key(_key_ev, keycode, value) = event.destructure() {
                            // value: 0 = release, 1 = press, 2 = repeat
                            // We forward press (1) and release (0), skip repeat (2).
                            if value == 0 || value == 1 {
                                let raw = RawKeyEvent {
                                    keycode: keycode.0 as u32,
                                    pressed: value == 1,
                                };
                                if tx.send(raw).await.is_err() {
                                    return; // channel closed — daemon shutting down
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "evdev read error — device disconnected or permission denied"
                        );
                        return;
                    }
                }
            }
        });
    }

    rx
}

/// Raw evdev key event before XKB translation.
#[derive(Debug, Clone, Copy)]
pub struct RawKeyEvent {
    /// Evdev keycode (e.g., 30 for `KEY_A`).
    pub keycode: u32,
    /// true = press, false = release.
    pub pressed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xkb_context_creation() {
        // This test may fail in environments without XKB data files installed.
        // That's acceptable — it exercises the creation path.
        let ctx = XkbContext::new();
        // Don't assert Some — CI may not have xkb data.
        if let Some(mut ctx) = ctx {
            // Process a key press for 'a' (evdev keycode 30).
            let event = ctx.process_key(30, true);
            assert!(event.pressed);
            assert_eq!(event.keycode, 30);
            // Keysym for 'a' is 0x0061.
            assert_eq!(event.keyval, 0x0061);
            assert_eq!(event.unicode, Some('a'));
        }
    }

    #[test]
    fn xkb_modifier_tracking() {
        let ctx = XkbContext::new();
        if let Some(mut ctx) = ctx {
            // Press left Alt (evdev keycode 56).
            let event = ctx.process_key(56, true);
            // Before the key is processed, Alt should NOT be in modifiers.
            assert_eq!(
                event.modifiers & (1 << 3),
                0,
                "Alt should not be in pre-press modifiers"
            );
            // After processing, Alt should be active.
            assert!(ctx.is_alt_active(), "Alt should be active after press");

            // Release Alt.
            let _event = ctx.process_key(56, false);
            assert!(
                !ctx.is_alt_active(),
                "Alt should not be active after release"
            );
        }
    }

    #[test]
    fn raw_key_event_copy() {
        let ev = RawKeyEvent {
            keycode: 30,
            pressed: true,
        };
        let ev2 = ev;
        assert_eq!(ev2.keycode, 30);
        assert!(ev2.pressed);
    }
}
