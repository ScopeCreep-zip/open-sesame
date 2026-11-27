//! Keyboard event capture via evdev and XKB keysym translation.
//!
//! Provides:
//! - [`XkbContext`]: xkbcommon state for keycode-to-keysym translation,
//!   producing the bus `InputKeyEvent`.
//! - [`spawn_keyboard_readers`]: async tasks that read every keyboard
//!   device and funnel its events through one channel.

use core_types::EventKind;
use evdev::EventSummary;
use tokio::sync::mpsc;

/// XKB context for translating evdev keycodes to keysyms and unicode.
///
/// Maintains xkbcommon keymap and state. Must be called from a single thread
/// (`xkb::State` is not `Send`/`Sync`). Process events sequentially.
pub struct XkbContext {
    state: xkbcommon::xkb::State,
}

/// The `InputKeyEvent` of `raw` translated by `xkb`; without an XKB
/// context, the raw keycode stands in for the keysym and no modifiers or
/// character are known.
pub fn translate(xkb: Option<&mut XkbContext>, raw: RawKeyEvent) -> EventKind {
    match xkb {
        Some(xkb) => xkb.process_key(raw.keycode, raw.pressed),
        None => EventKind::InputKeyEvent {
            keyval: raw.keycode,
            keycode: raw.keycode,
            pressed: raw.pressed,
            modifiers: 0,
            unicode: None,
        },
    }
}

impl XkbContext {
    /// Create a new XKB context with the system's default keymap.
    ///
    /// Returns `None` if xkbcommon fails to initialize (missing XKB data files).
    #[must_use]
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

    /// Process an evdev key event: the `InputKeyEvent` with its keysym,
    /// character (presses only), and GDK-compatible modifier mask.
    ///
    /// IMPORTANT: reads keysym and modifiers BEFORE updating state. This ensures
    /// that when the Alt key itself is pressed, the modifier mask does NOT yet
    /// include Alt — critical for correct Alt-release detection on the receiving end.
    pub fn process_key(&mut self, evdev_keycode: u32, pressed: bool) -> EventKind {
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

        EventKind::InputKeyEvent {
            keyval,
            keycode: evdev_keycode,
            pressed,
            modifiers,
            unicode,
        }
    }

    /// Query whether Alt (Mod1) is currently active in the XKB state.
    #[cfg(test)]
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
/// This is not fatal: daemon-wm's overlay surface still receives keyboard
/// input from the compositor.
pub fn spawn_keyboard_readers() -> mpsc::Receiver<RawKeyEvent> {
    let (tx, rx) = mpsc::channel::<RawKeyEvent>(256);

    let keyboards: Vec<_> = platform_linux::input::enumerate_devices()
        .into_iter()
        .filter(|d| d.is_keyboard)
        .collect();

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
                                    keycode: u32::from(keycode.0),
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

    /// The system keymap; the tests need the XKB data files.
    fn context() -> XkbContext {
        XkbContext::new().expect("no XKB keymap: install xkeyboard-config to run the xkb tests")
    }

    /// The fields of an `InputKeyEvent`.
    fn fields(event: &EventKind) -> (u32, u32, bool, u32, Option<char>) {
        match *event {
            EventKind::InputKeyEvent {
                keyval,
                keycode,
                pressed,
                modifiers,
                unicode,
            } => (keyval, keycode, pressed, modifiers, unicode),
            ref other => panic!("not an InputKeyEvent: {other:?}"),
        }
    }

    #[test]
    fn xkb_translates_keycodes_to_keysyms_and_characters() {
        let mut ctx = context();
        // 'a' is evdev keycode 30, keysym 0x0061.
        assert_eq!(
            fields(&ctx.process_key(30, true)),
            (0x0061, 30, true, 0, Some('a'))
        );
    }

    #[test]
    fn xkb_modifier_tracking() {
        let mut ctx = context();
        // Press left Alt (evdev keycode 56): the mask predates the press.
        let (keyval, _, _, modifiers, _) = fields(&ctx.process_key(56, true));
        assert_eq!(keyval, core_types::keysym::ALT_L);
        assert_eq!(
            modifiers & (1 << 3),
            0,
            "Alt should not be in pre-press modifiers"
        );
        assert!(ctx.is_alt_active(), "Alt should be active after press");
        ctx.process_key(56, false);
        assert!(
            !ctx.is_alt_active(),
            "Alt should not be active after release"
        );
    }

    #[test]
    fn without_xkb_the_keycode_stands_in() {
        let raw = RawKeyEvent {
            keycode: 30,
            pressed: false,
        };
        assert_eq!(fields(&translate(None, raw)), (30, 30, false, 0, None));
    }
}
