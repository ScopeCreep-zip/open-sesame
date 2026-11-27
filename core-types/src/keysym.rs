//! The X11 keysyms the bus carries in `InputKeyEvent::keyval` and the
//! window switcher acts on (`xkbcommon-keysyms.h`).

/// `XK_space`.
pub const SPACE: u32 = 0x0020;
/// `XK_BackSpace`.
pub const BACKSPACE: u32 = 0xFF08;
/// `XK_Tab`.
pub const TAB: u32 = 0xFF09;
/// `XK_Return`.
pub const RETURN: u32 = 0xFF0D;
/// `XK_KP_Enter`.
pub const KP_ENTER: u32 = 0xFF8D;
/// `XK_Escape`.
pub const ESCAPE: u32 = 0xFF1B;
/// `XK_Up`.
pub const UP: u32 = 0xFF52;
/// `XK_Down`.
pub const DOWN: u32 = 0xFF54;
/// `XK_Meta_L`.
pub const META_L: u32 = 0xFFE7;
/// `XK_Meta_R`.
pub const META_R: u32 = 0xFFE8;
/// `XK_Alt_L`.
pub const ALT_L: u32 = 0xFFE9;
/// `XK_Alt_R`.
pub const ALT_R: u32 = 0xFFEA;

/// Whether `keyval` is an Alt or Meta key, the modifiers whose release
/// ends a window-switcher cycle.
#[must_use]
pub const fn is_alt_or_meta(keyval: u32) -> bool {
    matches!(keyval, META_L | META_R | ALT_L | ALT_R)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_and_meta_are_the_cycle_modifiers() {
        for keyval in [META_L, META_R, ALT_L, ALT_R] {
            assert!(is_alt_or_meta(keyval));
        }
        for keyval in [BACKSPACE, RETURN, ESCAPE, UP, DOWN, 0xFFE1, 0xFFEB] {
            assert!(!is_alt_or_meta(keyval));
        }
    }
}
