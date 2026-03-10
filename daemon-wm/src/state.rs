//! Window switcher state machine.
//!
//! Four operational states controlling the overlay lifecycle:
//!
//! - `Idle`: No overlay visible. Activation goes directly to `FullOverlay`.
//! - `BorderOnly`: Legacy state reachable only from internal transitions
//!   (e.g. slow modifier release from border). Not entered from `on_activate()`.
//! - `FullOverlay`: Window list with hint labels and input buffer. Hint matching,
//!   selection movement, search, Enter to confirm, Escape to cancel. Tracks
//!   `entered_at` for quick-switch detection on fast Alt release.
//! - `PendingActivation`: Target window selected, waiting `activation_delay_ms`
//!   before activating. Continued typing can change the target. Backspace
//!   returns to `FullOverlay`.

use std::time::Instant;

/// Maximum input buffer length (matches v1's MAX_INPUT_LENGTH).
const MAX_INPUT_LENGTH: usize = 64;

/// Overlay state machine states.
#[derive(Debug, Clone)]
pub enum WmState {
    Idle,
    BorderOnly {
        entered_at: Instant,
        frame_count: u32,
    },
    FullOverlay {
        input_buffer: String,
        selection: usize,
        window_count: usize,
        entered_at: Instant,
    },
    PendingActivation {
        target: usize,
        pending_key: Option<char>,
        entered_at: Instant,
        /// Input buffer that led to this match (for backspace restoration).
        input_buffer: String,
    },
}

/// Actions produced by state machine transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Show border-only indicator on the focused window.
    ShowBorder,
    /// Show the full overlay with window list and hints.
    ShowOverlay,
    /// Activate the window at the given index.
    ActivateWindow(usize),
    /// Quick-switch to the previous MRU window.
    QuickSwitch,
    /// Dismiss the overlay and return to idle.
    Dismiss,
    /// Redraw the overlay (input or selection changed).
    Redraw,
    /// Launch an application by command string (launch-or-focus: no window matched).
    LaunchApp(String),
    /// No action needed.
    None,
}

impl WmState {
    /// Create a new idle state machine.
    #[must_use]
    pub fn new() -> Self {
        Self::Idle
    }

    /// Activation key pressed — show the overlay immediately.
    ///
    /// Goes directly to FullOverlay so the overlay acquires
    /// KeyboardMode::Exclusive immediately and captures the Alt release
    /// event. The `entered_at` timestamp enables quick-switch: if the user
    /// releases Alt within `quick_switch_threshold_ms`, `on_modifier_release`
    /// returns `QuickSwitch` instead of `ActivateWindow` — no GUI shown.
    ///
    /// The rendering pipeline sends a non-blocking border frame first
    /// (visual hint while the window list loads), but the state machine
    /// is already in FullOverlay so keyboard exclusivity is held throughout.
    ///
    /// When already showing, re-activation advances the selection.
    pub fn on_activate(&mut self) -> Action {
        match self {
            Self::Idle => {
                *self = Self::FullOverlay {
                    input_buffer: String::new(),
                    selection: 0,
                    window_count: 0,
                    entered_at: Instant::now(),
                };
                Action::ShowOverlay
            }
            Self::BorderOnly { .. } => {
                *self = Self::FullOverlay {
                    input_buffer: String::new(),
                    selection: 1,
                    window_count: 0,
                    entered_at: Instant::now(),
                };
                Action::ShowOverlay
            }
            Self::FullOverlay {
                selection,
                window_count,
                ..
            } => {
                if *window_count > 0 {
                    *selection = (*selection + 1) % *window_count;
                }
                Action::Redraw
            }
            Self::PendingActivation { .. } => {
                // Already committed to a target — ignore re-activation.
                Action::None
            }
        }
    }

    /// Launcher mode activation — delegates to `on_activate`.
    pub fn on_activate_launcher(&mut self) -> Action {
        self.on_activate()
    }

    /// Frame rendered in border-only mode.
    /// Increments frame counter and checks transition to full overlay.
    pub fn on_frame(&mut self, overlay_delay_ms: u32) -> Action {
        match self {
            Self::BorderOnly {
                entered_at,
                frame_count,
            } => {
                *frame_count += 1;
                let elapsed = entered_at.elapsed().as_millis() as u32;
                if elapsed >= overlay_delay_ms && *frame_count >= 2 {
                    *self = Self::FullOverlay {
                        input_buffer: String::new(),
                        selection: 0,
                        window_count: 0,
                        entered_at: *entered_at,
                    };
                    Action::ShowOverlay
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        }
    }

    /// Set the window count when entering full overlay.
    ///
    /// Must be called immediately after `Action::ShowOverlay` is dispatched
    /// so the state machine knows how many windows are available.
    pub fn set_window_count(&mut self, count: usize) {
        if let Self::FullOverlay {
            window_count,
            selection,
            ..
        } = self
        {
            *window_count = count;
            if *selection >= count && count > 0 {
                *selection = count - 1;
            }
        }
    }

    /// Alt key released — quick-switch or activate based on timing.
    ///
    /// If released within `quick_switch_threshold_ms` of entering FullOverlay
    /// (and no user interaction occurred), returns `QuickSwitch` — no GUI shown.
    /// Otherwise activates the current selection.
    pub fn on_modifier_release(&mut self, quick_switch_threshold_ms: u32, _overlay_delay_ms: u32) -> Action {
        match self {
            Self::BorderOnly { entered_at, .. } => {
                let elapsed = entered_at.elapsed().as_millis() as u32;
                if elapsed < quick_switch_threshold_ms {
                    *self = Self::Idle;
                    Action::QuickSwitch
                } else {
                    *self = Self::FullOverlay {
                        input_buffer: String::new(),
                        selection: 0,
                        window_count: 0,
                        entered_at: *entered_at,
                    };
                    Action::ShowOverlay
                }
            }
            Self::FullOverlay {
                selection,
                window_count,
                entered_at,
                input_buffer,
            } => {
                if *window_count == 0 {
                    *self = Self::Idle;
                    return Action::Dismiss;
                }
                let elapsed = entered_at.elapsed().as_millis() as u32;
                // Quick-switch: fast release with no user interaction.
                if elapsed < quick_switch_threshold_ms
                    && *selection == 0
                    && input_buffer.is_empty()
                {
                    *self = Self::Idle;
                    Action::QuickSwitch
                } else {
                    let target = *selection;
                    *self = Self::Idle;
                    Action::ActivateWindow(target)
                }
            }
            Self::PendingActivation { target, .. } => {
                let target = *target;
                *self = Self::Idle;
                Action::ActivateWindow(target)
            }
            _ => Action::None,
        }
    }

    /// Character input in full overlay mode.
    pub fn on_char(&mut self, ch: char) -> Action {
        match self {
            Self::BorderOnly { .. } => {
                *self = Self::FullOverlay {
                    input_buffer: ch.to_string(),
                    selection: 0,
                    window_count: 0,
                    entered_at: Instant::now(),
                };
                Action::ShowOverlay
            }
            Self::FullOverlay { input_buffer, .. } => {
                if input_buffer.len() >= MAX_INPUT_LENGTH {
                    return Action::None;
                }
                input_buffer.push(ch);
                Action::Redraw
            }
            Self::PendingActivation { pending_key, .. } => {
                *pending_key = Some(ch);
                Action::Redraw
            }
            _ => Action::None,
        }
    }

    /// Backspace in full overlay or pending activation.
    pub fn on_backspace(&mut self) -> Action {
        match self {
            Self::FullOverlay { input_buffer, .. } => {
                input_buffer.pop();
                Action::Redraw
            }
            Self::PendingActivation { input_buffer, .. } => {
                // Return to overlay, preserving input minus last char.
                let mut buf = input_buffer.clone();
                buf.pop();
                *self = Self::FullOverlay {
                    input_buffer: buf,
                    selection: 0,
                    window_count: 0,
                    entered_at: Instant::now(),
                };
                Action::ShowOverlay
            }
            _ => Action::None,
        }
    }

    /// Move selection down (Tab / Down arrow). Wraps around.
    pub fn on_selection_down(&mut self) -> Action {
        if let Self::BorderOnly { .. } = self {
            *self = Self::FullOverlay {
                input_buffer: String::new(),
                selection: 1,
                window_count: 0,
                entered_at: Instant::now(),
            };
            return Action::ShowOverlay;
        }
        if let Self::FullOverlay {
            selection,
            window_count,
            ..
        } = self
        {
            if *window_count > 0 {
                *selection = (*selection + 1) % *window_count;
            }
            Action::Redraw
        } else {
            Action::None
        }
    }

    /// Move selection up (Shift+Tab / Up arrow). Wraps around.
    pub fn on_selection_up(&mut self) -> Action {
        if let Self::BorderOnly { .. } = self {
            *self = Self::FullOverlay {
                input_buffer: String::new(),
                selection: usize::MAX,
                window_count: 0,
                entered_at: Instant::now(),
            };
            return Action::ShowOverlay;
        }
        if let Self::FullOverlay {
            selection,
            window_count,
            ..
        } = self
        {
            if *window_count > 0 {
                *selection = selection.checked_sub(1).unwrap_or(*window_count - 1);
            }
            Action::Redraw
        } else {
            Action::None
        }
    }

    /// Confirm selection (Enter key).
    pub fn on_confirm(&mut self) -> Action {
        match self {
            Self::FullOverlay {
                selection,
                window_count,
                input_buffer,
                ..
            } => {
                if *window_count == 0 {
                    return Action::None;
                }
                let target = *selection;
                let buf = input_buffer.clone();
                *self = Self::PendingActivation {
                    target,
                    pending_key: None,
                    entered_at: Instant::now(),
                    input_buffer: buf,
                };
                Action::ActivateWindow(target)
            }
            Self::PendingActivation { target, .. } => Action::ActivateWindow(*target),
            _ => Action::None,
        }
    }

    /// Set target from hint match (exact match found).
    pub fn on_hint_match(&mut self, index: usize) -> Action {
        match self {
            Self::FullOverlay { input_buffer, .. } => {
                let buf = input_buffer.clone();
                *self = Self::PendingActivation {
                    target: index,
                    pending_key: None,
                    entered_at: Instant::now(),
                    input_buffer: buf,
                };
                Action::ActivateWindow(index)
            }
            _ => Action::None,
        }
    }

    /// Escape key — cancel and dismiss.
    pub fn on_escape(&mut self) -> Action {
        match self {
            Self::Idle => Action::None,
            _ => {
                *self = Self::Idle;
                Action::Dismiss
            }
        }
    }

    /// Check pending activation timeout.
    pub fn check_activation_timeout(&mut self, activation_delay_ms: u32) -> Action {
        if let Self::PendingActivation {
            target, entered_at, ..
        } = self
            && entered_at.elapsed().as_millis() as u32 >= activation_delay_ms
        {
            let target = *target;
            *self = Self::Idle;
            return Action::ActivateWindow(target);
        }
        Action::None
    }

    /// Current input buffer contents (if in overlay mode).
    #[must_use]
    pub fn input_buffer(&self) -> Option<&str> {
        match self {
            Self::FullOverlay { input_buffer, .. } => Some(input_buffer),
            _ => None,
        }
    }

    /// Current selection index (if in overlay mode).
    #[must_use]
    pub fn selection(&self) -> Option<usize> {
        match self {
            Self::FullOverlay { selection, .. } => Some(*selection),
            _ => None,
        }
    }

    /// Whether the overlay should be visible.
    #[must_use]
    pub fn is_overlay_visible(&self) -> bool {
        matches!(
            self,
            Self::BorderOnly { .. } | Self::FullOverlay { .. } | Self::PendingActivation { .. }
        )
    }

    /// Whether we are in idle state.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }
}

impl Default for WmState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Helper to construct a FullOverlay with entered_at = now.
    fn full_overlay(input: &str, selection: usize, window_count: usize) -> WmState {
        WmState::FullOverlay {
            input_buffer: input.into(),
            selection,
            window_count,
            entered_at: Instant::now(),
        }
    }

    /// Helper to construct a FullOverlay with a past entered_at.
    fn full_overlay_aged(input: &str, selection: usize, window_count: usize, age: Duration) -> WmState {
        WmState::FullOverlay {
            input_buffer: input.into(),
            selection,
            window_count,
            entered_at: Instant::now() - age,
        }
    }

    // ========================================================================
    // Activation (Idle -> FullOverlay)
    // ========================================================================

    #[test]
    fn idle_to_full_overlay_on_activate() {
        let mut state = WmState::new();
        let action = state.on_activate();
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { selection: 0, .. }));
    }

    #[test]
    fn double_activate_cycles_selection() {
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(5);
        let action = state.on_activate();
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.selection(), Some(1));
    }

    #[test]
    fn activate_from_full_overlay_cycles_selection() {
        let mut state = full_overlay("", 0, 5);
        assert_eq!(state.on_activate(), Action::Redraw);
        assert_eq!(state.selection(), Some(1));
    }

    #[test]
    fn launcher_delegates_to_activate() {
        let mut state = WmState::new();
        let action = state.on_activate_launcher();
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { selection: 0, .. }));
    }

    // ========================================================================
    // BorderOnly -> FullOverlay (frame tick)
    // ========================================================================

    #[test]
    fn border_to_overlay_after_delay_and_frames() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        assert_eq!(state.on_frame(0), Action::None);
        let action = state.on_frame(0);
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn border_frame_before_delay_is_noop() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        state.on_frame(99999);
        assert_eq!(state.on_frame(99999), Action::None);
        assert!(matches!(state, WmState::BorderOnly { .. }));
    }

    // ========================================================================
    // Modifier release: quick-switch vs activate
    // ========================================================================

    #[test]
    fn quick_release_from_border_quick_switches() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::QuickSwitch);
        assert!(state.is_idle());
    }

    #[test]
    fn slow_release_from_border_forces_overlay() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now() - Duration::from_millis(200),
            frame_count: 0,
        };
        let action = state.on_modifier_release(100, 150);
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn fast_release_from_full_overlay_quick_switches() {
        // on_activate() → FullOverlay with entered_at=now.
        // Quick Alt release → QuickSwitch (no GUI).
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(3);
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::QuickSwitch);
        assert!(state.is_idle());
    }

    #[test]
    fn slow_release_from_full_overlay_activates() {
        // After threshold, release activates the current selection.
        let mut state = full_overlay_aged("", 0, 3, Duration::from_millis(300));
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(0));
        assert!(state.is_idle());
    }

    #[test]
    fn release_after_interaction_activates_even_if_fast() {
        // User typed a char — no longer eligible for quick-switch.
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(3);
        state.on_char('g');
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(0));
        assert!(state.is_idle());
    }

    #[test]
    fn release_after_tab_activates_even_if_fast() {
        // User tabbed — selection != 0, not eligible for quick-switch.
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(3);
        state.on_selection_down(); // selection=1
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(1));
        assert!(state.is_idle());
    }

    #[test]
    fn alt_release_full_overlay_activates_selected() {
        let mut state = full_overlay_aged("", 2, 5, Duration::from_millis(500));
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(state.is_idle());
    }

    #[test]
    fn alt_release_full_overlay_empty_dismisses() {
        let mut state = full_overlay("", 0, 0);
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::Dismiss);
        assert!(state.is_idle());
    }

    #[test]
    fn alt_release_pending_activates_target() {
        let mut state = WmState::PendingActivation {
            target: 1,
            pending_key: None,
            entered_at: Instant::now(),
            input_buffer: String::new(),
        };
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(1));
        assert!(state.is_idle());
    }

    #[test]
    fn alt_release_idle_is_noop() {
        let mut state = WmState::Idle;
        assert_eq!(state.on_modifier_release(250, 500), Action::None);
    }

    // ========================================================================
    // Character input
    // ========================================================================

    #[test]
    fn char_in_border_transitions_to_overlay() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        let action = state.on_char('g');
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
        assert_eq!(state.input_buffer(), Some("g"));
    }

    #[test]
    fn char_in_idle_is_noop() {
        let mut state = WmState::Idle;
        assert_eq!(state.on_char('g'), Action::None);
    }

    #[test]
    fn char_input_and_backspace() {
        let mut state = full_overlay("", 0, 3);
        state.on_char('a');
        assert_eq!(state.input_buffer(), Some("a"));
        state.on_char('b');
        assert_eq!(state.input_buffer(), Some("ab"));
        state.on_backspace();
        assert_eq!(state.input_buffer(), Some("a"));
    }

    #[test]
    fn max_input_length_enforced() {
        let mut state = full_overlay(&"a".repeat(MAX_INPUT_LENGTH), 0, 3);
        let action = state.on_char('x');
        assert_eq!(action, Action::None);
        assert_eq!(state.input_buffer().unwrap().len(), MAX_INPUT_LENGTH);
    }

    #[test]
    fn max_input_length_allows_backspace_then_push() {
        let mut state = full_overlay(&"a".repeat(MAX_INPUT_LENGTH), 0, 3);
        state.on_backspace();
        assert_eq!(state.input_buffer().unwrap().len(), MAX_INPUT_LENGTH - 1);
        let action = state.on_char('z');
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.input_buffer().unwrap().len(), MAX_INPUT_LENGTH);
    }

    // ========================================================================
    // Tab / Shift+Tab in BorderOnly
    // ========================================================================

    #[test]
    fn tab_in_border_transitions_to_overlay() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        let action = state.on_selection_down();
        assert_eq!(action, Action::ShowOverlay);
        assert_eq!(state.selection(), Some(1));
    }

    #[test]
    fn shift_tab_in_border_transitions_to_overlay_last() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        let action = state.on_selection_up();
        assert_eq!(action, Action::ShowOverlay);
        state.set_window_count(5);
        assert_eq!(state.selection(), Some(4));
    }

    #[test]
    fn set_window_count_clamps_selection() {
        let mut state = full_overlay("", 10, 0);
        state.set_window_count(3);
        assert_eq!(state.selection(), Some(2));
    }

    #[test]
    fn tab_after_activate_cycles() {
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(3);
        state.on_selection_down();
        assert_eq!(state.selection(), Some(1));
    }

    // ========================================================================
    // Selection wrapping in FullOverlay
    // ========================================================================

    #[test]
    fn selection_wraps_around_down() {
        let mut state = full_overlay("", 2, 3);
        state.on_selection_down();
        assert_eq!(state.selection(), Some(0));
    }

    #[test]
    fn selection_wraps_around_up() {
        let mut state = full_overlay("", 0, 3);
        state.on_selection_up();
        assert_eq!(state.selection(), Some(2));
    }

    #[test]
    fn selection_down_with_zero_windows() {
        let mut state = full_overlay("", 0, 0);
        let action = state.on_selection_down();
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.selection(), Some(0));
    }

    #[test]
    fn selection_up_with_zero_windows() {
        let mut state = full_overlay("", 0, 0);
        let action = state.on_selection_up();
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.selection(), Some(0));
    }

    // ========================================================================
    // Confirm
    // ========================================================================

    #[test]
    fn confirm_in_empty_overlay_is_noop() {
        let mut state = full_overlay("", 0, 0);
        assert_eq!(state.on_confirm(), Action::None);
    }

    #[test]
    fn confirm_activates_selection() {
        let mut state = full_overlay("", 2, 5);
        let action = state.on_confirm();
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(matches!(state, WmState::PendingActivation { target: 2, .. }));
    }

    #[test]
    fn confirm_in_pending_activates_target() {
        let mut state = WmState::PendingActivation {
            target: 3,
            pending_key: None,
            entered_at: Instant::now(),
            input_buffer: String::new(),
        };
        assert_eq!(state.on_confirm(), Action::ActivateWindow(3));
    }

    // ========================================================================
    // Hint match
    // ========================================================================

    #[test]
    fn hint_match_transitions_to_pending() {
        let mut state = full_overlay("", 0, 5);
        let action = state.on_hint_match(3);
        assert_eq!(action, Action::ActivateWindow(3));
        assert!(matches!(state, WmState::PendingActivation { target: 3, .. }));
    }

    #[test]
    fn hint_match_from_non_overlay_is_noop() {
        let mut state = WmState::Idle;
        assert_eq!(state.on_hint_match(0), Action::None);
    }

    // ========================================================================
    // Escape from every state
    // ========================================================================

    #[test]
    fn escape_from_idle_is_noop() {
        let mut state = WmState::Idle;
        assert_eq!(state.on_escape(), Action::None);
    }

    #[test]
    fn escape_from_border_only() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        assert_eq!(state.on_escape(), Action::Dismiss);
        assert!(state.is_idle());
    }

    #[test]
    fn escape_from_full_overlay() {
        let mut state = full_overlay("abc", 2, 5);
        assert_eq!(state.on_escape(), Action::Dismiss);
        assert!(state.is_idle());
    }

    #[test]
    fn escape_from_pending_activation() {
        let mut state = WmState::PendingActivation {
            target: 2,
            pending_key: None,
            entered_at: Instant::now(),
            input_buffer: String::new(),
        };
        assert_eq!(state.on_escape(), Action::Dismiss);
        assert!(state.is_idle());
    }

    // ========================================================================
    // Backspace from every state
    // ========================================================================

    #[test]
    fn backspace_from_idle_is_noop() {
        let mut state = WmState::Idle;
        assert_eq!(state.on_backspace(), Action::None);
    }

    #[test]
    fn backspace_from_border_is_noop() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        assert_eq!(state.on_backspace(), Action::None);
    }

    #[test]
    fn backspace_from_pending_returns_to_overlay() {
        let mut state = WmState::PendingActivation {
            target: 0,
            pending_key: None,
            entered_at: Instant::now(),
            input_buffer: String::new(),
        };
        let action = state.on_backspace();
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn backspace_empty_buffer_stays_in_overlay() {
        let mut state = full_overlay("", 0, 3);
        let action = state.on_backspace();
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.input_buffer(), Some(""));
    }

    // ========================================================================
    // Activation timeout
    // ========================================================================

    #[test]
    fn activation_timeout_fires() {
        let mut state = WmState::PendingActivation {
            target: 2,
            pending_key: None,
            entered_at: Instant::now() - Duration::from_millis(300),
            input_buffer: String::new(),
        };
        let action = state.check_activation_timeout(200);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(state.is_idle());
    }

    #[test]
    fn activation_timeout_not_yet() {
        let mut state = WmState::PendingActivation {
            target: 2,
            pending_key: None,
            entered_at: Instant::now(),
            input_buffer: String::new(),
        };
        assert_eq!(state.check_activation_timeout(5000), Action::None);
    }

    #[test]
    fn activation_timeout_from_idle_is_noop() {
        let mut state = WmState::Idle;
        assert_eq!(state.check_activation_timeout(100), Action::None);
    }

    // ========================================================================
    // Lifecycle scenarios
    // ========================================================================

    #[test]
    fn scenario_quick_alt_tab_quick_switches() {
        // Fast alt+tab+release → QuickSwitch (no GUI).
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(3);
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::QuickSwitch);
        assert!(state.is_idle());
    }

    #[test]
    fn scenario_hold_tab_release() {
        let mut state = WmState::new();
        state.on_activate();
        assert!(matches!(state, WmState::FullOverlay { .. }));
        state.set_window_count(5);
        state.on_selection_down();
        assert_eq!(state.selection(), Some(1));
        state.on_selection_down();
        assert_eq!(state.selection(), Some(2));
        // Tab interaction means selection != 0 → ActivateWindow, not QuickSwitch.
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(state.is_idle());
    }

    #[test]
    fn scenario_type_hint_activate() {
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(5);
        let action = state.on_char('g');
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.input_buffer(), Some("g"));
        let action = state.on_hint_match(2);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(matches!(state, WmState::PendingActivation { target: 2, .. }));
    }

    #[test]
    fn scenario_tab_then_release() {
        let mut state = WmState::new();
        state.on_activate();
        state.set_window_count(3);
        state.on_selection_down();
        state.on_selection_down();
        assert_eq!(state.selection(), Some(2));
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(2));
    }

    #[test]
    fn scenario_slow_alt_tab_activates_first() {
        // Held past threshold with no interaction → ActivateWindow(0).
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 3,
            entered_at: Instant::now() - Duration::from_millis(500),
        };
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(0));
        assert!(state.is_idle());
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    #[test]
    fn input_buffer_returns_none_for_non_overlay() {
        assert!(WmState::Idle.input_buffer().is_none());
    }

    #[test]
    fn selection_returns_none_for_non_overlay() {
        assert!(WmState::Idle.selection().is_none());
    }

    #[test]
    fn is_overlay_visible_covers_all_states() {
        assert!(!WmState::Idle.is_overlay_visible());
        let border = WmState::BorderOnly {
            entered_at: Instant::now(),
            frame_count: 0,
        };
        assert!(border.is_overlay_visible());
        assert!(full_overlay("", 0, 0).is_overlay_visible());
        let pending = WmState::PendingActivation {
            target: 0,
            pending_key: None,
            entered_at: Instant::now(),
            input_buffer: String::new(),
        };
        assert!(pending.is_overlay_visible());
    }
}
