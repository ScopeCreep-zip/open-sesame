//! Window switcher state machine.
//!
//! Four operational states controlling the overlay lifecycle:
//!
//! - `Idle`: No overlay visible. Transitions to `BorderOnly` on activation key.
//! - `BorderOnly`: Focused window border highlight shown. After `overlay_delay_ms`
//!   AND >= 2 rendered frames, transitions to `FullOverlay`. Alt-release during
//!   this state triggers quick-switch to previous window.
//! - `FullOverlay`: Window list with hint labels and input buffer. Hint matching,
//!   selection movement, search, Enter to confirm, Escape to cancel.
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

    /// Activation key pressed — begin the overlay sequence.
    ///
    /// When already showing (BorderOnly/FullOverlay/PendingActivation),
    /// re-activation advances the selection instead of being a no-op.
    /// This matches traditional alt+tab behavior where repeated presses
    /// cycle through the window list.
    pub fn on_activate(&mut self) -> Action {
        match self {
            Self::Idle => {
                *self = Self::BorderOnly {
                    entered_at: Instant::now(),
                    frame_count: 0,
                };
                Action::ShowBorder
            }
            Self::BorderOnly { .. } => {
                // Skip border phase, go straight to full overlay with
                // selection at index 1 (second window, same as Tab).
                *self = Self::FullOverlay {
                    input_buffer: String::new(),
                    selection: 1,
                    window_count: 0,
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

    /// Launcher mode activation -- go directly to FullOverlay (skip border phase).
    ///
    /// Re-activation while visible cycles selection (same as `on_activate`).
    pub fn on_activate_launcher(&mut self) -> Action {
        match self {
            Self::Idle => {
                *self = Self::FullOverlay {
                    input_buffer: String::new(),
                    selection: 0,
                    window_count: 0,
                };
                Action::ShowOverlay
            }
            Self::BorderOnly { .. } => {
                *self = Self::FullOverlay {
                    input_buffer: String::new(),
                    selection: 1,
                    window_count: 0,
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
            Self::PendingActivation { .. } => Action::None,
        }
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

    /// Alt key released — quick-switch if still in border-only mode.
    ///
    /// `quick_switch_threshold_ms`: if released within this time, quick-switch.
    /// `overlay_delay_ms`: if released after this time, force overlay.
    pub fn on_modifier_release(&mut self, quick_switch_threshold_ms: u32, _overlay_delay_ms: u32) -> Action {
        match self {
            Self::BorderOnly { entered_at, .. } => {
                let elapsed = entered_at.elapsed().as_millis() as u32;
                if elapsed < quick_switch_threshold_ms {
                    // Quick switch — user tapped and released quickly.
                    *self = Self::Idle;
                    Action::QuickSwitch
                } else {
                    // Past overlay delay but not enough frames yet — force overlay.
                    *self = Self::FullOverlay {
                        input_buffer: String::new(),
                        selection: 0,
                        window_count: 0,
                    };
                    Action::ShowOverlay
                }
            }
            Self::FullOverlay {
                selection,
                window_count,
                ..
            } => {
                if *window_count == 0 {
                    *self = Self::Idle;
                    return Action::Dismiss;
                }
                let target = *selection;
                *self = Self::Idle;
                Action::ActivateWindow(target)
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

    // ========================================================================
    // Activation (Idle -> BorderOnly)
    // ========================================================================

    #[test]
    fn idle_to_border_on_activate() {
        let mut state = WmState::new();
        let action = state.on_activate();
        assert_eq!(action, Action::ShowBorder);
        assert!(matches!(state, WmState::BorderOnly { .. }));
    }

    #[test]
    fn double_activate_transitions_to_full_overlay() {
        let mut state = WmState::new();
        state.on_activate();
        let action = state.on_activate();
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { selection: 1, .. }));
    }

    #[test]
    fn activate_from_full_overlay_cycles_selection() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 5,
        };
        assert_eq!(state.on_activate(), Action::Redraw);
        assert_eq!(state.selection(), Some(1));
    }

    // ========================================================================
    // BorderOnly -> FullOverlay (frame tick)
    // ========================================================================

    #[test]
    fn border_to_overlay_after_delay_and_frames() {
        let mut state = WmState::new();
        state.on_activate();
        assert_eq!(state.on_frame(0), Action::None);
        let action = state.on_frame(0);
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn border_frame_before_delay_is_noop() {
        let mut state = WmState::new();
        state.on_activate();
        // Even with 2 frames, 99999ms delay prevents transition.
        state.on_frame(99999);
        assert_eq!(state.on_frame(99999), Action::None);
        assert!(matches!(state, WmState::BorderOnly { .. }));
    }

    // ========================================================================
    // TASK-01: Modifier release in FullOverlay / PendingActivation
    // ========================================================================

    #[test]
    fn quick_switch_on_fast_release() {
        let mut state = WmState::new();
        state.on_activate();
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::QuickSwitch);
        assert!(state.is_idle());
    }

    #[test]
    fn slow_release_forces_overlay() {
        let mut state = WmState::BorderOnly {
            entered_at: Instant::now() - Duration::from_millis(200),
            frame_count: 0,
        };
        let action = state.on_modifier_release(100, 150);
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn alt_release_full_overlay_activates_selected() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 2,
            window_count: 5,
        };
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(state.is_idle());
    }

    #[test]
    fn alt_release_full_overlay_empty_dismisses() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 0,
        };
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
    // TASK-02: Character input in BorderOnly
    // ========================================================================

    #[test]
    fn char_in_border_transitions_to_overlay() {
        let mut state = WmState::new();
        state.on_activate();
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
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 3,
        };
        state.on_char('a');
        assert_eq!(state.input_buffer(), Some("a"));
        state.on_char('b');
        assert_eq!(state.input_buffer(), Some("ab"));
        state.on_backspace();
        assert_eq!(state.input_buffer(), Some("a"));
    }

    #[test]
    fn max_input_length_enforced() {
        let mut state = WmState::FullOverlay {
            input_buffer: "a".repeat(MAX_INPUT_LENGTH),
            selection: 0,
            window_count: 3,
        };
        let action = state.on_char('x');
        assert_eq!(action, Action::None);
        assert_eq!(state.input_buffer().unwrap().len(), MAX_INPUT_LENGTH);
    }

    #[test]
    fn max_input_length_allows_backspace_then_push() {
        let mut state = WmState::FullOverlay {
            input_buffer: "a".repeat(MAX_INPUT_LENGTH),
            selection: 0,
            window_count: 3,
        };
        state.on_backspace();
        assert_eq!(state.input_buffer().unwrap().len(), MAX_INPUT_LENGTH - 1);
        let action = state.on_char('z');
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.input_buffer().unwrap().len(), MAX_INPUT_LENGTH);
    }

    // ========================================================================
    // TASK-03: Tab / Shift+Tab in BorderOnly
    // ========================================================================

    #[test]
    fn tab_in_border_transitions_to_overlay() {
        let mut state = WmState::new();
        state.on_activate();
        let action = state.on_selection_down();
        assert_eq!(action, Action::ShowOverlay);
        assert_eq!(state.selection(), Some(1));
    }

    #[test]
    fn shift_tab_in_border_transitions_to_overlay_last() {
        let mut state = WmState::new();
        state.on_activate();
        let action = state.on_selection_up();
        assert_eq!(action, Action::ShowOverlay);
        // selection is usize::MAX, clamped by set_window_count.
        state.set_window_count(5);
        assert_eq!(state.selection(), Some(4));
    }

    #[test]
    fn set_window_count_clamps_selection() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 10,
            window_count: 0,
        };
        state.set_window_count(3);
        assert_eq!(state.selection(), Some(2));
    }

    #[test]
    fn tab_in_border_clamped_by_set_window_count() {
        let mut state = WmState::new();
        state.on_activate();
        state.on_selection_down(); // selection=1
        state.set_window_count(1); // only 1 window, clamp to 0
        assert_eq!(state.selection(), Some(0));
    }

    // ========================================================================
    // Selection wrapping in FullOverlay
    // ========================================================================

    #[test]
    fn selection_wraps_around_down() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 2,
            window_count: 3,
        };
        state.on_selection_down();
        assert_eq!(state.selection(), Some(0));
    }

    #[test]
    fn selection_wraps_around_up() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 3,
        };
        state.on_selection_up();
        assert_eq!(state.selection(), Some(2));
    }

    #[test]
    fn selection_down_with_zero_windows() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 0,
        };
        let action = state.on_selection_down();
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.selection(), Some(0));
    }

    #[test]
    fn selection_up_with_zero_windows() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 0,
        };
        let action = state.on_selection_up();
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.selection(), Some(0));
    }

    // ========================================================================
    // Confirm
    // ========================================================================

    #[test]
    fn confirm_in_empty_overlay_is_noop() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 0,
        };
        assert_eq!(state.on_confirm(), Action::None);
    }

    #[test]
    fn confirm_activates_selection() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 2,
            window_count: 5,
        };
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
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 5,
        };
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
        let mut state = WmState::new();
        state.on_activate();
        assert_eq!(state.on_escape(), Action::Dismiss);
        assert!(state.is_idle());
    }

    #[test]
    fn escape_from_full_overlay() {
        let mut state = WmState::FullOverlay {
            input_buffer: "abc".into(),
            selection: 2,
            window_count: 5,
        };
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
        let mut state = WmState::new();
        state.on_activate();
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
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 3,
        };
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
    fn scenario_quick_alt_tab() {
        let mut state = WmState::new();
        state.on_activate();
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::QuickSwitch);
        assert!(state.is_idle());
    }

    #[test]
    fn scenario_hold_tab_release() {
        let mut state = WmState::new();
        state.on_activate();
        // Transition to full overlay via frames.
        state.on_frame(0);
        state.on_frame(0);
        assert!(matches!(state, WmState::FullOverlay { .. }));
        state.set_window_count(5);
        // Tab twice.
        state.on_selection_down();
        assert_eq!(state.selection(), Some(1));
        state.on_selection_down();
        assert_eq!(state.selection(), Some(2));
        // Release alt.
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(state.is_idle());
    }

    #[test]
    fn scenario_type_hint_activate() {
        let mut state = WmState::new();
        state.on_activate();
        state.on_frame(0);
        state.on_frame(0);
        state.set_window_count(5);
        // Type a character.
        let action = state.on_char('g');
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.input_buffer(), Some("g"));
        // Hint match found.
        let action = state.on_hint_match(2);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(matches!(state, WmState::PendingActivation { target: 2, .. }));
    }

    #[test]
    fn scenario_type_during_border() {
        let mut state = WmState::new();
        state.on_activate();
        // Type during border phase.
        let action = state.on_char('f');
        assert_eq!(action, Action::ShowOverlay);
        assert_eq!(state.input_buffer(), Some("f"));
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn scenario_tab_during_border() {
        let mut state = WmState::new();
        state.on_activate();
        let action = state.on_selection_down();
        assert_eq!(action, Action::ShowOverlay);
        state.set_window_count(3);
        assert_eq!(state.selection(), Some(1));
        // Tab again.
        state.on_selection_down();
        assert_eq!(state.selection(), Some(2));
        // Release alt.
        let action = state.on_modifier_release(250, 500);
        assert_eq!(action, Action::ActivateWindow(2));
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
        let overlay = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 0,
        };
        assert!(overlay.is_overlay_visible());
        let pending = WmState::PendingActivation {
            target: 0,
            pending_key: None,
            entered_at: Instant::now(),
            input_buffer: String::new(),
        };
        assert!(pending.is_overlay_visible());
    }
}
