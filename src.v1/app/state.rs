//! Application state machine
//!
//! Pure state transitions with no side effects. All state is explicit,
//! all transitions are through handle_event(), all side effects are
//! returned as Actions to be executed by the caller.

use crate::config::Config;
use crate::core::{HintMatcher, MatchResult, WindowHint};
use crate::util::TimeoutTracker;
use smithay_client_toolkit::seat::keyboard::Keysym;
use std::time::{Duration, Instant};

/// Application lifecycle state
#[derive(Debug, Clone)]
pub enum AppState {
    /// Border-only phase, waiting for overlay_delay
    BorderOnly {
        /// When the border phase started
        start_time: Instant,
        /// Number of frames rendered in this phase
        frame_count: u32,
    },

    /// Full overlay visible with window list
    FullOverlay {
        /// Index into original hints array (NOT filtered)
        selected_hint_index: usize,
        /// User input buffer for hint matching
        input: String,
    },

    /// Exact hint match, waiting for activation_delay timeout
    PendingActivation {
        /// Index of the matched hint
        hint_index: usize,
        /// Current input buffer
        input: String,
        /// Timeout tracker for activation delay
        timeout: TimeoutTracker,
    },

    /// Application is exiting with a result
    Exiting {
        /// The activation result
        result: ActivationResult,
    },
}

/// Result of the application session
#[derive(Debug, Clone)]
pub enum ActivationResult {
    /// Activate window at hint index
    Window(usize),
    /// Quick Alt+Tab - activate previous window
    QuickSwitch,
    /// Launch app for key (no matching window)
    Launch(String),
    /// User cancelled
    Cancelled,
}

/// Events that can trigger state transitions
#[derive(Debug, Clone)]
pub enum Event {
    /// Key pressed
    KeyPress {
        keysym: Keysym,
        shift: bool,
    },
    /// Alt modifier released
    AltReleased,
    /// Timer tick for checking timeouts
    Tick,
    /// Frame callback received - safe to render
    FrameCallback,
    /// IPC signal to cycle selection
    CycleForward,
    CycleBackward,
    /// Surface configured with dimensions
    Configure {
        width: u32,
        height: u32,
    },
}

/// Actions to be executed after state transition
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Schedule a redraw on next frame
    ScheduleRedraw,
    /// Exit the event loop
    Exit,
}

/// State transition result
pub struct Transition {
    pub new_state: AppState,
    pub actions: Vec<Action>,
}

impl AppState {
    /// Creates initial state based on launcher mode.
    ///
    /// Launcher mode initializes with FullOverlay state and selects the previous window
    /// from MRU tracking, ensuring quick Alt+Space release behavior matches quick Alt+Tab.
    pub fn initial(
        launcher_mode: bool,
        hints: &[WindowHint],
        previous_window_id: Option<&str>,
    ) -> Self {
        if launcher_mode {
            // Find index of previous window for default selection
            let selected_index = previous_window_id
                .and_then(|prev_id| hints.iter().position(|h| h.window_id.as_str() == prev_id))
                .unwrap_or(0);

            tracing::info!(
                "FullOverlay initial: selected_index={} (previous_window_id={:?})",
                selected_index,
                previous_window_id
            );

            AppState::FullOverlay {
                selected_hint_index: selected_index,
                input: String::new(),
            }
        } else {
            AppState::BorderOnly {
                start_time: Instant::now(),
                frame_count: 0,
            }
        }
    }

    /// Processes an event and returns new state with actions.
    pub fn handle_event(
        &self,
        event: Event,
        config: &Config,
        hints: &[WindowHint],
        previous_window_id: Option<&str>,
    ) -> Transition {
        match (self, event) {
            // === BorderOnly transitions ===

            // Frame rendered in border phase increments counter
            (
                AppState::BorderOnly {
                    start_time,
                    frame_count,
                },
                Event::FrameCallback,
            ) => Transition {
                new_state: AppState::BorderOnly {
                    start_time: *start_time,
                    frame_count: frame_count + 1,
                },
                actions: vec![],
            },

            // Phase transition checked on tick event
            (
                AppState::BorderOnly {
                    start_time,
                    frame_count,
                },
                Event::Tick,
            ) => {
                let elapsed = start_time.elapsed();
                let delay = Duration::from_millis(config.settings.overlay_delay);

                // Transition requires both time elapsed and minimum frames rendered
                if elapsed >= delay && *frame_count >= 2 {
                    // Find index of previous window for default selection
                    let selected_index = previous_window_id
                        .and_then(|prev_id| {
                            hints.iter().position(|h| h.window_id.as_str() == prev_id)
                        })
                        .unwrap_or(0);

                    Transition {
                        new_state: AppState::FullOverlay {
                            selected_hint_index: selected_index,
                            input: String::new(),
                        },
                        actions: vec![Action::ScheduleRedraw],
                    }
                } else {
                    Transition {
                        new_state: self.clone(),
                        actions: vec![],
                    }
                }
            }

            // Alt released in border phase triggers quick switch
            (AppState::BorderOnly { start_time, .. }, Event::AltReleased) => {
                let elapsed = start_time.elapsed();
                let threshold = Duration::from_millis(config.settings.quick_switch_threshold);

                let result = if elapsed < threshold {
                    // Quick Alt+Tab attempts to activate previous window
                    if let Some(prev_id) = previous_window_id {
                        if let Some((idx, _)) = hints
                            .iter()
                            .enumerate()
                            .find(|(_, h)| h.window_id.as_str() == prev_id)
                        {
                            ActivationResult::Window(idx)
                        } else {
                            // Previous window not found, defaults to first window
                            ActivationResult::Window(0)
                        }
                    } else {
                        ActivationResult::QuickSwitch
                    }
                } else {
                    // Non-quick release activates first window
                    ActivationResult::Window(0)
                };

                Transition {
                    new_state: AppState::Exiting { result },
                    actions: vec![Action::Exit],
                }
            }

            // Tab in border phase cycles selection and transitions to full overlay
            (AppState::BorderOnly { .. }, Event::KeyPress { keysym, shift }) => {
                if is_tab(keysym) {
                    let idx = if shift {
                        hints.len().saturating_sub(1)
                    } else {
                        1.min(hints.len().saturating_sub(1))
                    };
                    Transition {
                        new_state: AppState::FullOverlay {
                            selected_hint_index: idx,
                            input: String::new(),
                        },
                        actions: vec![Action::ScheduleRedraw],
                    }
                } else if keysym == Keysym::Escape {
                    Transition {
                        new_state: AppState::Exiting {
                            result: ActivationResult::Cancelled,
                        },
                        actions: vec![Action::Exit],
                    }
                } else if let Some(c) = keysym_to_char(keysym) {
                    // Character key transitions to full overlay with character preserved
                    // Ensures first keypress captured during border-only to full overlay transition
                    let input = c.to_string();
                    let matcher = HintMatcher::new(hints);
                    match matcher.match_input(&input) {
                        MatchResult::Exact { index, .. } => {
                            // Exact match transitions to pending activation state
                            let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
                            timeout.start();
                            Transition {
                                new_state: AppState::PendingActivation {
                                    hint_index: index,
                                    input,
                                    timeout,
                                },
                                actions: vec![Action::ScheduleRedraw],
                            }
                        }
                        MatchResult::Partial(_) => {
                            // Partial match shows full overlay with current input
                            Transition {
                                new_state: AppState::FullOverlay {
                                    selected_hint_index: 0,
                                    input,
                                },
                                actions: vec![Action::ScheduleRedraw],
                            }
                        }
                        MatchResult::None => {
                            // No match checks for launch configuration
                            let key_str = c.to_string();
                            if config.launch_config(&key_str).is_some() {
                                Transition {
                                    new_state: AppState::Exiting {
                                        result: ActivationResult::Launch(key_str),
                                    },
                                    actions: vec![Action::Exit],
                                }
                            } else {
                                // Invalid key ignored, shows full overlay with empty input
                                Transition {
                                    new_state: AppState::FullOverlay {
                                        selected_hint_index: 0,
                                        input: String::new(),
                                    },
                                    actions: vec![Action::ScheduleRedraw],
                                }
                            }
                        }
                    }
                } else {
                    // Non-character key shows full overlay without input modification
                    Transition {
                        new_state: AppState::FullOverlay {
                            selected_hint_index: 0,
                            input: String::new(),
                        },
                        actions: vec![Action::ScheduleRedraw],
                    }
                }
            }

            // IPC cycle in border phase transitions to full overlay
            (AppState::BorderOnly { .. }, Event::CycleForward) => Transition {
                new_state: AppState::FullOverlay {
                    selected_hint_index: 1.min(hints.len().saturating_sub(1)),
                    input: String::new(),
                },
                actions: vec![Action::ScheduleRedraw],
            },

            (AppState::BorderOnly { .. }, Event::CycleBackward) => Transition {
                new_state: AppState::FullOverlay {
                    selected_hint_index: hints.len().saturating_sub(1),
                    input: String::new(),
                },
                actions: vec![Action::ScheduleRedraw],
            },

            // === FullOverlay transitions ===

            // Tab cycles selection forward/backward
            (
                AppState::FullOverlay {
                    selected_hint_index,
                    input,
                },
                Event::KeyPress { keysym, shift },
            ) if is_tab(keysym) => {
                let new_idx = cycle_index(*selected_hint_index, hints.len(), !shift);
                Transition {
                    new_state: AppState::FullOverlay {
                        selected_hint_index: new_idx,
                        input: input.clone(),
                    },
                    actions: vec![Action::ScheduleRedraw],
                }
            }

            // Arrow keys cycle selection
            (
                AppState::FullOverlay {
                    selected_hint_index,
                    input,
                },
                Event::KeyPress { keysym, .. },
            ) if keysym == Keysym::Down || keysym == Keysym::KP_Down => {
                let new_idx = cycle_index(*selected_hint_index, hints.len(), true);
                Transition {
                    new_state: AppState::FullOverlay {
                        selected_hint_index: new_idx,
                        input: input.clone(),
                    },
                    actions: vec![Action::ScheduleRedraw],
                }
            }

            (
                AppState::FullOverlay {
                    selected_hint_index,
                    input,
                },
                Event::KeyPress { keysym, .. },
            ) if keysym == Keysym::Up || keysym == Keysym::KP_Up => {
                let new_idx = cycle_index(*selected_hint_index, hints.len(), false);
                Transition {
                    new_state: AppState::FullOverlay {
                        selected_hint_index: new_idx,
                        input: input.clone(),
                    },
                    actions: vec![Action::ScheduleRedraw],
                }
            }

            // Enter activates selected window
            (
                AppState::FullOverlay {
                    selected_hint_index,
                    ..
                },
                Event::KeyPress { keysym, .. },
            ) if keysym == Keysym::Return || keysym == Keysym::KP_Enter => Transition {
                new_state: AppState::Exiting {
                    result: ActivationResult::Window(*selected_hint_index),
                },
                actions: vec![Action::Exit],
            },

            // Escape cancels operation
            (AppState::FullOverlay { .. }, Event::KeyPress { keysym, .. })
                if keysym == Keysym::Escape =>
            {
                Transition {
                    new_state: AppState::Exiting {
                        result: ActivationResult::Cancelled,
                    },
                    actions: vec![Action::Exit],
                }
            }

            // Backspace removes last character from input
            (
                AppState::FullOverlay {
                    selected_hint_index,
                    input,
                },
                Event::KeyPress { keysym, .. },
            ) if keysym == Keysym::BackSpace => {
                let mut new_input = input.clone();
                new_input.pop();
                Transition {
                    new_state: AppState::FullOverlay {
                        selected_hint_index: *selected_hint_index,
                        input: new_input,
                    },
                    actions: vec![Action::ScheduleRedraw],
                }
            }

            // Character input performs hint matching
            (
                AppState::FullOverlay {
                    selected_hint_index,
                    input,
                },
                Event::KeyPress { keysym, .. },
            ) => {
                if let Some(c) = keysym_to_char(keysym) {
                    let mut new_input = input.clone();
                    new_input.push(c);

                    let matcher = HintMatcher::new(hints);
                    match matcher.match_input(&new_input) {
                        MatchResult::Exact { index, .. } => {
                            // Exact match starts pending activation timeout
                            let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
                            timeout.start();
                            Transition {
                                new_state: AppState::PendingActivation {
                                    hint_index: index,
                                    input: new_input,
                                    timeout,
                                },
                                actions: vec![Action::ScheduleRedraw],
                            }
                        }
                        MatchResult::Partial(_) => {
                            // Partial match updates input while preserving selection
                            Transition {
                                new_state: AppState::FullOverlay {
                                    selected_hint_index: *selected_hint_index,
                                    input: new_input,
                                },
                                actions: vec![Action::ScheduleRedraw],
                            }
                        }
                        MatchResult::None => {
                            // No match checks for launch configuration
                            let key_str = c.to_string();
                            if config.launch_config(&key_str).is_some() {
                                Transition {
                                    new_state: AppState::Exiting {
                                        result: ActivationResult::Launch(key_str),
                                    },
                                    actions: vec![Action::Exit],
                                }
                            } else {
                                // Invalid input preserves current state
                                Transition {
                                    new_state: AppState::FullOverlay {
                                        selected_hint_index: *selected_hint_index,
                                        input: input.clone(),
                                    },
                                    actions: vec![],
                                }
                            }
                        }
                    }
                } else {
                    // Non-character key ignored
                    Transition {
                        new_state: self.clone(),
                        actions: vec![],
                    }
                }
            }

            // Alt released activates current selection
            (
                AppState::FullOverlay {
                    selected_hint_index,
                    ..
                },
                Event::AltReleased,
            ) => Transition {
                new_state: AppState::Exiting {
                    result: ActivationResult::Window(*selected_hint_index),
                },
                actions: vec![Action::Exit],
            },

            // IPC cycle
            (
                AppState::FullOverlay {
                    selected_hint_index,
                    input,
                },
                Event::CycleForward,
            ) => {
                let new_idx = cycle_index(*selected_hint_index, hints.len(), true);
                Transition {
                    new_state: AppState::FullOverlay {
                        selected_hint_index: new_idx,
                        input: input.clone(),
                    },
                    actions: vec![Action::ScheduleRedraw],
                }
            }

            (
                AppState::FullOverlay {
                    selected_hint_index,
                    input,
                },
                Event::CycleBackward,
            ) => {
                let new_idx = cycle_index(*selected_hint_index, hints.len(), false);
                Transition {
                    new_state: AppState::FullOverlay {
                        selected_hint_index: new_idx,
                        input: input.clone(),
                    },
                    actions: vec![Action::ScheduleRedraw],
                }
            }

            // === PendingActivation transitions ===

            // Tick checks activation timeout
            (
                AppState::PendingActivation {
                    hint_index,
                    timeout,
                    ..
                },
                Event::Tick,
            ) => {
                if timeout.has_elapsed() {
                    Transition {
                        new_state: AppState::Exiting {
                            result: ActivationResult::Window(*hint_index),
                        },
                        actions: vec![Action::Exit],
                    }
                } else {
                    Transition {
                        new_state: self.clone(),
                        actions: vec![],
                    }
                }
            }

            // Additional character while pending may change match state
            (
                AppState::PendingActivation {
                    hint_index, input, ..
                },
                Event::KeyPress { keysym, .. },
            ) => {
                if let Some(c) = keysym_to_char(keysym) {
                    let mut new_input = input.clone();
                    new_input.push(c);

                    let matcher = HintMatcher::new(hints);
                    match matcher.match_input(&new_input) {
                        MatchResult::Exact { index, .. } => {
                            // New exact match restarts timeout
                            let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
                            timeout.start();
                            Transition {
                                new_state: AppState::PendingActivation {
                                    hint_index: index,
                                    input: new_input,
                                    timeout,
                                },
                                actions: vec![Action::ScheduleRedraw],
                            }
                        }
                        MatchResult::Partial(_) => {
                            // Partial match returns to full overlay state
                            Transition {
                                new_state: AppState::FullOverlay {
                                    selected_hint_index: *hint_index,
                                    input: new_input,
                                },
                                actions: vec![Action::ScheduleRedraw],
                            }
                        }
                        MatchResult::None => {
                            // Invalid input preserves pending state
                            Transition {
                                new_state: self.clone(),
                                actions: vec![],
                            }
                        }
                    }
                } else if keysym == Keysym::Escape {
                    Transition {
                        new_state: AppState::Exiting {
                            result: ActivationResult::Cancelled,
                        },
                        actions: vec![Action::Exit],
                    }
                } else if keysym == Keysym::BackSpace {
                    // Backspace cancels pending and returns to full overlay
                    let mut new_input = input.clone();
                    new_input.pop();
                    Transition {
                        new_state: AppState::FullOverlay {
                            selected_hint_index: *hint_index,
                            input: new_input,
                        },
                        actions: vec![Action::ScheduleRedraw],
                    }
                } else {
                    Transition {
                        new_state: self.clone(),
                        actions: vec![],
                    }
                }
            }

            // Alt released during pending activates immediately
            (AppState::PendingActivation { hint_index, .. }, Event::AltReleased) => Transition {
                new_state: AppState::Exiting {
                    result: ActivationResult::Window(*hint_index),
                },
                actions: vec![Action::Exit],
            },

            // === Default: stay in current state ===
            _ => Transition {
                new_state: self.clone(),
                actions: vec![],
            },
        }
    }

    /// Returns the selected hint index for rendering.
    pub fn selected_hint_index(&self) -> usize {
        match self {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => *selected_hint_index,
            AppState::PendingActivation { hint_index, .. } => *hint_index,
            _ => 0,
        }
    }

    /// Returns the current input string for rendering.
    pub fn input(&self) -> &str {
        match self {
            AppState::FullOverlay { input, .. } => input,
            AppState::PendingActivation { input, .. } => input,
            _ => "",
        }
    }

    /// Returns whether full overlay is displayed (vs border only).
    pub fn is_full_overlay(&self) -> bool {
        matches!(
            self,
            AppState::FullOverlay { .. } | AppState::PendingActivation { .. }
        )
    }

    /// Returns whether the application is exiting.
    pub fn is_exiting(&self) -> bool {
        matches!(self, AppState::Exiting { .. })
    }

    /// Returns the activation result if exiting, None otherwise.
    pub fn activation_result(&self) -> Option<&ActivationResult> {
        match self {
            AppState::Exiting { result } => Some(result),
            _ => None,
        }
    }
}

// === Helper functions ===

fn is_tab(keysym: Keysym) -> bool {
    keysym == Keysym::Tab
        || keysym == Keysym::ISO_Left_Tab
        || keysym.raw() == 0xff09
        || keysym.raw() == 0xfe20
}

fn cycle_index(current: usize, len: usize, forward: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if forward {
        (current + 1) % len
    } else if current == 0 {
        len - 1
    } else {
        current - 1
    }
}

fn keysym_to_char(keysym: Keysym) -> Option<char> {
    let raw = keysym.raw();
    // ASCII printable characters
    if (0x20..=0x7e).contains(&raw) {
        Some(raw as u8 as char)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{HintSequence, WindowId};

    // ==========================================================================
    // TEST FIXTURES
    // ==========================================================================

    fn make_test_config() -> Config {
        let mut config = Config::default();
        config.settings.overlay_delay = 500;
        config.settings.activation_delay = 200;
        config.settings.quick_switch_threshold = 250;
        config
    }

    /// Creates test hints with sequential letter assignments starting from 'a'.
    fn make_hints(count: usize) -> Vec<WindowHint> {
        (0..count)
            .map(|i| WindowHint {
                hint: HintSequence::new((b'a' + i as u8) as char, 1),
                app_id: format!("app{}", i),
                window_id: WindowId::new(format!("window{}", i)),
                title: format!("Window {}", i),
                index: i,
            })
            .collect()
    }

    /// Creates realistic test hints matching real application configuration.
    fn make_realistic_hints() -> Vec<WindowHint> {
        vec![
            WindowHint {
                hint: HintSequence::new('e', 1),
                app_id: "microsoft-edge".to_string(),
                window_id: WindowId::new("win-edge-abc123"),
                title: "Microsoft Edge".to_string(),
                index: 0,
            },
            WindowHint {
                hint: HintSequence::new('f', 1),
                app_id: "firefox".to_string(),
                window_id: WindowId::new("win-firefox-def456"),
                title: "Mozilla Firefox".to_string(),
                index: 1,
            },
            WindowHint {
                hint: HintSequence::new('g', 1),
                app_id: "com.mitchellh.ghostty".to_string(),
                window_id: WindowId::new("win-ghostty-ghi789"),
                title: "ghostty".to_string(),
                index: 2,
            },
        ]
    }

    // ==========================================================================
    // INITIAL STATE TESTS
    // ==========================================================================

    #[test]
    fn test_initial_state_switcher_mode() {
        let hints = make_hints(3);
        let state = AppState::initial(false, &hints, None);
        assert!(
            matches!(state, AppState::BorderOnly { .. }),
            "Switcher mode starts in BorderOnly state"
        );
    }

    #[test]
    fn test_initial_state_launcher_mode() {
        let hints = make_hints(3);
        let state = AppState::initial(true, &hints, None);
        match state {
            AppState::FullOverlay {
                selected_hint_index,
                input,
            } => {
                assert_eq!(
                    selected_hint_index, 0,
                    "Starts with first item selected when no previous window"
                );
                assert!(input.is_empty(), "Starts with empty input");
            }
            _ => panic!("Launcher mode starts in FullOverlay state"),
        }
    }

    #[test]
    fn test_initial_state_launcher_mode_with_previous() {
        let hints = make_realistic_hints();
        // Previous window (firefox) at index 1
        let state = AppState::initial(true, &hints, Some("win-firefox-def456"));
        match state {
            AppState::FullOverlay {
                selected_hint_index,
                input,
            } => {
                assert_eq!(
                    selected_hint_index, 1,
                    "Starts with previous window selected"
                );
                assert!(input.is_empty(), "Starts with empty input");
            }
            _ => panic!("Launcher mode starts in FullOverlay state"),
        }
    }

    #[test]
    fn test_initial_state_launcher_mode_with_invalid_previous() {
        let hints = make_realistic_hints();
        // Previous window does not exist
        let state = AppState::initial(true, &hints, Some("nonexistent-window"));
        match state {
            AppState::FullOverlay {
                selected_hint_index,
                input,
            } => {
                assert_eq!(
                    selected_hint_index, 0,
                    "Falls back to index 0 when previous window not found"
                );
                assert!(input.is_empty(), "Starts with empty input");
            }
            _ => panic!("Launcher mode starts in FullOverlay state"),
        }
    }

    // ==========================================================================
    // HELPER FUNCTION TESTS
    // ==========================================================================

    #[test]
    fn test_cycle_forward() {
        assert_eq!(cycle_index(0, 3, true), 1);
        assert_eq!(cycle_index(1, 3, true), 2);
        assert_eq!(cycle_index(2, 3, true), 0, "Wraps to 0");
    }

    #[test]
    fn test_cycle_backward() {
        assert_eq!(cycle_index(2, 3, false), 1);
        assert_eq!(cycle_index(1, 3, false), 0);
        assert_eq!(cycle_index(0, 3, false), 2, "Wraps to last");
    }

    #[test]
    fn test_cycle_empty() {
        assert_eq!(cycle_index(0, 0, true), 0, "Empty list returns 0");
        assert_eq!(cycle_index(0, 0, false), 0);
    }

    #[test]
    fn test_keysym_to_char_letters() {
        // Lowercase letter keysym values equal ASCII codes
        assert_eq!(keysym_to_char(Keysym::from(0x67)), Some('g'));
        assert_eq!(keysym_to_char(Keysym::from(0x66)), Some('f'));
        assert_eq!(keysym_to_char(Keysym::from(0x65)), Some('e'));
    }

    #[test]
    fn test_keysym_to_char_non_printable() {
        assert_eq!(keysym_to_char(Keysym::Tab), None);
        assert_eq!(keysym_to_char(Keysym::Escape), None);
        assert_eq!(keysym_to_char(Keysym::Return), None);
    }

    #[test]
    fn test_is_tab() {
        assert!(is_tab(Keysym::Tab));
        assert!(is_tab(Keysym::ISO_Left_Tab));
        assert!(is_tab(Keysym::from(0xff09)));
        assert!(is_tab(Keysym::from(0xfe20)));
        assert!(!is_tab(Keysym::Return));
        assert!(!is_tab(Keysym::from(0x67)));
    }

    // ==========================================================================
    // BORDER ONLY STATE TESTS
    // ==========================================================================

    #[test]
    fn test_border_only_tick_before_delay() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 5,
        };

        let transition = state.handle_event(Event::Tick, &config, &hints, None);

        assert!(
            matches!(transition.new_state, AppState::BorderOnly { .. }),
            "Remains in BorderOnly state before delay elapsed"
        );
        assert!(
            transition.actions.is_empty(),
            "No redraw scheduled before delay elapsed"
        );
    }

    #[test]
    fn test_border_only_tick_after_delay_transitions() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // State created with elapsed start time
        let state = AppState::BorderOnly {
            start_time: Instant::now() - Duration::from_millis(600),
            frame_count: 5,
        };

        let transition = state.handle_event(Event::Tick, &config, &hints, None);

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                input,
            } => {
                assert_eq!(selected_hint_index, 0);
                assert!(input.is_empty());
            }
            _ => panic!("Transitions to FullOverlay after delay"),
        }
        assert!(transition.actions.contains(&Action::ScheduleRedraw));
    }

    #[test]
    fn test_border_only_requires_minimum_frames() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Elapsed start time but insufficient frames rendered
        let state = AppState::BorderOnly {
            start_time: Instant::now() - Duration::from_millis(600),
            frame_count: 1, // Less than 2
        };

        let transition = state.handle_event(Event::Tick, &config, &hints, None);

        assert!(
            matches!(transition.new_state, AppState::BorderOnly { .. }),
            "Does not transition without minimum frames rendered"
        );
    }

    #[test]
    fn test_border_only_frame_callback_increments_counter() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 0,
        };

        let transition = state.handle_event(Event::FrameCallback, &config, &hints, None);

        match transition.new_state {
            AppState::BorderOnly { frame_count, .. } => {
                assert_eq!(frame_count, 1, "Frame count increments");
            }
            _ => panic!("Remains in BorderOnly state"),
        }
    }

    #[test]
    fn test_border_only_quick_alt_release_with_previous_window() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Quick release before threshold
        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 0,
        };

        let transition = state.handle_event(
            Event::AltReleased,
            &config,
            &hints,
            Some("win-firefox-def456"),
        );

        match transition.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 1, "Activates firefox at index 1");
            }
            _ => panic!("Exits with window activation result"),
        }
        assert!(transition.actions.contains(&Action::Exit));
    }

    #[test]
    fn test_border_only_quick_alt_release_no_previous() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 0,
        };

        let transition = state.handle_event(Event::AltReleased, &config, &hints, None);

        match transition.new_state {
            AppState::Exiting {
                result: ActivationResult::QuickSwitch,
            } => {}
            _ => panic!("Exits with QuickSwitch when no previous window"),
        }
    }

    #[test]
    fn test_border_only_slow_alt_release_activates_first() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Slow release after threshold
        let state = AppState::BorderOnly {
            start_time: Instant::now() - Duration::from_millis(300),
            frame_count: 0,
        };

        let transition = state.handle_event(Event::AltReleased, &config, &hints, None);

        match transition.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 0, "Activates first window");
            }
            _ => panic!("Exits with window 0 activation"),
        }
    }

    #[test]
    fn test_border_only_tab_transitions_to_full() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 0,
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Tab,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(selected_hint_index, 1, "Tab selects index 1");
            }
            _ => panic!("Tab transitions to FullOverlay"),
        }
    }

    #[test]
    fn test_border_only_shift_tab_selects_last() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 0,
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Tab,
                shift: true,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(selected_hint_index, 2, "Shift+Tab selects last");
            }
            _ => panic!("Shift+Tab transitions to FullOverlay"),
        }
    }

    #[test]
    fn test_border_only_character_key_goes_to_pending_on_exact_match() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 0,
        };

        // Press 'g' matches ghostty exactly
        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::from(0x67), // 'g'
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::PendingActivation {
                hint_index, input, ..
            } => {
                assert_eq!(hint_index, 2, "Matches ghostty at index 2");
                assert_eq!(input, "g");
            }
            _ => panic!(
                "Character key with exact match transitions to PendingActivation, got {:?}",
                transition.new_state
            ),
        }
    }

    #[test]
    fn test_border_only_escape_cancels() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let state = AppState::BorderOnly {
            start_time: Instant::now(),
            frame_count: 0,
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Escape,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        assert!(matches!(
            transition.new_state,
            AppState::Exiting {
                result: ActivationResult::Cancelled
            }
        ));
    }

    // ==========================================================================
    // FULL OVERLAY STATE TESTS
    // ==========================================================================

    #[test]
    fn test_full_overlay_tab_cycles_selection() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 0,
            input: String::new(),
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Tab,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(selected_hint_index, 1);
            }
            _ => panic!("Expected FullOverlay"),
        }
    }

    #[test]
    fn test_full_overlay_down_arrow_cycles() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 0,
            input: String::new(),
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Down,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(selected_hint_index, 1);
            }
            _ => panic!("Down arrow should cycle selection"),
        }
    }

    #[test]
    fn test_full_overlay_up_arrow_cycles() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 1,
            input: String::new(),
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Up,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(selected_hint_index, 0);
            }
            _ => panic!("Up arrow should cycle selection"),
        }
    }

    #[test]
    fn test_full_overlay_enter_activates_selected() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 2,
            input: String::new(),
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Return,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 2);
            }
            _ => panic!("Enter should activate selected window"),
        }
    }

    #[test]
    fn test_full_overlay_escape_cancels() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 0,
            input: String::new(),
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Escape,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        assert!(matches!(
            transition.new_state,
            AppState::Exiting {
                result: ActivationResult::Cancelled
            }
        ));
    }

    #[test]
    fn test_full_overlay_backspace_removes_char() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 0,
            input: "ab".to_string(),
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::BackSpace,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::FullOverlay { input, .. } => {
                assert_eq!(input, "a");
            }
            _ => panic!("Backspace should stay in FullOverlay"),
        }
    }

    #[test]
    fn test_full_overlay_alt_released_activates() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 1,
            input: String::new(),
        };

        let transition = state.handle_event(Event::AltReleased, &config, &hints, None);

        match transition.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 1);
            }
            _ => panic!("Alt release should activate selected window"),
        }
    }

    #[test]
    fn test_full_overlay_character_exact_match_goes_pending() {
        let config = make_test_config();
        let hints = make_realistic_hints();
        let state = AppState::FullOverlay {
            selected_hint_index: 0,
            input: String::new(),
        };

        // Press 'f' which should match firefox exactly
        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::from(0x66), // 'f'
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::PendingActivation {
                hint_index, input, ..
            } => {
                assert_eq!(hint_index, 1, "Should match firefox");
                assert_eq!(input, "f");
            }
            _ => panic!("Exact match should go to PendingActivation"),
        }
    }

    #[test]
    fn test_full_overlay_ipc_cycle_forward() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 0,
            input: String::new(),
        };

        let transition = state.handle_event(Event::CycleForward, &config, &hints, None);

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(selected_hint_index, 1);
            }
            _ => panic!("CycleForward should update selection"),
        }
    }

    #[test]
    fn test_full_overlay_ipc_cycle_backward() {
        let config = make_test_config();
        let hints = make_hints(3);
        let state = AppState::FullOverlay {
            selected_hint_index: 1,
            input: String::new(),
        };

        let transition = state.handle_event(Event::CycleBackward, &config, &hints, None);

        match transition.new_state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(selected_hint_index, 0);
            }
            _ => panic!("CycleBackward should update selection"),
        }
    }

    // ==========================================================================
    // PENDING ACTIVATION STATE TESTS
    // ==========================================================================

    #[test]
    fn test_pending_activation_timeout_activates() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Create pending state with old timeout
        let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
        timeout.start();
        // Simulate elapsed timeout by creating state and sleeping
        let state = AppState::PendingActivation {
            hint_index: 2,
            input: "g".to_string(),
            timeout,
        };
        // Sleep to ensure timeout has elapsed
        std::thread::sleep(Duration::from_millis(250));

        let transition = state.handle_event(Event::Tick, &config, &hints, None);

        match transition.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 2);
            }
            _ => panic!("Timeout should activate window"),
        }
    }

    #[test]
    fn test_pending_activation_no_timeout_yet() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
        timeout.start();
        let state = AppState::PendingActivation {
            hint_index: 2,
            input: "g".to_string(),
            timeout,
        };

        let transition = state.handle_event(Event::Tick, &config, &hints, None);

        assert!(
            matches!(transition.new_state, AppState::PendingActivation { .. }),
            "Should stay pending before timeout"
        );
    }

    #[test]
    fn test_pending_activation_escape_cancels() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
        timeout.start();
        let state = AppState::PendingActivation {
            hint_index: 2,
            input: "g".to_string(),
            timeout,
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Escape,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        assert!(matches!(
            transition.new_state,
            AppState::Exiting {
                result: ActivationResult::Cancelled
            }
        ));
    }

    #[test]
    fn test_pending_activation_backspace_returns_to_full() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
        timeout.start();
        let state = AppState::PendingActivation {
            hint_index: 2,
            input: "g".to_string(),
            timeout,
        };

        let transition = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::BackSpace,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match transition.new_state {
            AppState::FullOverlay { input, .. } => {
                assert!(input.is_empty(), "Backspace should remove char");
            }
            _ => panic!("Backspace should return to FullOverlay"),
        }
    }

    #[test]
    fn test_pending_activation_alt_release_activates_immediately() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
        timeout.start();
        let state = AppState::PendingActivation {
            hint_index: 1,
            input: "f".to_string(),
            timeout,
        };

        let transition = state.handle_event(Event::AltReleased, &config, &hints, None);

        match transition.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 1);
            }
            _ => panic!("Alt release should activate immediately"),
        }
    }

    // ==========================================================================
    // FULL LIFECYCLE SCENARIO TESTS
    // ==========================================================================

    #[test]
    fn test_scenario_launcher_type_g_wait_activate() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Start in launcher mode
        let mut state = AppState::initial(true, &hints, None);
        assert!(
            matches!(state, AppState::FullOverlay { .. }),
            "Launcher starts in FullOverlay"
        );

        // Type 'g'
        let trans = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::from(0x67),
                shift: false,
            },
            &config,
            &hints,
            None,
        );
        state = trans.new_state;
        assert!(
            matches!(state, AppState::PendingActivation { hint_index: 2, .. }),
            "Should match ghostty (index 2)"
        );

        // Sleep to ensure timeout elapses
        std::thread::sleep(Duration::from_millis(250));

        // Tick should trigger activation
        let trans = state.handle_event(Event::Tick, &config, &hints, None);
        state = trans.new_state;

        match state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 2, "Should activate ghostty");
            }
            _ => panic!("Should exit with window activation"),
        }
    }

    #[test]
    fn test_scenario_switcher_quick_alt_tab() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Start in switcher mode
        let state = AppState::initial(false, &hints, None);
        assert!(matches!(state, AppState::BorderOnly { .. }));

        // Quick Alt release with previous window set
        let trans = state.handle_event(
            Event::AltReleased,
            &config,
            &hints,
            Some("win-firefox-def456"),
        );

        match trans.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 1, "Should switch to previous window (firefox)");
            }
            _ => panic!("Quick Alt+Tab should activate previous window"),
        }
    }

    #[test]
    fn test_scenario_switcher_hold_and_tab() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Start in switcher mode
        let mut state = AppState::initial(false, &hints, None);

        // Tab to cycle
        let trans = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Tab,
                shift: false,
            },
            &config,
            &hints,
            None,
        );
        state = trans.new_state;

        match &state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(*selected_hint_index, 1);
            }
            _ => panic!("Tab should transition to FullOverlay"),
        }

        // Tab again
        let trans = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Tab,
                shift: false,
            },
            &config,
            &hints,
            None,
        );
        state = trans.new_state;

        match &state {
            AppState::FullOverlay {
                selected_hint_index,
                ..
            } => {
                assert_eq!(*selected_hint_index, 2);
            }
            _ => panic!("Second Tab should update selection"),
        }

        // Release Alt
        let trans = state.handle_event(Event::AltReleased, &config, &hints, None);

        match trans.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 2, "Should activate final selection");
            }
            _ => panic!("Alt release should activate"),
        }
    }

    #[test]
    fn test_scenario_launcher_arrow_navigate_enter() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Start in launcher mode
        let mut state = AppState::initial(true, &hints, None);

        // Navigate down twice
        let trans = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Down,
                shift: false,
            },
            &config,
            &hints,
            None,
        );
        state = trans.new_state;

        let trans = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Down,
                shift: false,
            },
            &config,
            &hints,
            None,
        );
        state = trans.new_state;

        // Press Enter
        let trans = state.handle_event(
            Event::KeyPress {
                keysym: Keysym::Return,
                shift: false,
            },
            &config,
            &hints,
            None,
        );

        match trans.new_state {
            AppState::Exiting {
                result: ActivationResult::Window(idx),
            } => {
                assert_eq!(idx, 2, "Should activate third item (down, down from 0)");
            }
            _ => panic!("Enter should activate"),
        }
    }

    #[test]
    fn test_scenario_escape_at_any_stage() {
        let config = make_test_config();
        let hints = make_realistic_hints();

        // Test escape from each state
        let mut timeout = TimeoutTracker::new(config.settings.activation_delay);
        timeout.start();
        let states = vec![
            AppState::initial(false, &hints, None), // BorderOnly
            AppState::initial(true, &hints, None),  // FullOverlay
            AppState::PendingActivation {
                hint_index: 0,
                input: "e".to_string(),
                timeout,
            },
        ];

        for state in states {
            let trans = state.handle_event(
                Event::KeyPress {
                    keysym: Keysym::Escape,
                    shift: false,
                },
                &config,
                &hints,
                None,
            );

            assert!(
                matches!(
                    trans.new_state,
                    AppState::Exiting {
                        result: ActivationResult::Cancelled
                    }
                ),
                "Escape should cancel from any state"
            );
        }
    }

    // ==========================================================================
    // STATE ACCESSOR TESTS
    // ==========================================================================

    #[test]
    fn test_selected_hint_index() {
        assert_eq!(
            AppState::FullOverlay {
                selected_hint_index: 5,
                input: String::new()
            }
            .selected_hint_index(),
            5
        );
        let mut timeout = TimeoutTracker::new(200);
        timeout.start();
        assert_eq!(
            AppState::PendingActivation {
                hint_index: 3,
                input: "x".to_string(),
                timeout
            }
            .selected_hint_index(),
            3
        );
        assert_eq!(
            AppState::BorderOnly {
                start_time: Instant::now(),
                frame_count: 0
            }
            .selected_hint_index(),
            0
        );
    }

    #[test]
    fn test_input_accessor() {
        assert_eq!(
            AppState::FullOverlay {
                selected_hint_index: 0,
                input: "abc".to_string()
            }
            .input(),
            "abc"
        );
        let mut timeout = TimeoutTracker::new(200);
        timeout.start();
        assert_eq!(
            AppState::PendingActivation {
                hint_index: 0,
                input: "xyz".to_string(),
                timeout
            }
            .input(),
            "xyz"
        );
        assert_eq!(
            AppState::BorderOnly {
                start_time: Instant::now(),
                frame_count: 0
            }
            .input(),
            ""
        );
    }

    #[test]
    fn test_is_full_overlay() {
        assert!(
            !AppState::BorderOnly {
                start_time: Instant::now(),
                frame_count: 0
            }
            .is_full_overlay()
        );
        assert!(
            AppState::FullOverlay {
                selected_hint_index: 0,
                input: String::new()
            }
            .is_full_overlay()
        );
        let mut timeout = TimeoutTracker::new(200);
        timeout.start();
        assert!(
            AppState::PendingActivation {
                hint_index: 0,
                input: String::new(),
                timeout
            }
            .is_full_overlay()
        );
        assert!(
            !AppState::Exiting {
                result: ActivationResult::Cancelled
            }
            .is_full_overlay()
        );
    }

    #[test]
    fn test_is_exiting() {
        assert!(
            !AppState::BorderOnly {
                start_time: Instant::now(),
                frame_count: 0
            }
            .is_exiting()
        );
        assert!(
            !AppState::FullOverlay {
                selected_hint_index: 0,
                input: String::new()
            }
            .is_exiting()
        );
        assert!(
            AppState::Exiting {
                result: ActivationResult::Cancelled
            }
            .is_exiting()
        );
    }

    #[test]
    fn test_activation_result_accessor() {
        assert!(
            AppState::BorderOnly {
                start_time: Instant::now(),
                frame_count: 0
            }
            .activation_result()
            .is_none()
        );

        let state = AppState::Exiting {
            result: ActivationResult::Window(5),
        };
        match state.activation_result() {
            Some(ActivationResult::Window(idx)) => assert_eq!(*idx, 5),
            _ => panic!("Should return Window(5)"),
        }
    }
}
