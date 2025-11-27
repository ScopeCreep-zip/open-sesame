//! Input processing pipeline
//!
//! Converts raw keyboard events into application actions.

use crate::core::{HintMatcher, MatchResult, WindowId};
use crate::input::InputBuffer;
use crate::util::TimeoutTracker;
use smithay_client_toolkit::seat::keyboard::Keysym;

/// Actions that result from input processing
#[derive(Debug, Clone)]
pub enum InputAction {
    /// No action needed (ignored key)
    Ignore,
    /// Buffer changed, update display
    BufferChanged,
    /// Selection changed via arrow keys
    SelectionChanged {
        /// Direction of selection change
        direction: SelectionDirection,
    },
    /// Exact match found, pending activation with timeout
    PendingActivation {
        /// The window ID to activate
        window_id: WindowId,
        /// Index of the matched window hint
        index: usize,
    },
    /// Activate immediately (Enter pressed)
    ActivateNow {
        /// The window ID to activate
        window_id: WindowId,
        /// Index of the matched window hint
        index: usize,
    },
    /// Activate the currently selected item
    ActivateSelected,
    /// No window match, try launching app with this key
    TryLaunch {
        /// The key to use for launch lookup
        key: char,
    },
    /// Cancel and exit
    Cancel,
}

/// Direction of selection movement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionDirection {
    /// Move selection up (previous item)
    Up,
    /// Move selection down (next item)
    Down,
}

/// Processes keyboard input into actions
pub struct InputProcessor {
    /// Current input buffer
    buffer: InputBuffer,
    /// Timeout tracker for activation delay
    timeout: TimeoutTracker,
    /// Pending match index (if any)
    pending_index: Option<usize>,
    /// Pending window ID (if any)
    pending_window_id: Option<WindowId>,
}

impl InputProcessor {
    /// Creates a new input processor with the given activation delay.
    pub fn new(activation_delay_ms: u64) -> Self {
        Self {
            buffer: InputBuffer::new(),
            timeout: TimeoutTracker::new(activation_delay_ms),
            pending_index: None,
            pending_window_id: None,
        }
    }

    /// Returns the current input buffer.
    pub fn buffer(&self) -> &InputBuffer {
        &self.buffer
    }

    /// Returns the input as a string.
    pub fn input_string(&self) -> String {
        self.buffer.as_str()
    }

    /// Returns true if there is a pending match.
    pub fn has_pending(&self) -> bool {
        self.pending_index.is_some()
    }

    /// Returns pending match information.
    pub fn pending(&self) -> Option<(usize, &WindowId)> {
        match (&self.pending_index, &self.pending_window_id) {
            (Some(idx), Some(id)) => Some((*idx, id)),
            _ => None,
        }
    }

    /// Returns true if timeout has elapsed for pending match.
    pub fn timeout_elapsed(&self) -> bool {
        self.timeout.has_elapsed()
    }

    /// Returns the pending activation if timeout has elapsed.
    pub fn check_timeout(&mut self) -> Option<(usize, WindowId)> {
        if self.timeout.has_elapsed()
            && let (Some(idx), Some(id)) =
                (self.pending_index.take(), self.pending_window_id.take())
        {
            self.timeout.cancel();
            return Some((idx, id));
        }
        None
    }

    /// Processes a key press and returns the resulting action.
    pub fn process_key<'a>(
        &mut self,
        key: Keysym,
        matcher: &HintMatcher<'a>,
        has_launch_config: impl Fn(&str) -> bool,
    ) -> InputAction {
        match key {
            Keysym::Escape => {
                tracing::debug!("Escape pressed, canceling");
                InputAction::Cancel
            }
            Keysym::BackSpace => {
                self.buffer.pop();
                self.clear_pending();
                self.timeout.reset();
                tracing::debug!("Input: '{}'", self.buffer);
                InputAction::BufferChanged
            }
            Keysym::Return | Keysym::KP_Enter => {
                // Activates pending match or current exact match immediately
                if let Some((idx, id)) = self.pending().map(|(i, id)| (i, id.clone())) {
                    self.clear_pending();
                    return InputAction::ActivateNow {
                        window_id: id,
                        index: idx,
                    };
                }

                // Attempts to match current input exactly
                if let MatchResult::Exact { index, window_id } =
                    matcher.match_input(&self.buffer.as_str())
                {
                    return InputAction::ActivateNow { window_id, index };
                }

                // Activates current selection if nothing is pending or matched
                InputAction::ActivateSelected
            }
            Keysym::Up | Keysym::KP_Up => InputAction::SelectionChanged {
                direction: SelectionDirection::Up,
            },
            Keysym::Down | Keysym::KP_Down => InputAction::SelectionChanged {
                direction: SelectionDirection::Down,
            },
            // Tab is handled by App for proper Shift+Tab support
            _ => {
                // Attempts to convert keysym to character
                let Some(c) = keysym_to_char(key) else {
                    return InputAction::Ignore;
                };

                self.buffer.push(c);
                self.timeout.reset();
                tracing::debug!("Input: '{}'", self.buffer);

                // Matches input against available hints
                match matcher.match_input(&self.buffer.as_str()) {
                    MatchResult::Exact { index, window_id } => {
                        tracing::debug!("Pending match: index={}", index);
                        self.pending_index = Some(index);
                        self.pending_window_id = Some(window_id.clone());
                        self.timeout.start();
                        InputAction::PendingActivation { window_id, index }
                    }
                    MatchResult::None => {
                        // Checks if an application should be launched when no window matches
                        let base_key = self.buffer.first_char();

                        if let Some(key) = base_key {
                            let key_str = key.to_string();
                            if has_launch_config(&key_str) {
                                tracing::info!("No window match, will launch: {}", key);
                                return InputAction::TryLaunch { key };
                            }
                        }

                        // Reverts input when no launch config is available
                        self.buffer.pop();
                        tracing::debug!("No match, reverting to: '{}'", self.buffer);
                        InputAction::BufferChanged
                    }
                    MatchResult::Partial(_) => {
                        // Clears pending state when multiple matches are possible
                        self.clear_pending();
                        InputAction::BufferChanged
                    }
                }
            }
        }
    }

    /// Clears pending match state.
    fn clear_pending(&mut self) {
        self.pending_index = None;
        self.pending_window_id = None;
        self.timeout.cancel();
    }
}

/// Converts a keysym to a character (alphanumeric only).
fn keysym_to_char(key: Keysym) -> Option<char> {
    key.key_char()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keysym_to_char() {
        // Tests alphanumeric key conversion
        assert_eq!(keysym_to_char(Keysym::a), Some('a'));
        assert_eq!(keysym_to_char(Keysym::A), Some('a'));
        assert_eq!(keysym_to_char(Keysym::_1), Some('1'));

        // Non-alphanumeric keys return None
        assert_eq!(keysym_to_char(Keysym::space), None);
        assert_eq!(keysym_to_char(Keysym::Return), None);
    }

    #[test]
    fn test_input_processor_basic() {
        let processor = InputProcessor::new(200);
        assert!(processor.buffer().is_empty());
        assert!(!processor.has_pending());
    }
}
