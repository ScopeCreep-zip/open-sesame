//! Input matching against hints
//!
//! Matches user keyboard input against assigned window hints.

use crate::core::hint::WindowHint;
use crate::core::window::WindowId;

/// Result of matching user input against hints
///
/// Represents the outcome of matching user keyboard input against
/// assigned window hints using [`HintMatcher`].
///
/// # Examples
///
/// ```
/// use open_sesame::MatchResult;
///
/// # let result = MatchResult::None;
/// if result.is_exact() {
///     println!("Exact match found!");
///     if let Some(window_id) = result.window_id() {
///         println!("Window ID: {}", window_id);
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum MatchResult {
    /// No hints match the input
    None,
    /// Multiple hints could match (need more input)
    Partial(Vec<usize>),
    /// Exactly one hint matches
    Exact {
        /// Index of the matched hint
        index: usize,
        /// Window ID for activation
        window_id: WindowId,
    },
}

impl MatchResult {
    /// Returns true if this is an exact match.
    pub fn is_exact(&self) -> bool {
        matches!(self, MatchResult::Exact { .. })
    }

    /// Returns true if there is no match.
    pub fn is_none(&self) -> bool {
        matches!(self, MatchResult::None)
    }

    /// Returns the window ID if this is an exact match.
    pub fn window_id(&self) -> Option<&WindowId> {
        match self {
            MatchResult::Exact { window_id, .. } => Some(window_id),
            _ => None,
        }
    }
}

/// Matcher for finding windows based on input
///
/// Matches user keyboard input against assigned window hints, supporting
/// both exact matches and partial matches for disambiguation.
///
/// # Examples
///
/// ```
/// use open_sesame::{HintMatcher, HintAssignment, Window};
///
/// let windows = vec![
///     Window::new("win-1", "firefox", "Tab 1"),
///     Window::new("win-2", "ghostty", "Terminal"),
/// ];
///
/// let assignment = HintAssignment::assign(&windows, |app_id| {
///     match app_id.as_str() {
///         "firefox" => Some('f'),
///         "ghostty" => Some('g'),
///         _ => None,
///     }
/// });
///
/// let matcher = HintMatcher::new(assignment.hints());
///
/// // Match user input
/// let result = matcher.match_input("g");
/// assert!(result.is_exact());
///
/// // Filter hints by input
/// let filtered = matcher.filter_hints("f");
/// assert_eq!(filtered.len(), 1);
/// ```
pub struct HintMatcher<'a> {
    hints: &'a [WindowHint],
}

impl<'a> HintMatcher<'a> {
    /// Creates a new matcher with the given hints.
    pub fn new(hints: &'a [WindowHint]) -> Self {
        Self { hints }
    }

    /// Matches input against hints and returns the match result.
    pub fn match_input(&self, input: &str) -> MatchResult {
        if input.is_empty() {
            return MatchResult::Partial(self.hints.iter().map(|h| h.index).collect());
        }

        // Finds all hints that could match the input
        let matches: Vec<_> = self
            .hints
            .iter()
            .filter(|h| h.hint.matches_input(input))
            .collect();

        match matches.len() {
            0 => MatchResult::None,
            1 => MatchResult::Exact {
                index: matches[0].index,
                window_id: matches[0].window_id.clone(),
            },
            _ => {
                // Checks for exact match among partial matches
                if let Some(exact) = matches.iter().find(|h| h.hint.equals_input(input)) {
                    MatchResult::Exact {
                        index: exact.index,
                        window_id: exact.window_id.clone(),
                    }
                } else {
                    MatchResult::Partial(matches.iter().map(|h| h.index).collect())
                }
            }
        }
    }

    /// Returns hints that match the current input for display filtering.
    pub fn filter_hints(&self, input: &str) -> Vec<&WindowHint> {
        if input.is_empty() {
            self.hints.iter().collect()
        } else {
            self.hints
                .iter()
                .filter(|h| h.hint.matches_input(input))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hint::HintAssignment;
    use crate::core::window::Window;

    fn create_test_hints() -> Vec<WindowHint> {
        let windows = vec![
            Window::mock("firefox", "Tab 1"),
            Window::mock("firefox", "Tab 2"),
            Window::mock("ghostty", "Terminal"),
        ];

        HintAssignment::assign(&windows, |app_id| match app_id.as_str() {
            "firefox" => Some('f'),
            "ghostty" => Some('g'),
            _ => None,
        })
        .hints
    }

    #[test]
    fn test_match_exact_single() {
        let hints = create_test_hints();
        let matcher = HintMatcher::new(&hints);

        // "g" should match ghostty exactly
        let result = matcher.match_input("g");
        assert!(result.is_exact());
    }

    #[test]
    fn test_match_exact_with_multiple_windows() {
        let hints = create_test_hints();
        let matcher = HintMatcher::new(&hints);

        // "f" is exact match for first firefox
        let result = matcher.match_input("f");
        assert!(result.is_exact());

        // "ff" is exact match for second firefox
        let result = matcher.match_input("ff");
        assert!(result.is_exact());
    }

    #[test]
    fn test_match_none() {
        let hints = create_test_hints();
        let matcher = HintMatcher::new(&hints);

        let result = matcher.match_input("x");
        assert!(result.is_none());
    }

    #[test]
    fn test_match_number_pattern() {
        let hints = create_test_hints();
        let matcher = HintMatcher::new(&hints);

        // "g1" = "g" = exact match
        let result = matcher.match_input("g1");
        assert!(result.is_exact());

        // "f2" = "ff" = exact match for second firefox
        let result = matcher.match_input("f2");
        assert!(result.is_exact());
    }

    #[test]
    fn test_filter_hints() {
        let hints = create_test_hints();
        let matcher = HintMatcher::new(&hints);

        // Empty input shows all
        let filtered = matcher.filter_hints("");
        assert_eq!(filtered.len(), 3);

        // "f" shows both firefox windows
        let filtered = matcher.filter_hints("f");
        assert_eq!(filtered.len(), 2);

        // "ff" shows only second firefox
        let filtered = matcher.filter_hints("ff");
        assert_eq!(filtered.len(), 1);
    }
}
