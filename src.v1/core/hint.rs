//! Hint assignment and sequences
//!
//! Assigns letter hints to windows based on app configuration.
//! Uses repeated letters for multiple windows: g, gg, ggg

use crate::core::window::{AppId, Window, WindowId};
use std::collections::HashMap;
use std::fmt;

/// A hint sequence (e.g., "g", "gg", "ggg")
///
/// Optimized for the common case of short sequences. Uses a base character
/// and repetition count to represent Vimium-style hints efficiently.
///
/// # Examples
///
/// ```
/// use open_sesame::core::hint::HintSequence;
///
/// // Create a hint sequence
/// let hint = HintSequence::new('g', 2);
/// assert_eq!(hint.base(), 'g');
/// assert_eq!(hint.count(), 2);
/// assert_eq!(hint.as_string(), "gg");
///
/// // Parse from string
/// let parsed = HintSequence::from_repeated("ggg").unwrap();
/// assert_eq!(parsed.count(), 3);
///
/// // Match user input
/// assert!(hint.matches_input("g"));
/// assert!(hint.matches_input("gg"));
/// assert!(!hint.matches_input("ggg"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HintSequence {
    /// The base character
    base: char,
    /// Number of repetitions (1 = "g", 2 = "gg", etc.)
    count: usize,
}

impl HintSequence {
    /// Create a new hint sequence
    pub fn new(base: char, count: usize) -> Self {
        Self {
            base: base.to_ascii_lowercase(),
            count: count.max(1),
        }
    }

    /// Create from a repeated letter string
    pub fn from_repeated(s: &str) -> Option<Self> {
        let s = s.to_lowercase();
        let mut chars = s.chars();
        let base = chars.next()?;

        if !base.is_ascii_alphabetic() {
            return None;
        }

        let count = s.len();
        // Ensures all characters match the base character
        if s.chars().all(|c| c == base) {
            Some(Self::new(base, count))
        } else {
            None
        }
    }

    /// Get the base character
    pub fn base(&self) -> char {
        self.base
    }

    /// Get the repetition count
    pub fn count(&self) -> usize {
        self.count
    }

    /// Convert to string representation
    pub fn as_string(&self) -> String {
        self.base.to_string().repeat(self.count)
    }

    /// Returns true if this sequence is a prefix of the given input.
    pub fn matches_input(&self, input: &str) -> bool {
        let normalized = normalize_input(input);
        self.as_string().starts_with(&normalized)
    }

    /// Returns true if this sequence exactly equals the input.
    pub fn equals_input(&self, input: &str) -> bool {
        let normalized = normalize_input(input);
        self.as_string() == normalized
    }
}

impl fmt::Display for HintSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

/// Normalizes input to canonical hint format.
///
/// Supports two input patterns:
/// - Repeated letters: g, gg, ggg
/// - Letter + number: g1, g2, g3
fn normalize_input(input: &str) -> String {
    let input = input.to_lowercase();

    // Handles letter + number pattern (e.g., "g2", "f3")
    if input.len() >= 2 {
        let chars: Vec<char> = input.chars().collect();
        let last = chars[chars.len() - 1];

        if last.is_ascii_digit() {
            // Locates the start of numeric suffix
            let mut letter_end = chars.len() - 1;
            while letter_end > 0 && chars[letter_end - 1].is_ascii_digit() {
                letter_end -= 1;
            }

            if letter_end > 0 {
                let letters: String = chars[..letter_end].iter().collect();
                let num_str: String = chars[letter_end..].iter().collect();

                if let Ok(num) = num_str.parse::<usize>()
                    && num > 0
                    && num <= 26  // Prevent integer overflow/memory exhaustion (26 is max reasonable)
                    && let Some(base) = letters.chars().next()
                    && letters.chars().all(|c| c == base)
                {
                    // Repeats the base letter 'num' times for valid pattern
                    return base.to_string().repeat(num);
                }
            }
        }
    }

    input
}

/// A hint assigned to a window
///
/// Associates a hint sequence with a specific window for activation.
///
/// # Examples
///
/// ```
/// use open_sesame::core::{WindowHint, hint::HintSequence, WindowId};
///
/// let hint = WindowHint {
///     hint: HintSequence::new('f', 1),
///     window_id: WindowId::new("window-123"),
///     app_id: "firefox".to_string(),
///     title: "GitHub".to_string(),
///     index: 0,
/// };
///
/// assert_eq!(hint.hint_string(), "f");
/// assert_eq!(hint.app_id, "firefox");
/// ```
#[derive(Debug, Clone)]
pub struct WindowHint {
    /// The hint sequence
    pub hint: HintSequence,
    /// Window ID for activation
    pub window_id: WindowId,
    /// Application ID (as string for display)
    pub app_id: String,
    /// Window title
    pub title: String,
    /// Original index in window list
    pub index: usize,
}

impl WindowHint {
    /// Returns the hint as a string for display.
    pub fn hint_string(&self) -> String {
        self.hint.to_string()
    }
}

/// Result of hint assignment
///
/// Contains all window hints generated from a window list, maintaining
/// MRU (Most Recently Used) order for Alt+Tab behavior.
///
/// # Examples
///
/// ```
/// use open_sesame::core::{HintAssignment, Window, AppId};
///
/// let windows = vec![
///     Window::new("win-1", "firefox", "Tab 1"),
///     Window::new("win-2", "firefox", "Tab 2"),
///     Window::new("win-3", "ghostty", "Terminal"),
/// ];
///
/// // Assign hints using a key lookup function
/// let assignment = HintAssignment::assign(&windows, |app_id| {
///     match app_id.as_str() {
///         "firefox" => Some('f'),
///         "ghostty" => Some('g'),
///         _ => None,
///     }
/// });
///
/// assert_eq!(assignment.hints().len(), 3);
///
/// // Check assigned hints
/// let hint_strings: Vec<_> = assignment.hints()
///     .iter()
///     .map(|h| h.hint_string())
///     .collect();
///
/// assert!(hint_strings.contains(&"f".to_string()));
/// assert!(hint_strings.contains(&"ff".to_string()));
/// assert!(hint_strings.contains(&"g".to_string()));
/// ```
#[derive(Debug)]
pub struct HintAssignment {
    /// Assigned hints sorted by hint string
    pub hints: Vec<WindowHint>,
}

impl HintAssignment {
    /// Creates a new hint assignment from windows.
    ///
    /// Uses a key lookup function to determine the base hint for each app.
    pub fn assign<F>(windows: &[Window], key_for_app: F) -> Self
    where
        F: Fn(&AppId) -> Option<char>,
    {
        let mut hints = Vec::new();

        // Groups windows by their preferred base letter
        let mut by_base: HashMap<char, Vec<(usize, &Window)>> = HashMap::new();

        for (i, window) in windows.iter().enumerate() {
            let base = key_for_app(&window.app_id)
                .or_else(|| auto_generate_key(&window.app_id))
                .unwrap_or('x');
            by_base.entry(base).or_default().push((i, window));
        }

        // Assigns hints using repeated letters
        for (base, windows_group) in &by_base {
            for (window_idx, (original_index, window)) in windows_group.iter().enumerate() {
                let hint = HintSequence::new(*base, window_idx + 1);

                hints.push(WindowHint {
                    hint,
                    window_id: window.id.clone(),
                    app_id: window.app_id.as_str().to_string(),
                    title: window.title.clone(),
                    index: *original_index,
                });
            }
        }

        // Maintains hints in window order (MRU order) for Alt+Tab behavior.
        // The first hint represents the "previous" window for quick switching.
        hints.sort_by_key(|a| a.index);

        Self { hints }
    }

    /// Get all hints
    pub fn hints(&self) -> &[WindowHint] {
        &self.hints
    }

    /// Find a hint by window ID
    pub fn find_by_window_id(&self, id: &WindowId) -> Option<&WindowHint> {
        self.hints.iter().find(|h| &h.window_id == id)
    }
}

/// Automatically generates a key from app ID.
fn auto_generate_key(app_id: &AppId) -> Option<char> {
    let name = app_id.last_segment().to_lowercase();
    name.chars().find(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hint_sequence() {
        let seq = HintSequence::new('g', 2);
        assert_eq!(seq.base(), 'g');
        assert_eq!(seq.count(), 2);
        assert_eq!(format!("{}", seq), "gg");
    }

    #[test]
    fn test_hint_sequence_from_repeated() {
        assert_eq!(
            HintSequence::from_repeated("ggg"),
            Some(HintSequence::new('g', 3))
        );
        assert_eq!(
            HintSequence::from_repeated("G"),
            Some(HintSequence::new('g', 1))
        );
        assert_eq!(HintSequence::from_repeated("gf"), None);
        assert_eq!(HintSequence::from_repeated("123"), None);
    }

    #[test]
    fn test_normalize_input() {
        // Letter + number patterns
        assert_eq!(normalize_input("g1"), "g");
        assert_eq!(normalize_input("g2"), "gg");
        assert_eq!(normalize_input("g3"), "ggg");
        assert_eq!(normalize_input("f10"), "ffffffffff");

        // Repeated letters pass through
        assert_eq!(normalize_input("g"), "g");
        assert_eq!(normalize_input("gg"), "gg");

        // Case insensitive
        assert_eq!(normalize_input("G2"), "gg");
    }

    #[test]
    fn test_hint_matching() {
        let seq = HintSequence::new('g', 1);
        assert!(seq.matches_input("g"));
        assert!(seq.matches_input("G"));
        assert!(seq.equals_input("g"));
        assert!(!seq.equals_input("gg"));
    }

    #[test]
    fn test_hint_assignment() {
        let windows = vec![
            Window::mock("firefox", "Tab 1"),
            Window::mock("firefox", "Tab 2"),
            Window::mock("ghostty", "Terminal"),
        ];

        let assignment = HintAssignment::assign(&windows, |app_id| match app_id.as_str() {
            "firefox" => Some('f'),
            "ghostty" => Some('g'),
            _ => None,
        });

        assert_eq!(assignment.hints.len(), 3);

        let hint_strings: Vec<_> = assignment.hints.iter().map(|h| h.hint_string()).collect();
        assert!(hint_strings.contains(&"f".to_string()));
        assert!(hint_strings.contains(&"ff".to_string()));
        assert!(hint_strings.contains(&"g".to_string()));
    }
}
