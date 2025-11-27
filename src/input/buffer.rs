//! Input buffer for collecting keyboard input
//!
//! Provides a clean abstraction over user input accumulation.

use std::fmt;

/// Maximum input buffer length to prevent unbounded memory growth
///
/// 64 characters is more than enough for any reasonable hint sequence
/// (typical hints are 1-3 characters). This prevents memory exhaustion
/// from malicious or buggy input sources.
const MAX_INPUT_LENGTH: usize = 64;

/// Buffer for collecting keyboard input
///
/// **Invariant:** All characters are stored in lowercase ASCII for case-insensitive
/// matching. Both `push()` and `From<&str>` enforce this by converting input.
#[derive(Debug, Clone, Default)]
pub struct InputBuffer {
    /// Characters entered so far (always lowercase)
    chars: Vec<char>,
}

impl InputBuffer {
    /// Create a new empty buffer
    pub fn new() -> Self {
        Self { chars: Vec::new() }
    }

    /// Pushes a character to the buffer.
    ///
    /// Returns `true` if the character was added, `false` if the buffer is full.
    pub fn push(&mut self, c: char) -> bool {
        if self.chars.len() >= MAX_INPUT_LENGTH {
            tracing::debug!(
                "Input buffer full ({} chars), ignoring input",
                MAX_INPUT_LENGTH
            );
            return false;
        }
        // Maintains invariant: stores lowercase for case-insensitive matching
        self.chars.push(c.to_ascii_lowercase());
        true
    }

    /// Removes and returns the last character.
    pub fn pop(&mut self) -> Option<char> {
        self.chars.pop()
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.chars.clear();
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Returns the number of characters in the buffer.
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// Returns the first character for determining launch key.
    pub fn first_char(&self) -> Option<char> {
        self.chars.first().copied()
    }

    /// Returns the buffer contents as a string.
    pub fn as_str(&self) -> String {
        self.chars.iter().collect()
    }

    /// Returns the characters as a slice.
    pub fn chars(&self) -> &[char] {
        &self.chars
    }
}

impl fmt::Display for InputBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&str> for InputBuffer {
    fn from(s: &str) -> Self {
        Self {
            chars: s.to_lowercase().chars().take(MAX_INPUT_LENGTH).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_buffer() {
        let buf = InputBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_str(), "");
    }

    #[test]
    fn test_push_pop() {
        let mut buf = InputBuffer::new();
        buf.push('g');
        buf.push('G'); // Should be lowercased
        assert_eq!(buf.as_str(), "gg");
        assert_eq!(buf.len(), 2);

        assert_eq!(buf.pop(), Some('g'));
        assert_eq!(buf.as_str(), "g");
    }

    #[test]
    fn test_first_char() {
        let mut buf = InputBuffer::new();
        assert_eq!(buf.first_char(), None);

        buf.push('f');
        buf.push('f');
        assert_eq!(buf.first_char(), Some('f'));
    }

    #[test]
    fn test_from_str() {
        let buf = InputBuffer::from("GGG");
        assert_eq!(buf.as_str(), "ggg");
    }

    #[test]
    fn test_display() {
        let buf = InputBuffer::from("test");
        assert_eq!(format!("{}", buf), "test");
    }

    #[test]
    fn test_max_length_push() {
        let mut buf = InputBuffer::new();
        // Fill the buffer to max
        for _ in 0..MAX_INPUT_LENGTH {
            assert!(buf.push('a'));
        }
        assert_eq!(buf.len(), MAX_INPUT_LENGTH);

        // Attempt to push more should fail
        assert!(!buf.push('b'));
        assert_eq!(buf.len(), MAX_INPUT_LENGTH);
    }

    #[test]
    fn test_max_length_from_str() {
        let long_string = "a".repeat(MAX_INPUT_LENGTH * 2);
        let buf = InputBuffer::from(long_string.as_str());
        assert_eq!(buf.len(), MAX_INPUT_LENGTH);
    }
}
