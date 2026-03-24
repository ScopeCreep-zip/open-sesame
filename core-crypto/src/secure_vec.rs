//! Password input buffer backed by page-aligned, guard-page-protected memory.
//!
//! Designed for collecting password input character-by-character in a
//! graphical overlay where the full password is not known in advance.
//! Provides UTF-8 aware push/pop for correct multi-byte character handling.
//!
//! Backed by [`core_memory::ProtectedAlloc`] for the same memory protection
//! guarantees as [`SecureBytes`]: guard pages, mlock, canary, volatile zeroize.

use core_memory::ProtectedAlloc;

/// Maximum password buffer size in bytes (UTF-8 encoded).
/// 512 bytes accommodates passwords up to ~128 4-byte Unicode characters.
const MAX_PASSWORD_BYTES: usize = 512;

/// A password input buffer backed by page-aligned, mlock'd, guard-page-protected memory.
///
/// - Pre-allocates a fixed-size buffer via `ProtectedAlloc` (no reallocation)
/// - Guard pages before and after (SIGSEGV on overflow)
/// - `mlock(2)` prevents swap exposure
/// - Canary verified on drop (detects corruption)
/// - Volatile zeroize of all pages before `munmap(2)`
/// - UTF-8 aware push/pop for correct multi-byte handling
/// - Redacted Debug output
///
/// `SecureVec::new()` creates an empty instance with no allocation.
/// `SecureVec::for_password()` allocates 512 bytes of protected memory.
pub struct SecureVec {
    /// Page-aligned protected backing memory. `None` for empty instances
    /// created via `new()` or `default()`. Allocated on `for_password()`
    /// or `with_capacity()`.
    inner: Option<ProtectedAlloc>,
    /// Current write position (byte offset into the data region).
    cursor: usize,
}

impl SecureVec {
    /// Create a new empty `SecureVec` with no allocation.
    ///
    /// No mmap, no mlock, no memory overhead. Call `for_password()` to
    /// allocate protected memory for password collection.
    #[must_use]
    pub fn new() -> Self {
        SecureVec {
            inner: None,
            cursor: 0,
        }
    }

    /// Create a pre-allocated `SecureVec` for password collection.
    ///
    /// Allocates 512 bytes in page-aligned, mlock'd, guard-page-protected
    /// memory. No reallocation ever occurs — push_char panics if the buffer
    /// is full.
    ///
    /// # Panics
    ///
    /// Panics if mlock or mmap fails.
    #[must_use]
    pub fn for_password() -> Self {
        let alloc = ProtectedAlloc::new(MAX_PASSWORD_BYTES)
            .unwrap_or_else(|e| panic!("SecureVec::for_password allocation failed: {e}"));
        SecureVec {
            inner: Some(alloc),
            cursor: 0,
        }
    }

    /// Create a new `SecureVec` with specified capacity.
    ///
    /// # Panics
    ///
    /// Panics if mlock or mmap fails, or if `cap` is 0.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        assert!(
            cap > 0,
            "SecureVec::with_capacity requires non-zero capacity"
        );
        let alloc = ProtectedAlloc::new(cap)
            .unwrap_or_else(|e| panic!("SecureVec::with_capacity allocation failed: {e}"));
        SecureVec {
            inner: Some(alloc),
            cursor: 0,
        }
    }

    /// Returns a mutable reference to the backing allocation, panicking if
    /// no allocation exists (i.e., created via `new()` without `for_password()`).
    fn alloc_mut(&mut self) -> &mut ProtectedAlloc {
        self.inner
            .as_mut()
            .expect("SecureVec has no allocation — call for_password() or with_capacity() first")
    }

    /// Returns a reference to the backing allocation, or None.
    fn alloc(&self) -> Option<&ProtectedAlloc> {
        self.inner.as_ref()
    }

    /// Capacity of the backing allocation in bytes, or 0 if unallocated.
    fn capacity(&self) -> usize {
        self.alloc().map_or(0, |a| a.len())
    }

    /// Append a Unicode character encoded as UTF-8 bytes.
    ///
    /// # Panics
    ///
    /// Panics if the character would cause the buffer to exceed its
    /// pre-allocated capacity, or if no allocation exists.
    pub fn push_char(&mut self, ch: char) {
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        let encoded_bytes = encoded.as_bytes();
        let cap = self.capacity();
        let cur = self.cursor;
        assert!(
            cur + encoded_bytes.len() <= cap,
            "password buffer full ({cur} + {} > {cap})",
            encoded_bytes.len(),
        );
        self.alloc_mut().as_bytes_mut()[cur..cur + encoded_bytes.len()]
            .copy_from_slice(encoded_bytes);
        self.cursor += encoded_bytes.len();
    }

    /// Remove the last Unicode character, returning it.
    ///
    /// Handles multi-byte UTF-8 correctly by scanning backwards to find
    /// the start of the last character. The removed bytes are zeroized
    /// in the protected allocation.
    pub fn pop_char(&mut self) -> Option<char> {
        if self.cursor == 0 {
            return None;
        }

        let cur = self.cursor;
        let alloc = self.alloc_mut();
        let data = &alloc.as_bytes()[..cur];

        // Find the start of the last UTF-8 character by scanning backwards.
        let mut start = cur - 1;
        while start > 0 && (data[start] & 0xC0) == 0x80 {
            start -= 1;
        }

        // Decode the character.
        let ch = std::str::from_utf8(&data[start..cur])
            .ok()
            .and_then(|s| s.chars().next());

        // Zeroize the removed bytes in the protected allocation.
        for byte in &mut alloc.as_bytes_mut()[start..cur] {
            *byte = 0;
        }
        self.cursor = start;

        ch
    }

    /// Number of Unicode characters (not bytes).
    #[must_use]
    pub fn char_count(&self) -> usize {
        match self.alloc() {
            Some(alloc) => alloc.as_bytes()[..self.cursor]
                .iter()
                .filter(|b| (**b & 0xC0) != 0x80)
                .count(),
            None => 0,
        }
    }

    /// Byte length of the buffer contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cursor
    }

    /// Returns true if the buffer contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursor == 0
    }

    /// View the buffer contents as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self.alloc() {
            Some(alloc) => &alloc.as_bytes()[..self.cursor],
            None => &[],
        }
    }

    /// Zeroize all bytes and reset the cursor to zero.
    ///
    /// Does NOT deallocate — the buffer can be reused for the next password
    /// entry (e.g., multi-profile sequential unlock).
    pub fn clear(&mut self) {
        if self.cursor > 0
            && let Some(alloc) = self.inner.as_mut()
        {
            for byte in &mut alloc.as_bytes_mut()[..self.cursor] {
                *byte = 0;
            }
        }
        self.cursor = 0;
    }
}

impl Default for SecureVec {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        // Zeroize any data in the buffer before ProtectedAlloc::drop
        // performs its own volatile zero + canary check + munmap.
        if self.cursor > 0
            && let Some(alloc) = self.inner.as_mut()
        {
            for byte in &mut alloc.as_bytes_mut()[..self.cursor] {
                *byte = 0;
            }
        }
        // ProtectedAlloc::drop handles the rest (if inner is Some).
    }
}

impl std::fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SecureVec([REDACTED; {} chars, {} bytes])",
            self.char_count(),
            self.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let sv = SecureVec::new();
        assert!(sv.is_empty());
        assert_eq!(sv.len(), 0);
        assert_eq!(sv.char_count(), 0);
        assert_eq!(sv.as_bytes(), &[]);
    }

    #[test]
    fn new_has_no_allocation() {
        let sv = SecureVec::new();
        assert!(sv.inner.is_none());
    }

    #[test]
    fn with_capacity_is_empty_but_allocated() {
        let sv = SecureVec::with_capacity(128);
        assert!(sv.is_empty());
        assert_eq!(sv.len(), 0);
        assert!(sv.inner.is_some());
    }

    #[test]
    fn push_pop_ascii() {
        let mut sv = SecureVec::for_password();
        sv.push_char('h');
        sv.push_char('e');
        sv.push_char('l');
        sv.push_char('l');
        sv.push_char('o');
        assert_eq!(sv.len(), 5);
        assert_eq!(sv.char_count(), 5);
        assert_eq!(sv.as_bytes(), b"hello");

        assert_eq!(sv.pop_char(), Some('o'));
        assert_eq!(sv.len(), 4);
        assert_eq!(sv.char_count(), 4);
        assert_eq!(sv.as_bytes(), b"hell");
    }

    #[test]
    fn push_pop_multibyte_utf8() {
        let mut sv = SecureVec::for_password();
        sv.push_char('\u{00E9}');
        assert_eq!(sv.len(), 2);
        assert_eq!(sv.char_count(), 1);

        sv.push_char('\u{4E16}');
        assert_eq!(sv.len(), 5);
        assert_eq!(sv.char_count(), 2);

        sv.push_char('\u{1F512}');
        assert_eq!(sv.len(), 9);
        assert_eq!(sv.char_count(), 3);

        assert_eq!(sv.pop_char(), Some('\u{1F512}'));
        assert_eq!(sv.len(), 5);
        assert_eq!(sv.char_count(), 2);

        assert_eq!(sv.pop_char(), Some('\u{4E16}'));
        assert_eq!(sv.len(), 2);
        assert_eq!(sv.char_count(), 1);

        assert_eq!(sv.pop_char(), Some('\u{00E9}'));
        assert!(sv.is_empty());
        assert_eq!(sv.char_count(), 0);
    }

    #[test]
    fn pop_empty_returns_none() {
        let mut sv = SecureVec::new();
        assert_eq!(sv.pop_char(), None);
    }

    #[test]
    fn clear_zeroizes_and_resets() {
        let mut sv = SecureVec::for_password();
        sv.push_char('s');
        sv.push_char('e');
        sv.push_char('c');
        sv.push_char('r');
        sv.push_char('e');
        sv.push_char('t');
        assert_eq!(sv.len(), 6);

        sv.clear();
        assert!(sv.is_empty());
        assert_eq!(sv.len(), 0);
        assert_eq!(sv.char_count(), 0);
    }

    #[test]
    fn debug_does_not_leak_contents() {
        let mut sv = SecureVec::for_password();
        sv.push_char('p');
        sv.push_char('@');
        sv.push_char('s');
        sv.push_char('s');
        let debug = format!("{sv:?}");
        assert!(!debug.contains("p@ss"));
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("4 chars"));
        assert!(debug.contains("4 bytes"));
    }

    #[test]
    fn password_special_characters() {
        let mut sv = SecureVec::for_password();
        for ch in "P@ssw0rd!#$%^&*()".chars() {
            sv.push_char(ch);
        }
        assert_eq!(sv.char_count(), 17);
        assert_eq!(sv.as_bytes(), b"P@ssw0rd!#$%^&*()");

        let mut popped = Vec::new();
        while let Some(ch) = sv.pop_char() {
            popped.push(ch);
        }
        popped.reverse();
        let reconstructed: String = popped.into_iter().collect();
        assert_eq!(reconstructed, "P@ssw0rd!#$%^&*()");
    }

    #[test]
    fn mixed_ascii_and_multibyte() {
        let mut sv = SecureVec::for_password();
        sv.push_char('a');
        sv.push_char('🔑');
        sv.push_char('b');
        sv.push_char('世');
        assert_eq!(sv.char_count(), 4);
        assert_eq!(sv.len(), 9);

        assert_eq!(sv.pop_char(), Some('世'));
        assert_eq!(sv.pop_char(), Some('b'));
        assert_eq!(sv.pop_char(), Some('🔑'));
        assert_eq!(sv.pop_char(), Some('a'));
        assert!(sv.is_empty());
    }

    #[test]
    fn default_is_new() {
        let sv = SecureVec::default();
        assert!(sv.is_empty());
        assert!(sv.inner.is_none());
    }

    #[test]
    fn pop_zeroizes_removed_bytes() {
        let mut sv = SecureVec::for_password();
        sv.push_char('x');
        sv.push_char('y');
        sv.push_char('z');

        sv.pop_char();
        assert_eq!(sv.as_bytes(), b"xy");
    }

    #[test]
    fn push_after_clear_works() {
        let mut sv = SecureVec::for_password();
        sv.push_char('a');
        sv.push_char('b');
        sv.clear();
        sv.push_char('c');
        assert_eq!(sv.char_count(), 1);
        assert_eq!(sv.as_bytes(), b"c");
    }
}
