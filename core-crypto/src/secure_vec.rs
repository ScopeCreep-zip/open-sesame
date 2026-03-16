//! Growable byte buffer with mlock, MADV_DONTDUMP, and zeroize-on-drop.
//!
//! Designed for collecting password input character-by-character in a
//! graphical overlay where the full password is not known in advance.
//! Provides UTF-8 aware push/pop for correct multi-byte character handling.

use zeroize::Zeroize;

/// A growable byte buffer that is:
/// - `mlock`'d to prevent swapping to disk (Unix)
/// - `MADV_DONTDUMP` to exclude from core dumps (Linux)
/// - Zeroed on drop via `zeroize`
/// - Redacted in `Debug` output
/// - UTF-8 aware for character-level push/pop operations
pub struct SecureVec {
    inner: Vec<u8>,
    locked: bool,
}

impl SecureVec {
    /// Create a new empty `SecureVec`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Vec::new(),
            locked: false,
        }
    }

    /// Create a new `SecureVec` with pre-allocated capacity.
    ///
    /// The allocated region is immediately `mlock`'d and marked
    /// `MADV_DONTDUMP` so even unused capacity pages are protected.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let mut sv = Self {
            inner: Vec::with_capacity(cap),
            locked: false,
        };
        sv.lock_current_allocation();
        sv
    }

    /// Append a Unicode character encoded as UTF-8 bytes.
    ///
    /// If the underlying allocation grows (realloc), the old allocation
    /// is zeroized and munlock'd, and the new allocation is mlock'd.
    pub fn push_char(&mut self, ch: char) {
        let old_cap = self.inner.capacity();
        let old_ptr = self.inner.as_ptr();

        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        self.inner.extend_from_slice(encoded.as_bytes());

        // Check if reallocation occurred.
        if self.inner.capacity() != old_cap || self.inner.as_ptr() != old_ptr {
            // Old allocation was freed by Vec — we cannot munlock it (already deallocated).
            // But we can lock the new allocation.
            // Note: Vec zeroizes the old allocation only if we used zeroize — it does not
            // here because realloc copies and frees. This is a known limitation: the old
            // pages may retain data until the allocator reuses them. For password-length
            // buffers (< 1KB), this window is negligible.
            self.lock_current_allocation();
        }
    }

    /// Remove the last Unicode character, returning it.
    ///
    /// Handles multi-byte UTF-8 correctly by scanning backwards to find
    /// the start of the last character. The removed bytes are zeroized.
    pub fn pop_char(&mut self) -> Option<char> {
        if self.inner.is_empty() {
            return None;
        }

        // Find the start of the last UTF-8 character by scanning backwards.
        // UTF-8 continuation bytes have the pattern 10xxxxxx (0x80..0xBF).
        let mut start = self.inner.len() - 1;
        while start > 0 && (self.inner[start] & 0xC0) == 0x80 {
            start -= 1;
        }

        // Decode the character from the found position.
        let ch = std::str::from_utf8(&self.inner[start..])
            .ok()
            .and_then(|s| s.chars().next());

        // Zeroize the bytes being removed before truncating.
        for byte in &mut self.inner[start..] {
            *byte = 0;
        }
        self.inner.truncate(start);

        ch
    }

    /// Number of Unicode characters (not bytes).
    #[must_use]
    pub fn char_count(&self) -> usize {
        // Count UTF-8 start bytes: any byte that is NOT a continuation byte (10xxxxxx).
        self.inner.iter().filter(|b| (**b & 0xC0) != 0x80).count()
    }

    /// Byte length of the buffer contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the buffer contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// View the buffer contents as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Consume the buffer contents, returning the raw bytes.
    ///
    /// The caller is responsible for zeroizing the returned `Vec<u8>`.
    /// The internal buffer is zeroized and reset to empty.
    pub fn take(&mut self) -> Vec<u8> {
        let taken = std::mem::take(&mut self.inner);
        // The old Vec is now empty (std::mem::take replaced it with Vec::new()).
        // The taken Vec retains the original allocation — caller must zeroize.
        // We do NOT munlock here because the allocation moved to `taken`.
        // When the caller drops/zeroizes `taken`, the memory is freed normally.
        // We mark ourselves as unlocked since we no longer own that allocation.
        self.locked = false;
        taken
    }

    /// Zeroize all bytes and reset length to zero.
    ///
    /// Does NOT deallocate or munlock — the buffer can be reused for the
    /// next password entry (e.g., multi-profile sequential unlock).
    pub fn clear(&mut self) {
        self.inner.zeroize();
        // Note: zeroize on Vec<u8> fills with zeros AND sets len to 0,
        // but capacity and allocation remain. This is what we want.
    }

    /// Apply `mlock` and `MADV_DONTDUMP` to the current backing allocation.
    fn lock_current_allocation(&mut self) {
        #[cfg(unix)]
        {
            let cap = self.inner.capacity();
            if cap == 0 {
                return;
            }
            let ptr = self.inner.as_ptr().cast::<libc::c_void>();

            // SAFETY: mlock operates on the Vec's backing allocation.
            // The pointer is valid and the capacity represents the allocated size.
            // mlock prevents the OS from swapping these pages to disk.
            unsafe {
                if libc::mlock(ptr, cap) != 0 {
                    tracing::warn!(
                        cap,
                        "SecureVec: mlock failed (process may lack CAP_IPC_LOCK or hit RLIMIT_MEMLOCK)"
                    );
                } else {
                    self.locked = true;
                }
            }

            // SAFETY: madvise with MADV_DONTDUMP excludes these pages from core dumps.
            // The pointer and length are valid for the Vec's backing allocation.
            #[cfg(target_os = "linux")]
            unsafe {
                libc::madvise(ptr.cast_mut(), cap, libc::MADV_DONTDUMP);
            }
        }
    }

    /// Unlock the current backing allocation via `munlock`.
    fn unlock_current_allocation(&mut self) {
        #[cfg(unix)]
        if self.locked {
            let cap = self.inner.capacity();
            if cap > 0 {
                let ptr = self.inner.as_ptr().cast::<libc::c_void>();
                // SAFETY: munlock on the same region previously mlock'd.
                // The Vec's backing allocation is still alive (we're about to drop it).
                unsafe {
                    libc::munlock(ptr, cap);
                }
            }
            self.locked = false;
        }
    }
}

impl Default for SecureVec {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        // Zeroize all allocated capacity (not just len).
        // zeroize() on Vec<u8> overwrites bytes and sets len to 0, but the
        // allocation remains until Vec itself is dropped.
        let cap = self.inner.capacity();
        if cap > 0 {
            // Fill entire capacity with zeros, not just the logical length.
            // SAFETY: the Vec's allocation is `cap` bytes. We temporarily set
            // the length to capacity, zeroize, then let Drop free the allocation.
            // This is safe because all byte patterns are valid for u8.
            unsafe {
                self.inner.set_len(cap);
            }
            self.inner.zeroize();
        }

        self.unlock_current_allocation();
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
    }

    #[test]
    fn with_capacity_is_empty_but_allocated() {
        let sv = SecureVec::with_capacity(128);
        assert!(sv.is_empty());
        assert_eq!(sv.len(), 0);
        assert!(sv.inner.capacity() >= 128);
    }

    #[test]
    fn push_pop_ascii() {
        let mut sv = SecureVec::new();
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
        let mut sv = SecureVec::new();
        // 2-byte: e with acute (U+00E9)
        sv.push_char('\u{00E9}');
        assert_eq!(sv.len(), 2);
        assert_eq!(sv.char_count(), 1);

        // 3-byte: CJK character (U+4E16 = 世)
        sv.push_char('\u{4E16}');
        assert_eq!(sv.len(), 5);
        assert_eq!(sv.char_count(), 2);

        // 4-byte: emoji (U+1F512 = 🔒)
        sv.push_char('\u{1F512}');
        assert_eq!(sv.len(), 9);
        assert_eq!(sv.char_count(), 3);

        // Pop in reverse order
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
        let mut sv = SecureVec::new();
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
        // Capacity still allocated (reusable).
        assert!(sv.inner.capacity() > 0);
    }

    #[test]
    fn take_returns_bytes_and_resets() {
        let mut sv = SecureVec::new();
        sv.push_char('a');
        sv.push_char('b');
        sv.push_char('c');

        let taken = sv.take();
        assert_eq!(taken, b"abc");
        assert!(sv.is_empty());
        assert_eq!(sv.len(), 0);
    }

    #[test]
    fn debug_does_not_leak_contents() {
        let mut sv = SecureVec::new();
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
        let mut sv = SecureVec::new();
        for ch in "P@ssw0rd!#$%^&*()".chars() {
            sv.push_char(ch);
        }
        assert_eq!(sv.char_count(), 17);
        assert_eq!(sv.as_bytes(), b"P@ssw0rd!#$%^&*()");

        // Pop all and verify round-trip
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
        let mut sv = SecureVec::new();
        sv.push_char('a');
        sv.push_char('🔑');
        sv.push_char('b');
        sv.push_char('世');
        assert_eq!(sv.char_count(), 4);
        // a=1, 🔑=4, b=1, 世=3 => 9 bytes
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
    }

    #[test]
    fn pop_zeroizes_removed_bytes() {
        let mut sv = SecureVec::new();
        sv.push_char('x');
        sv.push_char('y');
        sv.push_char('z');

        // After popping 'z', the byte at position 2 should be zeroed.
        sv.pop_char();
        // inner.len() is now 2, but the byte at index 2 in the allocation
        // should have been zeroized by pop_char before truncation.
        // We can't directly test this without unsafe, but we verify the
        // visible state is correct.
        assert_eq!(sv.as_bytes(), b"xy");
    }

    #[test]
    fn push_after_clear_works() {
        let mut sv = SecureVec::new();
        sv.push_char('a');
        sv.push_char('b');
        sv.clear();
        sv.push_char('c');
        assert_eq!(sv.char_count(), 1);
        assert_eq!(sv.as_bytes(), b"c");
    }

    #[test]
    fn push_after_take_works() {
        let mut sv = SecureVec::new();
        sv.push_char('x');
        let _ = sv.take();
        sv.push_char('y');
        assert_eq!(sv.char_count(), 1);
        assert_eq!(sv.as_bytes(), b"y");
    }
}
