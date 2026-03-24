//! Secure byte buffer backed by page-aligned, guard-page-protected memory.
//!
//! This is the primary vehicle for carrying cryptographic key material
//! (master keys, vault keys, derived keys, KEKs). The backing memory is
//! provided by [`core_memory::ProtectedAlloc`] which guarantees:
//!
//! - Page-aligned `mmap(2)` allocation (not heap)
//! - Guard pages before and after the data region (`PROT_NONE` → `SIGSEGV` on overflow)
//! - `mlock(2)` to prevent swap
//! - `madvise(MADV_DONTDUMP)` to exclude from core dumps (Linux)
//! - Canary verification on drop (detects buffer corruption)
//! - Volatile zeroize of all pages before `munmap(2)`

use core_memory::ProtectedAlloc;
use zeroize::Zeroize;

/// A secure byte buffer backed by page-aligned, mlock'd, guard-page-protected memory.
///
/// Cannot be serialized (secrets must not cross serialization boundaries
/// without explicit conversion to [`core_types::SensitiveBytes`]).
///
/// Debug output is redacted to prevent log exposure.
///
/// Empty `SecureBytes` is permitted (for denial/error paths where no key
/// material exists). Internally, empty data is backed by a 1-byte sentinel
/// allocation to satisfy `ProtectedAlloc` invariants.
pub struct SecureBytes {
    inner: ProtectedAlloc,
    /// Actual user data length. May be 0 even though `inner` holds 1 byte
    /// (sentinel for empty case). This field is the source of truth for
    /// `len()`, `is_empty()`, `as_bytes()`, and `clone()`.
    actual_len: usize,
}

impl SecureBytes {
    /// Create a `SecureBytes` from a `Vec<u8>`.
    ///
    /// **Prefer [`from_slice`](Self::from_slice) whenever possible.** This
    /// method exists only for callers that receive an owned `Vec<u8>` from
    /// an external API (e.g., AES-GCM decrypt, platform keyring retrieve)
    /// where a `&[u8]` is not available. The `Vec` is copied into protected
    /// memory and zeroized, but the secret briefly exists on the unprotected
    /// heap during the copy — `from_slice` avoids this by copying directly
    /// from a borrowed reference.
    ///
    /// Empty data is permitted.
    ///
    /// # Panics
    ///
    /// Panics if mlock, mmap, or mprotect fails.
    pub fn new(mut data: Vec<u8>) -> Self {
        let actual_len = data.len();
        // ProtectedAlloc requires non-zero size. For empty data, use a
        // 1-byte sentinel that is never exposed through the public API.
        let alloc = ProtectedAlloc::from_slice_or_sentinel(&data)
            .unwrap_or_else(|e| panic!("SecureBytes allocation failed: {e}"));
        // Zeroize the source Vec — it was on the unprotected heap.
        data.zeroize();
        SecureBytes {
            inner: alloc,
            actual_len,
        }
    }

    /// Create a `SecureBytes` directly from a byte slice.
    ///
    /// The caller retains ownership of the source slice and is responsible
    /// for zeroizing it if it contains secret material.
    ///
    /// # Panics
    ///
    /// Same as [`SecureBytes::new`].
    pub fn from_slice(data: &[u8]) -> Self {
        let actual_len = data.len();
        let alloc = ProtectedAlloc::from_slice_or_sentinel(data)
            .unwrap_or_else(|e| panic!("SecureBytes allocation failed: {e}"));
        SecureBytes {
            inner: alloc,
            actual_len,
        }
    }

    /// View the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // Return only actual_len bytes, not the sentinel byte for empty case.
        &self.inner.as_bytes()[..self.actual_len]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.actual_len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actual_len == 0
    }

    /// Consume the `SecureBytes` and return the inner `ProtectedAlloc` and
    /// actual length. Zero-copy transfer — the `ProtectedAlloc` moves to
    /// the caller with no heap exposure.
    ///
    /// Used by `SensitiveBytes::from_protected()` to transfer key material
    /// between type wrappers without leaving copies on the heap.
    #[must_use]
    pub fn into_protected_alloc(self) -> (ProtectedAlloc, usize) {
        let actual_len = self.actual_len;
        // Prevent Drop from running — we're transferring ownership.
        let inner = {
            let me = std::mem::ManuallyDrop::new(self);
            // SAFETY: We're moving the ProtectedAlloc out of the ManuallyDrop.
            // The ManuallyDrop ensures SecureBytes::drop doesn't run (which
            // would be a no-op anyway since ProtectedAlloc::drop does the work).
            // We must ensure the ProtectedAlloc is either dropped by the new
            // owner or consumed — it is, because we return it.
            unsafe { std::ptr::read(&me.inner) }
        };
        (inner, actual_len)
    }
}

impl Clone for SecureBytes {
    /// Clone creates a new independent `ProtectedAlloc` with its own
    /// guard pages, mlock, and canary. Both original and clone independently
    /// zeroize on drop.
    fn clone(&self) -> Self {
        Self::from_slice(self.as_bytes())
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // ProtectedAlloc::drop handles:
        // 1. Canary verification (abort on corruption)
        // 2. Volatile zero of entire data region
        // 3. munlock
        // 4. munmap
        //
        // Nothing additional needed here — the ProtectedAlloc field is
        // dropped automatically and performs all cleanup.
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {} bytes])", self.actual_len)
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_contents() {
        let sb = SecureBytes::new(b"super_secret_password".to_vec());
        let debug = format!("{sb:?}");
        assert!(!debug.contains("super_secret"));
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("21 bytes"));
    }

    #[test]
    fn as_bytes_returns_original_data() {
        let data = vec![1, 2, 3, 4, 5];
        let sb = SecureBytes::new(data.clone());
        assert_eq!(sb.as_bytes(), &data);
    }

    #[test]
    fn clone_is_independent() {
        let sb1 = SecureBytes::new(vec![1, 2, 3]);
        let sb2 = sb1.clone();
        assert_eq!(sb1.as_bytes(), sb2.as_bytes());
        // Both can be dropped independently.
        drop(sb1);
        assert_eq!(sb2.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn from_slice_works() {
        let data = [42u8; 32];
        let sb = SecureBytes::from_slice(&data);
        assert_eq!(sb.as_bytes(), &data);
    }

    #[test]
    fn len_and_is_empty() {
        let sb = SecureBytes::new(vec![1, 2, 3]);
        assert_eq!(sb.len(), 3);
        assert!(!sb.is_empty());
    }

    #[test]
    fn empty_is_valid() {
        let sb = SecureBytes::new(Vec::new());
        assert!(sb.is_empty());
        assert_eq!(sb.len(), 0);
        assert_eq!(sb.as_bytes(), &[]);
    }

    #[test]
    fn empty_clone() {
        let sb1 = SecureBytes::new(Vec::new());
        let sb2 = sb1.clone();
        assert!(sb2.is_empty());
        assert_eq!(sb2.as_bytes(), &[]);
    }

    #[test]
    fn empty_from_slice() {
        let sb = SecureBytes::from_slice(&[]);
        assert!(sb.is_empty());
        assert_eq!(sb.len(), 0);
    }

    #[test]
    fn into_protected_alloc_transfers_data() {
        let sb = SecureBytes::new(vec![0xAA, 0xBB, 0xCC]);
        let (alloc, len) = sb.into_protected_alloc();
        assert_eq!(len, 3);
        assert_eq!(&alloc.as_bytes()[..len], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn into_protected_alloc_empty() {
        let sb = SecureBytes::new(Vec::new());
        let (alloc, len) = sb.into_protected_alloc();
        assert_eq!(len, 0);
        // The alloc holds a 1-byte sentinel but len=0 means no user data.
        assert!(alloc.len() >= 1); // sentinel
    }

    #[test]
    fn empty_debug() {
        let sb = SecureBytes::new(Vec::new());
        let debug = format!("{sb:?}");
        assert!(debug.contains("0 bytes"));
    }
}
