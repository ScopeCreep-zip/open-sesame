//! Heap-allocated byte buffer with mlock, MADV_DONTDUMP, and zeroize-on-drop.

use zeroize::Zeroize;

/// A heap-allocated byte buffer that is:
/// - `mlock`'d to prevent swapping to disk (Unix)
/// - `MADV_DONTDUMP` to exclude from core dumps (Linux)
/// - Zeroed on drop via `zeroize`
/// - Redacted in `Debug` output
pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    /// Create a new `SecureBytes` from raw data.
    ///
    /// On Unix, the backing memory is immediately `mlock`'d and marked
    /// `MADV_DONTDUMP`. Failure to mlock is logged but not fatal (the
    /// process may lack `CAP_IPC_LOCK` or hit `RLIMIT_MEMLOCK`).
    pub fn new(data: Vec<u8>) -> Self {
        let sb = Self { inner: data };
        #[cfg(unix)]
        {
            // SAFETY: mlock and madvise operate on the Vec's backing allocation.
            // The pointer and length are valid for the lifetime of `sb.inner`.
            // mlock prevents the OS from swapping these pages to disk.
            // MADV_DONTDUMP excludes pages from core dumps.
            unsafe {
                let ptr = sb.inner.as_ptr().cast::<libc::c_void>();
                let len = sb.inner.len();
                if libc::mlock(ptr, len) != 0 {
                    tracing::warn!(
                        len,
                        "mlock failed (process may lack CAP_IPC_LOCK or hit RLIMIT_MEMLOCK)"
                    );
                }
                // MADV_DONTDUMP is Linux-specific (value 16).
                #[cfg(target_os = "linux")]
                {
                    libc::madvise(ptr.cast_mut(), len, libc::MADV_DONTDUMP);
                }
            }
        }
        sb
    }

    /// View the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Consume the `SecureBytes` and return the inner `Vec<u8>`.
    ///
    /// The caller takes ownership of the raw bytes and is responsible for
    /// zeroizing them. This avoids creating a temporary unprotected copy
    /// when transferring key material to another zeroizing container.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        // Take the inner Vec, replacing it with an empty Vec so that
        // Drop::drop (which calls zeroize) operates on the empty Vec
        // rather than double-zeroing the data the caller now owns.
        std::mem::take(&mut self.inner)
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        #[cfg(unix)]
        let original_len = self.inner.len();
        #[cfg(unix)]
        let original_ptr = self.inner.as_ptr();

        // Zero the memory before releasing.
        // zeroize() overwrites all bytes with 0x00 then sets len to 0.
        self.inner.zeroize();

        #[cfg(unix)]
        {
            // SAFETY: munlock the previously mlock'd region using the
            // pointer and length captured BEFORE zeroize cleared them.
            // The Vec's backing allocation is still alive (we're in Drop,
            // before dealloc), even though its logical length is now 0.
            if original_len > 0 {
                unsafe {
                    libc::munlock(original_ptr.cast::<libc::c_void>(), original_len);
                }
            }
        }
    }
}

impl Clone for SecureBytes {
    /// Clone allocates a new `Vec`, copies bytes, and applies `mlock` +
    /// `MADV_DONTDUMP` to the new allocation. Both the original and clone
    /// independently zeroize + munlock on drop.
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {} bytes])", self.inner.len())
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
    fn empty_secure_bytes() {
        let sb = SecureBytes::new(Vec::new());
        assert!(sb.is_empty());
        assert_eq!(sb.len(), 0);
    }
}
