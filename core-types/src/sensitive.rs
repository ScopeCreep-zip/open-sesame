use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Sensitive byte buffer with automatic zeroize-on-drop and memory locking.
///
/// Used for secret values and passwords in IPC `EventKind` variants.
/// On Unix, the backing memory is `mlock`'d and marked `MADV_DONTDUMP`.
/// Zeroes the backing memory when dropped to prevent heap forensics.
/// Debug output is redacted to prevent log exposure.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Deserialize)]
#[serde(transparent)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    /// # Panics
    ///
    /// Panics if the platform memory lock (`mlock`) syscall fails.
    #[must_use]
    #[allow(unsafe_code)]
    pub fn new(data: Vec<u8>) -> Self {
        let sb = Self(data);
        #[cfg(unix)]
        {
            let len = sb.0.len();
            if len > 0 {
                let ptr = sb.0.as_ptr().cast::<libc::c_void>();
                // SAFETY: mlock and madvise operate on the Vec's backing allocation.
                // The pointer and length are valid for the lifetime of `sb.0`.
                unsafe {
                    if libc::mlock(ptr, len) != 0 {
                        let errno = *libc::__errno_location();
                        panic!(
                            "mlock failed: errno {errno} (len={len}). \
                             Check RLIMIT_MEMLOCK (ulimit -l) and CAP_IPC_LOCK."
                        );
                    }
                    #[cfg(target_os = "linux")]
                    {
                        // MADV_DONTDUMP is defense-in-depth (exclude from core dumps).
                        // Can fail on non-page-aligned heap allocations — not fatal.
                        let _ = libc::madvise(ptr.cast_mut(), len, libc::MADV_DONTDUMP);
                    }
                }
            }
        }
        sb
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SensitiveBytes {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        #[cfg(unix)]
        let original_len = self.0.len();
        #[cfg(unix)]
        let original_ptr = self.0.as_ptr();

        self.0.zeroize();

        #[cfg(unix)]
        {
            if original_len > 0 {
                // SAFETY: munlock the previously mlock'd region using the
                // pointer and length captured BEFORE zeroize cleared them.
                unsafe {
                    libc::munlock(original_ptr.cast::<libc::c_void>(), original_len);
                }
            }
        }
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.0.len())
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}
