use core_memory::ProtectedAlloc;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Sensitive byte buffer backed by page-aligned, guard-page-protected memory.
///
/// Used for secret values and passwords in IPC `EventKind` variants.
/// Backed by [`core_memory::ProtectedAlloc`] which provides:
/// - Page-aligned mmap with guard pages (SIGSEGV on overflow)
/// - mlock to prevent swap exposure
/// - Canary verification on drop
/// - Volatile zeroize before munmap
///
/// Custom `Serialize`/`Deserialize` implementations ensure wire compatibility
/// with postcard. During deserialization, a temporary `Vec<u8>` is created by
/// postcard's deserializer, then immediately copied into protected memory and
/// zeroized. The exposure window is bounded to the deserialization call.
///
/// Debug output is redacted to prevent log exposure.
pub struct SensitiveBytes {
    inner: ProtectedAlloc,
    /// Actual user data length. 0 for empty (backed by 1-byte sentinel).
    actual_len: usize,
}

impl SensitiveBytes {
    /// Create a new `SensitiveBytes` from a `Vec<u8>`.
    ///
    /// The data is copied into page-aligned protected memory and the source
    /// Vec is zeroized. Empty data is permitted (for denial/error responses).
    ///
    /// # Panics
    ///
    /// Panics if mlock or mmap fails.
    #[must_use]
    pub fn new(mut data: Vec<u8>) -> Self {
        let actual_len = data.len();
        let alloc = ProtectedAlloc::from_slice_or_sentinel(&data)
            .unwrap_or_else(|e| panic!("SensitiveBytes allocation failed: {e}"));
        data.zeroize();
        SensitiveBytes {
            inner: alloc,
            actual_len,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
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
}

impl Clone for SensitiveBytes {
    fn clone(&self) -> Self {
        Self::new(self.as_bytes().to_vec())
    }
}

impl PartialEq for SensitiveBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for SensitiveBytes {}

impl Serialize for SensitiveBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize the actual bytes directly from protected memory.
        // postcard reads the slice without copying.
        self.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SensitiveBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // postcard deserializes into a temporary Vec<u8> on the heap.
        // SensitiveBytes::new() copies into protected memory and zeroizes
        // the source Vec. One copy, one zeroize, minimal exposure window.
        let temp: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(SensitiveBytes::new(temp))
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        // ProtectedAlloc::drop handles canary check, volatile zero, munlock, munmap.
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.actual_len)
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}
