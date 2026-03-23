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
/// with postcard. Deserialization uses a custom `Visitor` that copies directly
/// from the deserializer's input buffer into protected memory — no intermediate
/// heap `Vec<u8>` is created when the deserializer supports `visit_bytes`
/// (which postcard does for in-memory deserialization). If the deserializer
/// can only provide owned bytes (`visit_byte_buf`), the `Vec<u8>` is zeroized
/// immediately after copying into protected memory.
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

    /// Create a `SensitiveBytes` from a byte slice.
    ///
    /// Copies directly into protected memory. No intermediate heap allocation.
    ///
    /// # Panics
    ///
    /// Panics if mlock or mmap fails.
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        let actual_len = data.len();
        let alloc = ProtectedAlloc::from_slice_or_sentinel(data)
            .unwrap_or_else(|e| panic!("SensitiveBytes allocation failed: {e}"));
        SensitiveBytes {
            inner: alloc,
            actual_len,
        }
    }

    /// Create a `SensitiveBytes` by taking ownership of a `ProtectedAlloc`.
    ///
    /// Zero-copy transfer from `SecureBytes` — no heap exposure. Use via:
    /// ```ignore
    /// let (alloc, len) = secure_bytes.into_protected_alloc();
    /// let sensitive = SensitiveBytes::from_protected(alloc, len);
    /// ```
    #[must_use]
    pub fn from_protected(alloc: ProtectedAlloc, actual_len: usize) -> Self {
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
        Self::from_slice(self.as_bytes())
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
        serializer.serialize_bytes(self.as_bytes())
    }
}

/// Visitor for deserializing bytes directly into protected memory.
///
/// When the deserializer provides borrowed bytes (`visit_bytes`), the data
/// is copied directly from the input buffer into a `ProtectedAlloc` with no
/// heap allocation. This is the zero-copy path used by postcard for
/// in-memory deserialization.
///
/// When the deserializer provides owned bytes (`visit_byte_buf`), the
/// `Vec<u8>` is copied into protected memory and immediately zeroized.
/// This path handles deserializers that must allocate (e.g., streaming).
struct SensitiveBytesVisitor;

impl<'de> serde::de::Visitor<'de> for SensitiveBytesVisitor {
    type Value = SensitiveBytes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a byte sequence")
    }

    /// Zero-copy path: deserializer provides a borrowed slice.
    /// postcard uses this for in-memory deserialization.
    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(SensitiveBytes::from_slice(v))
    }

    /// Fallback path: deserializer provides an owned Vec.
    /// The Vec is zeroized after copying into protected memory.
    fn visit_byte_buf<E: serde::de::Error>(self, mut v: Vec<u8>) -> Result<Self::Value, E> {
        let sb = SensitiveBytes::from_slice(&v);
        v.zeroize();
        Ok(sb)
    }

    /// Handle sequences (serde may encode bytes as a sequence of u8).
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // Collect into a Vec, copy to protected memory, zeroize.
        let mut buf: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(byte) = seq.next_element()? {
            buf.push(byte);
        }
        let sb = SensitiveBytes::from_slice(&buf);
        buf.zeroize();
        Ok(sb)
    }
}

impl<'de> Deserialize<'de> for SensitiveBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_byte_buf(SensitiveBytesVisitor)
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
