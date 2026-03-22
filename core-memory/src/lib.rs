//! Page-aligned secure memory allocator for Open Sesame.
//!
//! Provides [`ProtectedAlloc`] — a page-aligned memory region backed by
//! `mmap(2)` with:
//!
//! - **Guard pages**: `PROT_NONE` pages before and after the data region.
//!   Buffer overflows and underflows trigger `SIGSEGV` immediately.
//! - **mlock**: Prevents the kernel from swapping secret pages to disk.
//! - **madvise(MADV_DONTDUMP)**: Excludes secret pages from core dumps
//!   (Linux only; no equivalent on macOS).
//! - **Canary values**: 16-byte random canary before user data, verified on
//!   free to detect heap corruption.
//! - **Zeroize-on-drop**: Volatile-write zeros to the entire data region
//!   before `munmap`, preventing data remanence.
//!
//! # Memory layout
//!
//! ```text
//! [guard page 0] [metadata page] [guard page 1] [data pages...] [guard page 2]
//!  PROT_NONE      PROT_READ       PROT_NONE      PROT_READ|WRITE  PROT_NONE
//! ```
//!
//! User data is right-aligned within the data pages so that buffer overflows
//! hit the trailing guard page. A 16-byte canary sits immediately before the
//! user data.
//!
//! # Platform support
//!
//! - **Linux**: full support (mmap, mlock, madvise MADV_DONTDUMP, getrandom)
//! - **macOS**: full support (mmap, mlock, getentropy, MADV_ZERO_WIRED_PAGES)
//! - **Other Unix**: compiles but returns `Unsupported` error at runtime
//! - **Non-Unix**: compiles with a stub that always returns `Unsupported`

#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(unix)]
mod alloc;

#[cfg(unix)]
pub use alloc::ProtectedAlloc;
#[cfg(unix)]
pub use alloc::ProtectedAllocError;

// Stub for non-Unix platforms so the crate compiles in workspace checks.
#[cfg(not(unix))]
mod stub {
    /// Stub error for unsupported platforms.
    #[derive(Debug)]
    pub enum ProtectedAllocError {
        /// This platform does not support secure memory allocation.
        Unsupported,
    }

    impl std::fmt::Display for ProtectedAllocError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "secure memory allocation is not supported on this platform"
            )
        }
    }

    impl std::error::Error for ProtectedAllocError {}

    /// Stub allocator that always fails on non-Unix platforms.
    pub struct ProtectedAlloc {
        _private: (),
    }

    impl ProtectedAlloc {
        /// Always returns `Err(Unsupported)` on non-Unix platforms.
        pub fn new(_len: usize) -> Result<Self, ProtectedAllocError> {
            Err(ProtectedAllocError::Unsupported)
        }

        /// Always returns `Err(Unsupported)` on non-Unix platforms.
        pub fn from_slice(_data: &[u8]) -> Result<Self, ProtectedAllocError> {
            Err(ProtectedAllocError::Unsupported)
        }

        /// Stub — unreachable on non-Unix.
        pub fn as_bytes(&self) -> &[u8] {
            unreachable!()
        }

        /// Stub — unreachable on non-Unix.
        pub fn as_bytes_mut(&mut self) -> &mut [u8] {
            unreachable!()
        }

        /// Stub — unreachable on non-Unix.
        pub fn len(&self) -> usize {
            unreachable!()
        }

        /// Stub — unreachable on non-Unix.
        pub fn is_empty(&self) -> bool {
            unreachable!()
        }
    }

    impl std::fmt::Debug for ProtectedAlloc {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ProtectedAlloc").finish_non_exhaustive()
        }
    }
}

#[cfg(not(unix))]
pub use stub::ProtectedAlloc;
#[cfg(not(unix))]
pub use stub::ProtectedAllocError;

/// Re-export for downstream convenience.
pub use zeroize::Zeroize;
