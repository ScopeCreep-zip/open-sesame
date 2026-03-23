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

/// Initialize the secure memory subsystem.
///
/// **Must be called before seccomp/sandbox is applied.** This probes for
/// `memfd_secret(2)` support (Linux 5.14+) via a raw syscall. If seccomp
/// is already active and doesn't allow syscall 447, the probe would kill
/// the calling thread. Calling `init()` early caches the probe result so
/// all subsequent allocations skip the probe.
///
/// Also initializes the process-wide canary and page size cache.
///
/// Safe to call multiple times — all initializations are idempotent via
/// `OnceLock`.
pub fn init() {
    #[cfg(unix)]
    {
        // Query RLIMIT_MEMLOCK for diagnostic logging.
        // SAFETY: getrlimit with RLIMIT_MEMLOCK is always safe. rlim is
        // a stack-allocated struct zeroed before the call.
        let memlock_limit = unsafe {
            let mut rlim: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim);
            rlim.rlim_cur
        };

        // Force canary, page size, and memfd_secret probe initialization.
        // The probe allocation exercises all code paths. The memfd_secret
        // probe result is logged from within try_memfd_secret_mmap().
        match ProtectedAlloc::new(1) {
            Ok(probe) => {
                let backend = if probe.is_secret_mem() {
                    "memfd_secret (pages removed from kernel direct map)"
                } else {
                    "mmap(MAP_ANONYMOUS) with mlock"
                };
                tracing::info!(
                    audit = "memory-protection",
                    event_type = "secure-memory-ready",
                    backend,
                    rlimit_memlock_bytes = memlock_limit,
                    "secure memory subsystem ready"
                );
            }
            Err(e) => {
                tracing::error!(
                    audit = "memory-protection",
                    event_type = "secure-memory-init-failed",
                    error = %e,
                    rlimit_memlock_bytes = memlock_limit,
                    "secure memory initialization failed — all secret-carrying \
                     types will panic on allocation. Check RLIMIT_MEMLOCK, \
                     CAP_IPC_LOCK, and available address space."
                );
            }
        }
    }
}

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
