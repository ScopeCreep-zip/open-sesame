//! Page-aligned secure memory allocator for Open Sesame.
//!
//! Provides [`ProtectedAlloc`] — a page-aligned memory region backed by
//! `memfd_secret(2)` (Linux 5.14+, `CONFIG_SECRETMEM=y`) with:
//!
//! - **Secret memory**: pages removed from the kernel direct map, invisible
//!   to `/proc/pid/mem`, kernel modules, DMA attacks, and `ptrace` as root
//! - **Guard pages**: `PROT_NONE` pages before and after the data region —
//!   buffer overflows and underflows trigger `SIGSEGV` immediately
//! - **Canary values**: 16-byte random canary before user data, verified in
//!   constant time on drop — corruption aborts the process
//! - **Zeroize-on-drop**: volatile-write zeros to the entire data region
//!   before `munmap`, preventing data remanence
//!
//! On systems without `memfd_secret` (older kernels, missing `CONFIG_SECRETMEM`),
//! falls back to `mmap(MAP_ANONYMOUS)` with `mlock` + `MADV_DONTDUMP`. This
//! fallback is a **security degradation** — pages remain on the kernel direct
//! map and are readable via `/proc/pid/mem`. An `ERROR`-level audit log is
//! emitted on every daemon startup when operating in fallback mode.
//!
//! # Memory layout
//!
//! ```text
//! [guard page 0] [metadata page] [guard page 1] [data pages...] [guard page 2]
//!  PROT_NONE      PROT_READ       PROT_NONE      PROT_READ|WRITE  PROT_NONE
//! ```
//!
//! User data is right-aligned within the data pages so that buffer overflows
//! hit the trailing guard page.
//!
//! # Platform support
//!
//! - **Linux 5.14+** with `CONFIG_SECRETMEM=y`: full protection (memfd_secret)
//! - **Linux < 5.14** or without `CONFIG_SECRETMEM`: degraded (mmap fallback, audit-logged)
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
/// **Must be called before seccomp/sandbox is applied.** Probes for
/// `memfd_secret(2)` via raw syscall 447. If seccomp is already active,
/// the probe would be killed. Calling `init()` pre-sandbox caches the
/// result for all subsequent allocations.
///
/// Logs the security posture at `INFO` (memfd_secret available) or
/// `ERROR` (fallback mode with degraded protection).
///
/// Safe to call multiple times — all initializations are idempotent.
pub fn init() {
    #[cfg(unix)]
    {
        // SAFETY: getrlimit with RLIMIT_MEMLOCK is always safe.
        let memlock_limit = unsafe {
            let mut rlim: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim);
            rlim.rlim_cur
        };

        match ProtectedAlloc::new(1) {
            Ok(probe) => {
                if probe.is_secret_mem() {
                    tracing::info!(
                        audit = "memory-protection",
                        event_type = "secure-memory-ready",
                        backend = "memfd_secret",
                        rlimit_memlock_bytes = memlock_limit,
                        "secure memory: memfd_secret active — secret pages removed from \
                         kernel direct map, invisible to /proc/pid/mem and ptrace"
                    );
                } else {
                    tracing::error!(
                        audit = "memory-protection",
                        event_type = "secure-memory-degraded",
                        backend = "mmap(MAP_ANONYMOUS) fallback",
                        rlimit_memlock_bytes = memlock_limit,
                        "SECURITY DEGRADED: memfd_secret unavailable — using mmap fallback. \
                         Secret pages remain on the kernel direct map and are readable via \
                         /proc/pid/mem by any same-UID process. This does NOT meet the \
                         security requirements for IL5/IL6, STIG, or PCI-DSS deployments. \
                         Required: Linux >= 5.14 with CONFIG_SECRETMEM=y. \
                         Check: zgrep CONFIG_SECRETMEM /proc/config.gz"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    audit = "memory-protection",
                    event_type = "secure-memory-init-failed",
                    error = %e,
                    rlimit_memlock_bytes = memlock_limit,
                    "secure memory initialization FAILED — all secret-carrying types \
                     will panic on allocation. The daemon cannot safely handle secrets. \
                     Check: RLIMIT_MEMLOCK (ulimit -l), CAP_IPC_LOCK, address space."
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

        /// Always returns `Err(Unsupported)` on non-Unix platforms.
        pub fn from_slice_or_sentinel(_data: &[u8]) -> Result<Self, ProtectedAllocError> {
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

        /// Stub — unreachable on non-Unix.
        pub fn is_secret_mem(&self) -> bool {
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
