//! Page-aligned secure memory allocator backed by `memfd_secret(2)`.
//!
//! Requires Linux 5.14+ with `CONFIG_SECRETMEM=y`. Secret pages are removed
//! from the kernel direct map, making them invisible to `/proc/pid/mem`,
//! kernel modules, DMA attacks, and `ptrace` — even as root.
//!
//! On kernels without `memfd_secret` support, falls back to
//! `mmap(MAP_ANONYMOUS|MAP_PRIVATE)` with a security degradation warning
//! logged at ERROR level. The fallback allocation lacks direct-map removal
//! and is vulnerable to `/proc/pid/mem` reads by same-UID processes.
//!
//! See crate-level documentation for the full memory layout specification.

use std::fmt;
use std::ptr::NonNull;
use std::sync::OnceLock;

use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 16-byte canary placed immediately before user data.
const CANARY_SIZE: usize = 16;

/// Fill byte for padding between data region start and canary.
/// Matches libsodium's garbage fill value.
const PADDING_FILL: u8 = 0xDB;

/// Overhead pages: guard0 + metadata + guard1 + guard2 = 4.
const OVERHEAD_PAGES: usize = 4;

// ---------------------------------------------------------------------------
// Process-global state
// ---------------------------------------------------------------------------

/// Process-wide canary value, initialized once from OS randomness.
static CANARY: OnceLock<[u8; CANARY_SIZE]> = OnceLock::new();

/// Cached system page size.
static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

/// Whether `memfd_secret` is available. Probed once, cached for process lifetime.
static MEMFD_SECRET_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Initialize or retrieve the process-wide canary.
fn global_canary() -> &'static [u8; CANARY_SIZE] {
    CANARY.get_or_init(|| {
        let mut buf = [0u8; CANARY_SIZE];

        #[cfg(target_os = "linux")]
        {
            // SAFETY: buf is a valid mutable buffer of CANARY_SIZE bytes.
            // flags=0 means block until entropy pool is initialized.
            let ret = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), CANARY_SIZE, 0) };
            assert!(
                ret == CANARY_SIZE as isize,
                "getrandom failed for canary: returned {ret}, errno {}",
                errno()
            );
        }

        #[cfg(target_os = "macos")]
        {
            // SAFETY: buf is a valid mutable buffer, CANARY_SIZE <= 256.
            let ret = unsafe { libc::getentropy(buf.as_mut_ptr().cast(), CANARY_SIZE) };
            assert!(ret == 0, "getentropy failed for canary: errno {}", errno());
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            use std::io::Read;
            let mut f = std::fs::File::open("/dev/urandom")
                .expect("failed to open /dev/urandom for canary initialization");
            f.read_exact(&mut buf)
                .expect("failed to read /dev/urandom for canary initialization");
        }

        buf
    })
}

/// Return the system page size.
fn page_size() -> usize {
    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: sysconf(_SC_PAGESIZE) is always safe.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(ps > 0, "sysconf(_SC_PAGESIZE) returned {ps}");
        ps as usize
    })
}

/// Round `n` up to the next multiple of `align`. `align` must be a power of 2.
#[inline]
const fn round_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Read the current thread-local errno.
#[inline]
fn errno() -> i32 {
    #[cfg(target_os = "linux")]
    // SAFETY: __errno_location returns a valid pointer to thread-local errno.
    unsafe {
        *libc::__errno_location()
    }

    #[cfg(target_os = "macos")]
    // SAFETY: __error returns a valid pointer to thread-local errno.
    unsafe {
        *libc::__error()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

/// Probe whether `memfd_secret` is available and cache the result.
///
/// Must be called before seccomp sandbox is applied (syscall 447 would be
/// blocked post-sandbox). Returns true if memfd_secret is usable.
fn probe_memfd_secret() -> bool {
    *MEMFD_SECRET_AVAILABLE.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            const SYS_MEMFD_SECRET: libc::c_long = 447;

            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                tracing::error!(
                    audit = "memory-protection",
                    event_type = "memfd-secret-probe",
                    available = false,
                    "memfd_secret not supported on this CPU architecture"
                );
                return false;
            }

            // SAFETY: syscall(SYS_MEMFD_SECRET, 0) either returns an fd or -1.
            let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0) } as libc::c_int;
            if fd < 0 {
                let e = errno();
                tracing::error!(
                    audit = "memory-protection",
                    event_type = "memfd-secret-probe",
                    available = false,
                    errno = e,
                    "SECURITY DEGRADED: memfd_secret unavailable (errno {e}). \
                     Secret memory pages are NOT removed from the kernel direct map. \
                     This means secret material is readable via /proc/pid/mem by any \
                     same-UID process, and may be visible to kernel modules and DMA. \
                     Required: Linux kernel >= 5.14 with CONFIG_SECRETMEM=y. \
                     Check: zgrep CONFIG_SECRETMEM /proc/config.gz || \
                     grep CONFIG_SECRETMEM /boot/config-$(uname -r). \
                     This is a security bypass — all secret-carrying types operate \
                     with reduced protection until this is resolved."
                );
                return false;
            }
            // SAFETY: fd is a valid open file descriptor.
            unsafe { libc::close(fd) };
            tracing::info!(
                audit = "memory-protection",
                event_type = "memfd-secret-probe",
                available = true,
                "memfd_secret available — secret pages removed from kernel direct map"
            );
            true
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::error!(
                audit = "memory-protection",
                event_type = "memfd-secret-probe",
                available = false,
                "SECURITY DEGRADED: memfd_secret is Linux-only. \
                 Secret memory on this platform uses mmap(MAP_ANONYMOUS) with \
                 mlock — pages are NOT removed from the kernel direct map."
            );
            false
        }
    })
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from secure memory allocation.
#[derive(Debug)]
pub enum ProtectedAllocError {
    /// Requested size was zero.
    ZeroSize,
    /// `memfd_secret` or `mmap` failed. Contains errno.
    MmapFailed(i32),
    /// `mprotect(2)` failed during setup. Contains errno and which call.
    MprotectFailed(i32, &'static str),
    /// Platform does not support secure allocation.
    Unsupported,
}

impl fmt::Display for ProtectedAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSize => write!(f, "cannot allocate zero bytes"),
            Self::MmapFailed(e) => write!(f, "mmap/memfd_secret failed: errno {e}"),
            Self::MprotectFailed(e, which) => {
                write!(f, "mprotect failed ({which}): errno {e}")
            }
            Self::Unsupported => write!(f, "secure memory not supported on this platform"),
        }
    }
}

impl std::error::Error for ProtectedAllocError {}

// ---------------------------------------------------------------------------
// ProtectedAlloc
// ---------------------------------------------------------------------------

/// A page-aligned, guard-page-protected memory region for secrets.
///
/// Backed by `memfd_secret(2)` when available (Linux 5.14+), which removes
/// pages from the kernel direct map. Falls back to `mmap(MAP_ANONYMOUS)` with
/// a security degradation warning on older kernels.
///
/// # Drop behavior
///
/// 1. Canary is verified in constant time (process aborts on corruption).
/// 2. Entire data region is volatile-zeroed.
/// 3. `munmap(2)` releases all pages back to the kernel.
pub struct ProtectedAlloc {
    /// Start of the mmap'd region (guard page 0).
    mmap_base: NonNull<u8>,
    /// Total mmap size in bytes.
    mmap_total: usize,
    /// Start of user data within the data region (right-aligned).
    user_data: NonNull<u8>,
    /// Length of user data in bytes.
    user_data_len: usize,
    /// Start of the data region (page-aligned, after guard page 1).
    data_region: NonNull<u8>,
    /// Size of the data region in bytes (data_pages * page_size).
    data_region_len: usize,
    /// Pointer to the canary (immediately before user_data).
    canary_ptr: NonNull<u8>,
    /// Whether this allocation is backed by memfd_secret (true) or
    /// mmap(MAP_ANONYMOUS) fallback (false). Affects Drop behavior.
    is_secret_mem: bool,
}

// SAFETY: The mmap'd region is process-local. MAP_SHARED for memfd_secret
// has the fd closed immediately — the mapping is not shared with other
// processes. All pointers are stable (no realloc, no partial munmap).
unsafe impl Send for ProtectedAlloc {}

// SAFETY: &ProtectedAlloc only provides &[u8] (immutable). &mut requires
// exclusive access via the borrow checker. No UnsafeCell.
unsafe impl Sync for ProtectedAlloc {}

impl ProtectedAlloc {
    /// Allocate a new protected memory region for `len` bytes of secret data.
    ///
    /// Prefers `memfd_secret(2)` for direct-map removal. Falls back to
    /// `mmap(MAP_ANONYMOUS)` with mlock if `memfd_secret` is unavailable,
    /// logging a security degradation warning.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAllocError`] if:
    /// - `len` is 0
    /// - Both `memfd_secret` and `mmap` fail
    /// - `mprotect` fails on guard or metadata pages
    pub fn new(len: usize) -> Result<Self, ProtectedAllocError> {
        if len == 0 {
            return Err(ProtectedAllocError::ZeroSize);
        }

        let page = page_size();
        let canary = global_canary();

        let data_bytes_needed = CANARY_SIZE
            .checked_add(len)
            .expect("allocation size overflow");
        let data_pages = round_up(data_bytes_needed, page) / page;
        let data_region_len = data_pages
            .checked_mul(page)
            .expect("data region size overflow");

        let total_pages = OVERHEAD_PAGES
            .checked_add(data_pages)
            .expect("page count overflow");
        let mmap_total = total_pages.checked_mul(page).expect("mmap size overflow");

        // Allocate: memfd_secret preferred, mmap(MAP_ANONYMOUS) fallback.
        let is_secret_mem = probe_memfd_secret();
        let mmap_base = if is_secret_mem {
            Self::memfd_secret_mmap(mmap_total)?
        } else {
            Self::anonymous_mmap(mmap_total)?
        };

        let base = mmap_base.cast::<u8>();

        let result = Self::init_region(
            base,
            mmap_total,
            page,
            len,
            data_pages,
            data_region_len,
            canary,
            is_secret_mem,
        );

        if result.is_err() {
            // SAFETY: mmap_base/mmap_total are from a successful mmap.
            unsafe {
                libc::munmap(mmap_base, mmap_total);
            }
        }

        result
    }

    /// Allocate via `memfd_secret(2)`.
    #[cfg(target_os = "linux")]
    fn memfd_secret_mmap(size: usize) -> Result<*mut libc::c_void, ProtectedAllocError> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        const SYS_MEMFD_SECRET: libc::c_long = 447;

        // SAFETY: SYS_MEMFD_SECRET with flags=0 is safe.
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0) } as libc::c_int;
        if fd < 0 {
            return Err(ProtectedAllocError::MmapFailed(errno()));
        }

        // SAFETY: fd is a valid memfd_secret file descriptor.
        let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if ret != 0 {
            let e = errno();
            // SAFETY: fd is a valid open file descriptor.
            unsafe { libc::close(fd) };
            return Err(ProtectedAllocError::MmapFailed(e));
        }

        // SAFETY: fd is valid, size > 0, MAP_SHARED required for memfd_secret.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        // SAFETY: fd is a valid open file descriptor.
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return Err(ProtectedAllocError::MmapFailed(errno()));
        }

        Ok(ptr)
    }

    #[cfg(not(target_os = "linux"))]
    fn memfd_secret_mmap(_size: usize) -> Result<*mut libc::c_void, ProtectedAllocError> {
        Err(ProtectedAllocError::Unsupported)
    }

    /// Fallback: allocate via `mmap(MAP_ANONYMOUS|MAP_PRIVATE)` with mlock.
    fn anonymous_mmap(size: usize) -> Result<*mut libc::c_void, ProtectedAllocError> {
        // SAFETY: Requesting anonymous private memory.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(ProtectedAllocError::MmapFailed(errno()));
        }

        Ok(ptr)
    }

    /// Initialize the mmap'd region.
    #[allow(clippy::too_many_arguments)]
    fn init_region(
        base: *mut u8,
        mmap_total: usize,
        page: usize,
        user_len: usize,
        data_pages: usize,
        data_region_len: usize,
        canary: &[u8; CANARY_SIZE],
        is_secret_mem: bool,
    ) -> Result<Self, ProtectedAllocError> {
        let guard0 = base;
        // SAFETY: All pointer arithmetic within the mmap'd region.
        let metadata = unsafe { base.add(page) };
        // SAFETY: Within region.
        let guard1 = unsafe { base.add(2 * page) };
        // SAFETY: Within region.
        let data_start = unsafe { base.add(3 * page) };
        // SAFETY: Last page boundary.
        let guard2 = unsafe { base.add(3 * page + data_region_len) };

        // --- Guard pages ---
        // SAFETY: guard0 is page-aligned (mmap base), 1 page, within region.
        if unsafe { libc::mprotect(guard0.cast(), page, libc::PROT_NONE) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "guard0"));
        }
        // SAFETY: guard1 = base + 2*PAGE, page-aligned, within region.
        if unsafe { libc::mprotect(guard1.cast(), page, libc::PROT_NONE) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "guard1"));
        }
        // SAFETY: guard2 = base + 3*PAGE + data_region_len, page-aligned, last page.
        if unsafe { libc::mprotect(guard2.cast(), page, libc::PROT_NONE) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "guard2"));
        }

        // --- Metadata page ---
        // SAFETY: metadata is within the region, currently writable.
        unsafe {
            let mp = metadata;
            (mp as *mut u64).write(mmap_total as u64);
            (mp.add(8) as *mut u64).write((3 * page) as u64);
            let user_data_offset = 3 * page + data_region_len - user_len;
            (mp.add(16) as *mut u64).write(user_data_offset as u64);
            (mp.add(24) as *mut u64).write(user_len as u64);
            (mp.add(32) as *mut u64).write(data_pages as u64);
            std::ptr::copy_nonoverlapping(canary.as_ptr(), mp.add(40), CANARY_SIZE);
        }
        // SAFETY: metadata is page-aligned.
        if unsafe { libc::mprotect(metadata.cast(), page, libc::PROT_READ) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "metadata_ro"));
        }

        // --- Data region: canary, padding, user data ---
        // SAFETY: Pointer arithmetic within data region.
        let user_data_ptr = unsafe { data_start.add(data_region_len - user_len) };
        // SAFETY: user_data_ptr - CANARY_SIZE >= data_start.
        let canary_ptr = unsafe { user_data_ptr.sub(CANARY_SIZE) };

        debug_assert!(canary_ptr >= data_start, "canary underflows data region");

        // SAFETY: canary_ptr within writable data region.
        unsafe {
            std::ptr::copy_nonoverlapping(canary.as_ptr(), canary_ptr, CANARY_SIZE);
        }

        let padding_len = canary_ptr as usize - data_start as usize;
        if padding_len > 0 {
            // SAFETY: data_start..canary_ptr within writable data region.
            unsafe {
                std::ptr::write_bytes(data_start, PADDING_FILL, padding_len);
            }
        }

        // --- Memory locking ---
        // memfd_secret pages are implicitly locked by the kernel.
        // Fallback mmap(MAP_ANONYMOUS) pages need explicit mlock + madvise.
        if !is_secret_mem {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: data_start page-aligned, data_region_len page-multiple.
                let ret = unsafe {
                    libc::madvise(data_start.cast(), data_region_len, libc::MADV_DONTDUMP)
                };
                if ret != 0 {
                    tracing::debug!(
                        audit = "memory-protection",
                        event_type = "madvise-dontdump-failed",
                        errno = errno(),
                        "madvise(MADV_DONTDUMP) failed on fallback allocation"
                    );
                }
            }

            // SAFETY: data_start page-aligned, data_region_len page-multiple.
            let ret = unsafe { libc::mlock(data_start.cast(), data_region_len) };
            if ret != 0 {
                let e = errno();
                if e == libc::ENOMEM {
                    tracing::warn!(
                        audit = "memory-protection",
                        event_type = "mlock-enomem",
                        errno = e,
                        data_region_bytes = data_region_len,
                        "SECURITY DEGRADED: mlock failed on fallback allocation \
                         (RLIMIT_MEMLOCK exceeded). Secret pages may be swapped to disk. \
                         This system is already operating without memfd_secret — swap \
                         exposure compounds the direct-map exposure. Remediation: \
                         (1) Upgrade to kernel >= 5.14 with CONFIG_SECRETMEM=y, \
                         (2) Set LimitMEMLOCK=67108864 in the systemd unit, \
                         (3) Disable swap entirely (swapoff -a)."
                    );
                } else {
                    tracing::error!(
                        audit = "memory-protection",
                        event_type = "mlock-fatal",
                        errno = e,
                        "mlock failed with non-ENOMEM error on fallback allocation"
                    );
                    return Err(ProtectedAllocError::MmapFailed(e));
                }
            }
        }

        tracing::trace!(
            audit = "memory-protection",
            event_type = "alloc-created",
            user_data_len = user_len,
            data_region_len,
            mmap_total,
            is_secret_mem,
            "secure allocation created"
        );

        Ok(ProtectedAlloc {
            mmap_base: NonNull::new(base).expect("mmap returned null"),
            mmap_total,
            user_data: NonNull::new(user_data_ptr).expect("user_data_ptr null"),
            user_data_len: user_len,
            data_region: NonNull::new(data_start).expect("data_start null"),
            data_region_len,
            canary_ptr: NonNull::new(canary_ptr).expect("canary_ptr null"),
            is_secret_mem,
        })
    }

    /// Create a `ProtectedAlloc` and copy `data` into it.
    pub fn from_slice(data: &[u8]) -> Result<Self, ProtectedAllocError> {
        if data.is_empty() {
            return Err(ProtectedAllocError::ZeroSize);
        }
        let alloc = Self::new(data.len())?;
        // SAFETY: user_data points to user_data_len writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                alloc.user_data.as_ptr(),
                alloc.user_data_len,
            );
        }
        Ok(alloc)
    }

    /// Create from a byte slice that may be empty (1-byte sentinel for empty).
    pub fn from_slice_or_sentinel(data: &[u8]) -> Result<Self, ProtectedAllocError> {
        if data.is_empty() {
            tracing::trace!(
                audit = "memory-protection",
                event_type = "sentinel-alloc",
                "empty data — allocating 1-byte sentinel (denial/error path)"
            );
            Self::from_slice(&[0u8])
        } else {
            Self::from_slice(data)
        }
    }

    /// Returns a shared reference to the user data.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: user_data points to user_data_len bytes within the mmap'd region.
        unsafe { std::slice::from_raw_parts(self.user_data.as_ptr(), self.user_data_len) }
    }

    /// Returns a mutable reference to the user data.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: user_data valid, &mut self ensures exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.user_data.as_ptr(), self.user_data_len) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.user_data_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.user_data_len == 0
    }

    #[inline]
    pub(crate) fn is_secret_mem(&self) -> bool {
        self.is_secret_mem
    }

    /// Constant-time byte comparison for fixed-length inputs.
    ///
    /// The length check at the top is NOT constant-time — it leaks whether
    /// the lengths match. This is acceptable because this function is only
    /// called to verify the canary, which is always exactly `CANARY_SIZE`
    /// bytes on both sides. For variable-length secret comparison, use a
    /// proper constant-time comparison library.
    fn fixed_len_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            acc |= x ^ y;
        }
        // SAFETY: acc is a stack variable.
        let result = unsafe { std::ptr::read_volatile(&acc) };
        result == 0
    }

    /// Volatile-zero a byte range via zeroize.
    fn volatile_zero(ptr: *mut u8, len: usize) {
        // SAFETY: ptr..ptr+len is a valid writable region.
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        slice.zeroize();
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for ProtectedAlloc {
    fn drop(&mut self) {
        let page = page_size();

        // 1. Verify canary.
        // SAFETY: canary_ptr points to CANARY_SIZE bytes within the data region.
        let canary_actual =
            unsafe { std::slice::from_raw_parts(self.canary_ptr.as_ptr(), CANARY_SIZE) };
        let canary_expected = global_canary();

        if !Self::fixed_len_constant_time_eq(canary_actual, canary_expected) {
            tracing::error!(
                audit = "memory-protection",
                event_type = "canary-corruption",
                user_data_len = self.user_data_len,
                data_region_len = self.data_region_len,
                is_secret_mem = self.is_secret_mem,
                "FATAL: canary corruption detected. Buffer underflow, heap corruption, \
                 or use-after-free in secret-handling code. Process will abort."
            );
            std::process::abort();
        }

        // 2. Volatile-zero entire data region.
        Self::volatile_zero(self.data_region.as_ptr(), self.data_region_len);

        // 3. Cleanup for fallback (non-memfd_secret) allocations.
        if !self.is_secret_mem {
            // SAFETY: same pointer/size as the mlock call in init_region.
            unsafe {
                libc::munlock(self.data_region.as_ptr().cast(), self.data_region_len);
            }

            // Re-enable core dump inclusion (Linux, mmap fallback only).
            // memfd_secret pages were never marked DONTDUMP and are not in
            // the direct map — DODUMP is meaningless for them.
            #[cfg(target_os = "linux")]
            if !self.is_secret_mem {
                // SAFETY: data_region pointer/size are valid.
                unsafe {
                    libc::madvise(
                        self.data_region.as_ptr().cast(),
                        self.data_region_len,
                        libc::MADV_DODUMP,
                    );
                }
            }
        }

        // 4. Zero metadata page.
        // SAFETY: mmap_base + page is the metadata page.
        let metadata_ptr = unsafe { self.mmap_base.as_ptr().add(page) };
        // SAFETY: metadata_ptr is page-aligned.
        unsafe {
            libc::mprotect(
                metadata_ptr.cast(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
            );
        }
        Self::volatile_zero(metadata_ptr, page);

        // 5. Release all pages.
        // SAFETY: mmap_base and mmap_total are the exact values from mmap.
        unsafe {
            let ret = libc::munmap(self.mmap_base.as_ptr().cast(), self.mmap_total);
            if ret != 0 {
                tracing::error!(
                    audit = "memory-protection",
                    event_type = "munmap-failed",
                    errno = errno(),
                    mmap_total = self.mmap_total,
                    "munmap failed in Drop — possible double-free or corrupted VMA state"
                );
            }
        }

        tracing::trace!(
            audit = "memory-protection",
            event_type = "alloc-dropped",
            user_data_len = self.user_data_len,
            data_region_len = self.data_region_len,
            is_secret_mem = self.is_secret_mem,
            "secure allocation zeroed and released"
        );
    }
}

impl Zeroize for ProtectedAlloc {
    fn zeroize(&mut self) {
        Self::volatile_zero(self.user_data.as_ptr(), self.user_data_len);
    }
}

impl fmt::Debug for ProtectedAlloc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedAlloc")
            .field("len", &self.user_data_len)
            .field("data_region_len", &self.data_region_len)
            .field("mmap_total", &self.mmap_total)
            .field("is_secret_mem", &self.is_secret_mem)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_read_back() {
        let data = b"hello secure world";
        let alloc = ProtectedAlloc::from_slice(data).expect("allocation failed");
        assert_eq!(alloc.as_bytes(), data);
        assert_eq!(alloc.len(), data.len());
        assert!(!alloc.is_empty());
    }

    #[test]
    fn alloc_32_byte_key() {
        let key = [0x42u8; 32];
        let alloc = ProtectedAlloc::from_slice(&key).expect("allocation failed");
        assert_eq!(alloc.as_bytes(), &key);
    }

    #[test]
    fn alloc_single_byte() {
        let alloc = ProtectedAlloc::from_slice(&[0xFF]).expect("allocation failed");
        assert_eq!(alloc.as_bytes(), &[0xFF]);
        assert_eq!(alloc.len(), 1);
    }

    #[test]
    fn alloc_exactly_one_page() {
        let page = page_size();
        let data = vec![0xAB; page];
        let alloc = ProtectedAlloc::from_slice(&data).expect("allocation failed");
        assert_eq!(alloc.as_bytes(), &data[..]);
    }

    #[test]
    fn alloc_larger_than_one_page() {
        let page = page_size();
        let data = vec![0xCD; page + 1];
        let alloc = ProtectedAlloc::from_slice(&data).expect("allocation failed");
        assert_eq!(alloc.as_bytes(), &data[..]);
    }

    #[test]
    fn alloc_canary_plus_data_spans_page_boundary() {
        let page = page_size();
        let user_len = page - CANARY_SIZE;
        let data = vec![0xEF; user_len];
        let alloc = ProtectedAlloc::from_slice(&data).expect("allocation failed");
        assert_eq!(alloc.as_bytes(), &data[..]);
    }

    #[test]
    fn zero_size_returns_error() {
        let result = ProtectedAlloc::new(0);
        assert!(matches!(result, Err(ProtectedAllocError::ZeroSize)));
    }

    #[test]
    fn empty_slice_returns_error() {
        let result = ProtectedAlloc::from_slice(&[]);
        assert!(matches!(result, Err(ProtectedAllocError::ZeroSize)));
    }

    #[test]
    fn mutate_and_read_back() {
        let mut alloc = ProtectedAlloc::new(4).expect("allocation failed");
        alloc.as_bytes_mut().copy_from_slice(b"test");
        assert_eq!(alloc.as_bytes(), b"test");
    }

    #[test]
    fn debug_does_not_leak_contents() {
        let alloc = ProtectedAlloc::from_slice(b"top secret").expect("allocation failed");
        let debug_str = format!("{alloc:?}");
        assert!(!debug_str.contains("top secret"));
        assert!(!debug_str.contains("top"));
        assert!(debug_str.contains("ProtectedAlloc"));
        assert!(debug_str.contains("len: 10"));
    }

    #[test]
    fn drop_does_not_panic() {
        let alloc = ProtectedAlloc::from_slice(b"temporary secret").expect("allocation failed");
        drop(alloc);
    }

    #[test]
    fn multiple_allocs_independent() {
        let a = ProtectedAlloc::from_slice(b"alpha").expect("alloc a failed");
        let b = ProtectedAlloc::from_slice(b"bravo").expect("alloc b failed");
        assert_eq!(a.as_bytes(), b"alpha");
        assert_eq!(b.as_bytes(), b"bravo");
    }

    #[test]
    fn zeroize_clears_user_data() {
        let mut alloc = ProtectedAlloc::from_slice(b"secret").expect("allocation failed");
        alloc.zeroize();
        assert_eq!(alloc.as_bytes(), &[0u8; 6]);
    }

    #[test]
    fn alloc_large_secret() {
        let data = vec![0xFF; 65536];
        match ProtectedAlloc::from_slice(&data) {
            Ok(alloc) => assert_eq!(alloc.len(), 65536),
            Err(e) => {
                eprintln!("Skipping large alloc test: {e}");
            }
        }
    }

    #[test]
    fn page_size_is_power_of_two() {
        let ps = page_size();
        assert!(ps > 0);
        assert!(ps.is_power_of_two());
    }

    #[test]
    fn round_up_works() {
        assert_eq!(round_up(1, 4096), 4096);
        assert_eq!(round_up(4096, 4096), 4096);
        assert_eq!(round_up(4097, 4096), 8192);
        assert_eq!(round_up(0, 4096), 0);
        assert_eq!(round_up(16384, 16384), 16384);
        assert_eq!(round_up(16385, 16384), 32768);
    }

    #[test]
    fn fixed_len_constant_time_eq_works() {
        assert!(ProtectedAlloc::fixed_len_constant_time_eq(
            b"hello", b"hello"
        ));
        assert!(!ProtectedAlloc::fixed_len_constant_time_eq(
            b"hello", b"world"
        ));
        assert!(!ProtectedAlloc::fixed_len_constant_time_eq(
            b"hello", b"hell"
        ));
        assert!(ProtectedAlloc::fixed_len_constant_time_eq(b"", b""));
    }

    #[test]
    fn canary_is_consistent() {
        let c1 = global_canary();
        let c2 = global_canary();
        assert_eq!(c1, c2);
        assert_ne!(c1, &[0u8; CANARY_SIZE]);
    }

    #[test]
    fn send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ProtectedAlloc>();
        assert_sync::<ProtectedAlloc>();
    }

    #[test]
    fn layout_arithmetic() {
        let page = page_size();

        let data_pages = round_up(CANARY_SIZE + 1, page) / page;
        assert_eq!(data_pages, 1);
        assert_eq!((OVERHEAD_PAGES + data_pages) * page, 5 * page);

        let data_pages = round_up(CANARY_SIZE + page - 1, page) / page;
        assert_eq!(data_pages, 2);

        let data_pages = round_up(CANARY_SIZE + page, page) / page;
        assert_eq!(data_pages, 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memfd_secret_probe_is_idempotent() {
        let r1 = probe_memfd_secret();
        let r2 = probe_memfd_secret();
        assert_eq!(r1, r2);
    }

    #[test]
    fn from_slice_or_sentinel_empty() {
        let alloc = ProtectedAlloc::from_slice_or_sentinel(&[]).expect("sentinel failed");
        assert_eq!(alloc.len(), 1);
    }

    #[test]
    fn from_slice_or_sentinel_nonempty() {
        let alloc = ProtectedAlloc::from_slice_or_sentinel(b"data").expect("alloc failed");
        assert_eq!(alloc.as_bytes(), b"data");
    }

    #[test]
    fn is_secret_mem_accessor() {
        let alloc = ProtectedAlloc::from_slice(b"test").expect("alloc failed");
        // On 5.14+ with CONFIG_SECRETMEM=y, this is true.
        // On older kernels, this is false. Either is valid.
        let _ = alloc.is_secret_mem();
    }
}
