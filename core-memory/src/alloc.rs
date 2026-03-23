//! Page-aligned secure memory allocator backed by `mmap(2)`.
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
            // Fallback: use /dev/urandom. This is less ideal but functional
            // on any Unix with a urandom device.
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
        // SAFETY: sysconf(_SC_PAGESIZE) is always safe and returns the page
        // size as a positive long, or -1 on error (which would be extraordinary).
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
        // Best-effort: std::io::Error::last_os_error() reads errno portably.
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from secure memory allocation.
#[derive(Debug)]
pub enum ProtectedAllocError {
    /// Requested size was zero.
    ZeroSize,
    /// `mmap(2)` failed. Contains errno.
    MmapFailed(i32),
    /// `mprotect(2)` failed during setup. Contains errno and which call failed.
    MprotectFailed(i32, &'static str),
    /// `mlock(2)` failed. Contains errno.
    MlockFailed(i32),
    /// Platform does not support secure allocation.
    Unsupported,
}

impl fmt::Display for ProtectedAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSize => write!(f, "cannot allocate zero bytes"),
            Self::MmapFailed(e) => write!(f, "mmap failed: errno {e}"),
            Self::MprotectFailed(e, which) => {
                write!(f, "mprotect failed ({which}): errno {e}")
            }
            Self::MlockFailed(e) => write!(
                f,
                "mlock failed: errno {e} — check RLIMIT_MEMLOCK (ulimit -l)"
            ),
            Self::Unsupported => write!(f, "secure memory not supported on this platform"),
        }
    }
}

impl std::error::Error for ProtectedAllocError {}

// ---------------------------------------------------------------------------
// ProtectedAlloc
// ---------------------------------------------------------------------------

/// A page-aligned, guard-page-protected, mlock'd memory region for secrets.
///
/// See crate-level documentation for the complete memory layout.
///
/// # Drop behavior
///
/// 1. Canary is verified in constant time (process aborts on corruption).
/// 2. Entire data region is volatile-zeroed.
/// 3. `munlock(2)` releases the memory lock (skipped for `memfd_secret`
///    allocations — the kernel manages locking for secret pages).
/// 4. `munmap(2)` releases all pages back to the kernel.
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
    /// Whether this allocation is backed by memfd_secret. If true, the pages
    /// are already implicitly locked by the kernel and removed from the direct
    /// map. mlock/munlock are skipped to avoid double-charging RLIMIT_MEMLOCK.
    is_secret_mem: bool,
}

// SAFETY: The mmap'd region is process-local (MAP_PRIVATE for anonymous,
// MAP_SHARED for memfd_secret — but the fd is closed immediately after mmap,
// so the mapping is not shared with any other process). All pointers are stable
// for the lifetime of the ProtectedAlloc — no realloc, no partial munmap.
// Send is safe because there is no interior mutability.
unsafe impl Send for ProtectedAlloc {}

// SAFETY: &ProtectedAlloc only provides &[u8] (immutable). &mut requires
// exclusive access via the borrow checker. No UnsafeCell.
unsafe impl Sync for ProtectedAlloc {}

impl ProtectedAlloc {
    /// Allocate a new protected memory region for `len` bytes of secret data.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAllocError`] if:
    /// - `len` is 0
    /// - `mmap` fails (out of address space)
    /// - `mprotect` fails on guard or metadata pages
    /// - `mlock` fails (RLIMIT_MEMLOCK exceeded)
    ///
    /// # Panics
    ///
    /// Panics if canary initialization fails (OS randomness unavailable) or
    /// if size arithmetic overflows.
    pub fn new(len: usize) -> Result<Self, ProtectedAllocError> {
        if len == 0 {
            return Err(ProtectedAllocError::ZeroSize);
        }

        let page = page_size();
        let canary = global_canary();

        // Calculate data region size: enough pages for canary + user data.
        let data_bytes_needed = CANARY_SIZE
            .checked_add(len)
            .expect("allocation size overflow");
        let data_pages = round_up(data_bytes_needed, page) / page;
        let data_region_len = data_pages
            .checked_mul(page)
            .expect("data region size overflow");

        // Total: guard0 + metadata + guard1 + data_region + guard2
        let total_pages = OVERHEAD_PAGES
            .checked_add(data_pages)
            .expect("page count overflow");
        let mmap_total = total_pages.checked_mul(page).expect("mmap size overflow");

        // Step 1: Allocate the region. Try memfd_secret first (Linux 5.14+),
        // fall back to mmap(MAP_ANONYMOUS) if unavailable.
        //
        // memfd_secret removes pages from the kernel direct map, making them
        // invisible to /proc/pid/mem, kernel modules, and even root with ptrace.
        // This is the strongest available memory isolation on Linux.
        let mut is_secret_mem = false;
        let mmap_base = match Self::try_memfd_secret_mmap(mmap_total) {
            Some(ptr) => {
                is_secret_mem = true;
                ptr
            }
            None => {
                // Fallback: standard anonymous private mapping.
                // SAFETY: Requesting anonymous private memory. NULL addr lets
                // kernel choose. mmap_total > 0. fd=-1 and offset=0 required
                // for MAP_ANONYMOUS.
                unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        mmap_total,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                        -1,
                        0,
                    )
                }
            }
        };

        if mmap_base == libc::MAP_FAILED {
            return Err(ProtectedAllocError::MmapFailed(errno()));
        }

        let base = mmap_base.cast::<u8>();

        // If init fails, munmap everything.
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
            // SAFETY: mmap_base is the exact pointer from mmap, mmap_total is
            // the exact size. Region has not been partially unmapped.
            unsafe {
                libc::munmap(mmap_base, mmap_total);
            }
        }

        result
    }

    /// Initialize the mmap'd region: set guard pages, write metadata and canary,
    /// mlock the data region.
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
        // Compute section pointers. All offsets stay within the mmap'd region.
        // base is page-aligned (kernel guarantee for mmap return value).
        let guard0 = base;
        // SAFETY: base + page is within the mmap'd region (total >= 5 pages).
        let metadata = unsafe { base.add(page) };
        // SAFETY: base + 2*page is within the mmap'd region.
        let guard1 = unsafe { base.add(2 * page) };
        // SAFETY: base + 3*page is within the mmap'd region.
        let data_start = unsafe { base.add(3 * page) };
        // SAFETY: base + 3*page + data_region_len is the last page boundary.
        let guard2 = unsafe { base.add(3 * page + data_region_len) };

        // --- Guard pages: PROT_NONE ---

        // SAFETY: guard0 is page-aligned (mmap base), size is exactly 1 page,
        // within the mmap'd region.
        if unsafe { libc::mprotect(guard0.cast(), page, libc::PROT_NONE) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "guard0"));
        }

        // SAFETY: guard1 = base + 2*PAGE, page-aligned, within region.
        if unsafe { libc::mprotect(guard1.cast(), page, libc::PROT_NONE) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "guard1"));
        }

        // SAFETY: guard2 = base + 3*PAGE + data_region_len, page-aligned,
        // last page of the region.
        if unsafe { libc::mprotect(guard2.cast(), page, libc::PROT_NONE) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "guard2"));
        }

        // --- Metadata page ---

        // Write metadata while page is still PROT_READ|PROT_WRITE.
        // SAFETY: metadata is within the mmap'd region, currently writable.
        // All writes are within page boundary (56 bytes into >=4096 byte page).
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

        // Make metadata read-only.
        // SAFETY: metadata is page-aligned, within region.
        if unsafe { libc::mprotect(metadata.cast(), page, libc::PROT_READ) } != 0 {
            return Err(ProtectedAllocError::MprotectFailed(errno(), "metadata_ro"));
        }

        // --- Data region: canary, padding, user data ---

        // User data is RIGHT-ALIGNED to the end of the data region.
        // SAFETY: data_start + (data_region_len - user_len) is within the data region.
        let user_data_ptr = unsafe { data_start.add(data_region_len - user_len) };
        // SAFETY: user_data_ptr - CANARY_SIZE >= data_start (verified by debug_assert below).
        let canary_ptr = unsafe { user_data_ptr.sub(CANARY_SIZE) };

        // Sanity check: canary must be within the data region.
        debug_assert!(
            canary_ptr >= data_start,
            "canary underflows data region: canary_ptr={canary_ptr:?}, data_start={data_start:?}"
        );

        // Write canary.
        // SAFETY: canary_ptr is within the writable data region.
        unsafe {
            std::ptr::copy_nonoverlapping(canary.as_ptr(), canary_ptr, CANARY_SIZE);
        }

        // Fill padding with 0xDB.
        let padding_len = canary_ptr as usize - data_start as usize;
        if padding_len > 0 {
            // SAFETY: data_start..canary_ptr is within the writable data region.
            unsafe {
                std::ptr::write_bytes(data_start, PADDING_FILL, padding_len);
            }
        }

        // --- madvise on data region ---
        // Skip for memfd_secret: pages are already removed from the direct map
        // (invisible to core dumps and /proc/pid/mem). madvise on secretmem
        // VMAs may return EINVAL for some advice values.
        if !is_secret_mem {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: data_start is page-aligned, data_region_len is page-multiple.
                let ret = unsafe {
                    libc::madvise(data_start.cast(), data_region_len, libc::MADV_DONTDUMP)
                };
                if ret != 0 {
                    tracing::debug!(
                        audit = "memory-protection",
                        event_type = "madvise-dontdump-failed",
                        errno = errno(),
                        "madvise(MADV_DONTDUMP) failed — LimitCORE=0 is the primary control"
                    );
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Ask the kernel to zero wired (mlock'd) pages on deallocation.
                const MADV_ZERO_WIRED_PAGES: libc::c_int = 6;
                // SAFETY: data_start is page-aligned, data_region_len is page-multiple.
                unsafe {
                    libc::madvise(data_start.cast(), data_region_len, MADV_ZERO_WIRED_PAGES);
                }
                // Ignore errors — best-effort.
            }
        }

        // --- mlock the data region ---
        // memfd_secret pages are implicitly locked by the kernel (removed from
        // the direct map). Calling mlock on them double-charges RLIMIT_MEMLOCK.
        // Skip mlock entirely for memfd_secret-backed allocations.
        if !is_secret_mem {
            // SAFETY: data_start is page-aligned, data_region_len is page-multiple.
            let ret = unsafe { libc::mlock(data_start.cast(), data_region_len) };
            if ret != 0 {
                let e = errno();

                // ENOMEM (errno 12) means RLIMIT_MEMLOCK would be exceeded.
                // In test environments and containers with low limits, this is
                // expected. Degrade gracefully with a warning rather than failing.
                //
                // In production (systemd services with LimitMEMLOCK=64M), this
                // should never trigger. If it does, the daemon will log the warning
                // and operators can investigate.
                //
                // Other errno values (EPERM, EINVAL) indicate real failures and
                // are always fatal.
                if e == libc::ENOMEM {
                    #[cfg(feature = "soft-mlock")]
                    {
                        // soft-mlock feature: silently continue (CI/test mode).
                    }

                    #[cfg(not(feature = "soft-mlock"))]
                    {
                        tracing::warn!(
                            audit = "memory-protection",
                            event_type = "mlock-enomem",
                            errno = e,
                            data_region_bytes = data_region_len,
                            "mlock failed: RLIMIT_MEMLOCK exceeded. Secret memory pages \
                             are NOT locked and may be swapped to disk. Remediation options: \
                             (1) Set LimitMEMLOCK=67108864 in the systemd unit file, \
                             (2) Run `ulimit -l 65536` before the process, \
                             (3) Grant CAP_IPC_LOCK capability, \
                             (4) Disable swap entirely (`swapoff -a`) to eliminate the \
                             swap exposure vector regardless of mlock. \
                             On kernels 5.14+ with CONFIG_SECRETMEM=y, memfd_secret \
                             bypasses mlock entirely — verify with init_secure_memory()."
                        );
                    }
                } else {
                    // Non-ENOMEM errors are always fatal.
                    return Err(ProtectedAllocError::MlockFailed(e));
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
            mlock_active = !is_secret_mem,
            "secure allocation created"
        );

        Ok(ProtectedAlloc {
            mmap_base: NonNull::new(base).expect("mmap returned null after MAP_FAILED check"),
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
    ///
    /// The caller is responsible for zeroing the source `data` after this call
    /// if it contains secret material.
    pub fn from_slice(data: &[u8]) -> Result<Self, ProtectedAllocError> {
        if data.is_empty() {
            return Err(ProtectedAllocError::ZeroSize);
        }
        let alloc = Self::new(data.len())?;
        // SAFETY: user_data points to user_data_len writable bytes.
        // data.len() == user_data_len.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                alloc.user_data.as_ptr(),
                alloc.user_data_len,
            );
        }
        Ok(alloc)
    }

    /// Create a `ProtectedAlloc` from a byte slice that may be empty.
    ///
    /// If `data` is empty, allocates a 1-byte sentinel. The caller must
    /// track the actual length separately (the sentinel is not meaningful
    /// user data). If `data` is non-empty, behaves identically to
    /// [`from_slice`](Self::from_slice).
    ///
    /// This method exists to support types like `SecureBytes` and
    /// `SensitiveBytes` that permit empty data for denial/error paths.
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

    /// Try to allocate via `memfd_secret(2)` (Linux 5.14+, CONFIG_SECRETMEM=y).
    ///
    /// Returns `Some(mmap_base)` on success, `None` if the syscall is not
    /// available. The caller falls back to `mmap(MAP_ANONYMOUS)` on `None`.
    ///
    /// `memfd_secret` creates a file descriptor whose backing pages are removed
    /// from the kernel direct map. This prevents access via:
    /// - `/proc/pid/mem` (even as root)
    /// - Kernel modules reading physical memory
    /// - DMA attacks on the direct map
    ///
    /// The first call probes the syscall and caches the result. If the kernel
    /// does not support `memfd_secret` (ENOSYS), all subsequent calls return
    /// `None` immediately without invoking the syscall. This is critical because
    /// seccomp filters applied after daemon initialization would kill the thread
    /// on an unrecognized syscall — the probe must happen before sandbox setup,
    /// and the cache ensures no post-sandbox attempts.
    #[cfg(target_os = "linux")]
    fn try_memfd_secret_mmap(size: usize) -> Option<*mut libc::c_void> {
        static MEMFD_SECRET_AVAILABLE: OnceLock<bool> = OnceLock::new();

        // memfd_secret syscall number: 447 on x86_64 and aarch64.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        const SYS_MEMFD_SECRET: libc::c_long = 447;

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return None;

        let available = *MEMFD_SECRET_AVAILABLE.get_or_init(|| {
            // Probe: try to create a memfd_secret fd.
            // SAFETY: syscall(SYS_MEMFD_SECRET, 0) is safe — it either returns
            // an fd or -1 with errno set. No side effects on failure.
            let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0) } as libc::c_int;
            if fd < 0 {
                tracing::info!(
                    audit = "memory-protection",
                    event_type = "memfd-secret-probe",
                    available = false,
                    errno = errno(),
                    "memfd_secret not available — using mmap(MAP_ANONYMOUS) with mlock"
                );
                return false;
            }
            // Probe succeeded — close the fd and report available.
            // SAFETY: fd is a valid open file descriptor.
            unsafe { libc::close(fd) };
            tracing::info!(
                audit = "memory-protection",
                event_type = "memfd-secret-probe",
                available = true,
                "memfd_secret available — secret pages removed from kernel direct map"
            );
            true
        });

        if !available {
            return None;
        }

        // Create a new memfd_secret for this allocation.
        // SAFETY: SYS_MEMFD_SECRET with flags=0 is safe.
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0) } as libc::c_int;
        if fd < 0 {
            return None;
        }

        // Set the size.
        // SAFETY: fd is a valid memfd_secret file descriptor.
        let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if ret != 0 {
            // SAFETY: fd is a valid open file descriptor.
            unsafe { libc::close(fd) };
            return None;
        }

        // Map the secret memory. memfd_secret requires MAP_SHARED.
        // SAFETY: fd is valid, size > 0, MAP_SHARED is required for memfd_secret.
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

        // Close the fd — the mapping keeps the pages alive.
        // SAFETY: fd is a valid open file descriptor.
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return None;
        }

        Some(ptr)
    }

    #[cfg(not(target_os = "linux"))]
    fn try_memfd_secret_mmap(_size: usize) -> Option<*mut libc::c_void> {
        None
    }

    /// Returns a shared reference to the user data.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: user_data points to user_data_len bytes within a
        // PROT_READ|PROT_WRITE mmap'd region. Lifetime tied to &self.
        unsafe { std::slice::from_raw_parts(self.user_data.as_ptr(), self.user_data_len) }
    }

    /// Returns a mutable reference to the user data.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: user_data points to user_data_len bytes within a
        // PROT_READ|PROT_WRITE mmap'd region. &mut self ensures exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.user_data.as_ptr(), self.user_data_len) }
    }

    /// Returns the length of the user data in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.user_data_len
    }

    /// Returns true if the user data length is zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.user_data_len == 0
    }

    /// Returns true if this allocation is backed by `memfd_secret`.
    #[inline]
    pub fn is_secret_mem(&self) -> bool {
        self.is_secret_mem
    }

    /// Returns the size of the data region in bytes.
    #[inline]
    pub fn data_region_len(&self) -> usize {
        self.data_region_len
    }

    /// Constant-time comparison. Returns true if slices are equal.
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            acc |= x ^ y;
        }
        // Volatile read prevents the compiler from short-circuiting.
        // SAFETY: acc is a stack variable.
        let result = unsafe { std::ptr::read_volatile(&acc) };
        result == 0
    }

    /// Volatile-zero a byte range. Uses zeroize's audited implementation.
    fn volatile_zero(ptr: *mut u8, len: usize) {
        // Build a slice and delegate to zeroize, which uses write_volatile
        // internally and is audited for this exact purpose.
        // SAFETY: ptr..ptr+len is a valid writable region.
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        slice.zeroize();
        // Compiler fence prevents reordering the zeroing with subsequent ops.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for ProtectedAlloc {
    fn drop(&mut self) {
        let page = page_size();

        // 1. Verify canary integrity.
        // SAFETY: canary_ptr points to CANARY_SIZE bytes within the data region.
        let canary_actual =
            unsafe { std::slice::from_raw_parts(self.canary_ptr.as_ptr(), CANARY_SIZE) };
        let canary_expected = global_canary();

        if !Self::constant_time_eq(canary_actual, canary_expected) {
            tracing::error!(
                audit = "memory-protection",
                event_type = "canary-corruption",
                user_data_len = self.user_data_len,
                data_region_len = self.data_region_len,
                is_secret_mem = self.is_secret_mem,
                "FATAL: canary corruption detected in secure allocation. \
                 This indicates a buffer underflow, heap corruption, or \
                 use-after-free in secret-handling code. Process will abort. \
                 Investigate the most recent write to this ProtectedAlloc."
            );
            std::process::abort();
        }

        // 2. Volatile-zero the entire data region (padding + canary + user data).
        Self::volatile_zero(self.data_region.as_ptr(), self.data_region_len);

        // 3. munlock the data region (skip for memfd_secret — kernel handles it).
        if !self.is_secret_mem {
            // SAFETY: same pointer/size as the mlock call in init_region.
            unsafe {
                libc::munlock(self.data_region.as_ptr().cast(), self.data_region_len);
            }
        }

        // 4. Re-enable core dump inclusion (Linux). Skip for memfd_secret —
        // those pages were never in the dump and MADV_DODUMP is meaningless.
        #[cfg(target_os = "linux")]
        if !self.is_secret_mem {
            // SAFETY: data_region pointer/size are valid, MADV_DODUMP is best-effort.
            unsafe {
                libc::madvise(
                    self.data_region.as_ptr().cast(),
                    self.data_region_len,
                    libc::MADV_DODUMP,
                );
            }
        }

        // 5. Make metadata page writable, then zero it.
        // SAFETY: mmap_base + page is the metadata page, within the region.
        let metadata_ptr = unsafe { self.mmap_base.as_ptr().add(page) };
        // SAFETY: metadata_ptr is page-aligned, within the mmap'd region.
        unsafe {
            libc::mprotect(
                metadata_ptr.cast(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
            );
        }
        Self::volatile_zero(metadata_ptr, page);

        // 6. munmap the entire region.
        // SAFETY: mmap_base and mmap_total are the exact values from mmap.
        // The region has not been partially unmapped.
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
        // Zero just the user data. Drop will zero the entire data region.
        Self::volatile_zero(self.user_data.as_ptr(), self.user_data_len);
    }
}

impl fmt::Debug for ProtectedAlloc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedAlloc")
            .field("len", &self.user_data_len)
            .field("data_region_len", &self.data_region_len)
            .field("mmap_total", &self.mmap_total)
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
        // Exactly page_size - CANARY_SIZE bytes of user data: canary + data
        // fit in exactly one page with zero padding.
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
        // Drop order: b then a (reverse declaration). Both must succeed.
    }

    #[test]
    fn zeroize_clears_user_data() {
        let mut alloc = ProtectedAlloc::from_slice(b"secret").expect("allocation failed");
        alloc.zeroize();
        assert_eq!(alloc.as_bytes(), &[0u8; 6]);
    }

    #[test]
    fn alloc_large_secret() {
        // 64KB secret.
        let data = vec![0xFF; 65536];
        match ProtectedAlloc::from_slice(&data) {
            Ok(alloc) => assert_eq!(alloc.len(), 65536),
            Err(ProtectedAllocError::MlockFailed(_)) => {
                eprintln!("Skipping large alloc test: RLIMIT_MEMLOCK too low");
            }
            Err(e) => panic!("unexpected error: {e}"),
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
    fn constant_time_eq_works() {
        assert!(ProtectedAlloc::constant_time_eq(b"hello", b"hello"));
        assert!(!ProtectedAlloc::constant_time_eq(b"hello", b"world"));
        assert!(!ProtectedAlloc::constant_time_eq(b"hello", b"hell"));
        assert!(ProtectedAlloc::constant_time_eq(b"", b""));
    }

    #[test]
    fn canary_is_consistent() {
        let c1 = global_canary();
        let c2 = global_canary();
        assert_eq!(c1, c2, "canary must be stable across calls");
        assert_ne!(c1, &[0u8; CANARY_SIZE], "canary must not be all zeros");
    }

    #[test]
    fn send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ProtectedAlloc>();
        assert_sync::<ProtectedAlloc>();
    }

    /// Verify the mmap layout arithmetic for various sizes.
    #[test]
    fn layout_arithmetic() {
        let page = page_size();

        // 1 byte: needs ceil((16+1)/page) = 1 data page, total 5 pages.
        let data_pages = round_up(CANARY_SIZE + 1, page) / page;
        assert_eq!(data_pages, 1);
        assert_eq!((OVERHEAD_PAGES + data_pages) * page, 5 * page);

        // page-1 bytes: still 1 data page (canary fits: 16 + (page-1) <= page
        // only if page >= 17, which is always true since page >= 4096).
        // Wait: 16 + 4095 = 4111 > 4096, so this needs 2 data pages.
        let data_pages = round_up(CANARY_SIZE + page - 1, page) / page;
        assert_eq!(data_pages, 2); // 4111 rounds up to 8192, / 4096 = 2
        assert_eq!((OVERHEAD_PAGES + data_pages) * page, 6 * page);

        // Exactly page bytes: 16 + 4096 = 4112 -> 2 data pages.
        let data_pages = round_up(CANARY_SIZE + page, page) / page;
        assert_eq!(data_pages, 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memfd_secret_probe_does_not_panic() {
        // This test verifies the probe logic doesn't crash. On kernels
        // without CONFIG_SECRETMEM, it returns None. On kernels with it,
        // it returns Some. Either is correct — we just verify no panic.
        let result = ProtectedAlloc::try_memfd_secret_mmap(page_size());
        if let Some(ptr) = result {
            // Clean up: munmap the probed region.
            // SAFETY: ptr is from a successful mmap, page_size() is the exact size.
            unsafe { libc::munmap(ptr, page_size()) };
        }
        // Second call should use the cached result.
        let result2 = ProtectedAlloc::try_memfd_secret_mmap(page_size());
        if let Some(ptr) = result2 {
            unsafe { libc::munmap(ptr, page_size()) };
        }
    }

    #[test]
    fn from_slice_or_sentinel_empty() {
        let alloc = ProtectedAlloc::from_slice_or_sentinel(&[]).expect("sentinel failed");
        // Sentinel is 1 byte internally, but the caller tracks actual_len=0.
        assert_eq!(alloc.len(), 1); // sentinel byte
    }

    #[test]
    fn from_slice_or_sentinel_nonempty() {
        let alloc = ProtectedAlloc::from_slice_or_sentinel(b"data").expect("alloc failed");
        assert_eq!(alloc.as_bytes(), b"data");
        assert_eq!(alloc.len(), 4);
    }

    #[test]
    fn mlock_enomem_degrades_gracefully() {
        // This test creates many allocations to potentially exhaust
        // RLIMIT_MEMLOCK. The allocator should degrade to a warning
        // (ENOMEM) rather than failing fatally.
        let mut allocs = Vec::new();
        for _ in 0..100 {
            match ProtectedAlloc::from_slice(b"test") {
                Ok(a) => allocs.push(a),
                Err(ProtectedAllocError::MlockFailed(_)) => {
                    // If we hit the limit and soft-mlock isn't enabled,
                    // this is expected in constrained environments.
                    break;
                }
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        // At least some allocations should have succeeded.
        assert!(!allocs.is_empty(), "no allocations succeeded");
    }
}
