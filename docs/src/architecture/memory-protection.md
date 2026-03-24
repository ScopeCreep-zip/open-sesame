# Memory Protection

All secret-carrying types in Open Sesame are backed by `core-memory::ProtectedAlloc`,
a page-aligned secure memory allocator that uses `memfd_secret(2)` on Linux 5.14+ to
remove secret pages from the kernel direct map entirely. This page documents the
allocator internals, the memory layout, the fallback path, and the type hierarchy
built on top of it.

## ProtectedAlloc Memory Layout

Every `ProtectedAlloc` instance maps a contiguous region of virtual memory containing
five sections: three `PROT_NONE` guard pages, one read-only metadata page, and one or
more read-write data pages. The layout is defined in `core-memory/src/alloc.rs:31-32`
where `OVERHEAD_PAGES` is set to 4 (guard0 + metadata + guard1 + guard2), and data
pages are sized to fit the 16-byte canary plus the requested user data length.

```text
                              mmap'd region (mmap_total bytes)
 +------------+------------+------------+---------------------------+------------+
 | guard pg 0 |  metadata  | guard pg 1 |       data pages ...      | guard pg 2 |
 | PROT_NONE  | PROT_READ  | PROT_NONE  |  PROT_READ | PROT_WRITE  | PROT_NONE  |
 +------------+------------+------------+---------------------------+------------+
 ^            ^            ^            ^                           ^
 |            |            |            |                           |
 mmap_base    +1 page      +2 pages     +3 pages                   +3 pages
              (metadata)                 (data_region)              +data_region_len
                                                                   (guard2)


              Detail of data pages (right-aligned user data):

 |<------------- data_region_len (data_pages * page_size) ------------->|
 +-------------------+-----------+--------------------------------------+
 |     padding       |  canary   |             user data                |
 |  (filled 0xDB)    |  16 bytes |           (user_len bytes)           |
 +-------------------+-----------+--------------------------------------+
 ^                   ^           ^                                      ^
 data_start          canary_ptr  user_data                              guard page 2
                                                                        (PROT_NONE)
```

### Byte-Level Sizes

Given a system page size `P` (typically 4096) and a requested allocation of `N` bytes:

| Component | Formula | Example (N=32, P=4096) |
|-----------|---------|----------------------|
| `data_pages` | `ceil((16 + N) / P)` | 1 |
| `data_region_len` | `data_pages * P` | 4096 |
| `mmap_total` | `(4 + data_pages) * P` | 20480 (5 pages) |
| `padding_len` | `data_region_len - 16 - N` | 4048 |

The padding is filled with `0xDB` (`PADDING_FILL`, `alloc.rs:29`), matching
libsodium's garbage fill convention.

### Guard Pages

Three guard pages are set to `PROT_NONE` via `mprotect(2)`
(`alloc.rs:422-434`). Any read or write to a guard page triggers an
immediate `SIGSEGV`:

- **guard0** (`mmap_base`): prevents underflow from adjacent
  lower-address allocations.
- **guard1** (`mmap_base + 2*P`): separates the read-only metadata page
  from the writable data region. Prevents metadata corruption from
  data-region underflow.
- **guard2** (`mmap_base + 3*P + data_region_len`): the trailing guard
  page. Because user data is right-aligned within the data region, a
  buffer overflow of even one byte hits this page immediately.

### Right-Alignment

User data is placed at the end of the data region (`alloc.rs:455`):

```rust
let user_data_ptr = data_start.add(data_region_len - user_len);
```

This right-alignment means a sequential buffer overflow crosses from user
data directly into the trailing guard page (guard2), triggering `SIGSEGV`
on the first out-of-bounds byte. Without right-alignment, an overflow
would silently write into unused padding within the same page before
reaching the guard.

### Metadata Page

The metadata page (`alloc.rs:438-451`) stores allocation bookkeeping at
fixed offsets, then is downgraded to `PROT_READ`:

| Offset | Size | Content |
|--------|------|---------|
| 0 | 8 bytes | `mmap_total` (total mapped size) |
| 8 | 8 bytes | Data region offset from `mmap_base` |
| 16 | 8 bytes | User data offset from `mmap_base` |
| 24 | 8 bytes | `user_len` (requested allocation size) |
| 32 | 8 bytes | `data_pages` count |
| 40 | 16 bytes | Copy of the process-wide canary |

The metadata page is restored to `PROT_READ|PROT_WRITE` during `Drop`
(`alloc.rs:688-694`) so it can be volatile-zeroed before `munmap`.

## memfd_secret(2) Backend

The preferred allocation backend on Linux is `memfd_secret(2)`, invoked
via raw syscall 447 (`alloc.rs:130,335`). This syscall, available since
Linux 5.14, creates an anonymous file descriptor whose pages are:

- **Removed from the kernel direct map**: the pages are not addressable
  by any kernel code path, including `/proc/pid/mem` reads,
  `process_vm_readv(2)`, kernel modules, and DMA engines.
- **Invisible to ptrace**: even `CAP_SYS_PTRACE` cannot read the page
  contents.
- **Implicitly locked**: the kernel does not swap `memfd_secret` pages to
  disk. No explicit `mlock(2)` is needed.

The syscall requires `CONFIG_SECRETMEM=y` in the kernel configuration.
To check whether a running kernel has this enabled:

```bash
zgrep CONFIG_SECRETMEM /proc/config.gz
# or
grep CONFIG_SECRETMEM /boot/config-$(uname -r)
```

### Probe and Caching

The allocator probes for `memfd_secret` availability once at process
startup via `probe_memfd_secret()` (`alloc.rs:125-188`) and caches the
result in a `OnceLock<bool>` (`alloc.rs:45`). The probe sequence:

1. Call `syscall(447, 0)` to create a secret fd.
2. If `fd < 0`, log an `ERROR`-level security degradation and cache
   `false`.
3. If `fd >= 0`, close the fd immediately and cache `true`.

### Allocation Sequence

The `memfd_secret_mmap()` function (`alloc.rs:333-372`) performs the full
allocation:

1. `syscall(447, 0)` -- create the secret fd.
2. `ftruncate(fd, size)` -- set the mapping size.
3. `mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)` -- map
   the pages. `MAP_SHARED` is required for `memfd_secret`.
4. `close(fd)` -- the mapping persists after the fd is closed.

## Fallback: mmap(MAP_ANONYMOUS)

On kernels without `memfd_secret` support (Linux < 5.14 or
`CONFIG_SECRETMEM` disabled), the allocator falls back to
`mmap(MAP_ANONYMOUS|MAP_PRIVATE)` (`alloc.rs:380-398`). This fallback
applies two additional protections that `memfd_secret` provides
implicitly:

- **`mlock(2)`** (`alloc.rs:495`): locks the data region pages into RAM,
  preventing the kernel from swapping them to disk. If `mlock` fails with
  `ENOMEM` (the `RLIMIT_MEMLOCK` limit is exceeded), the allocator logs a
  `WARN`-level security degradation but continues (`alloc.rs:498-511`).
  If `mlock` fails with any other errno, allocation fails with
  `ProtectedAllocError::MmapFailed`.
- **`madvise(MADV_DONTDUMP)`** (`alloc.rs:482`): excludes the data
  region from core dumps. This is Linux-specific.

The fallback is a **security degradation**: pages remain on the kernel
direct map and are readable via `/proc/pid/mem` by any process running
as the same UID. An `ERROR`-level audit log is emitted by both
`probe_memfd_secret()` (`alloc.rs:147-161`) and `core_memory::init()`
(`core-memory/src/lib.rs:83-91`) when operating in fallback mode. The
log message explicitly states that fallback mode does not meet
IL5/IL6, STIG, or PCI-DSS requirements (`lib.rs:88`).

## Canary Verification

Each `ProtectedAlloc` instance places a 16-byte canary (`CANARY_SIZE`,
`alloc.rs:25`) immediately before the user data region. The canary value
is a process-wide random generated once from `getrandom(2)` (on Linux,
`alloc.rs:56`) or `getentropy(2)` (on macOS, `alloc.rs:67`) and cached
in a `OnceLock<[u8; 16]>` (`alloc.rs:39`).

### Placement

The canary is written at `user_data_ptr - 16` (`alloc.rs:457-464`). A
copy is also stored in the metadata page at offset 40 (`alloc.rs:446`).

### Constant-Time Verification on Drop

During `ProtectedAlloc::drop()` (`alloc.rs:636-720`), the canary is
verified before any cleanup:

1. The 16 bytes at `canary_ptr` are read as a slice
   (`alloc.rs:641-642`).
2. They are compared to the global canary using
   `fixed_len_constant_time_eq()` (`alloc.rs:613-624`). This function
   XORs each byte pair into an accumulator and reads the result through
   `read_volatile` to prevent the compiler from short-circuiting the
   comparison:

    ```rust
    fn fixed_len_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            acc |= x ^ y;
        }
        let result = unsafe { std::ptr::read_volatile(&acc) };
        result == 0
    }
    ```

3. If the comparison fails, an `ERROR`-level audit log is emitted and
   the process aborts via `std::process::abort()` (`alloc.rs:656`). The
   process aborts rather than continuing with potentially compromised
   key material.

Canary corruption indicates a buffer underflow, heap corruption, or
use-after-free in secret-handling code.

## Volatile Zeroize

After canary verification passes, the entire data region (not just the
user data portion) is volatile-zeroed via `volatile_zero()`
(`alloc.rs:627-632`):

```rust
fn volatile_zero(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
```

The `zeroize` crate (`Cargo.toml:85`) performs volatile writes that the
compiler cannot elide. The `compiler_fence(SeqCst)` (`alloc.rs:631`)
provides an additional barrier preventing reordering of the zeroize with
the subsequent `munmap`. This zeroes the canary, the `0xDB` padding, and
the user data before the pages are returned to the kernel.

### Drop Sequence

The full `Drop` implementation (`alloc.rs:636-720`) proceeds in order:

1. **Canary check** -- constant-time comparison, abort on corruption.
2. **Volatile-zero the data region** -- `data_region_len` bytes starting
   at `data_region`.
3. **munlock** (fallback only) -- unlock data pages (`alloc.rs:665`).
4. **MADV_DODUMP** (fallback only, Linux) -- re-enable core dump
   inclusion for the zeroed pages (`alloc.rs:675`).
5. **Zero metadata page** -- restore `PROT_READ|PROT_WRITE`,
   volatile-zero (`alloc.rs:686-695`).
6. **munmap** -- release the entire mapping back to the kernel
   (`alloc.rs:700`).

## Type Hierarchy

Three types build on `ProtectedAlloc` to provide ergonomic secret
handling at different layers of the system.

### SecureBytes (`core-crypto/src/secure_bytes.rs`)

`SecureBytes` is the primary vehicle for cryptographic key material:
master keys, vault keys, derived keys, and KEKs. It wraps a
`ProtectedAlloc` with an `actual_len` field to support empty values
(backed by a 1-byte sentinel allocation, `secure_bytes.rs:55-56`).

Key properties:

- **`from_slice(&[u8])`** (`secure_bytes.rs:73-81`): copies directly
  into protected memory with no intermediate heap allocation. This is
  the preferred constructor.
- **`new(Vec<u8>)`** (`secure_bytes.rs:51-63`): accepts an owned `Vec`,
  copies into protected memory, then zeroizes the source `Vec` on the
  unprotected heap. The doc comment (`secure_bytes.rs:37-44`) explicitly
  notes the brief heap exposure and recommends `from_slice` when
  possible.
- **`into_protected_alloc()`** (`secure_bytes.rs:107-120`): zero-copy
  transfer of the inner `ProtectedAlloc` to a new owner. Uses
  `ManuallyDrop` to suppress the `SecureBytes` destructor and `ptr::read`
  to move the allocation out. The `ProtectedAlloc` is never copied or
  re-mapped.
- **`Clone`** (`secure_bytes.rs:124-129`): creates a fully independent
  `ProtectedAlloc` with its own guard pages, canary, and mlock. Both
  original and clone zeroize independently on drop.
- **`Debug`** (`secure_bytes.rs:146-148`): redacted output showing only
  byte count (`SecureBytes([REDACTED; 32 bytes])`), never contents.

`SecureBytes` does not implement `Serialize` or `Deserialize`. Secrets
must be explicitly converted to `SensitiveBytes` before crossing a
serialization boundary.

### SecureVec (`core-crypto/src/secure_vec.rs`)

`SecureVec` is a password input buffer designed for character-by-character
collection in graphical overlays where the full password length is not
known in advance. It pre-allocates a fixed-size `ProtectedAlloc` (512
bytes for `for_password()`, `secure_vec.rs:14,61`) and provides UTF-8
aware `push_char`/`pop_char` operations.

Key properties:

- **No reallocation**: the buffer is fixed-size. `push_char` panics if
  the buffer is full (`secure_vec.rs:118-122`). The 512-byte limit
  accommodates passwords up to approximately 128 four-byte Unicode
  characters (`secure_vec.rs:13`).
- **Lazy allocation**: `SecureVec::new()` (`secure_vec.rs:43-48`) creates
  an empty instance with `inner: None` and no mmap. `for_password()` or
  `with_capacity()` triggers the actual `ProtectedAlloc`.
- **UTF-8 aware pop**: `pop_char()` (`secure_vec.rs:133-160`) scans
  backwards to find multi-byte character boundaries (checking the `0xC0`
  continuation mask) and zeroizes the removed bytes in-place before
  adjusting the cursor.
- **`clear()`** (`secure_vec.rs:199-208`): zeroizes all written bytes and
  resets the cursor without deallocating, allowing buffer reuse for
  sequential vault unlocks.
- **Double zeroize on drop**: `Drop` (`secure_vec.rs:217-229`) zeroizes
  written bytes before `ProtectedAlloc::drop` performs its own
  volatile-zero of the entire data region.

### SensitiveBytes (`core-types/src/sensitive.rs`)

`SensitiveBytes` is the wire-compatible type for secret values in
`EventKind` IPC messages. It wraps a `ProtectedAlloc` and implements
`Serialize`/`Deserialize` for postcard framing.

Key properties:

- **Zero-copy deserialization path**: the custom `SensitiveBytesVisitor`
  (`sensitive.rs:112-146`) implements `visit_bytes`
  (`sensitive.rs:123-125`) which receives a borrowed `&[u8]` from the
  deserializer and copies directly into a `ProtectedAlloc`. When postcard
  performs in-memory deserialization, this path avoids any intermediate
  heap `Vec<u8>`.
- **Fallback deserialization path**: `visit_byte_buf`
  (`sensitive.rs:129-132`) handles deserializers that provide owned bytes.
  The `Vec<u8>` is copied into protected memory and immediately zeroized.
- **Sequence fallback**: `visit_seq` (`sensitive.rs:136-145`) handles
  deserializers that encode bytes as a sequence of `u8` values. The
  collected `Vec<u8>` is zeroized after copying.
- **`from_protected()`** (`sensitive.rs:57-62`): accepts a
  `ProtectedAlloc` and `actual_len` directly, enabling zero-copy transfer
  from `SecureBytes`.
- **Serialization** (`sensitive.rs:95-99`): calls
  `serializer.serialize_bytes()` directly from the protected memory
  slice. postcard reads the slice without copying.
- **`Debug`** (`sensitive.rs:160-163`): redacted output
  (`[REDACTED; 32 bytes]`).

## Zero-Copy Lifecycle

The three types form a zero-copy pipeline for secret material:

1. A vault key is derived by `core-crypto` and stored as `SecureBytes`
   (in `ProtectedAlloc`).
2. When the key must cross the IPC bus,
   `SecureBytes::into_protected_alloc()` transfers the `ProtectedAlloc`
   to `SensitiveBytes::from_protected()` with no heap copy and no
   re-mapping.
3. `SensitiveBytes` serializes directly from the `ProtectedAlloc` pages
   into the Noise-encrypted IPC frame.
4. On the receiving end, postcard's `visit_bytes` path deserializes
   directly into a new `ProtectedAlloc`.

At no point does plaintext key material exist on the unprotected heap,
provided the `from_slice` constructor path is used rather than
`SecureBytes::new(Vec<u8>)`.

## init_secure_memory() Pre-Sandbox Probe

The `core_memory::init()` function (`core-memory/src/lib.rs:58-107`)
must be called before the seccomp sandbox is applied. It performs a probe
allocation of 1 byte (`lib.rs:68`) which triggers `probe_memfd_secret()`
internally, caching whether syscall 447 is available. If this probe ran
after seccomp activation, the raw syscall would be killed by the filter.

The function also reads `RLIMIT_MEMLOCK` via `getrlimit(2)`
(`lib.rs:62-65`) and logs it alongside the security posture:

- **memfd_secret available**: `INFO`-level log with
  `backend = "memfd_secret"` and the `rlimit_memlock_bytes` value
  (`lib.rs:71-78`).
- **memfd_secret unavailable**: `ERROR`-level log with
  `backend = "mmap(MAP_ANONYMOUS) fallback"` and remediation
  instructions (`lib.rs:83-91`).
- **Probe allocation failure**: `ERROR`-level log warning that all
  secret-carrying types will panic on allocation (`lib.rs:95-103`).

The function is idempotent (`lib.rs:57`). The `OnceLock` values for
`CANARY`, `PAGE_SIZE`, and `MEMFD_SECRET_AVAILABLE` (`alloc.rs:39,42,45`)
ensure that the probe syscall, the `getrandom` call, and the `sysconf`
call each execute exactly once per process regardless of how many times
`init()` is called.

## Guard Page SIGSEGV Test Methodology

The guard page tests (`core-memory/tests/guard_page_sigsegv.rs`) use a
subprocess harness pattern because the expected outcome is process death
by signal, which cannot be caught within a single test process.

### Test Structure

Each test case consists of a parent test and a child harness:

1. **Parent test** (e.g., `overflow_hits_trailing_guard_page`,
   `guard_page_sigsegv.rs:58-62`): spawns the test binary targeting the
   harness function by name via `--exact`, with a gating environment
   variable `__GUARD_PAGE_HARNESS`.
2. **Child harness** (e.g., `overflow_harness`,
   `guard_page_sigsegv.rs:66-83`): checks the environment variable,
   allocates a `ProtectedAlloc` via `from_slice(b"test")`, performs a
   deliberate out-of-bounds `read_volatile`, and calls `exit(1)` if the
   read succeeds (which it must not).
3. **Signal assertion** (`assert_signal_death`,
   `guard_page_sigsegv.rs:25-53`): the parent verifies the child was
   killed by `SIGSEGV` (signal 11) or `SIGBUS` (signal 7), handling both
   direct signal death (`ExitStatusExt::signal()`) and the 128+signal
   exit code convention used by some platforms.

### Test Cases

| Test | Action | Expected Signal |
|------|--------|----------------|
| `overflow_hits_trailing_guard_page` | Reads one byte past `ptr.add(len)` (`guard_page_sigsegv.rs:78`) | SIGSEGV (11) |
| `underflow_hits_leading_guard_page` | Reads one page before `ptr` via `ptr.sub(page_size)` (`guard_page_sigsegv.rs:112`) | SIGSEGV (11) or SIGBUS (7) |

The overflow test validates right-alignment: because user data is flush
against guard page 2, the very first out-of-bounds byte lands on a
`PROT_NONE` page. The underflow test reads backward past the canary and
padding into guard page 1 (between metadata and data region).

The environment variable gate (`guard_page_sigsegv.rs:67`) ensures that
when the test binary is run normally (without `__GUARD_PAGE_HARNESS`
set), the harness functions return immediately without performing any
unsafe operations.

## Platform Support Summary

| Platform | Backend | Protection Level |
|----------|---------|-----------------|
| Linux 5.14+ with `CONFIG_SECRETMEM=y` | `memfd_secret(2)` | Full: pages removed from kernel direct map |
| Linux < 5.14 or without `CONFIG_SECRETMEM` | `mmap(MAP_ANONYMOUS)` + `mlock` + `MADV_DONTDUMP` | Degraded: pages on direct map, audit-logged |
| Non-Unix | Compile-time stub | `ProtectedAlloc::new()` returns `Err(Unsupported)` |

The non-Unix stub (`core-memory/src/lib.rs:111-182`) exists solely so
the crate compiles in workspace-wide `cargo check` runs. All methods on
the stub panic or return errors; no secrets can be handled on unsupported
platforms.

## See Also

- [Architecture Overview](./overview.md) -- crate topology and daemon model
- [IPC Protocol](./ipc-protocol.md) -- Noise IK transport that carries `SensitiveBytes` payloads
- [Sandbox Model](./sandbox-model.md) -- Landlock and seccomp filters applied after `init_secure_memory()`
