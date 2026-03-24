# Sandbox Model

Open Sesame enforces a three-layer process containment model on Linux:
Landlock filesystem sandboxing, seccomp-bpf syscall filtering, and
systemd unit hardening. Each daemon receives a tailored sandbox that
grants the minimum privileges required for its function. Sandbox
application is mandatory --- every daemon treats sandbox failure as fatal
and refuses to start unsandboxed.

## Process Hardening

Before any sandbox is applied, every daemon calls `harden_process()`
(`platform-linux/src/security.rs:14`). This function performs two
operations:

1. **`PR_SET_DUMPABLE(0)`** --- prevents `ptrace` attachment by
   non-root processes and prevents core dumps from containing process
   memory (`security.rs:19`).
2. **`RLIMIT_CORE(0,0)`** --- sets both soft and hard core dump limits
   to zero, preventing core files even if dumpable is re-enabled by
   setuid (`security.rs:32-36`).

Resource limits are applied via `apply_resource_limits()`
(`security.rs:66`). All daemons set `RLIMIT_NOFILE` to 4096. The
`memlock_bytes` parameter is set to 0 at the application level; systemd
units provide the actual `LimitMEMLOCK=64M` constraint.

These hardening calls log errors but do not abort. A daemon still
proceeds to Landlock and seccomp even if `prctl` or `setrlimit` fails.
The Landlock and seccomp layers are the hard security boundary.

## Landlock Filesystem Sandbox

Landlock provides unprivileged filesystem sandboxing on Linux
kernels >= 5.13. The shared implementation lives in
`platform-linux/src/sandbox.rs`. Each daemon defines its own ruleset in
a per-daemon `apply_sandbox()` function.

### ABI Level and Enforcement Policy

The sandbox targets Landlock ABI V6 (`sandbox.rs:77`), which covers
filesystem access (`AccessFs`), network access (`AccessNet`), and scope
restrictions (abstract Unix sockets and cross-process signals via
`Scope`). The `Ruleset` is created with
`handle_access(AccessFs::from_all(abi))` and
`handle_access(AccessNet::from_all(abi))` to handle all access types at
the V6 level (`sandbox.rs:85-96`).

Partial enforcement is treated as a fatal error. If the kernel ABI
cannot fully enforce the requested rules, `apply_landlock()` returns an
error and the daemon aborts (`sandbox.rs:157-161`). There is no graceful
degradation path.

### ENOENT Handling

Paths that do not exist at sandbox application time are silently skipped
(`sandbox.rs:114-120`). This is strictly more restrictive than granting
the path, because Landlock denies access to any path not present in the
ruleset. This design handles the case where directories have not yet
been created --- for example, the vaults directory before `sesame init`
runs, or `$XDG_RUNTIME_DIR/pds/` before daemon-profile creates it.

### Nix Symlink Resolution

On NixOS, configuration files are symlinks into `/nix/store`. Each
daemon calls `core_config::resolve_config_real_dirs()` before applying
Landlock to discover the real filesystem paths behind config symlinks.
These resolved paths are added as read-only Landlock rules so that
config hot-reload can follow symlinks after the sandbox is applied.

daemon-wm additionally grants blanket read-only access to `/nix/store`
(`daemon-wm/src/sandbox.rs:68-69`) for shared libraries, GLib schemas,
locale data, and XKB keyboard rules.

daemon-profile creates its Landlock target directories if they do not
exist before opening `PathFd` handles
(`daemon-profile/src/sandbox.rs:38-42`). This handles the race condition
where systemd restarts daemon-profile after a
`sesame init --wipe-reset-destroy-all-data` before the directories are
recreated.

### Non-Directory Inode Handling

The implementation performs `fstat()` on each `PathFd` after opening it
to detect whether the inode is a directory or a non-directory file
(`sandbox.rs:130-136`). For non-directory inodes (sockets, regular
files), directory-only access flags (`ReadDir`, `MakeDir`, etc.) are
masked off using `AccessFs::from_file(abi)`. This prevents the Landlock
crate's `PathBeneath::try_compat_inner` from reporting
`PartiallyEnforced` on non-directory fds.

The `FsAccess::ReadWriteFile` variant (`sandbox.rs:22-24`) exists
specifically for non-directory paths such as Unix domain sockets,
granting file-level read-write access without directory-only flags.

### Scope Restrictions

Two scope modes are available via the `LandlockScope` enum
(`sandbox.rs:54-60`):

- **`Full`** --- blocks both abstract Unix sockets and cross-process
  signals. Uses `Scope::from_all(abi)` which on ABI V6 includes
  `AbstractUnixSocket` and `Signal`.
- **`SignalOnly`** --- blocks cross-process signals only, permitting
  abstract Unix sockets. Uses `Scope::Signal` alone.

Daemons that need D-Bus or Wayland communication via abstract Unix
sockets use `SignalOnly`. Daemons with no such requirement use `Full`.

### Per-Daemon Filesystem Rules

#### daemon-profile

Source: `daemon-profile/src/sandbox.rs:29`. Scope: **SignalOnly**
(needs D-Bus).

| Path | Access | Purpose |
|------|--------|---------|
| `~/.config/pds/` | ReadWrite | Audit log, config, vault metadata |
| `$XDG_RUNTIME_DIR/pds/` | ReadWrite | IPC bus socket, keys, runtime state |
| `$NOTIFY_SOCKET` | ReadWriteFile | systemd sd_notify keepalives |
| `$SSH_AUTH_SOCK` + canonicalized target + parent | ReadWriteFile / ReadOnly | SSH agent auto-unlock |
| `~/.ssh/` + `agent.sock` + canonicalized target + parent | ReadOnly / ReadWriteFile | Stable SSH agent symlink fallback |
| Resolved config symlink targets | ReadOnly | Config hot-reload on NixOS |

daemon-profile is the only daemon that hosts the IPC bus server socket.
It requires ReadWrite on the entire `$XDG_RUNTIME_DIR/pds/` directory
because it creates the `bus.sock` and `bus.pub` files at startup.

SSH agent socket handling resolves symlinks to their target inodes. On
Konductor VMs, `~/.ssh/agent.sock` is a stable symlink to a per-session
`/tmp/ssh-XXXX/agent.PID` path. Landlock resolves symlinks to their
target inodes, so the implementation grants access to the symlink path,
the canonicalized target, and the parent directory of the target for
path traversal (`daemon-profile/src/sandbox.rs:81-149`).

#### daemon-secrets

Source: `daemon-secrets/src/sandbox.rs:7`. Scope: **Full** (no abstract
Unix sockets needed).

| Path | Access | Purpose |
|------|--------|---------|
| `~/.config/pds/` | ReadWrite | Vault SQLCipher databases, salt storage |
| `$XDG_RUNTIME_DIR/pds/keys/` | ReadOnly | IPC client keypair |
| `$XDG_RUNTIME_DIR/pds/bus.pub` | ReadOnly | Bus server public key |
| `$XDG_RUNTIME_DIR/pds/bus.sock` | ReadWriteFile | IPC bus socket |
| `$XDG_RUNTIME_DIR/bus` | ReadWriteFile | D-Bus filesystem socket |
| `$NOTIFY_SOCKET` | ReadWriteFile | systemd sd_notify keepalives |
| Resolved config symlink targets | ReadOnly | Config hot-reload on NixOS |

daemon-secrets has the narrowest Landlock ruleset of all daemons that
handle secret material. It uses `LandlockScope::Full` to block abstract
Unix sockets. The D-Bus filesystem socket at `$XDG_RUNTIME_DIR/bus` is
granted as a `ReadWriteFile` rule because it is a non-directory inode
(`daemon-secrets/src/sandbox.rs:44-47`).

#### daemon-wm

Source: `daemon-wm/src/sandbox.rs:8`. Scope: **SignalOnly** (Wayland
uses abstract sockets).

| Path | Access | Purpose |
|------|--------|---------|
| `$XDG_RUNTIME_DIR/pds/keys/` | ReadOnly | IPC client keypair |
| `$XDG_RUNTIME_DIR/pds/bus.pub` | ReadOnly | Bus server public key |
| `$XDG_RUNTIME_DIR/pds/bus.sock` | ReadWriteFile | IPC bus socket |
| `$WAYLAND_DISPLAY` socket | ReadWriteFile | Wayland compositor protocol |
| `~/.cache/open-sesame/` | ReadWrite | MRU state, overlay cache |
| `/etc/fonts` | ReadOnly | Fontconfig configuration |
| `/usr/share/fonts` | ReadOnly | System font files |
| `~/.config/cosmic/` | ReadOnly | COSMIC desktop theme integration |
| `/nix/store` | ReadOnly | Shared libs, schemas, XKB (NixOS) |
| `/proc` | ReadOnly | xdg-desktop-portal PID verification |
| `/usr/share` | ReadOnly | System shared data (fonts, icons, mime, locale) |
| `/usr/share/X11/xkb` | ReadOnly | XKB system rules (non-NixOS) |
| `~/.local/share/` | ReadOnly | User fonts and theme data |
| `~/.config/pds/vaults/` | ReadOnly | Salt files and SSH enrollment blobs |
| `$SSH_AUTH_SOCK` + canonicalized paths | ReadWriteFile / ReadOnly | SSH agent auto-unlock |
| `$NOTIFY_SOCKET` | ReadWriteFile | systemd sd_notify keepalives |
| Resolved config symlink targets | ReadOnly | Config hot-reload on NixOS |

daemon-wm has the broadest Landlock ruleset because it renders a Wayland
overlay using SCTK and tiny-skia. It requires access to fonts, theme
data, and system shared resources. GPU/DRI access is intentionally
excluded --- rendering uses `wl_shm` CPU shared memory buffers only
(`daemon-wm/src/sandbox.rs:91-93`).

#### daemon-clipboard

Source: `daemon-clipboard/src/main.rs:306`. Scope: **Full**.

| Path | Access | Purpose |
|------|--------|---------|
| `$XDG_RUNTIME_DIR/pds/keys/` | ReadOnly | IPC client keypair |
| `$XDG_RUNTIME_DIR/pds/bus.pub` | ReadOnly | Bus server public key |
| `$XDG_RUNTIME_DIR/pds/bus.sock` | ReadWriteFile | IPC bus socket |
| `$WAYLAND_DISPLAY` socket | ReadWriteFile | Wayland data-control protocol |
| `~/.cache/open-sesame/` | ReadWrite | Clipboard history SQLite database |
| Resolved config symlink targets | ReadOnly | Config hot-reload on NixOS |

#### daemon-input

Source: `daemon-input/src/main.rs:319`. Scope: **Full**.

| Path | Access | Purpose |
|------|--------|---------|
| `$XDG_RUNTIME_DIR/pds/keys/` | ReadOnly | IPC client keypair |
| `$XDG_RUNTIME_DIR/pds/bus.pub` | ReadOnly | Bus server public key |
| `$XDG_RUNTIME_DIR/pds/bus.sock` | ReadWriteFile | IPC bus socket |
| `/dev/input` | ReadOnly | evdev keyboard device nodes |
| `/sys/class/input` | ReadOnly | evdev device enumeration symlinks |
| `/sys/devices` | ReadOnly | evdev device metadata via sysfs |
| Resolved config symlink targets | ReadOnly | Config hot-reload on NixOS |

daemon-input is the only daemon with access to `/dev/input` and
`/sys/class/input`. It reads raw keyboard events via evdev.

#### daemon-snippets

Source: `daemon-snippets/src/main.rs:241`. Scope: **Full**.

| Path | Access | Purpose |
|------|--------|---------|
| `$XDG_RUNTIME_DIR/pds/keys/` | ReadOnly | IPC client keypair |
| `$XDG_RUNTIME_DIR/pds/bus.pub` | ReadOnly | Bus server public key |
| `$XDG_RUNTIME_DIR/pds/bus.sock` | ReadWriteFile | IPC bus socket |
| `~/.config/pds/` | ReadOnly | Config directory (snippet templates) |
| Resolved config symlink targets | ReadOnly | Config hot-reload on NixOS |

daemon-snippets has the narrowest Landlock ruleset of all sandboxed
daemons. It requires only IPC bus access and read-only config access.

#### daemon-launcher

daemon-launcher does **not** apply Landlock or seccomp. It spawns
arbitrary desktop applications as child processes via `fork`+`exec`.
Landlock and seccomp filters inherit across `fork`+`exec` and would kill
every spawned application (`daemon-launcher/src/main.rs:119-121`). The
security boundary for daemon-launcher is IPC bus authentication via
Noise IK. systemd unit hardening provides the process containment layer.

## seccomp-bpf Syscall Filtering

The seccomp implementation uses `libseccomp` to build per-daemon BPF
filters (`platform-linux/src/sandbox.rs:259`). seccomp is always applied
**after** Landlock because Landlock setup requires syscalls
(`landlock_create_ruleset`, `landlock_add_rule`,
`landlock_restrict_self`) that the seccomp filter does not permit.

### Default Action

The default action for disallowed syscalls is
`ScmpAction::KillThread` (`SECCOMP_RET_KILL_THREAD`)
(`sandbox.rs:268`). This sends `SIGSYS` to the offending thread rather
than using `KillProcess`, which would skip the signal handler entirely.
The choice of `KillThread` over `Errno` or `Log` is deliberate ---
`Errno` or `Log` would allow an attacker to probe for allowed syscalls
(`sandbox.rs:256-258`).

### SIGSYS Handler

A custom `SIGSYS` signal handler is installed before the seccomp filter
is loaded (`sandbox.rs:173-238`). The handler is designed to be
async-signal-safe:

- It uses no allocator and makes no heap allocations.
- It extracts the syscall number from `siginfo_t` at byte offset 24 from
  the struct base on x86_64 (`sandbox.rs:201`). This offset corresponds
  to `si_call_addr` (8-byte pointer) followed by `si_syscall` (4-byte
  int) within the `_sigsys` union member, which starts at byte offset 16
  from the struct base.
- It formats the number into a stack-allocated buffer and writes
  `"SECCOMP VIOLATION: syscall=NNN"` to stderr via raw `libc::write()`
  on fd 2.
- After logging, it resets `SIGSYS` to `SIG_DFL` via `libc::signal()`
  and re-raises the signal via `libc::raise()`
  (`sandbox.rs:226-228`).

The handler is registered with `SA_SIGINFO | SA_RESETHAND` flags
(`sandbox.rs:235`). `SA_RESETHAND` ensures the handler fires only
once --- subsequent `SIGSYS` deliveries use the default disposition.

### Per-Daemon Syscall Differences

All six sandboxed daemons share a common baseline of approximately 50
syscalls covering I/O basics (`read`, `write`, `close`, `openat`,
`lseek`, `pread64`, `fstat`, `stat`, `newfstatat`, `statx`, `access`),
memory management (`mmap`, `mprotect`, `munmap`, `madvise`, `brk`),
process/threading (`futex`, `clone3`, `clone`, `set_robust_list`,
`set_tid_address`, `rseq`, `sched_getaffinity`, `prlimit64`, `prctl`,
`getpid`, `gettid`, `getuid`, `geteuid`, `kill`), epoll (`epoll_wait`,
`epoll_ctl`, `epoll_create1`, `eventfd2`, `poll`, `ppoll`), timers
(`clock_gettime`, `timer_create`, `timer_settime`, `timer_delete`),
networking (`socket`, `connect`, `sendto`, `recvfrom`, `recvmsg`,
`sendmsg`, `getsockname`, `getpeername`, `setsockopt`, `socketpair`,
`shutdown`, `getsockopt`), signals (`sigaltstack`, `rt_sigaction`,
`rt_sigprocmask`, `rt_sigreturn`, `tgkill`), inotify
(`inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`), and misc
(`exit_group`, `exit`, `getrandom`, `memfd_secret`, `ftruncate`,
`restart_syscall`, `pipe2`, `dup`).

The following table lists syscalls that differentiate the daemons:

| Syscall | profile | secrets | wm | clipboard | input | snippets | Purpose |
|---------|:-------:|:-------:|:--:|:---------:|:-----:|:--------:|---------|
| `bind` | Y | - | Y | - | - | - | Server socket / Wayland |
| `listen` | Y | - | Y | - | - | - | Server socket / Wayland |
| `accept4` | Y | - | Y | - | - | - | Server socket / Wayland |
| `mlock` | - | Y | Y | - | - | - | Secret zeroization / SCTK buffers |
| `munlock` | - | Y | - | - | - | - | Secret zeroization |
| `mlock2` | - | - | Y | - | - | - | SCTK/Wayland runtime |
| `mremap` | - | - | Y | - | - | - | SCTK buffer reallocation |
| `pwrite64` | - | Y | - | - | - | - | SQLCipher journal writes |
| `fallocate` | - | Y | - | - | - | - | SQLCipher space preallocation |
| `flock` | Y | Y | Y | Y | - | - | Database/file locking |
| `chmod` / `fchmod` | Y | - | Y | - | - | - | File permission management |
| `fchown` | Y | - | - | - | - | - | IPC socket ownership |
| `rename` | Y | Y | Y | - | - | - | Atomic file replacement |
| `unlink` | Y | Y | Y | - | - | - | File/socket cleanup |
| `statfs` / `fstatfs` | - | - | Y | - | - | - | Filesystem info (SCTK) |
| `sched_get_priority_max` | - | - | Y | - | - | - | Thread priority (SCTK) |
| `sysinfo` | - | - | Y | - | - | - | System memory info (SCTK) |
| `memfd_create` | Y | - | Y | - | - | - | D-Bus / Wayland shared memory |
| `nanosleep` | Y | Y | Y | - | - | - | Event loop timing |
| `clock_nanosleep` | Y | Y | Y | - | - | - | Event loop timing |
| `sched_yield` | Y | - | Y | - | - | - | Cooperative thread scheduling |
| `timerfd_create` | Y | - | Y | - | - | - | D-Bus / Wayland event loops |
| `timerfd_settime` | Y | - | Y | - | - | - | D-Bus / Wayland event loops |
| `timerfd_gettime` | Y | - | Y | - | - | - | D-Bus / Wayland event loops |
| `getresuid` / `getresgid` | Y | Y | Y | - | - | - | D-Bus credential passing |
| `getgid` / `getegid` | Y | Y | Y | - | - | - | D-Bus credential passing |
| `writev` / `readv` | Y | Y | Y | - | - | - | Scatter/gather I/O |
| `readlinkat` | Y | Y | Y | - | - | - | Symlink resolution |
| `uname` | Y | Y | Y | - | - | - | D-Bus / Wayland runtime |
| `getcwd` | Y | Y | Y | - | - | - | Working directory resolution |

Key observations:

- **daemon-secrets** uniquely requires `mlock`/`munlock` for zeroization
  of secret material in memory, plus `pwrite64` and `fallocate` for
  SQLCipher database journal operations.
- **daemon-wm** has the broadest syscall allowlist (~88 syscalls) due to
  Wayland/SCTK runtime requirements including `mremap`, `mlock2`,
  `statfs`/`fstatfs`, `sysinfo`, and `sched_get_priority_max`.
- **daemon-profile** requires `bind`/`listen`/`accept4` because it hosts
  the IPC bus server socket. It also requires `fchown` for setting socket
  ownership.
- **daemon-input** and **daemon-snippets** have the narrowest allowlists
  (~57-60 syscalls).
- All sandboxed daemons permit `memfd_secret` for secure memory
  allocation and `getrandom` for cryptographic random number generation.

## systemd Unit Hardening

Each daemon runs as a `Type=notify` systemd user service with
`WatchdogSec=30`. Service files are located in `contrib/systemd/`.

### Common Directives

All seven daemons share the following systemd hardening:

| Directive | Value | Effect |
|-----------|-------|--------|
| `NoNewPrivileges` | `yes` | Prevents privilege escalation via setuid/setgid binaries |
| `LimitCORE` | `0` | Disables core dumps at the cgroup level |
| `LimitMEMLOCK` | `64M` | Caps locked memory at 64 MiB |
| `Restart` | `on-failure` | Automatic restart on non-zero exit |
| `RestartSec` | `5` | Five-second delay between restarts |
| `WatchdogSec` | `30` | Daemon must call `sd_notify(WATCHDOG=1)` within 30 seconds |

### Per-Daemon systemd Differences

| Directive | profile | secrets | wm | launcher | clipboard | input | snippets |
|-----------|:-------:|:-------:|:--:|:--------:|:---------:|:-----:|:--------:|
| `ProtectHome` | read-only | read-only | read-only | - | read-only | read-only | read-only |
| `ProtectSystem` | strict | strict | strict | - | strict | strict | strict |
| `PrivateNetwork` | - | **yes** | - | - | - | - | - |
| `ProtectClock` | - | - | - | **yes** | - | - | - |
| `ProtectKernelTunables` | - | - | - | **yes** | - | - | - |
| `ProtectKernelModules` | - | - | - | **yes** | - | - | - |
| `ProtectKernelLogs` | - | - | - | **yes** | - | - | - |
| `ProtectControlGroups` | - | - | - | **yes** | - | - | - |
| `LockPersonality` | - | - | - | **yes** | - | - | - |
| `RestrictSUIDSGID` | - | - | - | **yes** | - | - | - |
| `SystemCallArchitectures` | - | - | - | **native** | - | - | - |
| `CapabilityBoundingSet` | - | - | - | **(empty)** | - | - | - |
| `KillMode` | - | - | - | **process** | - | - | - |
| `LimitNOFILE` | 4096 | **1024** | 4096 | 4096 | 4096 | 4096 | 4096 |
| `MemoryMax` | 128M | **256M** | 128M | - | 128M | 128M | 128M |

Notable design decisions:

- **daemon-secrets** (`open-sesame-secrets.service:18`) is the only
  daemon with `PrivateNetwork=yes`, placing it in its own network
  namespace with no connectivity. It communicates exclusively via the
  Unix domain IPC bus socket. It has the lowest `LimitNOFILE` (1024) but
  the highest `MemoryMax` (256M) to accommodate Argon2id, which
  allocates 19 MiB per key derivation.
- **daemon-launcher** (`open-sesame-launcher.service:17-21`) does not
  set `ProtectHome` or `ProtectSystem` because these mount namespace
  restrictions inherit to child processes spawned via
  `systemd-run --scope`. Firefox, for example, writes to
  `/run/user/1000/dconf/` and fails with "Read-only file system" when
  `ProtectSystem=strict` is applied to the launcher. Instead,
  daemon-launcher uses kernel control plane protections and an empty
  `CapabilityBoundingSet` to drop all Linux capabilities.
  `KillMode=process` ensures spawned applications survive launcher
  restarts.
- **ReadWritePaths** vary per daemon: daemon-profile and daemon-secrets
  get `%t/pds` and `%h/.config/pds`; daemon-wm and daemon-clipboard get
  `%h/.cache/open-sesame`; daemon-wm additionally gets
  `%h/.cache/fontconfig`.

## Sandbox Application Order

The sandbox layers are applied in a strict sequence during daemon
startup:

1. `harden_process()` --- `PR_SET_DUMPABLE(0)`, `RLIMIT_CORE(0,0)`
2. `apply_resource_limits()` --- `RLIMIT_NOFILE`, `RLIMIT_MEMLOCK`
3. Pre-sandbox I/O --- open file descriptors, connect to IPC bus, read
   keypairs, scan desktop entries (daemon-launcher), open evdev devices
   (daemon-input)
4. `init_secure_memory()` --- probe `memfd_secret` before seccomp locks
   down syscalls
5. `apply_landlock()` --- filesystem containment (implicitly sets
   `PR_SET_NO_NEW_PRIVS` via `landlock_restrict_self`)
6. `apply_seccomp()` --- syscall filtering (must follow Landlock)

This ordering is critical. Landlock setup requires the
`landlock_create_ruleset`, `landlock_add_rule`, and
`landlock_restrict_self` syscalls, which are not in any daemon's seccomp
allowlist. The IPC bus connection must be established before Landlock
restricts filesystem access, because the daemon reads its keypair from
`$XDG_RUNTIME_DIR/pds/keys/`.

## Daemon Sandbox Capability Matrix

| Daemon | harden_process | Landlock | seccomp | Landlock Scope | PrivateNetwork | ProtectSystem | Approx. Syscalls |
|--------|:--------------:|:--------:|:-------:|:--------------:|:--------------:|:-------------:|:----------------:|
| daemon-profile | Y | Y | Y | SignalOnly | - | strict | ~80 |
| daemon-secrets | Y | Y | Y | Full | Y | strict | ~72 |
| daemon-wm | Y | Y | Y | SignalOnly | - | strict | ~88 |
| daemon-launcher | Y | - | - | N/A | - | - | N/A |
| daemon-clipboard | Y | Y | Y | Full | - | strict | ~60 |
| daemon-input | Y | Y | Y | Full | - | strict | ~60 |
| daemon-snippets | Y | Y | Y | Full | - | strict | ~57 |
