# Sandbox Model

Every daemon but daemon-launcher runs inside three layers of containment on Linux: Landlock
(filesystem, sockets, scopes), seccomp-bpf (system calls and socket families), and systemd unit
hardening. Each daemon is granted what its work needs and nothing else. Every daemon runs under the
strongest sandbox the running kernel enforces: Landlock's rights and scopes are requested
best-effort, so a newer kernel tightens the sandbox and an older one runs with its own subset,
reported at startup and by `sesame status --doctor`. seccomp and the unit hardening apply on every
kernel, and a sandbox that cannot be built or applied (a rule that cannot be opened, a failed
system call) is fatal.

## Process Hardening

Before the sandbox, every daemon calls `platform_linux::security::harden_process()`
(`PR_SET_DUMPABLE(0)`: no `ptrace` attach by other processes of the user, no core dump content;
`RLIMIT_CORE` 0) and `apply_resource_limits()` (`RLIMIT_NOFILE` 4096). These log a failure and
continue; Landlock and seccomp are the boundary.

## Applying the Sandbox

`core_daemon::sandbox::apply(layout, rules, seccomp)` applies Landlock, then seccomp. It runs in
`main` while the process has exactly one thread, before the async runtime, the configuration
watcher, or any other thread starts, so every thread of the daemon is inside the sandbox: a second
thread is an error, not a partial sandbox. Everything a daemon opens afterwards (the bus, Wayland,
its keys, the vaults) is reached through a rule. `core_types::init_secure_memory()` probes
`memfd_secret` before the sandbox, and `memfd_secret` stays in every allowlist.

## Landlock

`platform-linux/src/sandbox.rs` holds the one Landlock ruleset definition; each daemon supplies
only its rules, derived from `core_layout::Layout` by the rule functions of
`core-daemon/src/sandbox.rs`, so the granted paths and the paths the daemon opens are one
derivation.

### Coverage: Every Right the Kernel Enforces

The ruleset requests every access right and scope of Landlock ABI 10 (Linux 7.2) under
`CompatLevel::BestEffort`, the compatibility model of the kernel's Landlock documentation
("Backward and forward compatibility") and of the landlock crate: the kernel enforces the rights
of its own ABI and the rest are dropped. The daemons therefore run on every kernel, and inherit
each protection a newer kernel adds without a change to the code. `restrict_self` reports the
result: fully enforced, partially enforced, or not enforced (no Landlock).

What a kernel does not enforce is a `core_types::SandboxProtection`, found by building a
`HardRequirement` ruleset of that protection's rights alone (nothing is created in the kernel and
nothing is restricted):

| Protection | Rights | Linux |
| --- | --- | --- |
| `Filesystem` | `AccessFs` of ABI 1 | 5.13 |
| `Reparenting` | `Refer` | 5.19 |
| `Truncation` | `Truncate` | 6.2 |
| `Tcp` | `BindTcp`, `ConnectTcp` | 6.7 |
| `DeviceIoctl` | `IoctlDev` | 6.10 |
| `Scopes` | abstract Unix sockets, signals | 6.12 |
| `PathnameSockets` | `ResolveUnix` | 7.1 |
| `Udp` | `BindUdp`, `ConnectSendUdp` | 7.2 |

A daemon on a kernel that lacks some logs `landlock: partially enforced` at warning level with
each missing protection and its consequence, and continues; without Landlock it logs
`landlock: not enforced` and continues under seccomp and its unit. `sesame status --doctor
platform` reports the same: `platform.kernel` carries the release and the enforcement
(`7.2.15, Landlock fully enforced`), and passes with no protection missing or warns naming each
missing one with the Linux release that enforces it.

### Floor: `[global.sandbox] require`

A protection named in `require` (the table's names in kebab case: `filesystem`, `reparenting`,
`truncation`, `tcp`, `device-ioctl`, `scopes`, `pathname-sockets`, `udp`) is a floor:

```toml
[global.sandbox]
require = ["filesystem", "scopes", "pathname-sockets"]
```

On a kernel that does not enforce one, every sandboxed daemon refuses to start with an error
naming each unmet protection, before anything is restricted, and `platform.kernel` fails, naming
the floor and what the kernel lacks of it. On a kernel that meets it, the floor's rights are
requested as `CompatLevel::HardRequirement` and every other right best-effort (the landlock
crate's pattern for a minimum with opportunistic additions). An unknown name fails the
configuration load, listing the accepted ones. The floor is read when a daemon starts; a reload
does not re-sandbox a running daemon.

`PathnameSockets` is the one whose absence opens a path out of the sandbox. Below ABI 9, Landlock
does not mediate `connect(2)` or addressed `sendmsg(2)` to a pathname Unix socket, so a sandboxed
process reaches every socket it can name: the session D-Bus bus among them, where
`org.freedesktop.systemd1` (`StartTransientUnit`) runs any command outside the sandbox. Under
systemd, `InaccessiblePaths=-%t/bus` removes the session bus socket from each sandboxed unit's
mount namespace on every kernel (see [systemd Unit Hardening](#systemd-unit-hardening)); a daemon
started outside its unit has only Landlock. With `ResolveUnix` handled, a socket is reachable only
under a rule granting it (`FsAccess::ReadWriteFile` on the socket, `FsAccess::ReadWrite` on its
directory).

### Scopes

On a kernel that enforces them (Linux 6.12), every daemon runs with both scopes: it cannot connect
to an abstract-namespace Unix socket created outside its domain (Xwayland and some session buses
listen on abstract addresses), and it cannot signal a process outside it. Abstract sockets cannot
be granted by a rule; every socket a daemon uses is a pathname socket (the user service manager's
`NOTIFY_SOCKET` is `$XDG_RUNTIME_DIR/systemd/notify`).

### Rules

| Rule function | Grants |
| --- | --- |
| `ipc_client_rules` | `<runtime>/pds/keys` (read), `<runtime>/pds/bus.endpoint` (read), `<runtime>/pds/bus.sock` (connect) |
| `config_rules(access)` | `~/.config/pds` with `access`, and read access to the directories its symlinks resolve into (`/nix/store` on NixOS) |
| `notify_rules` | The systemd notification socket, when it is a filesystem socket that exists |
| `ssh_agent_rules` | Every SSH agent socket candidate (`$SSH_AUTH_SOCK`, `~/.ssh/agent.sock`) and its directory, and, for a symlink, its resolved target and the target's directory |
| `wayland_rules` | The Wayland compositor socket |
| `system_bus_rules` | The system D-Bus socket of `Layout::system_bus_socket` (`$DBUS_SYSTEM_BUS_ADDRESS`, one `unix:path=` address, or `/var/run/dbus/system_bus_socket`) |

No rule function grants the session D-Bus bus, and no daemon is granted it. The platform keyring
factor of the overlay's inline unlock is read by daemon-launcher (`KeyringUnlockRequest`), outside
the sandboxes.

A rule for a path that does not exist yet (the vaults before `sesame init`) is skipped: Landlock
denies every path outside the ruleset, so a skipped rule grants less. A path whose existence cannot
be determined is an error. On a non-directory inode (a socket, a file), directory-only rights are
masked off before the rule is added.

| Daemon | Rules |
| --- | --- |
| daemon-profile | `config_rules(ReadWrite)`, `<runtime>/pds` (read-write: it binds the bus socket and writes the keys and endpoint), `notify_rules`; with the `desktop` feature `system_bus_rules` (the Wi-Fi monitor) and, in a Wayland session, `wayland_rules` (the focus monitor) |
| daemon-secrets | `ipc_client_rules`, `config_rules(ReadWrite)` (vault databases, salts, metadata), `notify_rules` |
| daemon-wm | `ipc_client_rules`, `wayland_rules`, `config_rules(ReadOnly)` (vault salts and enrollments for inline unlock), `ssh_agent_rules`, `notify_rules`; `~/.cache/open-sesame` (read-write: MRU stack); read: `~/.config/cosmic` (the COSMIC theme, opened only where its config directories exist), user data, `/etc/fonts`, `/usr/share/fonts`, `/lib`, `/nix/store`, `/proc`, `/usr/share`, `/usr/share/X11/xkb`. No DRI or GPU paths: rendering is `wl_shm` |
| daemon-clipboard | `ipc_client_rules`, `config_rules(ReadOnly)`, `notify_rules`, `wayland_rules`, `~/.cache/open-sesame` (read-write: history database) |
| daemon-input | `ipc_client_rules`, `config_rules(ReadOnly)`, `notify_rules`; read: `/dev/input`, `/sys/class/input`, `/sys/devices` (evdev) |
| daemon-snippets | `ipc_client_rules`, `config_rules(ReadOnly)`, `notify_rules` |

### daemon-launcher

daemon-launcher applies neither Landlock nor seccomp: both are inherited across `fork` and `exec`
and would confine every application it launches. Its boundary is bus authentication (Noise IK).
It is also the broker of the platform keyring factor for daemon-wm, serving
`KeyringUnlockRequest` only from the bus-verified sender `daemon-wm`: the request unlocks a vault
without the user.

## seccomp-bpf

`apply_seccomp` loads a libseccomp filter whose default action kills the process
(`SECCOMP_RET_KILL_PROCESS`): killing a thread would leave the daemon running without it, and an
error return would let a compromised process probe the allowlist. A system call through another
architecture's ABI also kills the process (`set_act_badarch`), which closes `socketcall(2)`
multiplexing and 32-bit entry points. The filter is synchronized onto every thread (`TSYNC`). The
kernel records each kill (`type=SECCOMP`) when `kill_process` is listed in
`/proc/sys/kernel/seccomp/actions_logged`.

`socket` and `socketpair` are admitted only with `AF_UNIX` as their family (argument 0): every
socket a daemon opens is Unix-domain, so no daemon creates a network, netlink, packet, or vsock
socket. `io_uring` is in no allowlist, so it cannot create sockets around the filter.

Every allowlist is `core_daemon::sandbox::BASE_SYSCALLS` (file I/O, memory, threads, the tokio
event loop and timers, Unix sockets, signals, inotify, `memfd_secret`, `getrandom`, `getcwd`,
which backtrace capture of an error report makes, and `mlock`/`munlock`: SQLCipher locks its
private heap at the first database use and unlocks it in its `atexit` shutdown, inside the
sandbox, as does `ProtectedAlloc` without `memfd_secret`) plus the calls of the daemon's own work. Work
that needs more than the base only once, before the sandbox, is done before it: daemon-input
compiles its XKB keymap before the sandbox, so neither the XKB data nor libxkbcommon's
real-versus-effective ID check (`getgid`, `getegid`) is granted afterwards.

| Daemon | Calls beyond the base |
| --- | --- |
| daemon-profile | `bind`, `listen`, `accept4` (bus server); `unlink`, `rename`, `chmod`, `fchmod`, `fchown`, `flock`, `fsync`, `fdatasync` (owner-only files written atomically); `getresuid`, `getresgid`, `getgid`, `getegid` (D-Bus credentials); `writev`, `readv`, `readlinkat`, `uname`, `memfd_create`, `nanosleep`, `clock_nanosleep`, `sched_yield`, `timerfd_create`, `timerfd_settime`, `timerfd_gettime` |
| daemon-secrets | `pwrite64`, `fallocate`, `flock`, `fsync`, `fdatasync`, `rename`, `unlink` (SQLCipher); `writev`, `readv`, `readlinkat`, `uname`, `nanosleep`, `clock_nanosleep` |
| daemon-wm | `flock`, `rename`, `unlink`, `chmod`, `fchmod`, `fsync`, `fdatasync` (MRU stack); `getresuid`, `getresgid`, `getgid`, `getegid`; `statfs`, `fstatfs`, `memfd_create`, `mlock2`, `mremap`, `writev`, `readv`, `readlinkat`, `uname`, `accept4`, `bind`, `listen`, `nanosleep`, `clock_nanosleep`, `sched_yield`, `sched_get_priority_max`, `timerfd_create`, `timerfd_settime`, `timerfd_gettime`, `sysinfo` (Wayland and SCTK runtime) |
| daemon-clipboard | `flock`, `fsync`, `fdatasync` (SQLite) |
| daemon-input | none |
| daemon-snippets | none |

`platform-linux/src/sandbox.rs` tests each property in a child process, since both layers last for
the process's life, and expects of each kernel what it enforces: an ungranted pathname socket is
refused where `PathnameSockets` is enforced and reachable where it is not, a granted one is
reachable, an abstract socket outside the domain is refused where `Scopes` is enforced, the status
`apply_landlock` returns is the one the kernel's gaps predict, and `socket(AF_INET)` kills the
process while `AF_UNIX` is admitted. A table test checks that the protections name every requested
right exactly once. `tests/protocol_validation.sh` runs every daemon of a build through its
lifecycle under an isolated root, each as a transient user service under the `[Service]`
sandboxing of its shipped unit (the read-only mounts included), checks that each reports the
enforcement the doctor predicts, and fails on any seccomp kill the kernel records for them. CI
installs the built `.deb`, `.rpm`, and `.pkg.tar.zst` in their distributions' systemd containers
(`scripts/docker/verify-install.sh`) and fails unless every headless daemon runs under its
installed unit; no release is tagged or published otherwise.

## systemd Unit Hardening

Each daemon is a systemd user service (`contrib/systemd/`), `Type=notify` (daemon-profile
`Type=notify-reload`) with `WatchdogSec=30`, `NoNewPrivileges=yes`, `LimitCORE=0`, and
`LimitMEMLOCK=64M`.

The six sandboxed daemons also set, as a second layer over the in-process filters:

| Directive | Effect |
| --- | --- |
| `ProtectSystem=strict`, `ProtectHome=read-only` | The file system is read-only except the unit's `ReadWritePaths` |
| `RestrictAddressFamilies=AF_UNIX` | systemd's socket family filter, the same as the in-process rule |
| `SystemCallArchitectures=native` | Only the native system call ABI |
| `InaccessiblePaths=-%t/bus` | The session D-Bus socket is absent from the daemon's mount namespace |

For a user service, the mount namespace options imply `PrivateUsers=` and require unprivileged
user namespaces. daemon-secrets also sets `PrivateNetwork=yes`.

daemon-launcher sets no mount namespace options: they would apply to every application it
launches (`systemd-run --user --scope` children share its namespace). It sets
`ProtectKernelTunables`, `ProtectControlGroups`, `LockPersonality`, `RestrictSUIDSGID`,
`SystemCallArchitectures=native`, and `KillMode=process` so launched applications survive a
launcher restart. It sets nothing that drops the capability bounding set
(`CapabilityBoundingSet`, `ProtectClock`, `ProtectKernelModules`, `ProtectKernelLogs`): a user
manager drops it only with `CAP_SETPCAP` in the service's user namespace, which
`kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 24.04's default) denies, failing the start
with `218/CAPABILITIES`; every launched application would inherit it; and an unprivileged user
holds none of those capabilities in the initial user namespace.

## Daemon Matrix

| Daemon | Landlock | seccomp | Session D-Bus | Network sockets | Unit mount namespace |
| --- | :---: | :---: | :---: | :---: | :---: |
| daemon-profile | Y | Y | - | - | Y |
| daemon-secrets | Y | Y | - | - (and `PrivateNetwork`) | Y |
| daemon-wm | Y | Y | - | - | Y |
| daemon-clipboard | Y | Y | - | - | Y |
| daemon-input | Y | Y | - | - | Y |
| daemon-snippets | Y | Y | - | - | Y |
| daemon-launcher | - | - | Y (`systemd-run`, keyring broker) | Y (launched applications) | - |
