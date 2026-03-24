# Multi-User

Open Sesame supports multiple users on a shared workstation. Each user operates an independent
set of daemons, vaults, and IPC buses with hardware-enforced isolation between users.

## Per-User Service Instances

Each user runs their own systemd user services. There is no system-wide Open Sesame daemon.
When user `alice` and user `bob` both log into the same machine:

- Alice's `daemon-profile` listens on `$XDG_RUNTIME_DIR/pds/bus.sock` (typically
  `/run/user/1000/pds/bus.sock`).
- Bob's `daemon-profile` listens on `/run/user/1001/pds/bus.sock`.
- Each user's daemon set is managed by their own `systemctl --user` instance.
- The two sets of daemons have no knowledge of each other.

### Isolation Boundaries

| Boundary | Mechanism |
|----------|-----------|
| IPC bus | Separate Unix domain sockets under each user's `$XDG_RUNTIME_DIR` |
| Configuration | Separate `~/.config/pds/` per user home directory |
| Vaults | Separate SQLCipher databases per user, per profile |
| Audit logs | Separate BLAKE3 hash chains per user |
| Secret memory | `memfd_secret(2)` pages are per-process; invisible to other UIDs and to root |
| Process isolation | Landlock + seccomp per daemon; `ProtectHome=read-only` prevents cross-user access |

## memfd_secret Isolation

On Linux 5.14+ with `CONFIG_SECRETMEM=y`, all secret-carrying memory allocations
(`SecureBytes`, `SecureVec`, `SensitiveBytes`) use `memfd_secret(2)`. Pages allocated via
this syscall are:

- Removed from the kernel direct map.
- Invisible to `/proc/pid/mem` reads.
- Inaccessible to kernel modules and DMA.
- Inaccessible via `ptrace` even as root.

This means that even a root-level compromise on the shared workstation cannot read another
user's decrypted secrets from memory. The secrets exist only in the virtual address space of
the owning process.

When `memfd_secret` is unavailable, the fallback is `mmap(MAP_ANONYMOUS)` with `mlock(2)` and
`MADV_DONTDUMP`. This prevents secrets from being swapped to disk or appearing in core dumps,
but does not remove them from the kernel direct map. The fallback is logged at ERROR level
with compliance impact.

### RLIMIT_MEMLOCK

Each daemon service sets `LimitMEMLOCK=64M` (see `contrib/systemd/*.service`). On a
multi-user workstation, the total `memfd_secret` and `mlock` usage is the sum across all
users' daemon instances. System administrators should verify that the system-wide locked
memory limit and per-user `RLIMIT_MEMLOCK` (via `/etc/security/limits.conf`) accommodate
the expected number of concurrent users.

## Shared Workstation Model

### Separate Vaults, Separate Profiles

Each user has their own `InstallationConfig` with a distinct installation UUID. Two users on
the same machine have different installation IDs, different vault encryption keys, and
different profile IDs even if both name a profile `work`. The `TrustProfileName` maps to a
per-user vault file at `~/.config/pds/vaults/{name}.db`.

### Hardware Security Key per User

Users can enroll different hardware security keys (FIDO2, YubiKey) as authentication factors.
The `AuthFactorId::Fido2` and `AuthFactorId::Yubikey` variants in `core-types/src/auth.rs`
support per-user enrollment. A shared YubiKey slot is not assumed; each user's enrollment
produces a distinct credential ID.

### Profile Activation Independence

Profile activation is per-user. Alice activating her `corporate` profile does not affect
Bob's active profile. The `daemon-profile` instance for each user independently evaluates
activation rules (`ActivationConfig` in `core-config/src/schema.rs`): WiFi SSID triggers,
USB device presence, time-of-day rules, and security key requirements.

## System Policy

Enterprise administrators can enforce organization-wide defaults via `/etc/pds/policy.toml`.
This file is read-only at runtime and applies to all users on the machine.

```toml
# /etc/pds/policy.toml

[[policy]]
key = "crypto.kdf"
value = "argon2id"
source = "enterprise-security-policy"

[[policy]]
key = "audit.enabled"
value = true
source = "enterprise-security-policy"

[[policy]]
key = "clipboard.max_history"
value = 0
source = "enterprise-data-loss-prevention"
```

Each entry corresponds to a `PolicyOverride` struct (`core-config/src/schema.rs`) with a
dotted key path, enforced value, and source identifier. Policy overrides take precedence
over user configuration. Users cannot override a policy-locked key.

### Policy Distribution

System policy files are managed by the organization's configuration management tooling
(Ansible, Puppet, Chef, NixOS modules, or similar). Open Sesame does not implement its own
policy distribution mechanism. The file at `/etc/pds/policy.toml` is a standard configuration
file managed by the operating system's package manager or configuration management.

## Kernel Requirements

For full multi-user isolation:

| Requirement | Purpose | Verification |
|-------------|---------|--------------|
| Linux 5.14+ | `memfd_secret(2)` | `uname -r` |
| `CONFIG_SECRETMEM=y` | Kernel direct-map removal | `grep SECRETMEM /boot/config-$(uname -r)` |
| systemd 255+ | Per-user service management | `systemctl --version` |
| Sufficient RLIMIT_MEMLOCK | Locked memory for all users | `ulimit -l` |

## Auditing in Multi-User Environments

Each user's audit log is independent. The BLAKE3 hash-chained audit log for a user resides at
`~/.config/pds/audit/` under that user's home directory. Audit verification with
`sesame audit verify` operates on the current user's chain only.

For centralized audit collection across all users on a workstation, the structured JSON
logging output (`global.logging.json = true`) can be forwarded to a central log aggregator
via journald or a sidecar log shipper. Each log entry includes the installation ID, which
uniquely identifies the user's Open Sesame instance.
