# Zero Trust Posture

This page describes how Open Sesame applies zero trust principles to its architecture. Zero
trust in this context means that no component, process, or network path is implicitly trusted.
Every interaction is authenticated, authorized, and audited, regardless of origin.

## Principles

### Never Trust, Always Verify

Every IPC message on the bus is authenticated via the Noise IK protocol. There is no
unauthenticated communication path between daemons.

**Implementation:** When a daemon connects to the IPC bus hosted by `daemon-profile`, the
Noise IK handshake verifies the connecting daemon's X25519 static public key against the
clearance registry (`core-ipc/src/registry.rs`). UCred (pid, uid, gid) from the Unix domain
socket is bound into the Noise prologue, preventing a compromised process from reusing
another process's Noise session.

Unregistered clients (e.g., the `sesame` CLI) receive `Open` clearance. They can send and
receive `Open`-level messages but are excluded from `Internal`, `ProfileScoped`, and
`SecretsOnly` traffic.

The `SecurityLevel` enum (`core-types/src/security.rs`) defines the clearance hierarchy:

```rust
pub enum SecurityLevel {
    Open,           // Visible to all, including extensions
    Internal,       // Authenticated daemons only
    ProfileScoped,  // Daemons with current profile's security context
    SecretsOnly,    // Secrets daemon only
}
```

A message at `SecretsOnly` level is delivered only to daemons registered at `SecretsOnly`
clearance. A daemon at `Internal` clearance never sees it. This is enforced in the IPC
server's message routing loop (`core-ipc/src/server.rs`): the server checks
`conn.security_clearance >= msg.security_level` before delivering each message, and checks
`conn.security_clearance >= msg.security_level` before accepting each sent message from a
daemon.

### Least Privilege

Each daemon operates with the minimum privileges required for its function. Privilege
boundaries are enforced at multiple layers:

#### Per-Daemon Clearance

| Daemon | Clearance | Rationale |
|--------|-----------|-----------|
| `daemon-secrets` | SecretsOnly | Holds decrypted vault keys; must not leak to other daemons |
| `daemon-clipboard` | ProfileScoped | Handles clipboard content scoped to the active profile |
| `daemon-profile` | Internal | IPC bus host; sees all Internal-level and below |
| `daemon-wm` | Internal | Window management; no access to secrets |
| `daemon-launcher` | Internal | Application launching; receives secrets only via env injection |
| `daemon-input` | Internal | Keyboard/mouse capture; no secret access |
| `daemon-snippets` | Internal | Snippet management; no secret access |

#### Filesystem Sandboxing (Landlock)

Each daemon restricts its own filesystem access at startup via Landlock. The secrets daemon,
for example, can access only `$XDG_RUNTIME_DIR/pds/` and `~/.config/pds/`. Attempts to read
or write outside these paths return `EACCES`.

Partially-enforced Landlock is a fatal error. If the kernel supports Landlock but enforcement
is incomplete (e.g., missing filesystem support), the daemon aborts rather than operating
with degraded isolation.

#### Syscall Filtering (seccomp-bpf)

Each daemon installs a seccomp-bpf filter with a per-daemon syscall allowlist. Unallowed
syscalls terminate the offending thread (`SECCOMP_RET_KILL_THREAD`). A SIGSYS handler logs
the denied syscall before the thread dies, providing visibility into unexpected syscall
usage.

#### systemd Hardening

All daemon services apply:

| Directive | Effect |
|-----------|--------|
| `NoNewPrivileges=yes` | Prevents privilege escalation via setuid/setgid binaries |
| `ProtectSystem=strict` | Root filesystem mounted read-only |
| `ProtectHome=read-only` | Home directory read-only except explicit `ReadWritePaths` |
| `LimitCORE=0` | Core dumps disabled |
| `LimitMEMLOCK=64M` | Locked memory budget for `memfd_secret` and `mlock` |
| `MemoryMax` | Per-daemon memory ceiling |

The secrets daemon additionally uses `PrivateNetwork=yes`, which creates a network namespace
with only a loopback interface. The secrets daemon has no path to any network socket.

#### Capability-Based Authorization

The `CapabilitySet` type (`core-types/src/security.rs`) implements fine-grained,
capability-based authorization. Each agent's `session_scope` defines exactly which
operations it can perform. The 16 defined capabilities are:

- `Admin`, `SecretRead`, `SecretWrite`, `SecretDelete`, `SecretList`
- `ProfileActivate`, `ProfileDeactivate`, `ProfileList`, `ProfileSetDefault`
- `StatusRead`, `AuditRead`, `ConfigReload`
- `Unlock`, `Lock`
- `Delegate`, `ExtensionInstall`, `ExtensionManage`

Delegation narrows scope via lattice intersection:
`effective = delegator_scope.intersection(grant.scope)`. A delegatee can never exceed the
delegator's capabilities.

### Continuous Verification

Trust is not established once and cached. Multiple mechanisms provide ongoing verification:

#### Watchdog

All daemons report health to systemd via `WatchdogSec=30`. If a daemon fails to report
within 30 seconds, systemd restarts it. This detects hung processes and ensures daemon
liveness.

#### Audit Chain

The BLAKE3 hash-chained audit log provides a tamper-evident record of all operations. Each
entry hashes the previous entry's hash, forming a chain from the genesis entry at
`sesame init` to the most recent operation. Verification via `sesame audit verify` detects:

- Modified entries (hash mismatch).
- Deleted entries (chain gap).
- Reordered entries (hash mismatch).
- Inserted entries (hash mismatch).

The hash algorithm is configurable: BLAKE3 (default) or SHA-256 (governance-compatible),
via `CryptoConfigToml.audit_hash` (`core-config/src/schema_crypto.rs`).

#### Authorization Freshness

The `TrustVector.authz_freshness` field (`core-types/src/security.rs`) tracks how long
since the last authorization refresh. Delegated capabilities expire via
`DelegationGrant.initial_ttl` and require periodic renewal via `heartbeat_interval`. A
stale authorization is equivalent to no authorization.

#### Heartbeat Renewal

The `Attestation::HeartbeatRenewal` variant records heartbeat events for time-bounded
attestations. Missing a heartbeat revokes the corresponding delegation.

### Device Health as Posture Signal

The availability of `memfd_secret(2)` is a binary posture signal. A system with
`memfd_secret` removes secret pages from the kernel direct map; a system without it leaves
secrets accessible to any process that can read `/proc/pid/mem` or perform DMA.

| Posture Signal | Value | Meaning |
|---------------|-------|---------|
| `memfd_secret` available | `device_posture: 1.0` | Secrets removed from kernel direct map |
| `memfd_secret` unavailable | `device_posture: 0.5` | Secrets on kernel direct map (mlock fallback) |
| No mlock | `device_posture: 0.0` | Secrets may be swapped to disk |

The `TrustVector.device_posture` field (`core-types/src/security.rs`) is a `f64` from 0.0
(unknown) to 1.0 (fully attested). In a federation context, a peer with low device posture
may be restricted from receiving high-sensitivity secrets.

Additional posture signals include:

- **Landlock enforcement status** -- whether the filesystem sandbox is active.
- **seccomp-bpf status** -- whether syscall filtering is active.
- **Machine binding** -- whether the installation is bound to specific hardware via
  `MachineBindingType::TpmBound` or `MachineBindingType::MachineId`.
- **Kernel version** -- whether the kernel meets minimum requirements for all security
  controls.

### Microsegmentation via Profile Isolation

Trust profiles are the microsegmentation boundary in Open Sesame. Each profile is an
isolated trust context:

| Boundary | Isolation Mechanism |
|----------|-------------------|
| Secrets | Separate SQLCipher vault per profile (`vaults/{name}.db`) |
| Encryption keys | Separate BLAKE3-derived vault key per profile |
| Clipboard | Profile-scoped clipboard history |
| Audit | Profile attribution in every audit entry |
| Frecency | Separate frecency database per profile |
| Environment | Profile-scoped secret injection via `sesame env -p {profile}` |

Cross-profile access is not possible without explicit configuration. A daemon operating in
the `work` profile cannot read secrets from the `personal` profile's vault. The vault
encryption keys are derived from different BLAKE3 context strings
(`"pds v2 vault-key work"` vs. `"pds v2 vault-key personal"`), so even with the master key,
the derived keys are distinct.

The `LaunchProfile` type (`core-types/src/profile.rs`) allows explicit profile stacking for
applications that need secrets from multiple profiles:

```rust
pub struct LaunchProfile {
    pub trust_profiles: Vec<TrustProfileName>,
    pub conflict_policy: ConflictPolicy,
}
```

When multiple profiles are stacked, the `ConflictPolicy` determines how secret key
collisions are handled: `Strict` (abort), `Warn` (log and use higher-precedence), or `Last`
(silently use higher-precedence). The default is `Strict`, preventing accidental secret
leakage across profile boundaries.

## Explicit Security Posture

Open Sesame does not degrade silently. Security controls that fail are fatal, with one
documented exception:

- Landlock enforcement failure: fatal. Daemon does not start.
- seccomp-bpf installation failure: fatal. Daemon does not start.
- `memfd_secret` unavailability: non-fatal. Daemon starts with `mlock` fallback. Logged at
  ERROR level with an explicit compliance impact statement naming affected frameworks
  (IL5/IL6, DISA STIG, PCI-DSS) and the exact remediation command.

The `memfd_secret` exception exists because the feature depends on kernel configuration that
application software cannot control. The ERROR-level log ensures the operator is informed of
the reduced posture, and the compliance impact statement provides actionable remediation
guidance.

## Network Trust Model

The `NetworkTrust` enum (`core-types/src/security.rs`) classifies the trust level of the
network path:

```rust
pub enum NetworkTrust {
    Local,           // Unix domain socket, same machine
    Encrypted,       // Noise IK, TLS, WireGuard
    Onion,           // Tor, Veilid
    PublicInternet,  // Unencrypted or minimally authenticated
}
```

The ordering represents decreasing trust: `Local` is most trusted (no network traversal),
`PublicInternet` is least trusted.

In the current implementation, all IPC communication uses `Local` (Unix domain socket). In
a federation context (Design Intent), `Encrypted` (Noise IK over TCP) would be used for
cross-machine communication. The `TrustVector.network_exposure` field allows authorization
policies to require stronger authentication for less-trusted network paths.
