# Fleet Management

> **Design Intent.** This page describes the architecture for managing Open Sesame across many
> devices. The primitives referenced below (`InstallationId`, `OrganizationNamespace`,
> `PolicyOverride`, structured logging) exist in the type system and configuration schema today.
> Fleet-scale orchestration tooling that consumes these primitives is not yet implemented.

## Overview

Fleet management treats each Open Sesame installation as an independently-operating node that
can be configured, monitored, and audited from a central control plane. The design relies on
three properties already present in the system:

1. Every installation has a globally unique `InstallationId` (UUID v4, generated at
   `sesame init`), defined in `core-types/src/security.rs`.
2. Installations can be grouped by `OrganizationNamespace` (domain-derived UUID), enabling
   fleet-wide identity correlation.
3. System policy (`/etc/pds/policy.toml`) is a static file that can be distributed by
   configuration management without requiring a running Open Sesame daemon.

## Profile and Policy Distribution

### Configuration Management Integration

Open Sesame's configuration is file-based. Fleet-wide profile templates and security policies
are distributed as files via existing configuration management tools:

```text
Configuration Management (Ansible/Puppet/Chef/NixOS)
  +-- /etc/pds/policy.toml            System policy overrides
  +-- ~/.config/pds/config.toml       User configuration template
  +-- ~/.config/pds/installation.toml  Pre-seeded installation identity (optional)
```

The `PolicyOverride` type (`core-config/src/schema.rs`) supports locking any configuration
key to an enforced value with a source identifier:

```toml
# Enforced by fleet management
[[policy]]
key = "crypto.kdf"
value = "argon2id"
source = "fleet-security-baseline-2025"

[[policy]]
key = "crypto.minimum_peer_profile"
value = "governance-compatible"
source = "fleet-security-baseline-2025"
```

### Pre-Seeded Installation Identity

For fleet provisioning, `installation.toml` can be pre-generated with a known UUID and
organizational namespace, then distributed to devices before `sesame init` runs. The
`InstallationConfig` (`core-config/src/schema_installation.rs`) fields are:

| Field | Purpose | Fleet Use |
|-------|---------|-----------|
| `id` | UUID v4, unique per device | Asset tracking, audit correlation |
| `namespace` | Derived UUID for deterministic profile IDs | Cross-device profile identity |
| `org.domain` | Organization domain | Fleet grouping |
| `org.namespace` | `uuid5(NAMESPACE_URL, domain)` | Deterministic namespace derivation |
| `machine_binding.binding_hash` | BLAKE3 hash of machine identity material | Hardware attestation |
| `machine_binding.binding_type` | `machine-id` or `tpm-bound` | Binding method |

Pre-seeding the `org` field ensures all fleet devices share a common organizational namespace,
enabling deterministic profile ID generation across the fleet.

## Centralized Audit Log Collection

Each Open Sesame installation produces a BLAKE3 hash-chained audit log and structured log
output. Fleet-scale audit aggregation uses the existing structured logging infrastructure.

### journald and Log Shipping

```toml
# config.toml on fleet devices
[global.logging]
level = "info"
json = true
journald = true
```

With `json = true` and `journald = true`, all daemon log entries are structured JSON emitted
to the systemd journal. A log shipper (Promtail, Fluentd, Vector, Filebeat) forwards journal
entries to a central aggregator.

Each structured log entry includes:

- `installation_id` -- the device's UUID from `installation.toml`.
- `daemon_id` -- which daemon emitted the entry (`DaemonId` from `core-types/src/ids.rs`).
- `profile` -- active trust profile name.
- `event` -- the operation performed.
- Timestamp, severity, and span context.

### Audit Chain Verification

The BLAKE3 hash-chained audit log provides tamper evidence at the device level. For fleet-wide
integrity verification:

1. Collect audit chain files from each device.
2. Run `sesame audit verify` against each chain independently.
3. Cross-reference audit entries with centralized log aggregator records.

A broken hash chain on any device indicates tampering or data loss on that device.

## Remote Unlock Patterns

Fleet devices may need to be unlocked without physical operator presence.

### SSH Agent Forwarding

An operator connects to a fleet device and forwards their SSH agent:

```bash
ssh -A operator@fleet-device-042
sesame unlock -p production --factor ssh-agent
```

The SSH agent factor (`AuthFactorId::SshAgent`) derives a KEK from the forwarded key's
deterministic signature without the private key leaving the operator's machine.

### Delegated Factors (Design Intent)

The `DelegationGrant` type (`core-types/src/security.rs`) models time-bounded,
scope-narrowed capability delegation. A fleet operator could issue a delegation grant to
an automation agent, authorizing it to unlock specific profiles on specific devices:

```text
DelegationGrant {
    delegator: <operator-agent-id>,
    scope: CapabilitySet { Unlock },
    initial_ttl: 3600s,
    heartbeat_interval: 300s,
    nonce: <16 random bytes>,
    signature: <Ed25519 over grant fields>,
}
```

The grant's `scope` is intersected with the delegator's own capabilities, ensuring the
automation agent cannot exceed the operator's authority. The `initial_ttl` and
`heartbeat_interval` fields enforce time-bounded access with mandatory renewal.

## Fleet Health Monitoring

### Daemon Health

All daemons use `Type=notify` with `WatchdogSec=30`. systemd restarts unhealthy daemons
automatically. Fleet monitoring collects systemd service states via standard node monitoring
(node_exporter, osquery, or equivalent).

### Security Posture Signals

Key posture signals per device:

| Signal | Source | Meaning |
|--------|--------|---------|
| `memfd_secret` availability | Daemon startup log | Whether secrets are removed from kernel direct map |
| Landlock enforcement | Daemon startup log | Whether filesystem sandboxing is active |
| seccomp-bpf active | Daemon startup log | Whether syscall filtering is active |
| Kernel version | `uname -r` | Whether platform meets minimum requirements |
| `CONFIG_SECRETMEM=y` | `/boot/config-*` | Kernel compiled with secret memory support |

Devices that log `memfd_secret` fallback at ERROR level are operating at a reduced security
posture. Fleet management should alert on this condition and schedule kernel upgrades.

### Structured Alerting

With JSON-structured logging forwarded to a central aggregator, fleet operators can define
alerts on:

- Vault unlock failures (rate limiting triggered).
- Audit chain verification failures.
- Daemon restart loops (watchdog failures).
- Security posture degradation (memfd_secret fallback).
- Policy override conflicts (user config conflicts with fleet policy).
