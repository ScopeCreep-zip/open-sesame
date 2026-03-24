# Multi-Cluster Federation

> **Design Intent.** This page describes cross-cluster secret synchronization between Open
> Sesame installations. The primitives referenced below (`InstallationId`, `ProfileRef`,
> `OrganizationNamespace`, `CryptoConfig`, Noise IK transport) exist in the type system and
> IPC layer today. The synchronization protocol, conflict resolution logic, and selective sync
> policies are architectural targets.

## Overview

Multi-cluster federation enables multiple Open Sesame installations to share secrets and
profiles across trust boundaries. Each installation operates independently and maintains full
functionality without connectivity to peers. Synchronization is an additive capability layered
on top of the existing single-installation model.

## Prerequisites

Federated installations must share an `OrganizationNamespace` (`core-types/src/security.rs`).
Installations in different organizations cannot federate without explicit trust establishment.
The shared org namespace ensures deterministic profile ID derivation, so the same profile name
on different installations can be correlated.

Each peer must meet the `minimum_peer_profile` requirement from `CryptoConfig`
(`core-types/src/crypto.rs`):

```rust
pub struct CryptoConfig {
    // ...
    pub minimum_peer_profile: CryptoProfile,  // LeadingEdge, GovernanceCompatible, or Custom
}
```

A peer advertising `GovernanceCompatible` algorithms (PBKDF2-SHA256, HKDF-SHA256, AES-GCM,
SHA-256) is rejected by an installation requiring `LeadingEdge` unless the policy explicitly
allows it.

## Profile-Scoped Synchronization

Synchronization is scoped to individual trust profiles. The `ProfileRef` type
(`core-types/src/profile.rs`) fully qualifies a profile in a federation context:

```rust
pub struct ProfileRef {
    pub name: TrustProfileName,
    pub id: ProfileId,
    pub installation: InstallationId,
}
```

Two installations with the profile `work` have different `ProfileRef` values because their
`InstallationId` fields differ. Federation maps these profiles to each other by matching on
`TrustProfileName` within the shared org namespace.

### Selective Sync Policies (Design Intent)

Not all secrets in a profile need to be synchronized. Selective sync policies control which
secrets replicate:

```text
Sync Policy for profile "work":
  - sync: secrets matching "shared/*"
  - exclude: secrets matching "local/*"
  - direction: bidirectional
  - peers: [installation-uuid-1, installation-uuid-2]
```

Secrets matching the `local/*` pattern remain on the originating installation. Secrets
matching `shared/*` replicate to specified peers. The policy is configured per-profile and
per-installation.

## Conflict Resolution (Design Intent)

When two installations modify the same secret independently (e.g., during a network
partition), a conflict arises at synchronization time.

### Last-Writer-Wins with Vector Clocks

Each secret carries a vector clock with one entry per installation that has modified it:

```text
Secret "shared/api-key":
  Installation A: version 3
  Installation B: version 2
```

On synchronization:

1. **No conflict.** One vector clock strictly dominates the other (all entries greater or
   equal, at least one strictly greater). The dominating version wins.

2. **Concurrent writes.** Neither vector clock dominates. This is a true conflict.
   Resolution strategy:
   - **Default: last-writer-wins.** The write with the latest wall-clock timestamp wins.
     The losing version is preserved in a conflict log for manual review.
   - **Configurable.** Future policy options include: reject (require manual resolution),
     merge (for structured secret formats), or defer to a specific installation.

### Conflict Log

All conflicts are recorded in the audit chain with both versions, their vector clocks, and
the resolution applied. The `sesame audit verify` command can surface unreviewed conflicts.

## Split-Brain Handling (Design Intent)

When network connectivity between peers is lost, each installation continues operating
independently. This is the normal mode of operation for Open Sesame -- the system is designed
for offline-first use.

### Partition Behavior

During a partition:

- Each installation reads and writes its local vault without restriction.
- No synchronization occurs.
- The audit chain continues recording local operations.

### Convergence on Reconnect

When connectivity is restored:

1. Each peer advertises its vector clock state for each synchronized profile.
2. Peers exchange only the secrets that have changed since the last synchronization point.
3. Conflicts are resolved per the configured policy.
4. Audit chains from both peers are cross-referenced to build a unified timeline.

The convergence protocol is idempotent: re-running synchronization after a successful sync
produces no changes.

## Encrypted Replication

All synchronization traffic between peers uses the Noise IK protocol, the same transport
used for local IPC. This provides:

| Property | Mechanism |
|----------|-----------|
| Mutual authentication | X25519 static keys, verified against clearance registry |
| Forward secrecy | Per-session Noise IK ephemeral keys |
| Encryption | ChaChaPoly (default) or AES-256-GCM (`NoiseCipher` in `core-types/src/crypto.rs`) |
| Integrity | Noise protocol MAC |
| Replay protection | Noise protocol nonce management |

Peer identity is established via the `Attestation::RemoteAttestation` variant
(`core-types/src/security.rs`):

```rust
Attestation::RemoteAttestation {
    remote_installation: InstallationId,
    remote_device_attestation: Box<Attestation>,
}
```

This nests the remote peer's device attestation (e.g., machine binding, TPM) inside a
remote attestation wrapper, providing end-to-end identity verification for the replication
channel.

## Topology

Federation supports multiple topologies:

### Hub-Spoke

A central installation acts as the synchronization hub. Leaf installations sync with the
hub only:

```text
      Hub
     / | \
    A  B  C
```

Simpler to manage. The hub is a single point of failure for synchronization (not for local
operation).

### Mesh

Every installation syncs with every other installation:

```text
    A --- B
    |  X  |
    C --- D
```

No single point of failure. Higher bandwidth and complexity. See
[Mesh Topology](mesh-topology.md) for the full mesh design.

### Partial Mesh

Selected installations sync with selected peers:

```text
    A --- B
          |
    C --- D
```

Supports organizational boundaries where teams share a subset of profiles.

## Security Considerations

### Trust Boundary

Each synchronized secret crosses a trust boundary at the profile level. An installation's
`SecurityLevel` hierarchy (`Open < Internal < ProfileScoped < SecretsOnly`) applies locally.
A remote peer with access to a shared profile can read secrets at the `ProfileScoped` level
for that profile, but cannot escalate to `SecretsOnly` on the local installation.

### Delegation for Sync Agents

The synchronization agent on each installation operates with a `DelegationGrant` scoped to
the secrets being synchronized:

```text
DelegationGrant {
    delegator: <local-operator>,
    scope: { SecretRead { key_pattern: "shared/*" }, SecretWrite { key_pattern: "shared/*" } },
    initial_ttl: 86400s,
    heartbeat_interval: 3600s,
    ...
}
```

This ensures the sync agent cannot access local-only secrets, even if compromised.

### Audit Trail

Every secret received from a remote peer is recorded in the local audit chain with the
remote peer's `InstallationId` and the grant under which the sync occurred. This provides
a tamper-evident record of which secrets were replicated from where.
