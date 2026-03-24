# Mesh Topology

> **Design Intent.** This page describes a peer-to-peer federation mesh where Open Sesame
> installations synchronize state without a central authority. The identity model
> (`InstallationId`, `OrganizationNamespace`), Noise IK transport (`core-ipc`), and attestation
> types (`Attestation::RemoteAttestation`) exist in the type system today. The gossip protocol,
> CRDT-based state merging, and convergence guarantees described below are architectural
> targets.

## Overview

A mesh topology connects Open Sesame installations as peers where each node can communicate
directly with any other node. There is no central server, certificate authority, or
coordinator. Trust is established through mutual Noise IK authentication and device
attestation. State convergence is achieved through gossip-based propagation and conflict-free
replicated data types (CRDTs).

## Trust Establishment

### Initial Bootstrap

Two installations establish trust through an out-of-band key exchange:

1. **Key display.** Installation A displays its X25519 static public key and
   `InstallationId`:

   ```bash
   sesame federation show-identity
   # Output:
   #   Installation: a1b2c3d4-...
   #   Org: braincraft.io
   #   Public key: base64(X25519 static key)
   #   Machine binding: machine-id (verified)
   ```

2. **Key import.** Installation B imports A's identity:

   ```bash
   sesame federation trust --installation a1b2c3d4-... --pubkey base64(...)
   ```

3. **Mutual verification.** Both installations perform a Noise IK handshake. Each peer
   verifies the other's static key matches the imported value. The
   `Attestation::RemoteAttestation` type records the result:

   ```rust
   Attestation::RemoteAttestation {
       remote_installation: InstallationId { id: a1b2c3d4-..., ... },
       remote_device_attestation: Box::new(Attestation::DeviceAttestation {
           binding: MachineBinding { binding_hash: [...], binding_type: MachineId },
           verified_at: 1711234567,
       }),
   }
   ```

### Trust Anchors

Each installation maintains a set of trusted peer identities (public keys + installation
IDs). This set is the trust anchor for the mesh. A peer not in the trust set is rejected
during Noise IK handshake. Trust anchors can be:

- **Manually established** (out-of-band, as described above).
- **Transitively established** (A trusts B, B trusts C, A can choose to trust C based on
  B's attestation).
- **Organizationally established** (all installations in the same `OrganizationNamespace`
  share a common trust anchor via policy distribution).

Transitive trust is opt-in and policy-controlled. An installation is never forced to trust a
peer it has not explicitly approved or that does not meet its configured policy.

## Gossip Protocol (Design Intent)

State changes propagate through the mesh via a gossip protocol.

### What is Gossiped

- **Profile metadata.** Profile names, IDs, and sync policies for synchronized profiles.
- **Secret updates.** Encrypted secret payloads for profiles configured for synchronization.
- **Policy updates.** Organization-wide policy changes from `/etc/pds/policy.toml`.
- **Peer identity.** New peer introductions (installation ID + public key) for mesh
  expansion.
- **Revocation notices.** Key revocation and delegation revocation events.

### Gossip Mechanics

1. A node produces a state change (e.g., writes a secret to a synchronized profile).
2. The node selects a random subset of its known peers (fanout factor, typically 3--5).
3. The node sends the update to the selected peers over Noise IK connections.
4. Each receiving peer checks whether the update is new (vector clock comparison). If new,
   the peer applies the update locally and re-gossips to its own random subset of peers.
5. Propagation continues until all nodes have seen the update.

### Dissemination Guarantees

With a fanout factor of `f` and `n` nodes:

- Expected propagation rounds: `O(log_f(n))`.
- For 100 nodes with fanout 3: approximately 5 rounds to reach all peers.
- Probabilistic guarantee: with sufficient fanout, all nodes receive the update with high
  probability. Deterministic delivery is not guaranteed per round; convergence is eventual.

## CRDT-Based State Merging (Design Intent)

To achieve convergence without coordination, synchronized state uses conflict-free replicated
data types.

### Secret State as a Map CRDT

Each synchronized profile's secret store is modeled as a map from secret key to (value,
vector clock) pairs:

```text
Profile "work" secrets:
  "shared/api-key" -> (encrypted_value, {install_A: 3, install_B: 2})
  "shared/db-url"  -> (encrypted_value, {install_A: 1})
```

The CRDT merge rule:

- **Concurrent writes to the same key.** Last-writer-wins based on wall-clock timestamp,
  with installation ID as tiebreaker. The losing value is preserved in a conflict log.
- **Non-conflicting writes.** Different keys or causally ordered writes merge automatically
  with no conflict.
- **Deletes.** A tombstone entry replaces the value. Tombstones are retained for a
  configurable duration (default: 30 days) to ensure propagation across partitioned nodes.

### Convergence Properties

| Property | Guarantee |
|----------|-----------|
| Eventual consistency | All connected peers converge to the same state |
| Commutativity | Updates can be applied in any order |
| Idempotency | Re-applying an update has no additional effect |
| Partition tolerance | Nodes operate independently during partitions |

## Partition Tolerance

### During Partition

Partitioned nodes continue operating independently. Each node:

- Reads and writes its local vault without restriction.
- Records all operations in its local audit chain.
- Queues outgoing gossip messages for delivery when connectivity is restored.

### On Reconnect

When a partitioned node reconnects:

1. The node exchanges vector clocks with peers to identify divergence.
2. Missing updates are transferred in both directions.
3. Conflicts (concurrent writes to the same key) are resolved per the CRDT merge rule.
4. Audit chains from both sides are cross-referenced.

### Convergence Verification

After reconnection, nodes can verify convergence:

```bash
sesame federation verify-convergence --profile work
```

This compares the local state hash with hashes reported by peers. A mismatch indicates an
update still in transit or an unresolved conflict.

## Peer Discovery and Mesh Expansion

### Manual Peer Addition

```bash
sesame federation trust --installation <uuid> --pubkey <base64>
```

### Organization-Scoped Discovery (Design Intent)

Within an `OrganizationNamespace`, peer discovery can be bootstrapped from a shared
configuration distributed via policy:

```toml
# /etc/pds/policy.toml
[[policy]]
key = "federation.bootstrap_peers"
value = [
    { installation = "a1b2c3d4-...", pubkey = "base64(...)" },
    { installation = "e5f6a7b8-...", pubkey = "base64(...)" },
]
source = "enterprise-fleet-management"
```

New installations in the org automatically discover existing peers from the bootstrap list.
Each peer still performs mutual Noise IK authentication before sharing state.

### Peer Removal

Removing a peer from the trust set:

```bash
sesame federation untrust --installation <uuid>
```

The removed peer's public key is revoked. Gossip messages from the revoked peer are rejected.
Secrets previously shared with the revoked peer remain encrypted in local vaults; they are
not retroactively expunged from the peer's copy.

## Security Properties

### No Central Authority

There is no CA, no coordinator, and no single point of compromise. Compromising one node
does not grant access to other nodes' local-only secrets. Synchronized secrets are limited
to what was explicitly configured for sync.

### Forward Secrecy

Each Noise IK connection uses ephemeral keys, providing forward secrecy per session.
Compromising a node's static key does not compromise past session traffic (though it does
compromise future sessions until the key is rotated and the old key revoked in peers' trust
sets).

### Minimum Peer Crypto Profile

The `CryptoConfig.minimum_peer_profile` field (`core-types/src/crypto.rs`) enforces a floor
on the cryptographic algorithms a peer must use:

```text
Local: LeadingEdge (Argon2id, BLAKE3, ChaChaPoly, BLAKE2s)
Peer:  GovernanceCompatible (PBKDF2-SHA256, HKDF-SHA256, AES-GCM, SHA-256)

If minimum_peer_profile = LeadingEdge:
  --> Peer rejected (does not meet minimum)

If minimum_peer_profile = GovernanceCompatible:
  --> Peer accepted
```

This prevents a mesh node with weak cryptographic configuration from weakening the overall
mesh security posture.
