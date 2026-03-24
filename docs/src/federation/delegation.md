# Delegation

Open Sesame implements capability delegation via the `DelegationGrant` type, enabling agents
to transfer a subset of their capabilities to other agents with time-bounded, scope-narrowed,
cryptographically signed grants.

## DelegationGrant

The `DelegationGrant` struct is defined in `core-types/src/security.rs`:

```rust
pub struct DelegationGrant {
    pub delegator: AgentId,
    pub scope: CapabilitySet,
    pub initial_ttl: Duration,
    pub heartbeat_interval: Duration,
    pub nonce: [u8; 16],
    pub point_of_use_filter: Option<OciReference>,
    pub signature: Vec<u8>,   // Ed25519 signature over the grant fields
}
```

| Field | Purpose |
|-------|---------|
| `delegator` | The `AgentId` of the agent issuing the grant |
| `scope` | Maximum capabilities the delegatee may exercise |
| `initial_ttl` | Time-to-live from grant creation; the grant expires after this duration |
| `heartbeat_interval` | How often the delegatee must renew; missed heartbeat revokes the grant |
| `nonce` | 16-byte anti-replay nonce, unique per grant |
| `point_of_use_filter` | Optional OCI reference restricting where the grant can be used |
| `signature` | Ed25519 signature over all other fields by the delegator |

## Scope Narrowing

Delegation enforces a fundamental invariant: a delegatee can never exceed its delegator's
capabilities. The delegatee's effective capabilities are computed as:

```text
effective = delegator_scope.intersection(grant.scope)
```

The `CapabilitySet` type (`core-types/src/security.rs`) implements lattice operations:

| Operation | Method | Semantics |
|-----------|--------|-----------|
| Union | `a.union(b)` | All capabilities from both sets |
| Intersection | `a.intersection(b)` | Only capabilities in both sets |
| Subset test | `a.is_subset(b)` | True if every capability in `a` is in `b` |
| Superset test | `a.is_superset(b)` | True if every capability in `b` is in `a` |
| Empty set | `CapabilitySet::empty()` | No capabilities |
| Full set | `CapabilitySet::all()` | All non-parameterized capabilities |

### Example

A human operator holds `{ Admin, SecretRead, SecretWrite, SecretList, Unlock }`. The
operator delegates to a CI agent with scope
`{ SecretRead { key_pattern: Some("ci/*") }, SecretList }`:

```text
Delegator scope:  { Admin, SecretRead, SecretWrite, SecretList, Unlock }
Grant scope:      { SecretRead { key_pattern: "ci/*" }, SecretList }
Effective:        { SecretRead { key_pattern: "ci/*" }, SecretList }
```

The CI agent can read secrets matching `ci/*` and list secret keys. It cannot write secrets,
unlock vaults, or perform admin operations, even though the delegator holds those
capabilities.

### Parameterized Capabilities

Several capabilities accept optional parameters that further restrict scope:

```rust
Capability::SecretRead { key_pattern: Option<String> }
Capability::SecretWrite { key_pattern: Option<String> }
Capability::SecretDelete { key_pattern: Option<String> }
Capability::Delegate { max_depth: u8, scope: Box<CapabilitySet> }
```

A `SecretRead` with `key_pattern: None` permits reading any secret. A `SecretRead` with
`key_pattern: Some("ci/*")` restricts reads to keys matching the glob pattern. Delegation
intersection treats parameterized capabilities as more restrictive: the result uses the
narrower pattern.

## Time-Bounded Grants

Every `DelegationGrant` has two temporal controls:

### initial_ttl

The grant is valid for `initial_ttl` from creation time. After this duration, the grant
expires regardless of heartbeat activity. This prevents indefinite capability transfer.

### heartbeat_interval

The delegatee must renew the grant at intervals not exceeding `heartbeat_interval`. A
missed heartbeat revokes the grant. This provides continuous verification that the delegatee
is still active and authorized.

The `Attestation::HeartbeatRenewal` variant (`core-types/src/security.rs`) records heartbeat
events:

```rust
Attestation::HeartbeatRenewal {
    original_attestation_type: AttestationType,
    renewal_attestation: Box<Attestation>,
    renewed_at: u64,
}
```

## Delegation Chains

Grants can be chained: agent A delegates to agent B, which delegates to agent C. The
`DelegationLink` struct tracks position in the chain:

```rust
pub struct DelegationLink {
    pub grant: DelegationGrant,
    pub depth: u8,   // 0 = direct from human operator
}
```

The `AgentIdentity.delegation_chain` field (`core-types/src/security.rs`) stores the full
chain of `DelegationLink` entries from the root delegator to the current agent.

### Chain Depth Control

The `Capability::Delegate` variant includes a `max_depth` field:

```rust
Capability::Delegate {
    max_depth: u8,
    scope: Box<CapabilitySet>,
}
```

`max_depth` limits how many times a delegation can be re-delegated. A grant with
`max_depth: 2` allows:

```text
Human (depth 0) -> Agent A (depth 1) -> Agent B (depth 2)
```

Agent B cannot further delegate because depth 2 equals `max_depth`. This prevents unbounded
delegation chains that would make audit trails difficult to follow.

### Chain Verification

To verify a delegation chain:

1. Start from the root delegator (depth 0). Verify the root is a known, trusted agent
   (typically `AgentType::Human`).
2. For each link in the chain:
   - Verify the `signature` over the `DelegationGrant` fields using the delegator's
     Ed25519 public key.
   - Verify that the grant has not expired (`initial_ttl` not exceeded).
   - Verify that the heartbeat is current (`heartbeat_interval` not exceeded).
   - Verify that `depth` does not exceed the `Delegate.max_depth` from the delegator's
     capability.
   - Compute effective scope as `previous_scope.intersection(grant.scope)`.
3. The final effective scope is the intersection of all grants in the chain.

### Monotonic Narrowing

Each link in the chain can only narrow capabilities, never widen them. The intersection
operation guarantees:

```text
scope_n <= scope_{n-1} <= ... <= scope_0
```

where `<=` means "is a subset of." This is a structural property of the lattice:
`a.intersection(b).is_subset(a)` is always true.

## Anti-Replay

Each `DelegationGrant` contains a 16-byte `nonce` field. The nonce must be unique across all
grants from a given delegator. A delegation verifier maintains a set of observed nonces and
rejects grants with previously-seen nonces. This prevents replay attacks where a revoked or
expired grant is re-presented.

## Point-of-Use Filter

The `point_of_use_filter` field is an optional `OciReference` (`core-types/src/oci.rs`) that
restricts where the delegation can be used:

```rust
pub struct OciReference {
    pub registry: String,
    pub principal: String,
    pub scope: String,
    pub revision: String,
    pub provenance: Option<String>,
}
```

When present, the delegation is only valid in the context of the specified OCI artifact. This
is intended for extension-scoped delegations: a grant that authorizes an extension to read
secrets only when running as part of a specific, content-addressed WASM module.

## The Delegate Capability

The `Capability::Delegate` variant is itself a capability that must be held to issue
delegations:

```rust
Capability::Delegate {
    max_depth: u8,
    scope: Box<CapabilitySet>,
}
```

An agent without `Capability::Delegate` in its `session_scope` cannot create
`DelegationGrant` entries. The `scope` field within the `Delegate` capability limits what
the agent can delegate, and `max_depth` limits the chain length. The ability to delegate is
itself subject to delegation narrowing.

## Revocation

Delegation grants are revoked in the following scenarios:

1. **TTL expiry.** The `initial_ttl` has elapsed since grant creation.
2. **Missed heartbeat.** The delegatee did not renew within `heartbeat_interval`.
3. **Delegator revocation.** The delegator explicitly revokes the grant (removes it from
   the active grant set).
4. **Chain invalidation.** Any link in the delegation chain is revoked, which invalidates
   all downstream links.

Revocation is immediate and does not require the delegatee's cooperation. The delegatee's
next operation that requires the revoked capability is denied.
