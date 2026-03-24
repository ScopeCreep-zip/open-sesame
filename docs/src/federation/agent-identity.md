# Agent Identity

Open Sesame models every entity that interacts with the system -- human operators, AI agents,
system services, and WASI extensions -- as an agent with a typed identity, local process
binding, and capability-scoped session.

## AgentId and AgentType

The `AgentId` type (`core-types/src/ids.rs`) is a UUID v7 wrapper generated via
`define_id!(AgentId, "agent")`. Each agent receives a unique identifier at registration
time, displayed with the `agent-` prefix (e.g., `agent-01941c8a-...`).

The `AgentType` enum (`core-types/src/security.rs`) classifies what kind of entity the
agent is:

```rust
pub enum AgentType {
    Human,
    AI { model_family: String },
    Service { unit: String },
    Extension { manifest_hash: [u8; 32] },
}
```

| Variant | Description | Example |
|---------|-------------|---------|
| `Human` | Interactive operator with keyboard/mouse | Desktop user |
| `AI { model_family }` | LLM-based agent, API-driven | `model_family: "claude-4"` |
| `Service { unit }` | systemd service or daemon process | `unit: "daemon-launcher.service"` |
| `Extension { manifest_hash }` | WASI extension, content-addressed | SHA-256 of the WASM module |

`AgentType` is descriptive metadata, not a trust tier. An AI agent with proper attestations
and a delegation chain can have higher effective trust than a human agent without a security
key. Trust is evaluated via `TrustVector`, not `AgentType`.

## Local Process Identity

The `LocalAgentId` enum (`core-types/src/security.rs`) binds an agent to a local process:

```rust
pub enum LocalAgentId {
    UnixUid(u32),
    ProcessIdentity { uid: u32, process_name: String },
    SystemdUnit(String),
    WasmHash([u8; 32]),
}
```

| Variant | Verification | Use Case |
|---------|-------------|----------|
| `UnixUid` | UCred from Unix domain socket | Minimal identity, CLI tools |
| `ProcessIdentity` | UCred + `/proc/{pid}/exe` inspection | Named processes |
| `SystemdUnit` | systemd unit name lookup | Daemon services |
| `WasmHash` | Content hash of WASM module bytes | Sandboxed extensions |

Local agent identity is established during IPC connection setup. When a process connects to
the Noise IK bus, the server extracts UCred (pid, uid, gid) from the Unix domain socket and
looks up the connecting process's identity.

## AgentIdentity

The `AgentIdentity` struct (`core-types/src/security.rs`) is the complete identity record
for an agent during a session:

```rust
pub struct AgentIdentity {
    pub id: AgentId,
    pub agent_type: AgentType,
    pub local_id: LocalAgentId,
    pub installation: InstallationId,
    pub attestations: Vec<Attestation>,
    pub session_scope: CapabilitySet,
    pub delegation_chain: Vec<DelegationLink>,
}
```

| Field | Purpose |
|-------|---------|
| `id` | Globally unique agent identifier (UUID v7) |
| `agent_type` | Classification: Human, AI, Service, Extension |
| `local_id` | Process-level binding on this machine |
| `installation` | Which Open Sesame installation this agent belongs to |
| `attestations` | Evidence accumulated during this session |
| `session_scope` | Effective capabilities for this session |
| `delegation_chain` | Chain of authority from the root delegator |

## AgentMetadata

The `AgentMetadata` struct (`core-types/src/security.rs`) describes an agent's type and the
attestation methods available to it:

```rust
pub struct AgentMetadata {
    pub agent_type: AgentType,
    pub available_attestation_methods: Vec<AttestationMethod>,
}
```

Available attestation methods vary by agent type:

| Agent Type | Typical Attestation Methods |
|------------|---------------------------|
| `Human` | `MasterPassword`, `SecurityKey`, `DeviceAttestation` |
| `AI` | `Delegation`, `ProcessAttestation` |
| `Service` | `ProcessAttestation`, `DeviceAttestation` |
| `Extension` | `ProcessAttestation` (WASM hash verification) |

The `AttestationMethod` enum (`core-types/src/security.rs`) defines the methods:

- `MasterPassword` -- password-based, for human agents.
- `SecurityKey` -- FIDO2/WebAuthn hardware token.
- `ProcessAttestation` -- process identity verification via `/proc` inspection.
- `Delegation` -- authority delegated from another agent.
- `DeviceAttestation` -- machine-level binding (TPM, machine-id).

## Attestation

The `Attestation` enum (`core-types/src/security.rs`) captures the evidence used to verify
an agent's identity claim. Each variant records the specific data for one verification
method:

| Variant | Evidence |
|---------|----------|
| `UCred` | pid, uid, gid from Unix domain socket |
| `NoiseIK` | X25519 public key, registry generation counter |
| `MasterPassword` | Timestamp of successful verification |
| `SecurityKey` | FIDO2 credential ID, verification timestamp |
| `ProcessAttestation` | pid, SHA-256 of executable, uid |
| `Delegation` | Delegator AgentId, granted CapabilitySet, chain depth |
| `DeviceAttestation` | MachineBinding, verification timestamp |
| `RemoteAttestation` | Remote InstallationId, nested remote device attestation |
| `HeartbeatRenewal` | Original attestation type, renewal attestation, renewal timestamp |

Multiple attestations compose to strengthen trust. For example, `UCred` + `MasterPassword`
produces a higher `TrustLevel` in the `TrustVector` than either alone. The `attestations`
vector on `AgentIdentity` accumulates all attestation evidence for the current session.

## Machine Agents

Service accounts and AI agents operate as machine agents with restricted capabilities. A
machine agent's `AgentIdentity` is established as follows:

1. **Registration.** The agent is registered with an `AgentId`, `AgentType`, and initial
   `CapabilitySet`. For example, a CI runner agent might receive:

   ```text
   CapabilitySet { SecretRead { key_pattern: Some("ci/*") }, SecretList }
   ```

2. **Attestation.** At connection time, the agent presents attestation evidence. For a
   `Service` agent, this is `Attestation::ProcessAttestation`:

   ```rust
   Attestation::ProcessAttestation {
       pid: 12345,
       exe_hash: <SHA-256 of /usr/bin/ci-runner>,
       uid: 1001,
   }
   ```

3. **Session scope.** The agent's `session_scope` is the intersection of its registered
   capabilities and any delegation grant's scope. The agent cannot exceed the capabilities
   it was registered with, and delegation further narrows scope.

## Agent Lifecycle

### Registration

Agent registration creates an `AgentId` and associates it with an `AgentType` and initial
capability set. For built-in daemons, registration is automatic at IPC bus connection via
the clearance registry (`core-ipc/src/registry.rs`). Each daemon's X25519 public key maps
to a `DaemonId` and `SecurityLevel`.

### Key Rotation (Design Intent)

The clearance registry maintains a `registry_generation` counter. When an agent's X25519
key pair is rotated:

1. The new public key is registered with an incremented generation.
2. The old public key is revoked (removed from the registry).
3. Peers that cached the old key receive a registry update.

The `Attestation::NoiseIK` variant records the `registry_generation` at the time of
verification, enabling peers to detect stale attestations.

### Revocation

Revoking an agent removes its public key from the clearance registry. Subsequent connection
attempts with the revoked key are rejected. Active sessions using the revoked key continue
until the next re-authentication interval.

## Human-to-Agent Delegation

A human operator can delegate capabilities to a machine agent via `DelegationGrant`
(`core-types/src/security.rs`). The delegation:

- Narrows scope: the delegatee's effective capabilities are
  `delegator_scope.intersection(grant.scope)`.
- Is time-bounded: `initial_ttl` sets the maximum grant lifetime.
- Requires heartbeat: `heartbeat_interval` sets how often the delegatee must renew.
- Is signed: Ed25519 signature over grant fields prevents tampering.
- Records depth: `DelegationLink.depth` tracks how many hops from the root delegator
  (0 = direct from human).

See the [Delegation](delegation.md) documentation for the full delegation model.

## Trust Evaluation

Agent trust is not determined by `AgentType` alone. The `TrustVector`
(`core-types/src/security.rs`) evaluates trust across multiple dimensions:

```rust
pub struct TrustVector {
    pub authn_strength: TrustLevel,       // None < Low < Medium < High < Hardware
    pub authz_freshness: Duration,        // Time since last authorization refresh
    pub delegation_depth: u8,             // 0 = direct human
    pub device_posture: f64,              // 0.0 = unknown, 1.0 = fully attested
    pub network_exposure: NetworkTrust,   // Local < Encrypted < Onion < PublicInternet
    pub agent_type: AgentType,            // Metadata, not a trust tier
}
```

Authorization decisions consume the `TrustVector` holistically. A `Service` agent on a
local Unix socket with `Hardware`-level authentication and zero delegation depth may be
trusted more than a `Human` agent on an encrypted network with `Medium` authentication
and a stale authorization token.
