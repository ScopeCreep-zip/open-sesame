# Human-Agent Orchestration

> **Design Intent.** This page describes mixed workflows where human operators and AI/service
> agents collaborate on secret-bearing operations. The agent identity model (`AgentIdentity`,
> `AgentType`, `DelegationGrant`, `TrustVector`) is defined in the type system today. The
> approval gate mechanisms, escalation protocols, and multi-party authorization described below
> are architectural targets.

## Overview

Open Sesame treats human operators and machine agents as peers in the same identity system.
Both are `AgentIdentity` instances with typed identities, attestations, capability sets, and
delegation chains. The difference is not in system architecture but in the attestation methods
available and the trust policies applied.

The core principle: agents can perform secret-bearing operations only to the extent that a
human has authorized them, either directly (via `DelegationGrant`) or via policy.

## Agent Types in Orchestration

The `AgentType` enum (`core-types/src/security.rs`) defines the entity classification:

| Type | Role in Orchestration |
|------|----------------------|
| `Human` | Approver, delegator, root of trust for capability chains |
| `AI { model_family }` | Automated operations, LLM-driven workflows, copilot actions |
| `Service { unit }` | Background processes, CI/CD pipelines, cron jobs |
| `Extension { manifest_hash }` | WASI plugins operating in a content-addressed sandbox |

## Approval Gates (Design Intent)

An approval gate is a policy that requires human authorization before an agent can access a
secret or perform a privileged operation.

### Gate Model

When an AI or Service agent requests a capability that requires approval:

1. The agent submits a request specifying the capability needed and the context (profile,
   secret key pattern, operation type).
2. The request is held in a pending state. The agent blocks or receives a pending response.
3. One or more human operators are notified.
4. The human reviews the request and either approves (issuing a `DelegationGrant`) or denies.
5. On approval, the agent's `session_scope` is updated with the granted capabilities for the
   duration of `initial_ttl`.

### Gate Conditions

Approval gates are triggered by the gap between an agent's `session_scope` and the
capabilities required for the requested operation:

```text
Agent session_scope: { SecretList, StatusRead }
Requested operation: SecretRead { key_pattern: "production/db-*" }

Gap: { SecretRead { key_pattern: "production/db-*" } }
  --> Approval gate triggered
```

If the agent already holds the required capability (e.g., from a prior delegation), no gate
is triggered.

## Escalation (Design Intent)

Escalation is the process by which an agent requests elevated capabilities beyond its current
session scope.

### Escalation Flow

```text
1. Agent detects it needs Capability::Unlock for profile "production"
2. Agent does not hold Unlock in session_scope
3. Agent submits escalation request:
     - Requested: { Unlock }
     - Context: profile "production", reason "scheduled key rotation"
     - Requested TTL: 300s
4. Human operator reviews escalation request
5. Human approves with narrowed scope:
     DelegationGrant {
         delegator: <human-agent-id>,
         scope: { Unlock },
         initial_ttl: 300s,          // 5 minutes, not the 1 hour requested
         heartbeat_interval: 60s,
         nonce: <random>,
         signature: <Ed25519>,
     }
6. Agent's effective scope becomes:
     session_scope.union(granted_scope).intersection(delegator_scope)
7. After 300s, the grant expires and the agent loses Unlock
```

The human can:

- Approve with the requested scope and TTL.
- Approve with a narrower scope or shorter TTL (the human always narrows, never widens).
- Deny the request.

### Automatic Escalation Policies (Design Intent)

For well-defined, repetitive workflows, policies can pre-authorize escalation without
human-in-the-loop:

```toml
# config.toml
[[agents.auto_escalation]]
agent_type = "service"
unit = "backup-agent.service"
capabilities = ["secret-read"]
key_pattern = "backup/*"
max_ttl = "1h"
require_device_attestation = true
```

This pre-authorization avoids interactive approval for routine operations while maintaining
the capability lattice's scope-narrowing invariant.

## Audit Trail

All agent actions are attributed in the audit log. The audit entry for any operation
includes:

| Field | Source |
|-------|--------|
| Agent ID | `AgentIdentity.id` |
| Agent type | `AgentIdentity.agent_type` |
| Delegation chain | `AgentIdentity.delegation_chain` -- full chain from root delegator |
| Effective capabilities | `AgentIdentity.session_scope` at time of operation |
| Operation | The specific action performed (read, write, delete, unlock, etc.) |
| Profile | Which trust profile the operation targeted |
| Timestamp | Operation time |
| Attestations | Which attestation methods were active |

### Chain Attribution

For delegated operations, the audit trail records the entire delegation chain:

```text
Audit entry for SecretRead("production/api-key"):
  Agent: agent-01941c8a-... (AI, model_family: "claude-4")
  Delegation chain:
    [0] Human operator-5678 -> DelegationGrant { scope: {SecretRead, SecretList}, ttl: 3600s }
    [1] agent-01941c8a-... (current agent)
  Attestations: [NoiseIK, Delegation]
```

This provides full provenance: who authorized the AI agent, what scope was granted, and when
the delegation expires.

## Multi-Party Authorization (Design Intent)

For critical operations (e.g., deleting a production secret, rotating a root key),
multi-party authorization requires approval from multiple human operators.

### N-of-M Model

A multi-party policy specifies:

- **M** -- total number of designated approvers.
- **N** -- minimum number who must approve.
- **Timeout** -- how long to wait for approvals before the request expires.

```text
Policy for Capability::SecretDelete { key_pattern: "production/*" }:
  Approvers: [operator-A, operator-B, operator-C]  (M = 3)
  Required:  2                                       (N = 2)
  Timeout:   1 hour
```

### Authorization Flow

1. An agent or human requests a capability that matches a multi-party policy.
2. All M approvers are notified.
3. Each approver independently reviews and approves or denies.
4. When N approvals are collected, a composite `DelegationGrant` is issued:
   - The `scope` is the intersection of all approvers' individual scopes.
   - The `initial_ttl` is the minimum of all approvers' specified TTLs.
   - Each approver's signature is recorded.
5. If the timeout expires before N approvals are collected, the request is denied.

### Multi-Party Attestation

The `Attestation::Delegation` variant records the delegator's `AgentId` and the granted
`scope`. For multi-party authorization, multiple `Attestation::Delegation` entries appear
in the agent's `attestations` vector, one per approver.

## Trust Vector in Orchestration

The `TrustVector` (`core-types/src/security.rs`) provides the quantitative basis for
authorization decisions in mixed human-agent workflows:

| Dimension | Effect on Orchestration |
|-----------|------------------------|
| `authn_strength` | Higher strength reduces approval gate friction |
| `authz_freshness` | Stale authorization triggers re-approval |
| `delegation_depth` | Deeper chains require stronger attestations at each link |
| `device_posture` | Low posture (no memfd_secret, no TPM) may trigger additional approval requirements |
| `network_exposure` | Remote agents (`Encrypted`, `Onion`, `PublicInternet`) face stricter policies than local agents |
| `agent_type` | Metadata for policy matching, not a trust tier |

## Worked Example: AI Copilot Accessing Secrets

1. A developer invokes an AI copilot to debug a production issue.
2. The copilot (`AgentType::AI`, `model_family: "claude-4"`) needs to read a database
   connection string.
3. The copilot's `session_scope` does not include `SecretRead` for `production/*`.
4. An approval gate fires. The developer receives a prompt:

   ```text
   Agent "copilot-agent-01941c8a" (AI/claude-4) requests:
     SecretRead { key_pattern: "production/db-connection" }
   Reason: "Debugging connection timeout in production service"
   Approve for 10 minutes? [y/N]
   ```

5. The developer approves. A `DelegationGrant` is issued with `initial_ttl: 600s`.
6. The copilot reads the secret. The audit log records the read with the full delegation
   chain.
7. After 10 minutes, the grant expires. The copilot can no longer read production secrets.
