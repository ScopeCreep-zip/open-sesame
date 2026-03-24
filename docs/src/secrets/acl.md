# Access Control

The secrets daemon enforces per-daemon per-key access control over secret operations. ACL rules
are defined in the configuration file and evaluated as pure functions over config state with no
I/O or mutable state. Rate limiting provides a second layer of defense against enumeration
attacks.

## Per-Daemon Per-Key ACL

Access control is implemented in `daemon-secrets/src/acl.rs` as two pure functions:
`check_secret_access()` for get/set/delete operations, and `check_secret_list_access()` for
list operations.

### Configuration

ACL rules are defined in the config file under `[profiles.<name>.secrets.access]`. Each entry
maps a daemon name to a list of secret key names that daemon is permitted to access:

```toml
[profiles.work.secrets.access]
daemon-launcher = ["api-key", "db-password"]
daemon-wm = []
```

In this example, `daemon-launcher` can access `api-key` and `db-password` in the `work`
profile. `daemon-wm` has an explicit empty list, which denies all access including listing.

### Evaluation Rules for Get/Set/Delete

The `check_secret_access()` function evaluates the following rules in order. The first matching
rule determines the outcome:

| Condition | Result | Rationale |
|---|---|---|
| Profile not in config, no ACL policy on any profile | **Allow** | Backward compatibility with pre-ACL deployments. |
| Profile not in config, ACL policy exists on any other profile | **Deny** | Fail-closed. An attacker must not bypass ACL by requesting a nonexistent profile. |
| Profile in config, empty access map | **Allow** | No ACL policy configured for this profile. |
| Unregistered client (`verified_sender_name` is `None`), ACL policy exists | **Deny** | Unregistered clients cannot be identity-verified. |
| Daemon name absent from access map | **Allow** | Backward compatible default. Only daemons explicitly listed are restricted. |
| Daemon name present, key in allowed list | **Allow** | Explicit grant. |
| Daemon name present, key not in allowed list | **Deny** | Allowlist is strict. |
| Daemon name present, empty allowed list | **Deny** | Explicit deny-all. Empty list means no access, not unrestricted access. |

### Evaluation Rules for List

The `check_secret_list_access()` function follows the same rules as get/set/delete with one
difference at the daemon-level check:

| Condition | Result |
|---|---|
| Daemon name present, non-empty allowed list | **Allow** (has at least some access) |
| Daemon name present, empty allowed list | **Deny** ("no keys allowed" means "cannot even see what keys exist") |

All other conditions match `check_secret_access()`.

### Test Coverage

The ACL module contains 15 tests (`acl_001` through `acl_015`) that verify every branch of
both functions. Each test is prefixed with a `SECURITY INVARIANT` comment documenting the
property it protects.

## Unregistered Client Handling

Client identity is determined by the `verified_sender_name` field on each IPC message. This
field is stamped by the IPC bus server from the Noise IK static key registry -- it is not
self-declared by the client. The `check_secret_requester()` function in
`daemon-secrets/src/acl.rs` logs an anomaly warning if a daemon other than `daemon-secrets` or
`daemon-launcher` requests secrets, since those are the only expected requesters.

Unregistered clients (those with `verified_sender_name` set to `None`) are CLI relay connections
that transit through daemon-profile with Open clearance. When any ACL policy is active,
unregistered clients are denied access to both individual secrets and the key listing. This
prevents bypass via unauthenticated connections.

## Audit Logging

Every secret operation emits a structured audit log entry via the `audit_secret_access()`
function, regardless of whether the operation succeeds or is denied. The log entry includes:

- `event_type`: The operation (`get`, `set`, `delete`, `list`, `unlock`, `lock`).
- `requester`: The `DaemonId` (UUID) of the requesting client.
- `profile`: The target trust profile name.
- `key`: The secret key name (or `-` for operations that do not target a specific key).
- `outcome`: The result (`success`, `denied-locked`, `denied-acl`, `rate-limited`,
  `not-found`, etc.).

In addition to local `tracing` logs, each operation also emits a `SecretOperationAudit` IPC
event that is published to the bus for persistent logging by daemon-profile. This event is
fire-and-forget: delivery failure does not block or fail the secret operation. Both audit paths
are required; the code comments explicitly state that neither should be removed assuming the
other is sufficient.

## Rate Limiting

Rate limiting is implemented in `daemon-secrets/src/rate_limit.rs` using the `governor` crate's
in-memory GCRA (Generic Cell Rate Algorithm) token bucket.

### Configuration

The rate limiter is configured with a fixed quota:

- **Sustained rate**: 10 requests per second
- **Burst capacity**: 20 requests

These values are hardcoded in `SecretRateLimiter::new()`.

### Per-Daemon Buckets

Each daemon receives an independent rate limit bucket, keyed on its `verified_sender_name`.
Exhausting one daemon's quota does not affect any other daemon's ability to access secrets.
Buckets are created lazily on first request from each daemon.

### Anonymous Client Isolation

All unregistered clients (those with `verified_sender_name` set to `None`) share a single rate
limit bucket keyed on the sentinel value `__anonymous__`. This prevents bypass via the
new-connection-per-request pattern: an attacker who opens a fresh IPC connection for every
request still draws from the same shared anonymous bucket.

The anonymous bucket is independent from all named daemon buckets. Exhausting the anonymous
bucket does not affect registered daemons, and vice versa.

### Rate Limiter Reset

When a lock-all operation succeeds (no profile specified in `LockRequest`), the rate limiter is
reset to a fresh instance with empty buckets. This occurs in `handle_lock_request()` in
`daemon-secrets/src/unlock.rs`.

### Test Coverage

The rate limiting module contains five tests (`rate_001` through `rate_005`) that verify:

- Burst capacity of 20 requests is allowed (`rate_001`).
- The 21st request after burst exhaustion is denied (`rate_002`).
- Daemon buckets are independent (`rate_003`).
- The anonymous bucket is independent from named daemon buckets (`rate_004`).
- All anonymous clients share a single bucket (`rate_005`).
