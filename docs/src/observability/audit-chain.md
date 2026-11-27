# Audit Chain

Open Sesame keeps a tamper-evident audit log: every auditable operation appends a JSONL entry
whose `prev_hash` is the hash of the previous entry's serialized line. Changing, deleting,
reordering, or injecting an entry breaks every later link.

`core-profile/src/audit.rs` is the only reader and writer of the log: `open_audit_log`
resumes the chain for appending, `read_audit_log` reads it, and `verify_audit_log` replays
it.

## Hash Algorithm

The chain hash is the configured `[crypto] audit_hash`: BLAKE3 (default) or SHA-256 for
governance-compatible deployments. A chain is verifiable only under the algorithm it was
written with: verifying a SHA-256 chain as BLAKE3 fails at the second entry.

## Appending

`AuditLogger` holds the chain head (`last_hash`, the hex hash of the last written line, and
`sequence`), the hash algorithm, and the default agent identity. `append(action)`:

1. Reads the wall clock (milliseconds since the Unix epoch); a clock before the epoch is an
   error.
2. Builds an `AuditEntry` with sequence `sequence + 1` and `prev_hash` the current head.
3. Serializes it to one JSON line, writes it, and flushes.
4. Only after the write succeeds, advances the head to the new line's hash and sequence: a
   failed write leaves the logger consistent with the log.

The first entry of a fresh log has an empty `prev_hash`.

## Entry Structure

```json
{
  "sequence": 1,
  "timestamp_ms": 1700000000000,
  "action": { "ProfileActivated": { "target": "...", "duration_ms": 42 } },
  "prev_hash": "",
  "agent_id": "..."
}
```

| Field | Type | Description |
| --- | --- | --- |
| `sequence` | `u64` | Monotonically increasing, starting at 1. |
| `timestamp_ms` | `u64` | Wall clock time in milliseconds since the Unix epoch. |
| `action` | `AuditAction` | The auditable operation (below). |
| `prev_hash` | `String` | Hex hash of the previous entry's line. Empty for the first entry. |
| `agent_id` | `Option<AgentId>` | The agent that triggered the action; omitted when unknown. |

## AuditAction Variants

`AuditAction` (`core-profile/src/lib.rs`, `#[non_exhaustive]`):

| Variant | Fields | Description |
| --- | --- | --- |
| `ProfileActivated` | `target`, `duration_ms` | A trust profile was activated. |
| `ProfileDeactivated` | `target`, `duration_ms` | A trust profile was deactivated. |
| `ProfileActivationFailed` | `target`, `reason` | An activation failed. |
| `ProfileDeactivationFailed` | `target`, `reason` | A deactivation failed or was not confirmed. |
| `DefaultProfileChanged` | `previous`, `current` | The default profile for new launches changed. |
| `IsolationViolationAttempt` | `from_profile`, `resource` | A cross-profile resource access was blocked. |
| `SecretAccessed` | `profile_id`, `secret_ref` | A secret was read from a vault. |
| `KeyRotationStarted` | `daemon_name`, `generation` | IPC key rotation began. |
| `KeyRotationCompleted` | `daemon_name`, `generation` | Key rotation completed. |
| `KeyRevoked` | `daemon_name`, `reason`, `generation` | A daemon's key was revoked. |
| `SecretOperationAudited` | `action`, `profile`, `key`, `requester`, `requester_name`, `outcome` | A secret operation was performed or denied. |
| `AgentConnected` | `agent_id`, `agent_type` | An agent connected. |
| `AgentDisconnected` | `agent_id`, `reason` | An agent disconnected. |
| `InstallationCreated` | `id`, `org`, `machine_binding_present` | An installation was created. |
| `AuthorizationRequired` | `request_id`, `operation` | An operation requires authorization. |
| `AuthorizationGranted` | `request_id`, `delegator`, `scope` | Authorization was granted. |
| `AuthorizationDenied` | `request_id`, `reason` | Authorization was denied. |
| `AuthorizationTimeout` | `request_id` | An authorization request timed out. |
| `DelegationRevoked` | `delegation_id`, `revoker`, `reason` | A delegation was revoked. |
| `HeartbeatRenewed` | `delegation_id`, `renewal_source` | A delegation heartbeat was renewed. |
| `FederationSessionEstablished` | `session_id`, `remote_installation` | A federation session was established. |
| `FederationSessionTerminated` | `session_id`, `reason` | A federation session ended. |
| `PostureEvaluated` | `composite_score` | A device posture evaluation produced a score. |

## Verification: sesame audit verify

`sesame audit verify` replays the chain of the log under the configured algorithm:

```text
$ sesame audit verify
OK: 1247 entries verified.
```

`verify_chain` iterates the non-empty lines in order, parses each as an `AuditEntry`, and
checks that its `prev_hash` is the hash of the previous line. The first mismatch is an error
naming the sequence number and the expected and actual `prev_hash`; an unparseable line is
an error naming its line number. The `core-profile` tests cover modified, deleted, and
reordered entries, and a chain resumed across a restart.

## sesame audit tail

```bash
sesame audit tail -n 10
sesame audit tail --follow
```

Without `--follow`, the last N entries are pretty-printed. With `--follow`, new appends are
printed as the file grows, until `Ctrl-C`.

## Startup and Recovery

daemon-profile opens the log once `installation.toml` exists (`open_audit`):

1. `open_audit_log` reads the chain head from the log's last non-empty line: its hash under
   the configured algorithm and its sequence. A missing or empty log starts a fresh chain.
2. A last line that does not parse is an error naming the file and `sesame audit verify`:
   starting a fresh chain after it would fork the log, so daemon-profile does not start until
   the log is inspected.
3. `verify_audit_log` then replays the whole chain. A broken chain is logged at `error` and
   the daemon keeps running: the log stays tamper-evident (`sesame audit verify` reports the
   break), and refusing to start would also stop recording new events.

The chain survives restarts: the first entry after a restart links to the last entry before
it.

## File Format and Location

- **Path**: `Layout::audit_log`, `<config dir>/audit.jsonl` (`~/.config/pds/audit.jsonl`).
- **Format**: JSON Lines, one entry per line.
- **Mode**: opened for appending and restricted to its owner (`0600`), including a log that
  already existed with wider permissions.
- **Agent identity**: daemon-profile's default agent is
  `uuid::Uuid::new_v5(&install_ns, "agent:human:uid{uid}")`, from the installation namespace
  and the process's Unix UID.

## Retention and Rotation

The log is not rotated or pruned by Open Sesame and grows without bound. External rotation
(for example `logrotate`) severs the chain at the rotation point: `sesame audit verify`
validates one contiguous file, so rotated segments must be archived and verified on their
own.
