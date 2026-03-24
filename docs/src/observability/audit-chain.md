# Audit Chain

Open Sesame maintains a tamper-evident audit log using a BLAKE3 hash chain. Every auditable
operation appends a JSONL entry whose `prev_hash` field contains the hash of the previous
entry's serialized JSON. Tampering with any entry invalidates all subsequent hashes.

## Hash Chain Mechanics

The `AuditLogger` in `core-profile/src/audit.rs` maintains three pieces of mutable state:

- `last_hash`: the hex-encoded hash of the most recently written entry.
- `sequence`: a monotonically increasing counter (starts at 1).
- `hash_algorithm`: either `Blake3` or `Sha256` (configurable at construction, default is
  BLAKE3).

When `append(action)` is called:

1. The sequence is incremented.
2. A wall-clock timestamp (milliseconds since Unix epoch) is captured.
3. An `AuditEntry` is constructed with the current `last_hash` as its `prev_hash`.
4. The entry is serialized to a single-line JSON string.
5. The JSON bytes are hashed with the configured algorithm (BLAKE3 or SHA-256).
6. The resulting hex digest becomes the new `last_hash`.
7. The JSON line is written to the underlying `Write` sink and flushed.

The first entry in a fresh log has an empty string as its `prev_hash`.

## Entry Structure

Each JSONL line contains:

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
|---|---|---|
| `sequence` | `u64` | Monotonically increasing, starting at 1. |
| `timestamp_ms` | `u64` | Wall clock time in milliseconds since Unix epoch. |
| `action` | `AuditAction` | The auditable operation (see variants below). |
| `prev_hash` | `String` | Hex-encoded hash of the previous entry's JSON. Empty for the first entry. |
| `agent_id` | `Option<AgentId>` | The agent identity that triggered the action, if known. |

## AuditAction Variants

The `AuditAction` enum in `core-profile/src/lib.rs` is `#[non_exhaustive]` and currently
defines:

| Variant | Fields | Description |
|---|---|---|
| `ProfileActivated` | `target: ProfileId`, `duration_ms: u32` | A trust profile was activated. |
| `ProfileDeactivated` | `target: ProfileId`, `duration_ms: u32` | A trust profile was deactivated. |
| `ProfileActivationFailed` | `target: ProfileId`, `reason: String` | Activation failed. |
| `DefaultProfileChanged` | `previous: ProfileId`, `current: ProfileId` | The default profile for new launches changed. |
| `IsolationViolationAttempt` | `from_profile`, `resource` | A cross-profile resource access was blocked. |
| `SecretAccessed` | `profile_id: ProfileId`, `secret_ref: String` | A secret was read from a vault. |
| `KeyRotationStarted` | `daemon_name: String`, `generation: u64` | IPC bus key rotation began. |
| `KeyRotationCompleted` | `daemon_name: String`, `generation: u64` | Key rotation completed. |
| `KeyRevoked` | `daemon_name: String`, `reason: String`, `generation: u64` | A daemon's key was revoked. |
| `SecretOperationAudited` | `action`, `profile`, `key`, `requester`, `outcome` | A secret operation was logged. |
| `AgentConnected` | `agent_id: AgentId`, `agent_type: AgentType` | An agent connected. |
| `AgentDisconnected` | `agent_id: AgentId`, `reason: String` | An agent disconnected. |
| `InstallationCreated` | `id`, `org`, `machine_binding_present` | A new installation was registered. |
| `ProfileIdMigrated` | `name`, `old_id`, `new_id` | A profile's internal ID was migrated. |
| `AuthorizationRequired` | `request_id: Uuid`, `operation: String` | An operation requires authorization. |
| `AuthorizationGranted` | `request_id`, `delegator`, `scope` | Authorization was granted. |
| `AuthorizationDenied` | `request_id: Uuid`, `reason: String` | Authorization was denied. |
| `AuthorizationTimeout` | `request_id: Uuid` | An authorization request timed out. |
| `DelegationRevoked` | `delegation_id`, `revoker`, `reason` | A delegation was revoked. |
| `HeartbeatRenewed` | `delegation_id`, `renewal_source` | A delegation heartbeat was renewed. |
| `FederationSessionEstablished` | `session_id`, `remote_installation` | A federation session was established. |
| `FederationSessionTerminated` | `session_id: Uuid`, `reason: String` | A federation session ended. |
| `PostureEvaluated` | `composite_score: f64` | A security posture evaluation produced a score. |

## Tamper Detection: sesame audit verify

The `sesame audit verify` command in `open-sesame/src/audit.rs` reads the audit log at
`~/.config/pds/audit.jsonl` and replays the hash chain:

```text
$ sesame audit verify
OK: 1247 entries verified.
```

The verification algorithm in `core_profile::verify_chain`:

1. Iterates each non-empty JSONL line in order.
2. Parses each line as an `AuditEntry`.
3. Checks that `entry.prev_hash` matches the hash computed from the previous line's raw JSON
   bytes.
4. If any mismatch is found, returns an error identifying the broken sequence number and the
   expected vs. actual `prev_hash`.

Verification detects: modified entries, deleted entries, reordered entries, and injected entries.
The test suite in `core-profile/src/audit.rs` explicitly validates detection of all four
tampering modes.

## sesame audit tail

The `sesame audit tail` command displays recent audit entries:

```bash
sesame audit tail 10
sesame audit tail --follow
```

Without `--follow`, the command reads the last N entries from the log file and pretty-prints
each as indented JSON separated by `---` dividers.

With `--follow`, it watches the audit log file for new appends using
`notify::RecommendedWatcher` (inotify on Linux). When the file grows, only the new bytes are
read (via `Seek::SeekFrom::Start(last_len)`), parsed line by line, and printed. The follow loop
exits on `Ctrl-C` (SIGINT).

## Chain Recovery After Corruption

On daemon-profile startup, the audit logger loads its state from the last line of the existing
log file. The `load_audit_state` function in `daemon-profile/src/context.rs`:

1. Reads the file contents (returns `(empty, 0)` if the file does not exist).
2. Finds the last non-empty line by iterating in reverse.
3. Attempts to parse it as an `AuditEntry`.
4. If successful, computes its BLAKE3 hash and extracts its sequence number.
5. If parsing fails (corrupt last entry), falls back to `(empty_hash, 0)`, starting a fresh
   chain segment.

After loading, the startup code runs `verify_chain` on the existing log if the sequence is
greater than 0. A verification failure is logged at `error` level but does not prevent the
daemon from starting -- the daemon continues appending to the potentially-broken chain.

## Chain Continuity Across Restarts

The audit chain survives daemon restarts. On restart, daemon-profile loads the last hash and
sequence from disk and continues appending. The hash of the last pre-restart entry becomes the
`prev_hash` of the first post-restart entry, maintaining an unbroken chain. The test
`chain_resumes_after_restart` in `core-profile/src/audit.rs` validates this property across two
simulated sessions with five total entries.

## File Format and Location

- **Path**: `~/.config/pds/audit.jsonl` (resolved via `core_config::config_dir()`).
- **Format**: JSON Lines -- one JSON object per line, newline-delimited.
- **Hash algorithm**: BLAKE3 by default. SHA-256 is supported as an alternative. The algorithm
  must be consistent within a single log file for verification to succeed.
- **Write mode**: append-only (`OpenOptions::new().create(true).append(true)`). Each write is
  followed by an explicit `flush()` via `BufWriter`.
- **Agent identity**: the `default_agent_id` is derived from the installation namespace and the
  Unix UID of the running process:
  `uuid::Uuid::new_v5(&install_ns, "agent:human:uid{uid}")`.

## Retention and Rotation

The current implementation does not perform automatic log rotation or retention. The audit log
grows unboundedly. External log rotation (e.g., `logrotate`) can be applied, but rotating the
file severs the hash chain -- `sesame audit verify` can only validate entries present in a
single contiguous file. Operators who require forensic auditability across rotation boundaries
should archive rotated segments and verify them independently.
