# Clipboard Daemon

The `daemon-clipboard` process manages per-profile clipboard history with sensitivity
classification. It runs as a single-threaded tokio process (`current_thread` runtime) connected
to the Noise IK IPC bus as a `BusClient`.

## Storage

Clipboard entries are stored in a SQLite database at `~/.cache/open-sesame/clipboard.db`, opened
via `rusqlite::Connection`. The parent directory is created if absent. The schema consists of a
single table:

```sql
CREATE TABLE IF NOT EXISTS clipboard_entries (
    entry_id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    content TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'text/plain',
    sensitivity TEXT NOT NULL DEFAULT 'public',
    preview TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clipboard_profile
    ON clipboard_entries(profile_id, timestamp_ms DESC);
```

The index on `(profile_id, timestamp_ms DESC)` supports efficient per-profile history queries
ordered by recency.

## Per-Profile History

All clipboard entries are associated with a `profile_id`. Queries filter by profile, ensuring
that clipboard history from one trust profile is not visible to another. This scoping is enforced
at the storage layer -- every `SELECT`, `DELETE`, and aggregate query includes a
`WHERE profile_id = ?` predicate.

## Sensitivity Classification

Each clipboard entry carries a `sensitivity` field stored as a text string in SQLite and mapped
to the `SensitivityClass` enum on read:

| Value | Enum Variant | Description |
|-------|-------------|-------------|
| `public` | `SensitivityClass::Public` | Non-sensitive content |
| `confidential` | `SensitivityClass::Confidential` | Internal or business data |
| `secret` | `SensitivityClass::Secret` | Credentials, tokens |
| `topsecret` | `SensitivityClass::TopSecret` | High-value secrets |

Unknown string values default to `Public`. The `entry_id` field uses UUIDv7
(`uuid::Uuid::now_v7()`), providing time-ordered unique identifiers.

## IPC Interface

The daemon handles the following IPC messages:

| Message | Response | Description |
|---------|----------|-------------|
| `ClipboardHistory` | `ClipboardHistoryResponse` | Returns the most recent `limit` entries for a profile |
| `ClipboardGet` | `ClipboardGetResponse` | Retrieves full content for a specific entry by UUID |
| `ClipboardClear` | `ClipboardClearResponse` | Deletes all clipboard entries for a profile |
| `KeyRotationPending` | -- | Reconnects with a rotated IPC keypair |

The `ClipboardHistory` response includes `entry_id`, `content_type`, `sensitivity`, `profile_id`,
`preview`, and `timestamp_ms` per entry. The `content` field is not included in history responses
to avoid transmitting large payloads over IPC. Use `ClipboardGet` to retrieve full content.

All IPC responses are correlated to the original request via `Message::with_correlation(msg.msg_id)`.

## Process Hardening

On Linux, daemon-clipboard applies the following security measures:

- `platform_linux::security::harden_process()` for process-level hardening.
- Resource limits: `nofile = 4096`, `memlock_bytes = 0`.
- `core_types::init_secure_memory()` for `memfd_secret` probing.
- Landlock filesystem sandbox restricting access to:
  - IPC key directory (`$XDG_RUNTIME_DIR/pds/keys/`) -- read-only.
  - Bus public key (`$XDG_RUNTIME_DIR/pds/bus.pub`) -- read-only.
  - Bus socket (`$XDG_RUNTIME_DIR/pds/bus.sock`) -- read-write.
  - Wayland socket (`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`) -- read-write.
  - Cache directory (`~/.cache/open-sesame/`) -- read-write (for SQLite database).
  - Config symlink targets (e.g., `/nix/store` paths) -- read-only.
- Seccomp syscall filter with an allowlist including: SQLite-relevant syscalls (`fsync`,
  `fdatasync`, `flock`, `pread64`, `lseek`), Wayland protocol syscalls (`socket`, `connect`,
  `sendmsg`, `recvmsg`), inotify syscalls for config hot-reload, and `memfd_secret` for secure
  memory.
- The sandbox panics on application failure (`"refusing to run unsandboxed"`), ensuring the
  daemon never operates without confinement.

## Configuration

The daemon loads configuration via `core_config::load_config()` and establishes a `ConfigWatcher`
with a callback channel for hot-reload. On config change, the callback sends a notification, and
the event loop publishes `ConfigReloaded { changed_keys: ["clipboard"] }` to the IPC bus.

## Lifecycle

1. **Startup**: Process hardening, directory bootstrap, config load, IPC bus connection with
   keypair retry (5 attempts, 500ms interval), sandbox application.
2. **Announcement**: Publishes `DaemonStarted { capabilities: ["clipboard", "history"] }`.
3. **Readiness**: Calls `platform_linux::systemd::notify_ready()`.
4. **Event loop**: `tokio::select!` over watchdog timer (15s), IPC messages, config reload
   notifications, SIGINT, and SIGTERM.
5. **Shutdown**: Publishes `DaemonStopped { reason: "shutdown" }`.
