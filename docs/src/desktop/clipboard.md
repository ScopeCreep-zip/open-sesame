# Clipboard Daemon

The `daemon-clipboard` process captures the text selections of the Wayland clipboard into
per-profile history and serves that history over the Noise IK IPC bus. It runs a single-threaded
tokio runtime (`current_thread`) beside one capture thread, and connects to the bus as a
`BusClient`.

## Capture

`platform_linux::clipboard::spawn_capture` watches the regular clipboard of the first seat through
wl-clipboard-rs's `Watcher`, over `ext-data-control-v1` or, when the compositor lacks it,
`wlr-data-control-v1`. cosmic-comp, sway, Hyprland, niri, and KWin offer data-control to clients
outside a security context; GNOME's Mutter does not, and there the daemon serves history without
capturing (`clipboard capture is off` in its log). Without a Wayland session capture is off as
well.

For each new selection the watcher reads the text type wl-paste reads (`select_mime_type` with
`MimeType::Text`: `text/plain;charset=utf-8`, then `UTF8_STRING`, then any text type). A selection
is skipped when it offers no text, its text is not UTF-8, it exceeds 1 MiB, or its source does not
deliver it within 2 seconds. The watcher's blocking wait runs on the `clipboard-capture` thread;
captures cross to the runtime over a channel. A Wayland failure after the start reconnects with
exponential backoff from 1 to 30 seconds.

### The Profile an Entry Belongs To

A selection is filed under the default profile: the one daemon-profile reports in
`StatusResponse` when daemon-clipboard starts (the configured `[global] default_profile` when
daemon-profile does not answer within 5 seconds), then each `DefaultProfileChanged` daemon-profile
announces when the context engine or `sesame profile default` changes it. Only announcements whose
server-verified sender is daemon-profile are followed.

Entries carry the installation-scoped profile identity, `ProfileId::of_profile` (UUID v5 of
`profile:<name>` in the installation namespace of `installation.toml`), the identity daemon-profile
and the audit log use. Before `sesame init` writes the installation identity, nothing is recorded;
the identity is read again on every configuration reload.

### Sensitivity

A selection whose source offers the password manager hint (`x-kde-passwordManagerHint` with the
content `secret`, as KeePassXC and other password managers set it) is a secret when the profile's
`clipboard.detect_sensitive` is true:

- It is held in memory only, in protected memory (`SensitiveBytes`), and is never written to the
  database.
- Its preview is `[secret]`; its content is served by `ClipboardGet` until it expires.
- It expires `clipboard.sensitive_ttl_s` seconds after capture (`ClipboardEntryExpired` is
  published); with a TTL of 0 it is not kept at all.

Every other selection is `Public` and persisted. A selection that repeats the profile's newest
persisted entry (same text and type) is not recorded again, and after each insert the profile's
history is pruned to its `clipboard.max_history` newest entries (0 records nothing). Each new entry
is announced as `ClipboardChanged { entry_id, sensitivity, content_type, profile_id }`.

| Setting (`[profiles.<name>.clipboard]`) | Default | Effect |
| --- | --- | --- |
| `max_history` | 1000 | Persisted entries kept per profile |
| `sensitive_ttl_s` | 30 | Seconds a secret is held |
| `detect_sensitive` | true | Honor the password manager hint |

## Storage

The database is `<cache dir>/clipboard.db` (`core_layout::Layout::clipboard_db`), by default
`~/.cache/open-sesame/clipboard.db`. Startup creates the parent directory when absent, opens the
database with `rusqlite`, and applies the schema idempotently:

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

`profile_id` holds the entry's `ProfileId`. The preview is the first 80 characters of the text,
with line breaks and other control characters shown as spaces. The index serves the per-profile,
most-recent-first history query and the pruning.

## Decoding Rows

A row decodes into a `ClipboardEntry` strictly; a malformed value is an error, never a default:

- `entry_id` and `profile_id` must be UUID strings.
- `sensitivity` must be one of the labels below. An unknown label is an error: a value that
  cannot be classified is never downgraded to `Public`.
- `timestamp_ms` must be non-negative.

| Label | `SensitivityClass` |
| --- | --- |
| `public` | `Public` |
| `confidential` | `Confidential` |
| `secret` | `Secret` |
| `topsecret` | `TopSecret` |

## IPC Interface

| Message | Response | Behavior |
| --- | --- | --- |
| `ClipboardHistory { profile, limit }` | `ClipboardHistoryResponse { entries }` | The profile's newest `limit` entries, held and persisted |
| `ClipboardGet { entry_id }` | `ClipboardGetResponse { content, content_type }` | One entry's content, or `None`s |
| `ClipboardClear { profile }` | `ClipboardClearResponse { success }` | Deletes the profile's held and persisted entries |

History entries carry `entry_id`, `profile_id`, `content_type`, `sensitivity`, `preview`, and
`timestamp_ms`, but not `content`; `ClipboardGet` returns the content of one entry. History and
clear resolve the named profile to its `ProfileId`; `ClipboardGet` selects by `entry_id` alone: an
entry ID (`clip-<uuid>`, UUIDv7, as `sesame clipboard history` prints it) names its entry in any
profile.

A failed history query is logged and answered with an empty list; a failed clear, or a clear
before `sesame init`, is answered with `success: false`; a failed or empty get is answered with
`None` content and type. Responses carry the request's message ID (`Message::with_correlation`).
The daemon ignores messages it published itself, and other message kinds.

## Process Hardening

On Linux the daemon calls `platform_linux::security::harden_process()`, sets resource limits
(`nofile = 4096`, `memlock_bytes = 0`), probes `memfd_secret` (`core_types::init_secure_memory()`),
and applies a Landlock and seccomp sandbox built from the layout (`core_daemon::sandbox`) before
the runtime and the capture thread start:

- **Bus client** (`ipc_client_rules`): the per-daemon key directory
  (`$XDG_RUNTIME_DIR/pds/keys`, read), the bus endpoint (`$XDG_RUNTIME_DIR/pds/bus.endpoint`,
  read), and the bus socket (`$XDG_RUNTIME_DIR/pds/bus.sock`, connect).
- **Configuration** (`config_rules`, read-only): the configuration directory (`~/.config/pds`,
  with `installation.toml`) and the directories its symlinks resolve into (for example
  `/nix/store`).
- **systemd notification** (`notify_rules`): the `$NOTIFY_SOCKET` socket when it is a filesystem
  socket that exists.
- **Wayland** (`wayland_rules`): the compositor socket (`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`,
  connect).
- **Cache** (read-write): the cache directory holding the database.

The seccomp allowlist is the base set (file I/O, memory, threads, the event loop, Unix sockets,
pipes, signals, inotify, `memfd_secret`) plus SQLite's `flock`, `fsync`, and `fdatasync`. A
selection is received through a pipe whose write end the compositor passes to the source client;
no file system grant is involved. When the sandbox cannot be applied, startup fails; the daemon
never runs unconfined.

## Lifecycle

1. **Startup**: process hardening; `core_daemon::startup()` (layout, directory bootstrap,
   configuration load); the database; the sandbox; the installation identity; the configuration
   watch; capture; the bus connection (`core_daemon::connect_bus`); the default profile
   (`StatusRequest`).
2. **Announcement**: `DaemonStarted { capabilities: ["clipboard", "history"] }`.
3. **Readiness**: `READY=1` (`platform_linux::systemd::notify_ready()`).
4. **Event loop** (`core_daemon::EventLoop`): the 15-second watchdog, bus messages, captured
   selections, the next secret's expiry, configuration reloads (`ConfigReloaded { changed_keys:
   ["clipboard"] }` is published), and SIGINT/SIGTERM. A closed bus ends the process (exit status
   1) for systemd to restart.
5. **Shutdown**: `DaemonStopped { reason: "shutdown" }`. Held secrets are zeroized when dropped.
