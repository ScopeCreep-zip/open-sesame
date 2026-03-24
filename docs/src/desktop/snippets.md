# Snippets Daemon

The `daemon-snippets` process manages text snippet templates with profile-scoped namespaces. It
runs as a single-threaded tokio process (`current_thread` runtime) connected to the Noise IK IPC
bus as a `BusClient`.

## Storage

Snippets are stored in an in-memory `HashMap<(String, String), String>` keyed by
`(profile_name, trigger)` with the template string as the value. The type alias `SnippetMap`
defines this type.

The config schema does not yet include a dedicated snippets section, so `build_snippet_map()`
returns an empty `HashMap` on startup and after every config reload. All snippet data is
populated at runtime via `SnippetAdd` IPC messages.

On config hot-reload, the snippet map is rebuilt by calling `build_snippet_map()` with the new
config, which currently clears all runtime-added snippets. This behavior will change when a
persistent config-based snippet definition is added to the schema.

## Profile Scoping

Every snippet is associated with a trust profile name as the first element of its
`(profile, trigger)` composite key. This ensures that two profiles can define different
expansions for the same trigger string without collision.

All operations are profile-scoped:

- **`SnippetList`**: Filters the entire map with
  `.filter(|((p, _), _)| p == &profile_str)`, returning only snippets belonging to the
  requested profile.
- **`SnippetExpand`**: Performs an exact `HashMap::get()` lookup with the `(profile, trigger)`
  tuple.
- **`SnippetAdd`**: Inserts or overwrites at the `(profile, trigger)` key. A snippet added
  under profile `"work"` is not visible from profile `"personal"`.

## IPC Interface

| Message | Response | Description |
|---------|----------|-------------|
| `SnippetList` | `SnippetListResponse` | Returns all snippets for the given profile |
| `SnippetExpand` | `SnippetExpandResponse` | Looks up the template for an exact trigger |
| `SnippetAdd` | `SnippetAddResponse` | Inserts or overwrites a snippet |
| `KeyRotationPending` | -- | Reconnects with a rotated IPC keypair |

The `SnippetList` response returns `Vec<SnippetInfo>` where each entry contains `trigger` and
`template_preview`. Previews are truncated to 80 characters: templates longer than 80 characters
are cut to 77 characters with `...` appended.

All IPC responses are correlated to the original request via
`Message::with_correlation(msg.msg_id)`.

## Trigger Matching

Trigger matching is exact and case-sensitive. The `trigger` field from a `SnippetExpand` request
must match the stored trigger string byte-for-byte. The snippet map uses `HashMap::get()` with
the `(profile.to_string(), trigger.clone())` tuple as the key. No fuzzy matching, prefix
matching, or normalization is performed.

## Template Format

Templates are stored and returned as plain strings. The module-level documentation describes
variable substitution and secret injection as design goals, but the current implementation
returns the template string verbatim from `SnippetExpand` without any processing. The expansion
pipeline for variable substitution (`${VAR}`) and secret injection (`${secret:name}`) is not yet
implemented.

## Process Hardening

On Linux, daemon-snippets applies the following security measures:

- `platform_linux::security::harden_process()` for process-level hardening.
- Resource limits: `nofile = 4096`, `memlock_bytes = 0`.
- `core_types::init_secure_memory()` for `memfd_secret` probing.
- Landlock filesystem sandbox restricting access to:
  - IPC key directory (`$XDG_RUNTIME_DIR/pds/keys/`) -- read-only.
  - Bus public key (`$XDG_RUNTIME_DIR/pds/bus.pub`) -- read-only.
  - Bus socket (`$XDG_RUNTIME_DIR/pds/bus.sock`) -- read-write.
  - Config directory (`~/.config/pds/`) -- read-only.
  - Config symlink targets (e.g., `/nix/store` paths) -- read-only.
- Seccomp syscall filter with an allowlist for standard I/O, memory management, networking (IPC
  socket), inotify (config hot-reload), `memfd_secret`, and process lifecycle syscalls.
- The sandbox panics on application failure, refusing to run unsandboxed.

The sandbox is notably more restrictive than other desktop daemons: daemon-snippets requires no
Wayland socket access, no `/dev/input` access, and no cache directory writes.

## Lifecycle

1. **Startup**: Process hardening, directory bootstrap, config load, snippet map build (empty),
   IPC bus connection with keypair retry (5 attempts, 500ms interval), sandbox application.
2. **Announcement**: Publishes `DaemonStarted { capabilities: ["snippets", "expansion"] }`.
3. **Readiness**: Calls `platform_linux::systemd::notify_ready()`.
4. **Event loop**: `tokio::select!` over watchdog timer (15s), IPC messages, config reload
   notifications (rebuilds snippet map from config), SIGINT, and SIGTERM.
5. **Shutdown**: Publishes `DaemonStopped { reason: "shutdown" }`.
