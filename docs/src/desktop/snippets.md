# Snippets Daemon

The `daemon-snippets` process holds text snippets per trust profile and answers list, expand, and
add requests over the Noise IK IPC bus. It runs a single-threaded tokio runtime
(`current_thread`) and connects to the bus as a `BusClient`.

## Storage

Snippets live in memory only, in a `BTreeMap<(String, String), String>` (the `SnippetMap` alias)
keyed by `(profile, trigger)` with the template as the value. The ordered map makes listings
deterministic: `SnippetList` returns a profile's snippets sorted by trigger.

The configuration schema has no snippets section. `build_snippet_map()` returns an empty map at
startup and on every configuration reload, so snippets exist only from a `SnippetAdd` until the
next reload or restart; a reload clears them.

## Profile Scoping

The profile is the first half of every key, so two profiles hold the same trigger without
collision, and no operation crosses profiles:

- **`SnippetList`** returns the entries whose key's profile is the requested one.
- **`SnippetExpand`** looks up the exact `(profile, trigger)` key.
- **`SnippetAdd`** inserts or replaces the `(profile, trigger)` key.

## IPC Interface

| Message | Response | Behavior |
| --- | --- | --- |
| `SnippetList { profile }` | `SnippetListResponse { snippets }` | The profile's snippets, by trigger |
| `SnippetExpand { profile, trigger }` | `SnippetExpandResponse { expanded }` | The template, or `None` |
| `SnippetAdd { profile, trigger, template }` | `SnippetAddResponse { success: true }` | Insert or replace |

Each `SnippetInfo` in a list carries `trigger` and `template_preview`. A template of at most 80
characters is its own preview; a longer one previews as its first 77 characters followed by
`...`. Previews count characters, not bytes, so a multibyte template never splits a code point.

Responses carry the request's message ID (`Message::with_correlation`). The daemon ignores
messages it published itself, and other message kinds.

## Triggers and Templates

Trigger lookup is exact and case-sensitive: the requested trigger must equal the stored one
byte for byte. `SnippetExpand` returns the stored template verbatim; templates are plain text,
with no variable or secret substitution.

## CLI

`sesame snippet list -p <profile>`, `sesame snippet expand -p <profile> <trigger>`, and
`sesame snippet add -p <profile> <trigger> <template>` send these requests. `expand` prints the
template, or fails naming the trigger when the profile has no such snippet.

## Process Hardening

On Linux the daemon calls `platform_linux::security::harden_process()`, sets resource limits
(`nofile = 4096`, `memlock_bytes = 0`), probes `memfd_secret` (`core_types::init_secure_memory()`),
and applies a Landlock and seccomp sandbox built from the layout (`core_daemon::sandbox`):

- **Bus client** (`ipc_client_rules`): the per-daemon key directory
  (`$XDG_RUNTIME_DIR/pds/keys`, read), the bus public key (`$XDG_RUNTIME_DIR/pds/bus.pub`,
  read), and the bus socket (`$XDG_RUNTIME_DIR/pds/bus.sock`, connect).
- **Configuration** (`config_rules`, read-only): the configuration directory (`~/.config/pds`)
  and the directories its symlinks resolve into (for example `/nix/store`).
- **systemd notification** (`notify_rules`): the `$NOTIFY_SOCKET` socket when it is a filesystem
  socket that exists.

It needs no Wayland socket, no `/dev/input`, and no cache directory. The seccomp allowlist covers
standard I/O, memory management, the IPC socket, inotify for configuration reload,
`memfd_secret`, and process lifecycle calls. When the sandbox cannot be applied, startup fails
with "refusing to run unsandboxed"; the daemon never runs unconfined.

## Lifecycle

1. **Startup**: process hardening; `core_daemon::startup()` (layout, directory bootstrap,
   configuration load); the empty snippet map; the configuration watch; the bus connection
   (`core_daemon::connect_bus`, up to 5 attempts 500 ms apart); the sandbox.
2. **Announcement**: `DaemonStarted { capabilities: ["snippets", "expansion"] }`.
3. **Readiness**: `READY=1` (`platform_linux::systemd::notify_ready()`).
4. **Event loop**: `tokio::select!` over the 15-second watchdog, bus messages, configuration
   reloads (the map is rebuilt, and `ConfigReloaded { changed_keys: ["snippets"] }` published),
   and SIGINT/SIGTERM. A closed bus ends the process (exit status 1) for systemd to restart.
5. **Shutdown**: `DaemonStopped { reason: "shutdown" }`.
