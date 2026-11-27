# Input Daemon

The `daemon-input` process reads keyboard events from Linux evdev, translates them with XKB, and
forwards them over the Noise IK IPC bus to `daemon-wm` while the window switcher holds a grab. It
runs a single-threaded tokio runtime (`current_thread`) and connects to the bus as a `BusClient`.

## Device Discovery

`spawn_keyboard_readers()` (`keyboard.rs`) enumerates input devices
(`platform_linux::input::enumerate_devices()`), keeps those with `is_keyboard`, and opens each as
an async event stream (`platform_linux::input::open_keyboard_stream()`). One tokio task per
keyboard feeds a single channel of capacity 256.

When enumeration fails or finds no keyboard (typically because the user is not in the `input`
group), the daemon logs a warning naming the remedy (`sudo usermod -aG input $USER`) and runs
with an empty channel; `daemon-wm` then relies on its layer-shell surface's keyboard. A device
that cannot be opened is skipped with a warning.

## Event Reading

Each reader forwards `EventSummary::Key` events:

- **value 1** (press): `RawKeyEvent { keycode, pressed: true }`.
- **value 0** (release): `RawKeyEvent { keycode, pressed: false }`.
- **value 2** (repeat): dropped; repetition is the consumer's concern.

`keycode` is the evdev code (30 for `KEY_A`). A read error (device removed, permission revoked)
ends that device's reader with a warning.

## XKB Translation

`XkbContext::new()` compiles the system default keymap (`Keymap::new_from_names` with empty
rules, model, layout, and variant) and returns `None` when the XKB data files are absent. Under
the nix desktop package, `daemon-input` is wrapped with `XKB_CONFIG_ROOT` pointing at
`xkeyboard-config`.

`process_key(evdev_keycode, pressed)` produces a `KeyboardEvent`:

1. The XKB keycode is `evdev_keycode + 8`.
2. The keysym (`key_get_one_sym`) and UTF-32 character (`key_get_utf32`) are read **before** the
   state is updated, so pressing Alt reports modifiers without Alt; `daemon-wm` relies on this to
   detect the Alt release.
3. The modifier mask is read (below).
4. The state is updated with the key direction.
5. `unicode` is set on presses only, when the character is non-zero.

| Modifier | XKB name | Bit | GDK name |
| --- | --- | --- | --- |
| Shift | `MOD_NAME_SHIFT` | 0 | `GDK_SHIFT_MASK` |
| Control | `MOD_NAME_CTRL` | 2 | `GDK_CONTROL_MASK` |
| Alt | `MOD_NAME_ALT` | 3 | `GDK_ALT_MASK` |
| Super | `MOD_NAME_LOGO` | 26 | `GDK_SUPER_MASK` |

Each is tested with `mod_name_is_active(…, STATE_MODS_EFFECTIVE)`.

Without an XKB context the daemon warns at startup, and during a grab forwards events with the
raw evdev code as `keyval`, no modifiers, and no character.

## Grab Protocol

The daemon tracks `grab_active` and `grab_requester`.

- **During a grab**, every press and release is translated and published as `InputKeyEvent`
  (`SecurityLevel::Internal`).
- **Outside a grab**, every event still updates the XKB state, so modifiers are right when a grab
  starts, and only releases of Meta_L, Meta_R, Alt_L, and Alt_R (keysyms `0xFFE7..=0xFFEA`) are
  published. A grab request can arrive after the user released Alt; forwarding these releases
  unconditionally lets `daemon-wm` see the release anyway, at the cost of at most four keysyms of
  extra traffic.

A failed `InputKeyEvent` publish ends the daemon: a lost key event would desynchronize the
overlay.

| Message | Response | Behavior |
| --- | --- | --- |
| `InputGrabRequest { requester }` | `InputGrabResponse { success: true }` | Starts a grab for `requester` |
| `InputGrabRelease { requester }` | -- | Ends the grab when `requester` holds it |
| `InputLayersList` | `InputLayersListResponse` | The single active `default` layer, no remaps |
| `InputStatus` | `InputStatusResponse` | Layer `default`, no grabbed devices, remapping off |

Key remapping is not implemented; the layer and status responses report exactly that.

## Deduplication and Key Mapping in daemon-wm

When the compositor gives the overlay keyboard focus, the same keystroke arrives twice: from the
layer surface and as `InputKeyEvent`. `daemon-wm`'s `KeyDeduplicator` (`ipc_keys.rs`) keeps the
last 8 `(keyval, pressed, time)` entries in a ring and rejects an event matching an entry's
keyval and direction within 50 ms. A press and a release of one key never deduplicate each other.

`map_ipc_key_to_event(keyval, modifiers, unicode)` maps a forwarded keysym to an overlay event:

| Keysym | Key | Event |
| --- | --- | --- |
| `0xFF1B` | Escape | `Escape` |
| `0xFF0D`, `0xFF8D` | Return, KP_Enter | `Confirm` |
| `0xFF09` | Tab | none |
| `0xFF54` | Down | `SelectionDown` |
| `0xFF52` | Up | `SelectionUp` |
| `0xFF08` | Backspace | `Backspace` |
| `0x0020` | Space | `Char(' ')` |
| other | -- | `Char(ch)` when `unicode` is printable ASCII or space |

Tab maps to nothing: the compositor intercepts Alt+Tab and re-activates the overlay
(`WmActivateOverlay` / `WmActivateOverlayBackward`), so forwarding Tab would advance the
selection twice.

## Process Hardening

On Linux the daemon calls `platform_linux::security::harden_process()`, sets resource limits
(`nofile = 4096`, `memlock_bytes = 0`), probes `memfd_secret` (`core_types::init_secure_memory()`),
and applies a Landlock and seccomp sandbox built from the layout (`core_daemon::sandbox`) plus
its device paths:

- **Bus client** (`ipc_client_rules`): the per-daemon key directory
  (`$XDG_RUNTIME_DIR/pds/keys`, read), the bus public key, and the bus socket (connect).
- **Configuration** (`config_rules`, read-only): `~/.config/pds` and the directories its
  symlinks resolve into.
- **systemd notification** (`notify_rules`): the `$NOTIFY_SOCKET` socket when it is a filesystem
  socket that exists.
- **Devices** (read-only): `/dev/input`, `/sys/class/input` (enumeration symlinks), and
  `/sys/devices` (their targets' metadata).

The seccomp allowlist includes `ioctl` for evdev queries, inotify for configuration reload,
`memfd_secret`, and standard I/O and process lifecycle calls. When the sandbox cannot be applied,
startup fails with "refusing to run unsandboxed"; the daemon never runs unconfined.

Reading evdev directly makes the overlay's input independent of compositor focus: exclusive
layer-shell keyboard interactivity may be granted late or not at all, and the grab request may
arrive after the triggering keystroke.

## Lifecycle

1. **Startup**: process hardening; `core_daemon::startup()` (layout, directory bootstrap,
   configuration load); the configuration watch; the keyboard readers and XKB context; the bus
   connection (`core_daemon::connect_bus`, up to 5 attempts 500 ms apart); the sandbox.
2. **Announcement**: `DaemonStarted { capabilities: ["input", "remap"] }`.
3. **Readiness**: `READY=1` (`platform_linux::systemd::notify_ready()`).
4. **Event loop**: `tokio::select!` over the 15-second watchdog, keyboard events, bus messages,
   configuration reloads (`ConfigReloaded { changed_keys: ["input"] }` is published), and
   SIGINT/SIGTERM. A closed bus ends the process (exit status 1) for systemd to restart.
5. **Shutdown**: `DaemonStopped { reason: "shutdown" }`.
