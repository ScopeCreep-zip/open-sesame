# Input Daemon

The `daemon-input` process captures keyboard events via Linux evdev and forwards them over the
Noise IK IPC bus for consumption by `daemon-wm`. It runs as a single-threaded tokio process
(`current_thread` runtime) connected to the IPC bus as a `BusClient`.

## Device Discovery

The `spawn_keyboard_readers()` function (`keyboard.rs`) enumerates input devices via
`platform_linux::input::enumerate_devices()`, filters to those with `is_keyboard = true`, and
opens each as an async `EventStream` via `platform_linux::input::open_keyboard_stream()`.

One tokio task is spawned per keyboard device. All tasks funnel events into a single `mpsc`
channel with a buffer size of 256. If no keyboard devices are found (typically because the user
is not in the `input` group), the function logs a warning with remediation advice
(`sudo usermod -aG input $USER`) and returns an empty receiver. This is non-fatal -- `daemon-wm`
falls back to SCTK keyboard input from its layer-shell surface.

## Event Reading

Each reader task processes evdev events via `stream.next_event().await` in a loop. Only
`EventSummary::Key` events are forwarded:

- **value 0**: Key release -- forwarded as `RawKeyEvent { keycode, pressed: false }`.
- **value 1**: Key press -- forwarded as `RawKeyEvent { keycode, pressed: true }`.
- **value 2**: Key repeat -- skipped. Repeat handling is left to the consumer.

The `keycode` field contains the evdev hardware scan code (e.g., 30 for `KEY_A`). The keycode is
cast from `evdev::Key` to `u32` via `keycode.0 as u32`. On read errors (device disconnect,
permission denied), the task logs a warning and returns, ending that device's reader.

## XKB Keysym Translation

The `XkbContext` struct wraps an `xkbcommon::xkb::State` initialized with the system's default
keymap. `XkbContext::new()` calls `Keymap::new_from_names()` with empty strings for rules, model,
layout, and variant (meaning system defaults), and `KEYMAP_COMPILE_NO_FLAGS`. It returns `None`
if xkbcommon fails to initialize (missing XKB data files).

### Translation Process

`process_key(evdev_keycode, pressed)` translates a raw evdev event into a `KeyboardEvent`:

1. **Offset**: Adds the XKB offset (`xkb_keycode = evdev_keycode + 8`) because evdev keycodes
   are offset by 8 from XKB keycodes.
2. **Pre-read**: Reads the keysym via `state.key_get_one_sym()` and UTF-32 character via
   `state.key_get_utf32()` **before** updating state. This ordering is critical: when the Alt
   key itself is pressed, the modifier mask returned by `active_modifiers()` must not yet include
   Alt, ensuring correct modifier-release detection on the receiving end (`daemon-wm`).
3. **Modifiers**: Calls `active_modifiers()` to build the current modifier bitmask.
4. **State update**: Calls `state.update_key()` with the key direction **after** reading.
5. **Unicode**: The `unicode` field is populated only on key press (`pressed == true`) and only
   when `key_get_utf32()` returns a non-zero value.

### Modifier Bitmask

The `active_modifiers()` method queries four XKB named modifiers and maps them to GDK-compatible
bit positions:

| Modifier | XKB Constant | Bit Position | GDK Name |
|----------|-------------|-------------|----------|
| Shift | `MOD_NAME_SHIFT` | bit 0 | `GDK_SHIFT_MASK` |
| Control | `MOD_NAME_CTRL` | bit 2 | `GDK_CONTROL_MASK` |
| Alt | `MOD_NAME_ALT` | bit 3 | `GDK_ALT_MASK` |
| Super | `MOD_NAME_LOGO` | bit 26 | `GDK_SUPER_MASK` |

Each modifier is checked via `state.mod_name_is_active()` with `STATE_MODS_EFFECTIVE`.

### Fallback

If `XkbContext::new()` returns `None`, the daemon logs a warning and constructs `KeyboardEvent`
structs with the raw evdev keycode as `keyval`, zero `modifiers`, and `None` for `unicode`.

## Grab Protocol

The daemon tracks keyboard grab state via two variables: `grab_active: bool` and
`grab_requester: Option<DaemonId>`.

### When Grab Is Active

All key events (press and release, value 0 and 1) are translated via `XkbContext::process_key()`
and published as `InputKeyEvent` messages on the IPC bus with `SecurityLevel::Internal`.

### When Grab Is Inactive

Key events still flow through `XkbContext::process_key()` to keep modifier tracking accurate for
future grabs. However, only Alt/Meta **release** events are forwarded. Specifically, if
`pressed == false` and the keyval is in the range `0xFFE7..=0xFFEA` (Meta_L, Meta_R, Alt_L,
Alt_R), the event is published as `InputKeyEvent`.

This unconditional forwarding of modifier releases solves a race condition inherent to
single-threaded runtimes: the `InputGrabRequest` IPC message may arrive after the user has
already released Alt. Without this forwarding, `daemon-wm` would never detect the Alt release
and the overlay would remain stuck. Only releases are forwarded (not presses), limiting
extraneous IPC traffic to at most 4 keycodes.

### IPC Messages

| Message | Response | Description |
|---------|----------|-------------|
| `InputGrabRequest` | `InputGrabResponse` | Activates the grab and records the requester |
| `InputGrabRelease` | -- | Deactivates the grab if requester matches |
| `InputLayersList` | `InputLayersListResponse` | Returns configured input remap layers |
| `InputStatus` | `InputStatusResponse` | Returns current daemon status |
| `KeyRotationPending` | -- | Reconnects with a rotated IPC keypair |

## KeyDeduplicator

The `KeyDeduplicator` (`daemon-wm/src/ipc_keys.rs`) prevents duplicate processing when both the
SCTK keyboard handler and IPC `InputKeyEvent` fire for the same physical keystroke. It is
instantiated in the `daemon-wm` main loop, not in `daemon-input`.

### Implementation

- An 8-entry ring buffer stores `(keyval: u32, pressed: bool, timestamp: Instant)` tuples,
  initialized to `(0, false, epoch)`.
- `accept(keyval, pressed)` scans the entire buffer. If any entry matches the same `keyval` and
  `pressed` direction within 50ms of the current time, the event is rejected (returns `false`).
  Otherwise, the event is recorded at the current ring index (which advances modulo 8) and
  accepted (returns `true`).
- Direction-aware: a press (`pressed = true`) and release (`pressed = false`) of the same key
  are treated as distinct events and do not deduplicate each other.
- The ring buffer wraps on overflow, overwriting the oldest entry.

### IPC Key Mapping

`map_ipc_key_to_event(keyval, modifiers, unicode)` in `daemon-wm/src/ipc_keys.rs` translates
XKB keysyms received via IPC into controller `Event` variants:

| Keysym | Constant | Event |
|--------|----------|-------|
| `0xFF1B` | Escape | `Event::Escape` |
| `0xFF0D` | Return | `Event::Confirm` |
| `0xFF8D` | KP_Enter | `Event::Confirm` |
| `0xFF09` | Tab | `None` (suppressed -- cycling handled by IPC re-activation) |
| `0xFF54` | Down | `Event::SelectionDown` |
| `0xFF52` | Up | `Event::SelectionUp` |
| `0xFF08` | Backspace | `Event::Backspace` |
| `0x0020` | Space | `Event::Char(' ')` |
| Other | -- | `Event::Char(ch)` if `unicode` is `Some` and passes `is_ascii_graphic()` |

Tab is explicitly suppressed because cycling through the window list is handled at the IPC level
by the compositor intercepting Alt+Tab and sending `WmActivateOverlay` /
`WmActivateOverlayBackward`. Forwarding Tab as `SelectionDown` would cause double-advancement.

## Process Hardening

On Linux, daemon-input applies:

- `platform_linux::security::harden_process()` for process-level hardening.
- Resource limits: `nofile = 4096`, `memlock_bytes = 0`.
- `core_types::init_secure_memory()` for `memfd_secret` probing.
- Landlock sandbox restricting access to:
  - IPC key directory (`$XDG_RUNTIME_DIR/pds/keys/`) -- read-only.
  - Bus public key and socket -- read-only and read-write respectively.
  - `/dev/input` -- read-only (evdev device access).
  - `/sys/class/input` -- read-only (device enumeration symlinks).
  - `/sys/devices` -- read-only (device metadata via symlink traversal).
  - Config symlink targets -- read-only.
- Seccomp syscall filter with evdev-relevant syscalls (`ioctl` for device queries), inotify for
  config hot-reload, `memfd_secret`, and standard I/O syscalls.
- The sandbox panics on failure, refusing to run unsandboxed.

## Compositor-Independent Operation

The daemon reads directly from `/dev/input/event*` devices rather than relying on compositor
keyboard focus. This design is necessary because:

1. The overlay's `KeyboardInteractivity::Exclusive` may not be granted immediately by all
   compositors.
2. The `InputGrabRequest` IPC message may arrive after the triggering keystroke.
3. Some compositors may not forward all key events to layer-shell surfaces.

By reading at the evdev level, `daemon-input` captures keystrokes regardless of which window has
compositor focus, providing a reliable input path for the overlay.

## Lifecycle

1. **Startup**: Process hardening, directory bootstrap, config load, keyboard reader spawn, XKB
   context creation, IPC bus connection with keypair retry (5 attempts, 500ms interval), sandbox
   application.
2. **Announcement**: Publishes `DaemonStarted { capabilities: ["input", "remap"] }`.
3. **Readiness**: Calls `platform_linux::systemd::notify_ready()`.
4. **Event loop**: `tokio::select!` over watchdog timer (15s), keyboard events, IPC messages,
   config reload notifications, SIGINT, and SIGTERM.
5. **Shutdown**: Publishes `DaemonStopped { reason: "shutdown" }`.
