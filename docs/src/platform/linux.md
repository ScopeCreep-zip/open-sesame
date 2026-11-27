# Linux Platform

The `platform-linux` crate wraps the Linux APIs the daemons use: Wayland toplevel and clipboard
protocols, evdev input, D-Bus, the Secret Service, systemd notification, Landlock, and seccomp. It
holds no business logic. Every module is compiled only on Linux (`#[cfg(target_os = "linux")]`).

## Feature Flags

| Feature | Modules | Dependencies |
| --- | --- | --- |
| none (default) | `cosmic_keys`, `dbus`, `global_shortcuts`, `keyring`, `sandbox`, `security`, `systemd` | zbus, ashpd, oo7, landlock, libseccomp, sd-notify, rustix |
| `desktop` | adds `compositor`, `backend_wlr`, `focus_monitor`, `clipboard`, `input`, `wayland` | wayland-client, wayland-protocols, wayland-protocols-wlr, wl-clipboard-rs, evdev |
| `cosmic` | implies `desktop`; adds `backend_cosmic`, `cosmic_theme` | cosmic-client-toolkit, cosmic-protocols, cosmic-theme, cosmic-config (GPL-3.0) |

The `cosmic` feature isolates the GPL-3.0 obligation of the COSMIC crates to builds that opt in.
daemon-wm builds with `cosmic`; daemon-clipboard, daemon-input, and daemon-profile (with its own
`desktop` feature) build with `desktop`; the headless daemons use the default.

## Compositor

### The `CompositorBackend` Trait

`compositor.rs` defines the toplevel operations daemon-wm performs. The trait is `Send + Sync`
and synchronous: the window list is a snapshot a dispatch thread maintains, and requests are
Wayland round-trips that block the calling thread, so async callers run them on a blocking thread.

| Method | Result |
| --- | --- |
| `list_windows()` | The open toplevels as `core_types::Window`s |
| `activate_window(id)` | The window brought to the foreground with input focus |
| `close_window(id)` | The window asked to close |
| `name()` | `cosmic` or `wlr`, for diagnostics |

An unknown window or an undeliverable request is `core_types::Error::Platform`.

`detect_compositor()` returns the first backend that connects: with the `cosmic` feature the
COSMIC backend, then the wlr backend; neither is `Error::Platform` ("no supported compositor
backend"). Detection runs once at daemon-wm startup.

### Shared Wayland Plumbing

`wayland.rs` holds what both backends and the focus monitor share:

- `dispatch_forever(conn, queue, state, name)`: the loop of a dedicated event thread, in the order
  `wayland_client::EventQueue` documents for an external poll loop: flush, `dispatch_pending`,
  `prepare_read`, `poll(2)` on the socket for at most 50 ms, read. A failed step is logged with the
  connection's protocol error and backs off exponentially from 100 ms to 30 s.
- `ToplevelState::decode(packed, values)`: the activated, minimized, and fullscreen flags of a
  toplevel `state` event's packed array of native-endian `u32` values (a trailing partial element
  is ignored), under each protocol's enum values (`WLR_STATE`, and the COSMIC values in
  `backend_cosmic`).

### COSMIC Backend

`backend_cosmic.rs` binds `ext_foreign_toplevel_list_v1` (version 1) and `zcosmic_toplevel_info_v1`
(versions 2 to 3) once and dispatches them forever on the `cosmic-dispatch` thread. Each new
toplevel gets its cosmic handle (`get_cosmic_toplevel`) for its state; the snapshot is republished
on every `Done`, cosmic `State`, and `Closed` event. Toplevels without an identifier or `app_id`
are not listed.

- **Window identity**: `WindowId` is UUID v5 of the protocol identifier in a fixed namespace (the
  bytes of `open-sesame-wind`), so it is stable across enumerations.
- **Order**: the focused window is moved to the end of the list.
- **Requests**: activate and close each use a disposable connection
  (`CosmicBackend::on_toplevel`). It enumerates, obtains the target's cosmic handle, issues the
  `zcosmic_toplevel_manager_v1` request with the seat, and round-trips. cosmic-comp panics when
  protocol objects are destroyed while a request is in flight, so the objects are never destroyed;
  the connection is dropped instead, isolating the shared dispatch connection.

### wlr Backend

`backend_wlr.rs` binds `wlr-foreign-toplevel-management-v1` (versions 1 to 3) and `wl_seat`
(versions 1 to 9), and dispatches on the `wlr-dispatch` thread. Pending per-toplevel state
(`app_id`, title, state) is published to the shared snapshot on each `Done`, the protocol's commit
point; `Closed` removes the toplevel and destroys its handle. `WindowId`s are UUIDv7s minted per
toplevel. Activate and close call the handle's proxy (proxies are `Send + Sync` in
wayland-client 0.31) and flush the shared connection. The protocol is offered by sway, Hyprland,
niri, Wayfire, and cosmic-comp.

### Focus Monitor

`focus_monitor::spawn(tx)` binds `wlr-foreign-toplevel-management-v1` (versions 1 to 3), receives
the existing toplevels on the calling thread, then dispatches on the `focus-monitor` thread. It
sends `FocusEvent::Focus(app_id)` on a `Done` whose toplevel is activated with an `app_id` other
than the last one sent, and `FocusEvent::Closed(app_id)` when a toplevel with an `app_id` closes.
Events are sent with `try_send`: a full channel drops the event and logs it. daemon-profile runs it
in a Wayland session for context-based profile activation.

## Clipboard

`clipboard::spawn_capture(tx)` captures the regular clipboard for daemon-clipboard through
wl-clipboard-rs's `Watcher`, over `ext-data-control-v1` or `wlr-data-control-v1`. cosmic-comp,
sway, Hyprland, niri, and KWin offer data-control to clients outside a security context; Mutter does
not, and there `spawn_capture` returns `Error::Platform` ("clipboard capture unavailable").

- **Thread**: the watcher's blocking wait runs on the `clipboard-capture` thread; each selection is
  sent to `tx` as a `Capture { content_type, text, password_manager_hint }` (its `Debug` shows the
  length, never the text).
- **Selection**: the text type wl-paste reads (`select_mime_type(_, MimeType::Text)`: UTF-8 plain
  text first). A selection without text, with non-UTF-8 text, or larger than `MAX_CAPTURE_BYTES`
  (1 MiB) is skipped, never truncated.
- **Source deadline**: the source client has 2 seconds to deliver a selection through its pipe
  (`poll(2)` bounded reads).
- **Secrets**: `password_manager_hint` is set when the source offers `x-kde-passwordManagerHint`
  with the content `secret`.
- **Recovery**: a Wayland failure after the start reconnects with backoff from 1 to 30 seconds; the
  thread ends when `tx` closes.

## Input

`input.rs` reads evdev devices for daemon-input:

- `enumerate_devices()`: the `/dev/input/event*` devices the process can open (the evdev crate's
  enumerator skips the rest), each a keyboard when it has `KEY_A`, `KEY_Z`, and `KEY_ENTER`, a
  pointer when it has `BTN_LEFT`.
- `open_keyboard_stream(path)`: the device as an async `EventStream` (`AsyncFd` underneath).

Devices are not grabbed (`EVIOCGRAB`): events also reach the compositor. Access requires `input`
group membership, never root. Nothing is injected; there is no uinput device.

## D-Bus: the NetworkManager SSID Monitor

`dbus::ssid_monitor(system_bus, tx)` reports the active Wi-Fi SSID for daemon-profile's context
engine. It connects to the system bus socket at `system_bus` (`Layout::system_bus_socket`, from
`DBUS_SYSTEM_BUS_ADDRESS` or `/var/run/dbus/system_bus_socket`) through
`zbus::connection::Builder::unix_stream`, on zbus with `default-features = false, features =
["tokio", "proxy"]`, so all I/O runs on the daemon's tokio runtime.

It subscribes to NetworkManager's `StateChanged` first and then reads the SSID, so a change between
the two is not missed; each state change re-reads it, and an SSID that differs from the last one
sent is sent. The read walks typed `#[zbus::proxy]` proxies, each built with
`CacheProperties::No` so every read is a fresh `Properties.Get`:

1. The primary connection (`/` means none).
2. Its type, which must be `802-11-wireless`.
3. Its first device.
4. The device's active access point (`/` means none).
5. The SSID bytes, as UTF-8 text.

A non-UTF-8 SSID, a Wi-Fi connection without a device, or a D-Bus failure fails that read;
monitoring continues with the next state change.

## Secret Service: `keyring`

`keyring::SecretServiceStore` is the Linux `core_types::CredentialStore`, over oo7: the freedesktop
Secret Service default collection (gnome-keyring, KWallet, oo7-daemon, KeePassXC) on the host, or
the Secret portal's file keyring inside a Flatpak. `connect()` uses the session bus;
`with_connection(conn)` uses a given connection.

- **Items**: credentials are items with the attributes `service` and `username`
  (`CredentialId`), the convention libsecret's `secret-tool` and keyring-rs share.
- **Unlocking**: a locked collection is unlocked before every operation (possibly raising the
  keyring's own prompt), so a locked keyring is never read as an empty one.
- **Ambiguity**: more than one item for an id is `CredentialError::Ambiguous`, never a guess.
- **Errors**: a dismissed prompt is `Dismissed`, a locked collection or portal keyring is `Locked`,
  and anything else is `Platform`.

The sandboxed daemons have no session bus; daemon-launcher reads the platform keyring factor
([Platform Keyring](../authentication/platform-keyring.md)).

## Overlay Shortcuts

The four overlay activations are `core_types::OverlayRequest`. Each request owns its bus event
(`WmActivateOverlay…`), its id, its description, its `sesame` arguments (`wm overlay` with
`--launcher` and `--backward`), and its shortcut, `OverlayRequest::trigger(launcher)`:

| Request | Shortcut |
| --- | --- |
| `Forward` | Alt+Tab |
| `Backward` | Alt+Shift+Tab |
| `Launcher` | `[global] launcher_key` (default `alt+space`) |
| `LauncherBackward` | the launcher key with Shift |

The launcher key is a `core_types::KeyCombo`. Its modifiers are `super` (`mod`, `logo`, `win`),
`ctrl` (`control`), `alt`, and `shift`, and its key is an XKB keysym name. An invalid
combination fails the configuration load with the accepted modifiers named.

### The Backend

One backend binds a session's shortcuts, never both, so a key cannot fire twice. It is chosen
by what the session and the system provide, not by the calling shell's environment
(`open-sesame/src/keybinding.rs`):

1. **The `GlobalShortcuts` portal**, when the session's portal implements
   `org.freedesktop.portal.GlobalShortcuts` (KDE, GNOME 48 and later, Hyprland).
2. **COSMIC's shortcut configuration**, when COSMIC's shortcut defaults are installed
   (`cosmic/com.system76.CosmicSettings.Shortcuts` under a system data directory,
   `Layout::cosmic_shortcut_defaults`). xdg-desktop-portal-cosmic does not implement
   GlobalShortcuts.
3. Neither: `sesame setup-keybinding` names both conditions, and `sesame init` reports the step
   and continues.

`sesame setup-keybinding [KEY]`, `remove-keybinding`, and `keybinding-status` act through the
chosen backend; `sesame init` binds the configured key.

### Portal: `global_shortcuts`

daemon-launcher holds the portal session, since it is outside the sandboxes and on the session
bus. At start it creates a session and binds every request:

- **Binding**: each request is bound under its id and description, with its trigger in the XDG
  shortcuts format as the preferred trigger (`ALT+Tab`, `ALT+SHIFT+Tab`, `ALT+space`,
  `ALT+SHIFT+space`). The desktop assigns the final keys, may ask the user to confirm them, and
  lets the user change them in its settings. The assigned triggers are logged.
- **Activation**: each `Activated` signal becomes the request of its id, published to daemon-wm.
- **Lifetime**: the session lives on daemon-launcher's session-bus connection.
- **Rebinding**: a reloaded configuration with another `launcher_key` ends the session and binds a
  new one, because a portal session binds once.

Without a session bus or a portal implementing the interface, daemon-launcher logs it and binds
nothing.

### COSMIC: `cosmic_keys`

`setup_keybinding(layout, launcher)`, `remove_keybinding(layout)`, and `keybinding_status(layout)`
manage the bindings in COSMIC's shortcut configuration under `Layout::cosmic_config_dir`, in
`com.system76.CosmicSettings.Shortcuts/v1/`:

- `system_actions`: `WindowSwitcher` and `WindowSwitcherPrevious` run the `Forward` and `Backward`
  requests' commands. COSMIC's own Alt+Tab binding then runs sesame and consumes the key at the
  compositor, where a competing `Spawn` binding would race the default and leak Alt to
  applications.
- `custom`: `Spawn` bindings for the `Launcher` and `LauncherBackward` requests at their
  triggers.

Commands are rendered from `OverlayRequest::command_args`, modifiers as COSMIC names them
(`Super`, `Ctrl`, `Alt`, `Shift`), and keys lowercased, since cosmic-comp matches lowercase keysym
names. Values are escaped for RON. Every write first copies the file to `<file>.bak`, and a failed
backup aborts the write. Removing the bindings deletes a `system_actions` file left empty, so
COSMIC falls back to its system defaults. cosmic-comp watches both files and reloads them on
change.

## COSMIC Theme: `cosmic_theme` (feature `cosmic`)

`cosmic_theme::CosmicTheme::load(cosmic_dir)` reads the theme of the COSMIC configuration under
`cosmic_dir` (`Layout::cosmic_config_dir`) for daemon-wm's overlay: the mode from
`com.system76.CosmicTheme.Mode`, then `com.system76.CosmicTheme.Dark` or `.Light`. It returns the
container, component, and accent colors as 8-bit RGBA, the medium corner radii, the frosted
settings and the blurred-container alpha, and the interface font family.

- **No writes**: a config is opened only when its version directory exists, so nothing is created
  and a non-COSMIC desktop is `None`. cosmic-config's `Config::new` runs `create_dir_all`.
- **No `get_active`**: `Theme::get_active` reads the mode from the `com.system76.CosmicTheme`
  config, which COSMIC does not write, so the theme is not loaded through it.
- **Fallbacks**: an unreadable config entry is logged and its defaults are used.

## systemd: `systemd`

Built on `sd-notify`, which leaves `NOTIFY_SOCKET` set so later notifications keep working; outside
systemd every notification is a no-op.

| Function | Notification |
| --- | --- |
| `notify_ready()` | `READY=1` (`Type=notify`) |
| `notify_reloading()` | `RELOADING=1` with `MONOTONIC_USEC` in one datagram (`Type=notify-reload`; systemd 253 and later require the timestamp); followed by `notify_ready()` |
| `notify_watchdog()` | `WATCHDOG=1` keepalive |
| `notify_status(status)` | `STATUS=` shown by `systemctl status` |

## Sandbox and Process Hardening: `sandbox`, `security`

`security::harden_process()` sets `PR_SET_DUMPABLE(0)` and `RLIMIT_CORE` 0;
`security::apply_resource_limits` sets `RLIMIT_NOFILE` and `RLIMIT_MEMLOCK`. Both log a failure
and continue.

`sandbox` holds the one Landlock ruleset definition (every access right and scope of ABI 10,
best-effort, so the kernel enforces the part it supports; `landlock_gaps()` names each
`core_types::SandboxProtection` it does not, and the configured floor, `[global.sandbox]
require`, is a hard requirement) and the seccomp filter
(default action kill-process, other architectures killed, `socket`/`socketpair` only for `AF_UNIX`,
synchronized onto every thread). `apply_sandbox(rules, seccomp)` applies both. The grants and
allowlists each daemon passes are described in [Sandbox Model](../architecture/sandbox-model.md).

## Adding a Compositor Backend

1. Create `backend_<name>.rs` implementing `CompositorBackend` (`Send + Sync`, synchronous
   methods; a dispatch thread through `wayland::dispatch_forever` keeps the snapshot).
2. Add `pub(crate) mod backend_<name>;` to `lib.rs` under its feature.
3. Add it to `detect_compositor()`, more specific protocols before generic ones.
4. Add the feature and its protocol dependencies to `Cargo.toml`.

An operation the compositor's protocols do not offer is `Error::Platform` naming it.
