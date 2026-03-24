# Linux Platform

The `platform-linux` crate provides safe Rust abstractions over Linux-specific APIs consumed by the daemon
crates. It contains no business logic. All modules are gated with `#[cfg(target_os = "linux")]`.

## Feature Flags

The crate uses two feature flags to control dependency scope:

- **No features (default):** Only headless-safe modules are compiled: `sandbox`, `security`, `systemd`,
  `dbus`, `cosmic_keys`, `cosmic_theme`, and the `clipboard` trait definition. This is sufficient for the
  `open-sesame` (headless) package.
- **`desktop`:** Enables Wayland compositor integration (`compositor`, `focus_monitor`), evdev input capture
  (`input`), and pulls in `wayland-client`, `wayland-protocols`, `wayland-protocols-wlr`,
  `smithay-client-toolkit`, and `evdev`.
- **`cosmic`:** Enables COSMIC-specific Wayland protocol support. Implies `desktop`. Pulls in
  `cosmic-client-toolkit` and `cosmic-protocols`, which are GPL-3.0 licensed. This feature flag isolates
  the GPL license obligation to builds that opt in.

## Compositor Abstraction

### The `CompositorBackend` Trait

Window and workspace management is abstracted behind the `CompositorBackend` trait defined in
`compositor.rs`. The trait requires `Send + Sync` and exposes these operations:

- `list_windows()` -- enumerate all toplevel windows
- `list_workspaces()` -- enumerate workspaces
- `activate_window(id)` -- bring a window to the foreground
- `set_window_geometry(id, geom)` -- resize/reposition a window
- `move_to_workspace(id, ws)` -- move a window to a different workspace
- `focus_window(id)` -- set input focus to a window
- `close_window(id)` -- request a window to close
- `name()` -- human-readable backend name for diagnostics

All methods return `Pin<Box<dyn Future<Output = T> + Send>>` (aliased as `BoxFuture`) to maintain
dyn-compatibility. This is required because `detect_compositor()` returns `Box<dyn CompositorBackend>`
for runtime backend selection.

The trait also defines a `Workspace` struct with fields `id` (`CompositorWorkspaceId`), `name`
(`String`), and `is_active` (`bool`).

### Runtime Backend Detection

The `detect_compositor()` factory function probes the Wayland display for supported protocols and
instantiates the appropriate backend:

1. If the `cosmic` feature is enabled, attempt to connect the `CosmicBackend`. On success, return it.
2. If COSMIC protocols are unavailable (or the feature is disabled), attempt to connect the `WlrBackend`.
3. If neither backend connects, return `Error::Platform`.

This detection runs once at daemon startup. The returned `Box<dyn CompositorBackend>` is stored and used
for the daemon's lifetime.

## CosmicBackend

The `CosmicBackend` (in `backend_cosmic.rs`) targets the COSMIC desktop compositor (cosmic-comp). It
uses three Wayland protocols:

- **`ext_foreign_toplevel_list_v1`** -- standard protocol for window enumeration (toplevel handles with
  identifier, app_id, title).
- **`zcosmic_toplevel_info_v1`** -- COSMIC-specific extension providing activation state detection via
  `State::Activated`.
- **`zcosmic_toplevel_manager_v1`** -- COSMIC-specific extension providing window activation
  (`manager.activate(handle, seat)`) and close operations.

### Connection and Protocol Probing

`CosmicBackend::connect()` opens a Wayland connection, initializes the registry, and verifies that all
three required protocol interfaces are advertised in the global list. It does not bind protocol objects
during probing -- binding `ExtForeignToplevelListV1` causes the compositor to start sending toplevel
events, and if the probe event queue is then dropped, those objects become zombies that cause the
compositor to close the connection.

The backend holds the `wayland_client::Connection` and an `op_lock` (`Mutex<()>`) that serializes all
protocol operations. Concurrent bind/destroy cycles on the same `wl_display` can corrupt compositor
state and crash cosmic-comp.

### Window Enumeration (2-Roundtrip Pattern)

`enumerate()` follows a two-roundtrip protocol flow:

1. **Roundtrip 1:** Bind `ext_foreign_toplevel_list_v1` and `zcosmic_toplevel_info_v1`. Receive all
   `ExtForeignToplevelHandleV1` events (identifier, app_id, title, Done).
2. Request `zcosmic_toplevel_handle` for each handle via `info.get_cosmic_toplevel()`.
3. **Roundtrip 2:** Receive cosmic state events. Detect activation by checking for `State::Activated`
   in the state byte array (packed `u32` values in native endian).

Windows are converted to `core_types::Window` structs. The `WindowId` is derived deterministically
using UUID v5 with a fixed namespace (`"open-sesame-wind"` as bytes) and the protocol identifier as
input. The focused window is reordered to the end of the list (MRU ordering for Alt+Tab).

After enumeration, all protocol objects are destroyed in the correct order per the protocol
specification: destroy cosmic handles, destroy foreign toplevel handles, stop the list, roundtrip for
the `finished` event, destroy the list, flush.

### Window Activation (3-Roundtrip Pattern)

`activate()` uses a separate disposable Wayland connection to avoid crashing cosmic-comp. The compositor
panics (`toplevel_management.rs:267 unreachable!()`) when protocol objects are destroyed while an
activation is in flight, which would kill the entire COSMIC desktop session. The disposable connection
isolates this breakage from the shared connection used for enumeration.

1. **Roundtrip 1:** Enumerate toplevels on the disposable connection.
2. Find the target window by deterministic UUID mapping. Request its cosmic handle.
3. **Roundtrip 2:** Receive the cosmic handle.
4. Call `manager.activate(cosmic_handle, seat)`.
5. **Roundtrip 3:** Ensure activation is processed.

Protocol objects are intentionally leaked. The leaked objects cause a broken pipe when the `EventQueue`
drops, but this only affects the disposable connection.

### Unsupported Operations

`set_window_geometry` and `move_to_workspace` return `Error::Platform` -- these operations are not
supported by the COSMIC toplevel protocols. `focus_window` delegates to `activate_window`.

## WlrBackend

The `WlrBackend` (in `backend_wlr.rs`) implements `CompositorBackend` using
`wlr-foreign-toplevel-management-v1`. This protocol is supported by sway, Hyprland, niri, Wayfire,
and COSMIC (which advertises it for backwards compatibility).

### Architecture

Unlike the COSMIC backend's re-enumerate-on-each-call approach, the WLR backend maintains a
continuously updated state snapshot:

- A **dedicated dispatch thread** (`wlr-dispatch`) continuously reads Wayland events using
  `prepare_read()` + `libc::poll()` with a 50ms periodic wake-up.
- On each `Done` event (the protocol's atomic commit point), the dispatch thread publishes the
  committed toplevel state to a shared `Arc<Mutex<WlrState>>`.
- On `Closed` events, the toplevel is removed from shared state and the handle proxy is destroyed.
- `list_windows()` reads the snapshot under the mutex. No Wayland roundtrips occur on the API thread.
- `activate_window()` and `close_window()` call proxy methods directly (wayland-client 0.31 proxies
  are `Send + Sync`) and flush the shared connection.

The dispatch loop uses exponential backoff (100ms to 30s) on read, dispatch, or flush errors.

### Unsupported Operations

`set_window_geometry` and `move_to_workspace` return `Error::Platform` -- the wlr-foreign-toplevel
protocol does not support these operations. `focus_window` delegates to `activate_window`.

## Focus Monitor

The `focus_monitor` module (in `focus_monitor.rs`) tracks the active window and sends `FocusEvent`
values through a `tokio::sync::mpsc` channel. It uses `wlr-foreign-toplevel-management-v1` and is
compatible with sway, Hyprland, niri, Wayfire, and COSMIC.

`FocusEvent` has two variants:

- `Focus(String)` -- an app gained focus; payload is the `app_id`.
- `Closed(String)` -- a window closed; payload is the `app_id`.

The monitor runs as a long-lived async task. It connects to the Wayland display, binds the wlr foreign
toplevel manager (version 1-3), and enters an async event loop using `tokio::io::unix::AsyncFd` on the
Wayland socket file descriptor. On each `Done` event, if the activated app_id changed, a
`FocusEvent::Focus` is sent via `try_send`. On `Closed` events, a `FocusEvent::Closed` is sent and the
handle proxy is destroyed.

The focus monitor is re-exported from `compositor` for backward compatibility: downstream crates import
`platform_linux::compositor::{FocusEvent, focus_monitor}`.

## Clipboard

The `clipboard` module defines the `DataControl` trait for Wayland clipboard access. It abstracts over
two protocols:

- **`ext-data-control-v1`** (preferred, standardized)
- **`wlr-data-control-v1`** (fallback for older compositors)

The trait provides:

- `read_selection()` -- read the current clipboard content with MIME type metadata.
- `write_selection(content)` -- write content to the clipboard.
- `subscribe()` -- subscribe to clipboard change notifications via a
  `tokio::sync::mpsc::Receiver<ClipboardContent>`.
- `protocol_name()` -- diagnostic name.

`ClipboardContent` carries a `mime_type` string and `data` byte vector.

The `connect_data_control()` factory function currently returns an error -- clipboard implementation is
deferred to a later phase. The trait definition and module are available as the integration contract.

On COSMIC, the `COSMIC_DATA_CONTROL_ENABLED=1` environment variable is required for data-control
protocol access.

## Input

The `input` module (in `input.rs`) provides evdev device discovery and async keyboard event streaming.

### Device Discovery

`enumerate_devices()` iterates `/dev/input/event*` via the evdev crate's built-in enumerator. Each
device is classified:

- **Keyboard:** supports `KEY_A`, `KEY_Z`, and `KEY_ENTER`. This heuristic excludes power buttons,
  media controllers, and other devices that report KEY events but lack a full key set.
- **Pointer:** supports `BTN_LEFT`.

The function returns a `Vec<DeviceInfo>` with `path`, `name`, `is_keyboard`, and `is_pointer` fields.
Devices that fail to open (EACCES) are silently skipped.

### Keyboard Streaming

`open_keyboard_stream(path)` opens an evdev device and returns an `EventStream` (from the evdev crate)
that uses `AsyncFd<Device>` internally. This is fully async with no `spawn_blocking` required. Call
`stream.next_event().await` to read events.

The device is not grabbed (`EVIOCGRAB` is not used). Events are read passively -- they also reach the
compositor. This is intentional: the system observes and forwards copies rather than stealing events.

Requires `input` group membership. Root is never required. For future remap support via `/dev/uinput`,
a udev rule is needed: `KERNEL=="uinput", GROUP="uinput", MODE="0660"`.

## D-Bus Integration

The `dbus` module (in `dbus.rs`) provides typed D-Bus proxies using `zbus` with
`default-features = false, features = ["tokio"]` to ensure all I/O runs on the tokio runtime with no
background threads.

### Session Bus

`SessionBus::connect()` opens a connection to the D-Bus session bus. It serves as the shared connection
handle for all proxies.

### Secret Service (`org.freedesktop.secrets`)

`SecretServiceProxy` provides raw store/retrieve/delete/has operations for the freedesktop Secret
Service API. It opens a plain-text session (secrets transmitted unencrypted over D-Bus, which is safe
because D-Bus is local transport). The proxy operates on the default collection
(`/org/freedesktop/secrets/aliases/default`) and identifies items by `application` and `account`
attributes with type `master-key-wrapped`.

This module provides only the low-level D-Bus proxy. Business logic (KeyLocker trait, key hierarchy)
lives in `daemon-secrets`.

### Global Shortcuts Portal (`org.freedesktop.portal.GlobalShortcuts`)

`GlobalShortcutsProxy` provides compositor-agnostic global hotkey registration through
`xdg-desktop-portal`. Supported on COSMIC, KDE Plasma 6.4+, and niri. The proxy supports
`create_session`, `bind_shortcuts`, and `list_shortcuts` operations.

### NetworkManager SSID Monitor

`ssid_monitor()` is a long-lived async task that monitors the active WiFi SSID via NetworkManager D-Bus
signals on the system bus. It subscribes to the `StateChanged` signal on
`org.freedesktop.NetworkManager`, re-reads the primary active connection's SSID on each state change,
and sends the SSID string through a `tokio::sync::mpsc::Sender<String>` when it changes.

The SSID reading traverses the NetworkManager object graph: primary connection -> connection type check
(must be `802-11-wireless`) -> device list -> active access point -> SSID byte array -> UTF-8 string.

This enables context-based profile activation (e.g., activate "work" profile when connected to the
office WiFi).

## COSMIC Key Injection

The `cosmic_keys` module (in `cosmic_keys.rs`) manages keybindings in COSMIC desktop's shortcut
configuration files:

- `~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom` -- custom `Spawn(...)` bindings
- `~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/system_actions` -- maps `System(...)`
  action variants to command strings

### System Actions Override Strategy

For Alt+Tab integration, the module overrides `system_actions` rather than adding a competing
`Spawn(...)` binding. COSMIC's default keybindings map Alt+Tab to `System(WindowSwitcher)`. Adding a
parallel `Spawn(...)` binding would race with the default and leak the Alt modifier to applications.
By overriding `system_actions`, the compositor's own built-in Alt+Tab binding fires sesame, and the key
event is consumed at compositor level before any application sees the Alt keypress.

The overrides point `WindowSwitcher` to `sesame wm overlay` and `WindowSwitcherPrevious` to
`sesame wm overlay --backward`.

### Injection Safety

All values written to RON configuration files are escaped through `escape_ron_string()`, which handles
backslash and double-quote characters to prevent RON injection.

### Configuration Files

The files are in RON (Rusty Object Notation) format. The compositor watches these files via
`cosmic_config::calloop::ConfigWatchSource` and live-reloads on change -- no logout is required.

Before writing, the module creates a `.bak` backup of the existing file. The
`setup_keybinding(launcher_key_combo)` function:

1. Overrides `system_actions` for WindowSwitcher/WindowSwitcherPrevious.
2. Adds a custom `Spawn(...)` binding for the launcher key (e.g., `alt+space`).
3. Adds a backward variant with Shift (e.g., `alt+shift+space`).

`remove_keybinding()` removes all sesame entries from both files. If `system_actions` becomes empty
after removal, the file is deleted so COSMIC falls back to system defaults at `/usr/share/cosmic/`.

## COSMIC Theme Integration

The `cosmic_theme` module (in `cosmic_theme.rs`) reads theme colors, fonts, corner radii, and dark/light
mode from COSMIC's RON configuration at `~/.config/cosmic/`:

- Theme mode: `com.system76.CosmicTheme.Mode/v1/is_dark`
- Dark theme: `com.system76.CosmicTheme.Dark/v1/`
- Light theme: `com.system76.CosmicTheme.Light/v1/`

`CosmicTheme::load()` reads the mode, selects the appropriate theme directory, and deserializes
`background`, `primary`, `secondary` containers, accent colors, and corner radii from individual RON
files. Returns `None` on non-COSMIC systems where these files do not exist.

The types (`CosmicColor`, `ComponentColors`, `Container`, `AccentColors`, `CornerRadii`) provide the
theme data needed for overlay rendering. `CosmicColor` stores RGBA as 0.0-1.0 floats with a
`to_rgba()` conversion to `(u8, u8, u8, u8)`.

## systemd Integration

The `systemd` module (in `systemd.rs`) provides three helpers using the `sd-notify` crate:

- `notify_ready()` -- sends `READY=1` to systemd for `Type=notify` services. Preserves `NOTIFY_SOCKET`
  (does not unset it) so subsequent watchdog pings continue to work.
- `notify_watchdog()` -- sends a watchdog keepalive ping.
- `notify_status(status)` -- updates the daemon's status string visible in `systemctl status`.

## Adding a New Compositor Backend

To add support for a new compositor (e.g., GNOME/Mutter via `org.gnome.Mutter.IdleMonitor`, KDE/KWin
via `org.kde.KWin`, or Hyprland IPC):

1. Create `backend_<name>.rs` in `platform-linux/src/` implementing the `CompositorBackend` trait.
2. Add `pub(crate) mod backend_<name>;` to `lib.rs`, gated behind an appropriate feature flag.
3. Add a match arm to `detect_compositor()` in `compositor.rs`. Place it in the detection order
   according to protocol specificity (more specific protocols first, generic fallbacks last).
4. Add the feature flag to `Cargo.toml` with any new protocol dependencies.

The backend struct must be `Send + Sync`. Methods return `BoxFuture` for dyn-compatibility. For
operations not supported by the target compositor's protocols, return `Error::Platform` with a
descriptive message.
