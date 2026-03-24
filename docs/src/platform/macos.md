# macOS Platform

The `platform-macos` crate provides safe Rust abstractions over macOS-specific APIs consumed by the
daemon crates. It contains no business logic. All modules are gated with `#[cfg(target_os = "macos")]`;
on other platforms the crate compiles as an empty library with no exports.

## Implementation Status

The crate is scaffolded with module declarations only. macOS implementations are deferred until the
Linux platform is validated on Pop!_OS / COSMIC. The module structure, API boundaries, and dependency
selections are defined. No functional code exists.

## Dependencies

The `Cargo.toml` declares macOS-specific dependencies:

| Crate | Purpose |
|-------|---------|
| `core-types` | Shared types (`Window`, `WindowId`, `Error`, etc.) |
| `security-framework` | Keychain Services API (create/read/delete keychain items) |
| `objc2` | Objective-C runtime bindings for Accessibility and AppKit APIs |
| `core-foundation` | CFString, CFDictionary, CFRunLoop interop |
| `core-graphics` | CGEventTap, CGEventPost for input monitoring and injection |
| `serde` | Serialization for configuration types |
| `tokio` | Async runtime integration |
| `tracing` | Structured logging |

## Module Structure

### `accessibility`

Window management via the Accessibility API (`AXUIElement`). This module will provide the macOS
equivalent of the Linux compositor backends: window enumeration, activation, geometry manipulation,
and close operations. On macOS, all window management goes through the Accessibility framework rather
than compositor-specific protocols.

### `clipboard`

Clipboard access via `NSPasteboard`. This module will provide read, write, and change-notification
functionality equivalent to the Linux `DataControl` trait. macOS clipboard access does not require
special permissions.

### `input`

Input monitoring via `CGEventTap` (listen-only) and input injection via `CGEventPost`. Both operations
require the Accessibility permission in TCC. The module will provide keyboard event observation
equivalent to the Linux evdev module. Unlike Linux evdev, macOS input monitoring is global by default
and does not require group membership -- it requires a TCC permission grant instead.

### `keychain`

Per-profile named keychains via the `security-framework` crate (Keychain Services API). This module
will store wrapped key-encryption keys, equivalent to the Linux `SecretServiceProxy` in the `dbus`
module. macOS uses per-user keychains rather than a D-Bus Secret Service.

### `launch_agent`

LaunchAgent plist generation and `launchctl` lifecycle management. This is the macOS equivalent of
systemd service units. The module will generate property list files for
`~/Library/LaunchAgents/`, register them with `launchctl`, and manage daemon lifecycle (start, stop,
status). Unlike systemd's `Type=notify`, LaunchAgents use process lifecycle for readiness signaling.

### `tcc`

Transparency, Consent, and Control (TCC) permission state introspection. This module will query the
TCC database to determine whether Accessibility and Input Monitoring permissions have been granted
before attempting operations that require them. This allows the system to provide actionable error
messages rather than silently failing.

## Platform-Specific Considerations

### Accessibility API vs. Wayland Protocols

On Linux, window management is mediated by compositor-specific Wayland protocols. On macOS, the
Accessibility API (`AXUIElement`) provides a single, compositor-independent interface for window
enumeration, activation, geometry, and close operations. The trade-off is that Accessibility access
requires an explicit TCC permission grant from the user, and the API surface is significantly
different from Wayland protocols.

### TCC Permissions

macOS requires explicit user consent for two operations that Open Sesame uses:

- **Accessibility:** Required for window management (`AXUIElement`) and input injection
  (`CGEventPost`).
- **Input Monitoring:** Required for keyboard event observation (`CGEventTap` in listen-only mode).

These permissions cannot be granted programmatically. The application must be added to the relevant
TCC lists in System Settings. The `tcc` module exists to detect permission state and guide the user
through the grant process.

### launchd vs. systemd

macOS uses `launchd` instead of `systemd` for daemon management. Key differences:

- **Readiness signaling:** systemd supports `Type=notify` with `sd_notify(READY=1)`. launchd uses
  process lifecycle -- a LaunchAgent is considered ready when the process is running.
- **Watchdog:** systemd supports `WatchdogSec` with periodic keepalive pings. launchd has `KeepAlive`
  which restarts crashed processes but does not support health-check pings.
- **Socket activation:** systemd supports `ListenStream` for socket-activated services. launchd
  supports `Sockets` in the plist for equivalent functionality.
- **Configuration format:** systemd uses INI-style unit files. launchd uses XML property lists in
  `~/Library/LaunchAgents/`.
- **Dependency ordering:** systemd supports `After=`, `Requires=`, `Wants=`. launchd has limited
  dependency support via `WatchPaths` and `QueueDirectories`.

### Keychain vs. Secret Service

Linux uses the freedesktop Secret Service API (`org.freedesktop.secrets`) over D-Bus for credential
storage. macOS uses the Keychain Services API directly. Both provide encrypted-at-rest storage scoped
to the user session, but the API surfaces are entirely different. The `keychain` module will present
the same logical operations (store, retrieve, delete, has) as the Linux `SecretServiceProxy`.
