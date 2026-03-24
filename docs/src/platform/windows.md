# Windows Platform

The `platform-windows` crate provides safe Rust abstractions over Windows-specific APIs consumed by
the daemon crates. It contains no business logic. All modules are gated with
`#[cfg(target_os = "windows")]`; on other platforms the crate compiles as an empty library with no
exports.

## Implementation Status

The crate is scaffolded with module declarations only. Windows implementations are deferred until the
Linux and macOS platforms are validated. The module structure, API boundaries, and dependency
selections are defined. No functional code exists.

## Dependencies

The `Cargo.toml` declares Windows-specific dependencies:

| Crate | Purpose |
|-------|---------|
| `core-types` | Shared types (`Window`, `WindowId`, `Error`, etc.) |
| `windows` | Official Microsoft Windows API bindings (Win32, COM, WinRT) |
| `serde` | Serialization for configuration types |
| `tokio` | Async runtime integration |
| `tracing` | Structured logging |

## Module Structure

### `clipboard`

Clipboard monitoring via `AddClipboardFormatListener`. This module will provide clipboard change
notifications and read/write operations, equivalent to the Linux `DataControl` trait. Windows
clipboard access uses the Win32 clipboard API and does not require elevated privileges.

### `credential`

Credential storage via `CryptProtectData` (DPAPI) and `CredRead`/`CredWrite` (Credential Manager).
This module will store wrapped key-encryption keys, equivalent to the Linux `SecretServiceProxy` in
the `dbus` module. DPAPI provides user-scoped encryption tied to the Windows login credentials. The
Credential Manager provides a higher-level API for named credentials visible in the Windows
Credential Manager UI.

### `hotkey`

Global hotkey registration via `RegisterHotKey`/`UnregisterHotKey`. This module will provide
compositor-independent hotkey capture, equivalent to the Linux Global Shortcuts portal or COSMIC key
injection. On Windows, global hotkeys are registered per-thread and deliver `WM_HOTKEY` messages to
the registering thread's message loop.

### `input_hook`

Input capture via `SetWindowsHookEx(WH_KEYBOARD_LL)`. This module will provide low-level keyboard
monitoring equivalent to the Linux evdev module. Low-level keyboard hooks see all keyboard input
system-wide. The crate documentation notes that EDR (Endpoint Detection and Response) disclosure is
required -- low-level keyboard hooks are flagged by security software and must be documented for
enterprise deployment.

### `named_pipe`

IPC bootstrap via Named Pipes. This is the Windows equivalent of Unix domain sockets used by the
Noise IK IPC bus on Linux. Named Pipes provide the transport layer for inter-daemon communication on
Windows. Security descriptors on the pipe control which processes can connect.

### `policy`

Enterprise policy reading via Group Policy registry keys. This module will read
`HKLM\Software\Policies\OpenSesame\` for enterprise-managed configuration overrides. This has no
direct Linux equivalent -- the closest analog is `/etc/pds/` system configuration, but Group Policy
provides domain-joined management capabilities.

### `task_scheduler`

Daemon autostart via Task Scheduler COM API. This is the Windows equivalent of systemd user services
and macOS LaunchAgents. The module will create scheduled tasks that run at user logon to start the
daemon processes.

### `ui_automation`

Window management and enumeration via UI Automation COM API. This module provides the Windows
equivalent of the Linux compositor backends. UI Automation exposes the desktop automation tree,
allowing enumeration of all top-level windows, reading their properties (title, class, process), and
performing actions (activate, minimize, close, move, resize).

### `virtual_desktop`

Workspace management via the Virtual Desktop COM API. This module will provide workspace enumeration
and window-to-desktop movement, equivalent to the Linux `list_workspaces` and `move_to_workspace`
compositor operations. The Windows Virtual Desktop API is undocumented and version-fragile -- COM
interface GUIDs change between Windows 10 and Windows 11 builds.

## Platform-Specific Considerations

### UI Automation vs. Wayland Protocols

On Linux, window management uses compositor-specific Wayland protocols (wlr-foreign-toplevel, COSMIC
toplevel). On Windows, UI Automation provides a single COM-based interface that works across all
window managers. The trade-off is COM initialization complexity and the need to handle apartment
threading models correctly (`CoInitializeEx` with `COINIT_MULTITHREADED` or
`COINIT_APARTMENTTHREADED`).

### Credential Manager vs. Secret Service

Linux uses the freedesktop Secret Service API over D-Bus. Windows uses DPAPI
(`CryptProtectData`/`CryptUnprotectData`) for raw encryption tied to user credentials, and the
Credential Manager API (`CredRead`/`CredWrite`) for named credential storage. Both provide
user-scoped encrypted-at-rest storage, but the APIs are entirely different.

### Task Scheduler vs. systemd

Windows uses the Task Scheduler for daemon autostart. Key differences from systemd:

- **Readiness signaling:** systemd supports `Type=notify`. Task Scheduler has no equivalent; the task
  is considered running when the process starts.
- **Watchdog:** systemd supports `WatchdogSec`. Task Scheduler can restart failed tasks but does not
  support health-check pings.
- **Dependencies:** systemd supports `After=`, `Requires=`. Task Scheduler supports task dependencies
  but with a less expressive model.
- **Configuration:** systemd uses INI-style unit files. Task Scheduler uses XML task definitions
  registered via COM or `schtasks.exe`.

### Named Pipes vs. Unix Domain Sockets

The Noise IK IPC bus uses Unix domain sockets on Linux. On Windows, Named Pipes provide equivalent
functionality with OS-level access control via security descriptors. Named Pipes support both
byte-mode and message-mode communication; the IPC bus would use byte-mode to match the stream
semantics of Unix domain sockets.

### EDR Disclosure

Low-level keyboard hooks (`WH_KEYBOARD_LL`) and clipboard monitoring are flagged by Endpoint
Detection and Response (EDR) software common in enterprise environments. Deployment in managed
environments requires documentation of these behaviors and may require allowlist entries in the
organization's security tooling.
