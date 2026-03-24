# Window Manager Daemon

The `daemon-wm` process implements a Wayland overlay window switcher with Vimium-style letter hints,
application launching, and inline vault unlock. It runs as a single-threaded tokio process
(`current_thread` runtime) connected to the IPC bus as a `BusClient`.

## Controller State Machine

The `OverlayController` (`controller.rs`) is the single owner of all overlay state, timing, and
decisions. The main loop feeds events in, executes the returned `Command` list, and does nothing
else. The controller never performs I/O directly.

### Phases

The controller tracks a `Phase` enum with the following variants:

- **Idle** -- Nothing happening. No overlay visible, no timers running.
- **Armed** -- Border visible, keyboard exclusive mode acquired via layer-shell. The picker is not
  yet visible. The controller waits for either modifier release (quick-switch) or dwell timeout
  (transition to Picking). Carries `entered_at: Instant`, `selection: usize`, `input: String`,
  `dwell_ms: u32`, and an optional `PendingLaunch`.
- **Picking** -- Full picker visible. The user is browsing the window list or typing hint
  characters. Carries the same `Snapshot`, `selection`, `input`, and optional `PendingLaunch`.
- **Launching** -- An application launch request has been sent to `daemon-launcher` via IPC. The
  overlay displays a status indicator while waiting for the response.
- **LaunchError** -- A launch failed. The overlay shows an error toast. Any keystroke dismisses.
- **Unlocking** -- Vault unlock in progress. Contains `profiles_to_unlock`, `current_index`,
  `password_len`, `unlock_mode` (one of `AutoAttempt`, `WaitingForTouch`, `Password`, `Verifying`),
  and the original launch command for retry after unlock.

### Events

The controller accepts the following `Event` variants:

| Event | Source | Description |
|-------|--------|-------------|
| `Activate` | IPC `WmActivateOverlay` | Forward activation (Alt+Tab) |
| `ActivateBackward` | IPC `WmActivateOverlayBackward` | Backward activation (Alt+Shift+Tab) |
| `ActivateLauncher` | IPC `WmActivateOverlayLauncher` | Launcher mode (Alt+Space) |
| `ActivateLauncherBackward` | IPC `WmActivateOverlayLauncherBackward` | Launcher mode backward |
| `ModifierReleased` | Overlay SCTK or IPC `InputKeyEvent` | Alt/Meta key released |
| `Char(char)` | Overlay or IPC key event | Alphanumeric character typed |
| `Backspace` | Overlay or IPC key event | Backspace pressed |
| `SelectionDown` / `SelectionUp` | Overlay or IPC key event | Arrow/Tab navigation |
| `Confirm` | Overlay or IPC key event | Enter pressed |
| `Escape` / `Dismiss` | Overlay or IPC key event | Cancel/timeout |
| `DwellTimeout` | Main loop deadline | Dwell timer expired |
| `LaunchResult` | Command executor callback | Launch IPC completed |
| `AutoUnlockResult` | Command executor callback | SSH agent unlock completed |
| `TouchResult` | Command executor callback | Hardware token touch completed |
| `UnlockResult` | Command executor callback | Password unlock IPC completed |

### Transitions

```text
Idle ──Activate──> Armed ──DwellTimeout──> Picking
                     |                        |
                     |<──────Activate──────────|  (re-activation cycles selection)
                     |                        |
                     |──ModifierReleased──> Idle (activate selected window)
                     |                        |
                     |──Char──> Picking        |──ModifierReleased──> Idle
                     |                        |──Escape──> Idle
                     |                        |──Confirm──> Idle
                     |                        +──launch match──> Launching
                     |
                     +──ModifierReleased (fast)──> Idle (quick-switch)

Launching ──LaunchResult(success)──> Idle
Launching ──LaunchResult(VaultsLocked)──> Unlocking
Launching ──LaunchResult(error)──> LaunchError ──any key──> Idle

Unlocking ──AutoUnlockResult(success)──> retry launch or next profile
Unlocking ──AutoUnlockResult(fail)──> Password prompt
Unlocking ──UnlockResult(success)──> retry launch or next profile
Unlocking ──Escape──> Idle
```

### Pre-computed Snapshot

At activation time, the controller builds a `Snapshot` that carries all data through the entire
overlay lifecycle. The snapshot contains:

- A copy of the window list, MRU-reordered via `mru::reorder()` and truncated to
  `max_visible_windows` (default: 20).
- The origin window (currently focused) rotated from MRU position 0 to the last index.
- Hint strings assigned via `hints::assign_app_hints()`, parallel to the window list.
- Overlay-ready `WindowInfo` structs containing `app_id` and `title`.
- A clone of the `key_bindings` map for launch-or-focus resolution.

No recomputation occurs after the snapshot is built. Keyboard actions only update the selection
index and input buffer.

## Quick-Switch

When `ModifierReleased` fires during the `Armed` phase, the controller evaluates three conditions
in `on_modifier_released()`:

1. Elapsed time since `entered_at` is below `quick_switch_threshold_ms` (default: 250ms from
   `WmConfig`).
2. No input characters have been typed (`input.is_empty()`).
3. The selection has not moved from `snap.initial_forward()`.

If all three hold, the controller activates `initial_forward()` -- the MRU previous window
(index 0 after origin rotation). Otherwise, it activates the current selection.

This enables fast Alt+Tab release to instantly switch to the previously focused window without
ever showing the picker overlay.

## Dwell Timeout

The main loop calls `controller.next_deadline()` on each iteration of the `tokio::select!` loop.
During the `Armed` phase, this returns `entered_at + Duration::from_millis(dwell_ms)`. The
`dwell_ms` value is set to:

- `quick_switch_threshold_ms` (default: 250ms) for `ActivationMode::Forward` and
  `ActivationMode::Backward`.
- `min(overlay_delay_ms, 100)` for `ActivationMode::Launcher` and
  `ActivationMode::LauncherBackward`, providing a shorter dwell to let the compositor grant
  keyboard exclusivity before the first keypress.

When the deadline fires, the main loop sends `Event::DwellTimeout`. The controller's
`on_dwell_timeout()` method transitions Armed to Picking and emits `Command::ShowPicker` with the
snapshot's pre-computed `overlay_windows` and `hints`.

## Reactivation

When an `Activate` or `ActivateBackward` event arrives while already in Armed or Picking (e.g.,
repeated Alt+Tab intercepted by the compositor):

1. The selection index advances forward or backward by one position, wrapping via modular
   arithmetic over `snap.windows.len()`.
2. If in Armed, the phase transitions to Picking with `Command::ShowPicker` and
   `Command::UpdatePicker`.
3. A `Command::ResetGrace` is emitted to reset the overlay's modifier-poll grace timer, proving
   Alt is still held.
4. `last_ipc_advance` is set to `Instant::now()`. Any `SelectionDown` or `SelectionUp` event
   within 100ms (`REACTIVATION_DEDUP_MS`) is suppressed by `is_reactivation_duplicate()` to
   prevent double-advancement from the same physical keystroke arriving via both IPC
   re-activation and the keyboard handler.

## Staged Launch

When the user types a character in `on_char()` and `check_hint_or_launch()` finds that the input
does not match any hint (`MatchResult::NoMatch`) but is a single character matching a
`key_bindings` entry with a `launch` command:

1. A `PendingLaunch` struct (containing `command`, `tags`, `launch_args`) is stored in the current
   phase via `set_pending_launch()`.
2. `Command::ShowLaunchStaged { command }` is emitted to display the intent in the overlay.
3. The launch is not executed immediately.

Commitment occurs when:

- **ModifierReleased**: `on_modifier_released()` checks for `pending_launch` before window
  activation. If present, the controller transitions to `Phase::Launching` and emits
  `Command::ShowLaunching` followed by `Command::LaunchApp`.
- **Confirm (Enter)**: `on_confirm()` follows the same path.
- **Backspace**: If `input.pop()` empties the buffer, `pending_launch` is set to `None`.
- **Escape**: `on_escape()` dismisses the overlay entirely, clearing all state.

## Overlay Lifecycle

### SCTK Layer-Shell Surface

The overlay runs on a dedicated OS thread spawned by `overlay::spawn_overlay()`, communicating
with the tokio event loop via `std::sync::mpsc` (commands in) and `tokio::sync::mpsc` (events
out). The `OverlayApp` struct holds all Wayland state and creates a `wlr-layer-shell` surface
with:

- `Layer::Overlay` -- renders above all other surfaces.
- `Anchor::TOP | Anchor::BOTTOM | Anchor::LEFT | Anchor::RIGHT` -- fullscreen coverage.
- `KeyboardInteractivity::Exclusive` -- captures all keyboard input when visible.

The overlay thread runs a manual poll loop using `prepare_read()` and `rustix::event::poll()` for
low-latency Wayland event dispatch, draining the command channel every `POLL_INTERVAL_MS` (4ms).

### Show/Hide

- **ShowBorder**: Creates the layer-shell surface if absent. Sets `OverlayPhase::BorderOnly`.
  Acquires keyboard exclusivity. Records `activated_at` for stale-activation timeout.
- **ShowFull**: Stores the `windows` and `hints` vectors, transitions to `OverlayPhase::Full`,
  and triggers a redraw.
- **HideAndSync**: Destroys the surface, performs a Wayland display sync via
  `wl_display.roundtrip()`, then sends `OverlayEvent::SurfaceUnmapped` as acknowledgment. The
  main loop's `execute_commands()` waits up to 5 seconds for this event before proceeding with
  window activation. This ensures the compositor no longer sees the exclusive-keyboard surface
  before focus transfers.
- **Hide**: Destroys the surface without synchronization. Used for escape/dismiss where no
  subsequent window activation is needed.

### Modifier Tracking

The overlay tracks `alt_held` via the SCTK `KeyboardHandler`'s modifier callback. After
activation, a grace period (`MODIFIER_POLL_GRACE_MS` = 150ms) prevents premature modifier-release
detection. If no keyboard event arrives within `STALE_ACTIVATION_TIMEOUT_MS` (3000ms), the overlay
sends `OverlayEvent::Dismiss` to handle cases where Alt was released before keyboard focus was
granted.

The `ConfirmKeyboardInput` command from the main loop (sent on the first IPC key event) sets
`received_key_event = true`, disabling the stale activation timeout.

### Overlay Phases

The overlay thread tracks `OverlayPhase`: `Hidden`, `BorderOnly`, `Full`, `Launching`,
`LaunchError`, `UnlockPrompt`, `UnlockProgress`. Each phase determines what the render module
draws.

## Rendering

The `render.rs` module implements software rendering using two libraries:

- **tiny-skia**: 2D path operations. `rounded_rect_path()` builds quadratic Bezier paths for
  rounded rectangles. `fill_rounded_rect()` and `stroke_rounded_rect()` render filled and stroked
  shapes onto a `tiny_skia::Pixmap`. Layout follows a Material Design 4-point grid with base
  constants: padding (20px), row height (48px), row spacing (8px), badge dimensions (48x32px),
  badge radius (8px), app column width (180px), text size (16px), border width (3px), corner
  radius (16px), and column gap (16px). All dimensions scale with HiDPI via the `Layout` struct.
- **cosmic-text**: Text shaping, layout, and glyph rasterization. `FontSystem` manages font
  discovery and caching. `SwashCache` provides glyph rasterization. Text is measured with
  `measure_text()` (returns width and height) and drawn with `draw_text()`, both operating on
  `Buffer` objects with configurable `Attrs` (family, weight) and `Metrics` (font size, line
  height at 1.3x).

### Theme

`OverlayTheme` defines colors for: `background`, `card_background`, `card_border`,
`text_primary`, `text_secondary`, `badge_background`, `badge_text`,
`badge_matched_background`, `badge_matched_text`, `selection_highlight`, `border_color`, plus
`border_width` and `corner_radius`. Theme construction follows a priority chain:

1. **COSMIC system theme**: `OverlayTheme::from_cosmic()` loads
   `platform_linux::cosmic_theme::CosmicTheme` and maps its semantic color tokens
   (`background.base`, `primary.base`, `primary.on`, `secondary.component.base`, `accent.base`,
   `accent.on`, `corner_radii.radius_m`) to overlay theme fields.
2. **User config overrides**: `OverlayTheme::from_config()` compares each `WmConfig` color field
   against its default. Non-default values override the COSMIC-derived theme.
3. **Hardcoded defaults**: Dark theme with Catppuccin-inspired palette (`#89b4fa` border,
   `#000000c8` background, `#1e1e1ef0` cards, `#646464` badges, `#4caf50` matched badges).

Colors are parsed from CSS hex notation (`#RRGGBB` or `#RRGGBBAA`) via `Color::from_hex()`.
Theme updates arrive via `OverlayCmd::UpdateTheme` on config hot-reload.

### Rendered Elements

- **Border-only phase**: A border indicator around the screen edges.
- **Full picker**: A centered card with: hint badges (letter hints with `badge_background` or
  `badge_matched_background` depending on match state), app ID column (optional, controlled by
  `show_app_id`), and title column per window row. The selected row receives a
  `selection_highlight` background. An input buffer is displayed for typed characters.
- **Launch status**: Staged launch intent, launching indicator, or error messages.
- **Unlock prompt**: Profile name, dot-masked password field (receives only `password_len`, never
  password bytes), and optional error message.
- **Unlock progress**: Profile name with status message (e.g., "Authenticating...",
  "Verifying...", "Touch your security key...").

## MRU Stack

The `mru.rs` module maintains a file-based most-recently-used window stack at
`~/.cache/open-sesame/mru`. The cache directory is created with mode `0o700` on Unix.

### File Format

One window ID per line, most recent first. The stack is capped at `MAX_ENTRIES` (64).

### Operations

- **`load()`**: Opens the file with a shared `flock` (`LOCK_SH | LOCK_NB` -- never blocks the
  tokio thread). Parses one ID per line, trimming whitespace and filtering empty lines. Returns
  `MruState` containing the ordered `stack: Vec<String>`.
- **`save(target)`**: Opens the file with an exclusive `flock` (`LOCK_EX | LOCK_NB`). Reads the
  current stack, removes `target` from its old position via `retain()`, inserts it at index 0,
  truncates to 64 entries, and writes back as newline-joined text. No-op if target is already at
  position 0.
- **`seed_if_empty(windows)`**: On first launch or after crash, seeds the stack from the
  compositor's window list. The focused window goes to position 0. No-op if the stack already
  has entries.
- **`reorder(windows, get_id, state)`**: Sorts a window slice by MRU stack position. Windows
  present in the stack sort by their position (0 = most recent). Windows not in the stack receive
  `usize::MAX` and sort after all tracked windows, preserving their relative compositor order.

### Origin Tracking

After `mru::reorder()`, the currently focused window (MRU position 0) sits at the beginning of
the sorted list. `Snapshot::build()` then rotates it to the end via `remove()` + `push()`. The
result:

- Index 0 = MRU previous (the quick-switch target).
- Last index = origin (currently focused, lowest switch priority).
- `initial_forward()` returns 0 unless that is the origin, in which case it returns 1.
- `initial_backward()` returns the last index unless that is the origin, in which case it returns
  `last - 1`.

The origin window remains in the list for display and is reachable by full-circle cycling or
explicit hint selection.

## Inline Vault Unlock

When a launch request returns a `LaunchDenial::VaultsLocked { locked_profiles }` denial,
`on_launch_result()` transitions to `Phase::Unlocking` without dismissing the overlay. The phase
stores the `locked_profiles` list, a `current_index` into it, and the original `retry_command`,
`retry_tags`, and `retry_launch_args` for replay after unlock.

### Unlock Flow

1. **Auto-unlock attempt** (`Command::AttemptAutoUnlock`): The
   `commands_unlock::attempt_auto_unlock()` handler reads the vault's salt file from
   `{config_dir}/vaults/{profile}.salt`, creates a `core_auth::AuthDispatcher`, calls
   `find_auto_backend()` to locate an SSH agent enrollment, and invokes `auto_backend.unlock()`.
   On success, the resulting master key is transferred into `SensitiveBytes::from_protected()`
   and sent to `daemon-secrets` via `SshUnlockRequest` IPC with a 30-second timeout. The
   `AutoUnlockResult` event is fed back through the controller.

2. **Touch prompt**: If the auto-unlock backend sets `needs_touch = true`, the controller
   transitions to `UnlockMode::WaitingForTouch` and emits `Command::ShowTouchPrompt`. The
   overlay displays "Touch your security key for {profile}...".

3. **Password fallback**: If auto-unlock fails (no backend available, agent error, or secrets
   rejection), the controller transitions to `UnlockMode::Password` and emits
   `Command::ShowPasswordPrompt`. Password bytes are accumulated in a `SecureVec` (pre-allocated
   with `mlock` via `SecureVec::for_password()`). The overlay receives only `password_len` via
   `OverlayCmd::ShowUnlockPrompt`, never password bytes.

4. **Password submission** (`Command::SubmitPasswordUnlock`): On Enter,
   `commands_unlock::submit_password_unlock()` copies the password from `SecureVec` into
   `SensitiveBytes::from_slice()` (mlock-to-mlock copy, no heap exposure), clears the `SecureVec`
   immediately, shows "Verifying..." in the overlay, and sends `UnlockRequest` IPC to
   `daemon-secrets` with a 30-second timeout (accommodating Argon2id KDF with high memory
   parameters). `AlreadyUnlocked` responses are treated as success.

5. **Multi-profile unlock**: If multiple profiles are locked,
   `advance_to_next_profile_or_retry()` increments `current_index` and starts the auto-unlock
   flow for the next profile.

6. **Retry**: After all profiles are unlocked, the controller emits `Command::ActivateProfiles`
   (sends `ProfileActivate` IPC for each profile) followed by `Command::LaunchApp` with the
   original command, tags, and launch args.

### Security Properties

- Password bytes never cross the thread boundary to the render thread. The overlay receives only
  `password_len: usize`.
- `SecureVec` uses `mlock` to prevent swap and core-dump exposure.
- `SensitiveBytes` uses `ProtectedAlloc` for the IPC transfer to `daemon-secrets`.
- The password buffer is zeroized via `Command::ClearPasswordBuffer` on escape, successful
  unlock, or any transition out of the Unlocking phase.

## Keyboard Input

Keyboard events arrive from two sources:

1. **SCTK keyboard handler**: The overlay's `wlr-layer-shell` surface receives Wayland keyboard
   events when it holds `KeyboardInteractivity::Exclusive`. The `KeyboardHandler` implementation
   maps `KeyEvent` and `Modifiers` to `OverlayEvent` variants.
2. **IPC `InputKeyEvent`**: `daemon-input` forwards evdev keyboard events over the IPC bus when
   a grab is active. The main loop maps these via `map_ipc_key_to_event()` to controller `Event`
   variants.

Both sources pass through a shared `KeyDeduplicator` instance (8-entry ring buffer, 50ms expiry
window, direction-aware) to ensure only the first arrival of each physical keystroke is processed.

When the overlay activates, `Command::ShowBorder` triggers an `InputGrabRequest` publish to
acquire keyboard forwarding from `daemon-input`. On hide (`Command::HideAndSync` or
`Command::Hide`), `InputGrabRelease` is published. The first IPC key event each activation cycle
sends `OverlayCmd::ConfirmKeyboardInput` to the overlay thread, setting
`ipc_keyboard_active = true` and stopping the stale activation timeout.

## IPC Interface

| Message | Response | Description |
|---------|----------|-------------|
| `WmListWindows` | `WmListWindowsResponse { windows }` | Returns MRU-reordered window list |
| `WmActivateWindow { window_id }` | `WmActivateWindowResponse { success }` | Activates a window by ID or `app_id` match, saves MRU state |
| `WmActivateOverlay` | -- | Triggers forward overlay activation |
| `WmActivateOverlayBackward` | -- | Triggers backward overlay activation |
| `WmActivateOverlayLauncher` | -- | Triggers launcher-mode activation |
| `WmActivateOverlayLauncherBackward` | -- | Triggers launcher-mode backward activation |
| `InputKeyEvent` | -- | Keyboard event from daemon-input (processed only when not idle) |
| `KeyRotationPending` | -- | Reconnects with rotated keypair via `BusClient::handle_key_rotation()` |

## Process Hardening

On Linux, daemon-wm applies the following security measures:

- `platform_linux::security::harden_process()` for process-level hardening.
- Resource limits: `nofile = 4096`, `memlock_bytes = 0`.
- `core_types::init_secure_memory()` probes `memfd_secret` and initializes secure memory before
  the sandbox is applied.
- Landlock filesystem sandbox via `daemon_wm::sandbox::apply_sandbox()`, applied after IPC
  keypair read and bus connection but before IPC traffic processing.
- systemd watchdog notification every 15 seconds via
  `platform_linux::systemd::notify_watchdog()`, with
  `platform_linux::systemd::notify_ready()` called at startup.

## Configuration

The `WmConfig` struct (`core-config/src/schema_wm.rs`) provides:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `hint_keys` | String | `"asdfghjkl"` | Characters used for hint assignment |
| `overlay_delay_ms` | u32 | 150 | Dwell delay before showing full picker |
| `activation_delay_ms` | u32 | 200 | Delay after activation before dismiss |
| `quick_switch_threshold_ms` | u32 | 250 | Fast-release threshold for instant switch |
| `border_width` | f32 | 4.0 | Border width in pixels |
| `border_color` | String | `"#89b4fa"` | Border color (CSS hex) |
| `background_color` | String | `"#000000c8"` | Overlay background (hex with alpha) |
| `card_color` | String | `"#1e1e1ef0"` | Card background color |
| `text_color` | String | `"#ffffff"` | Primary text color |
| `hint_color` | String | `"#646464"` | Hint badge color |
| `hint_matched_color` | String | `"#4caf50"` | Matched hint badge color |
| `key_bindings` | BTreeMap | (see [Hints](hints.md)) | Per-key app bindings |
| `show_title` | bool | true | Show window titles in overlay |
| `show_app_id` | bool | false | Show app IDs in overlay |
| `max_visible_windows` | u32 | 20 | Maximum windows in picker |

Configuration hot-reloads via `core_config::ConfigWatcher`. When the watcher fires, the main loop
reads the new `WmConfig`, builds an `OverlayTheme::from_config()`, sends
`OverlayCmd::UpdateTheme` to the overlay thread, updates the shared `wm_config` mutex, and
publishes `ConfigReloaded` on the IPC bus.

## Compositor Backend

Window list polling runs on a dedicated OS thread named `wm-winlist-poll` because the compositor
backend (`platform_linux::compositor::CompositorBackend`) performs synchronous Wayland roundtrips
with `libc::poll()`. On the `current_thread` tokio runtime, this would block all IPC message
processing. The thread calls `backend.list_windows()` every 2 seconds, sending results to the
tokio runtime via a `tokio::sync::mpsc` channel.

If `platform_linux::compositor::detect_compositor()` fails (e.g., no
`wlr-foreign-toplevel-management` protocol support), daemon-wm falls back to a D-Bus focus
monitor (`platform_linux::compositor::focus_monitor`). This monitor receives
`FocusEvent::Focus(app_id)` and `FocusEvent::Closed(app_id)` events, maintaining a synthetic
window list by tracking focus changes and window closures.

## Dependencies

The `daemon-wm` crate depends on the following workspace crates: `core-types`, `core-config`,
`core-ipc`, `core-crypto`, `core-auth`, `core-profile`. External dependencies include
`smithay-client-toolkit` (SCTK), `wayland-client`, `wayland-protocols-wlr`, `tiny-skia`, and
`cosmic-text`, all gated behind the `wayland` feature (enabled by default). The `platform-linux`
crate is used with the `cosmic` feature for compositor backend and theme integration.
