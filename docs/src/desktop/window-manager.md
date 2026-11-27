# Window Manager Daemon

The `daemon-wm` process implements a Wayland overlay window switcher with mnemonic letter hints,
application launching, and inline vault unlock. It runs a single-threaded tokio runtime
(`current_thread`) connected to the IPC bus as a `BusClient`, plus two OS threads: the overlay
(`overlay-sctk`) and the window list poll (`wm-winlist-poll`).

## Event Loop

`main.rs` drives a `core_daemon::EventLoop`. Each iteration wakes for one of:

| Wake | Source | Handling |
| --- | --- | --- |
| `Wake::Message` | IPC bus | `Runtime::message`: overlay activations, `InputKeyEvent`, `WmListWindows`, `WmActivateWindow` |
| `Wake::Own(Local::Overlay(Some(event)))` | Overlay thread | `Runtime::overlay_event`: keyboard events, dismissal |
| `Wake::Own(Local::Overlay(None))` | Overlay thread exited | `Runtime::overlay_died`: discard the activation, release the keyboard, schedule a respawn |
| `Wake::Own(Local::Respawn)` | Respawn timer (2 s) | `Runtime::respawn_overlay`: a new overlay thread |
| `Wake::Own(Local::Deadline)` | `controller.next_deadline()` | `Event::DwellTimeout` |
| `Wake::Own(Local::CompositorLost)` | Window list poll thread | The daemon stops with an error; systemd restarts it |
| `Wake::ConfigReloaded` | Configuration watcher | `Runtime::reconfigure`: new `WmConfig`, new theme, `ConfigReloaded` announced |
| `Wake::Shutdown` | SIGTERM/SIGINT | The overlay thread quits; `DaemonStopped` announced |

`serve::Respawns::next` orders the daemon's own sources: a lost compositor first, then the
pending respawn while the overlay thread is dead (otherwise its next event), then the
controller deadline. An overlay thread that dies more than 5 times within 2 minutes stops the
daemon for a systemd restart. A bus connection loss is an error from the event loop and stops
the daemon the same way.

## Controller State Machine

The `OverlayController` (`controller.rs`) is the single owner of all overlay state, timing, and
decisions. `Runtime::handle` feeds it an `Event`, and `Runtime::execute` performs the returned
`Command` list in order. The controller performs no I/O.

### Phases

- **Idle** -- Nothing happening. No overlay visible, no timers running.
- **Armed** -- The overlay surface is mapped but draws nothing, holding keyboard exclusivity.
  The controller waits for a modifier release (quick-switch) or the dwell deadline (Picking).
  Carries `entered_at`, the `Snapshot`, `selection`, `input`, `dwell_ms`, and an optional
  pending `LaunchRequest`.
- **Picking** -- The picker is visible. The user browses the window list or types hint
  characters. Carries the `Snapshot`, `selection`, `input`, and an optional pending launch.
- **Launching** -- A `LaunchExecute` request is in flight to `daemon-launcher`.
- **LaunchError** -- A launch failed. The overlay shows the reason; any key dismisses.
- **Unlocking** -- Vault unlock in progress: `profiles_to_unlock`, `current_index`,
  `password_len`, `unlock_mode` (`Resolving`, `Password`, `Verifying`),
  and the `LaunchRequest` retried after unlock.

### Events

| Event | Source | Description |
| --- | --- | --- |
| `Activate` | IPC `WmActivateOverlay` | Forward activation (Alt+Tab) |
| `ActivateBackward` | IPC `WmActivateOverlayBackward` | Backward activation (Alt+Shift+Tab) |
| `ActivateLauncher` | IPC `WmActivateOverlayLauncher` | Launcher mode (`[global] launcher_key`, default Alt+Space) |
| `ActivateLauncherBackward` | IPC `WmActivateOverlayLauncherBackward` | Launcher mode, backward (launcher key with Shift) |
| `ModifierReleased` | Overlay keyboard or IPC `InputKeyEvent` | Alt/Meta released |
| `Char(char)` | Overlay or IPC key event | Character typed (alphanumeric characters are kept) |
| `Backspace` | Overlay or IPC key event | Backspace |
| `SelectionDown` / `SelectionUp` | Overlay or IPC key event | Arrow navigation |
| `Confirm` | Overlay or IPC key event | Enter |
| `Escape` / `Dismiss` | Overlay or IPC key event / stale activation | Cancel |
| `DwellTimeout` | Controller deadline | Dwell expired |
| `LaunchResult` | Launch executor | The `LaunchOutcome` of a request |
| `UnlockStatus` | Unlock executor | Where a vault's unlock stands: `Unlocked`, `NeedsPassword { error }`, or `Failed { message }` |

The four activations are `core_types::OverlayRequest`, the one definition of each request's bus
event, shortcut id (the `sesame wm overlay` fast-path datagram and the GlobalShortcuts portal id),
description, `sesame` command arguments, and shortcut (`OverlayRequest::trigger`). The shortcuts
reach daemon-wm through the session's keybinding backend ([Linux
Platform](../platform/linux.md#overlay-shortcuts)).

### Transitions

```text
Idle ──Activate──> Armed ──DwellTimeout──> Picking
                     |                        |
                     |──Activate──> Picking   |──Activate──> Picking (selection cycles)
                     |                        |
                     |──Char / Selection──> Picking
                     |                        |──ModifierReleased──> Idle (activate selection)
                     |                        |──Confirm──> Idle (activate selection)
                     |                        |──Escape──> Idle
                     |
                     |──ModifierReleased──> Idle (quick-switch or selection)
                     +──staged launch + ModifierReleased / Confirm──> Launching

Launching ──LaunchResult(Launched)──> Idle
Launching ──LaunchResult(VaultsLocked)──> Unlocking
Launching ──LaunchResult(other)──> LaunchError ──any key──> Idle

Unlocking ──UnlockStatus(Unlocked)──> next profile or Launching (retry)
Unlocking ──UnlockStatus(NeedsPassword)──> password prompt (with the error, if any)
Unlocking ──UnlockStatus(Failed)──> LaunchError
Unlocking ──Escape──> Idle
```

An activation in Launching, LaunchError, or Unlocking is ignored.

### Snapshot

A fresh activation builds a `Snapshot` that carries all window data through the overlay
lifecycle:

1. MRU entries for windows that no longer exist are pruned.
2. The window list is MRU-ordered (`mru::reorder`) and truncated to `max_visible_windows`
   (default 20).
3. The origin (the focused window, top of the MRU stack) is moved to the last index.
4. Hints are assigned with `hints::assign_app_hints` (see [Hints](hints.md)), parallel to the
   window list, with the overlay rows (`WindowInfo`: `app_id`, `title`).
5. The key bindings are copied for focus-or-launch.

Keyboard actions only update the selection and input. The picker the overlay draws is always
the snapshot's rows at the controller's selection (`Snapshot::picker_at`), so the highlighted
row is the one a release or Enter activates.

Before a fresh activation, `Runtime::activate` re-reads the theme (dark/light, accent, and
frosted-glass changes apply without a restart) and asks the poll thread for a fresh window
list, waiting up to 200 ms (`FRESH_WINDOWS_WAIT`) so windows closed since the last poll are not
offered.

## Quick-Switch

On `ModifierReleased` in Armed, the controller activates `initial_forward()` (the MRU previous
window) when all of these hold:

1. Less than `dwell_ms` has elapsed since `entered_at`.
2. No input has been typed.
3. The selection has not moved from `initial_forward()`.

Otherwise it activates the current selection. A fast Alt+Tab release therefore switches to the
previous window without the picker ever drawing.

## Dwell

`controller.next_deadline()` returns `entered_at + dwell_ms` in Armed. `dwell_ms` is:

- `quick_switch_threshold_ms` (default 250) for forward and backward activation.
- `min(overlay_delay_ms, 100)` for launcher activation: a short dwell that lets the compositor
  grant keyboard exclusivity before the first keypress. Launcher mode activates even with no
  windows; the switcher modes require at least one.

At the deadline, `on_dwell_timeout()` enters Picking and shows the picker.

## Reactivation

An `Activate` or `ActivateBackward` while Armed or Picking (a repeated Alt+Tab the compositor
intercepted) moves the selection one step, wrapping, enters Picking, and emits
`Command::ResetGrace` so the overlay's modifier grace period restarts (Alt is still held). The
advance is timestamped: one `SelectionDown`/`SelectionUp` within 100 ms
(`REACTIVATION_DEDUP`) is the same keystroke arriving through the keyboard and is suppressed.

## Staged Launch

When the typed input matches no hint and is a single key whose binding has a `launch` command
(`hints::binding_for_key`), the controller stages a `LaunchRequest` (command, tags, launch
args) and emits `Command::ShowLaunchStaged`. The launch is not executed yet:

- **ModifierReleased** or **Confirm** with a staged launch enters Launching and emits
  `Command::ShowLaunching` and `Command::LaunchApp`.
- Typing more, or a hint match, clears the staged launch; so does a Backspace that empties the
  input.
- **Escape** dismisses the overlay.

`Runtime::launch_app` releases the keyboard grab, sends `LaunchExecute` under the configured
default profile with a 10-second timeout (`LAUNCH_TIMEOUT`), and feeds the outcome back as
`Event::LaunchResult`. An unanswered request is `LaunchOutcome::Failed`.

## Overlay Thread

`surface::wayland::spawn_overlay` starts the `overlay-sctk` thread, themed and laid out from
`WmConfig`. The daemon sends it `OverlayCmd` over `std::sync::mpsc` and receives
`OverlayEvent` over a tokio channel (capacity 64).

### Layer-Shell Surface

`OverlayApp::recreate_layer_surface` creates a `zwlr_layer_shell_v1` surface:

- `Layer::Overlay`, namespace `sesame`, anchored to all four edges, exclusive zone `-1`.
- Keyboard interactivity `None` and an empty input region while hidden or armed, so the
  surface takes no input until it is shown.
- An `ext_background_effect_surface_v1` object for blur when the compositor offers
  `ext_background_effect_manager_v1`.

### Loop

`run_sctk_overlay` repeats until `Quit`, a dropped command channel, or a failed Wayland
connection:

1. Flush requests, poll the display fd for up to 4 ms (`POLL_TIMEOUT`), read, and dispatch.
2. Apply every queued `OverlayCmd`.
3. Poll the activation (modifier release, stale activation).
4. Render when the view changed.

Without `wl_compositor` or `wl_shm` the thread ends. Without a layer shell it runs a stub loop
that answers activations with `Dismiss` and `HideAndSync` with `SurfaceUnmapped`, so the daemon
never waits on a surface that does not exist.

### Views

The overlay shows one `View`: `Hidden`, `Border` (armed: an invisible surface holding the
keyboard), `Picker`, `Launching`, `LaunchError`, `UnlockPrompt`, or `UnlockProgress`.

| Command | Effect |
| --- | --- |
| `ShowBorder` | Starts an activation, view `Border`, keyboard `Exclusive` |
| `ShowFull { windows, hints }` | View `Picker` with empty input (starts an activation when none is running) |
| `UpdateInput { input, selection }` | Picker input and selection; clears the staged launch |
| `ShowLaunchStaged { command }` | Picker shows `Launch <command>` when the input leaves no row |
| `ShowLaunching` / `ShowLaunchError` | Launch status views |
| `ShowUnlockPrompt` / `ShowUnlockProgress` | Unlock views (the prompt receives `password_len`, never password bytes) |
| `Hide` | View `Hidden`: keyboard `None`, empty input region, no blur |
| `HideAndSync` | `Hide`, then `SurfaceUnmapped` to the daemon |
| `ResetGrace` | Restarts the activation's grace period |
| `ConfirmKeyboardInput` | Keyboard input arrives over IPC this activation |
| `UpdateTheme` | New theme, redraw |
| `Quit` | The thread ends |

`Runtime::hide_and_sync` releases the keyboard grab, sends `HideAndSync`, and waits up to
5 seconds (`UNMAP_TIMEOUT`) for `SurfaceUnmapped` before a window is activated, so the window
activated next receives focus from an overlay already gone.

### Activation Polling

`poll::Activation` tracks the keyboard source of one activation (`Unconfirmed`, `Compositor`,
or `Ipc`) and reports at most one end:

- No key event within 3 seconds (`STALE_ACTIVATION_TIMEOUT`): `Dismiss`. While unconfirmed,
  the overlay re-requests exclusive keyboard focus on every poll.
- IPC keyboard but no input within 30 seconds (`IPC_IDLE_TIMEOUT`): `Dismiss`.
- Compositor keyboard, past the 150 ms grace period (`MODIFIER_POLL_GRACE`), Alt released:
  `ModifierReleased`. Alt held again rearms the release.

### Scale and Buffers

The output scale comes from SCTK's `scale_factor_changed` (the preferred buffer scale on
`wl_surface` v6, the largest output scale otherwise). The buffer is the configured logical size
times the scale, in a shm `SlotPool` resized with the surface.

## Rendering

`render::Canvas` draws one frame on a transparent `tiny_skia::Pixmap` (tiny-skia zero-fills
it, so the Armed view draws nothing). Each view returns the card it drew:

- **Picker**: a centered card with one row per visible window: the hint badge (matched,
  partially matched, or unmatched colors), the app name column (`show_app_id`), and the title
  column (`show_title`, ellipsized). The selected row gets the selection wash. Typed input shows
  in a pill below the card. Input that leaves no row shows `Launch <command>` for a staged
  launch, or that nothing matches.
- **Messages**: launch status, launch errors, the unlock prompt (one dot per character, at
  most 32), and unlock progress, each on a centered card.

Layout metrics (`render::layout::Layout`) follow a 4-point grid in logical pixels -- padding 20,
row height 48, row spacing 8, badge 48x32 with radius 8, app column 180, text 16, column gap 16,
card outline 1 -- scaled by the output scale. Text is shaped and rasterized with cosmic-text
(`FontSystem`, `SwashCache`) in the theme's font family.

`render_frame::present` attaches the ARGB8888 buffer, sets the buffer scale and damage, sets the
blur region behind the drawn card (converted to surface-local logical coordinates), and commits
once: the blur region is double-buffered state applied by that same commit.

### Theme

`OverlayTheme` holds `card_background`, `card_border`, `text_primary`, `text_secondary`,
`badge_background`, `badge_text`, `badge_matched_background`, `badge_matched_text`,
`selection_highlight`, `corner_radius`, and `font_family`. `OverlayTheme::from_config` builds
it in priority order:

1. **COSMIC system theme** (`platform_linux::cosmic_theme::CosmicTheme`): primary, accent,
   and secondary component colors, the medium corner radius, and the interface font. The card
   is translucent so the compositor blur shows through: the theme's blurred alpha when frosted,
   half opacity otherwise.
2. **Configuration**: each `WmConfig` color set to other than its default overrides the theme
   (`card_color`, `border_color`, `text_color`, `hint_color`, `hint_matched_color`).
3. **Defaults** when no COSMIC theme is available.

Colors are CSS hex (`#RRGGBB` or `#RRGGBBAA`) parsed by `Color::from_hex`.

## MRU Stack

`mru::MruStore` keeps the most-recently-used window stack in the file `Layout::mru_file`
names: one window ID per line, most recent first, capped at 64 entries.

- `load()` reads under a shared `flock`; a missing file is an empty stack.
- `save(target)` moves `target` to the top under an exclusive `flock`.
- `prune(live_ids)` drops entries for windows that no longer exist.
- `seed_if_empty(windows)` seeds an empty stack with the focused window at startup.
- `reorder(windows, get_id, state)` sorts by stack position; windows not in the stack keep
  their compositor order after the tracked ones.

The stack orders the overlay and is not authoritative: `MruStore` logs I/O failures and
degrades to an empty stack or an unchanged file.

## Inline Vault Unlock

A launch denied with `LaunchDenial::VaultsLocked { locked_profiles }` enters Unlocking without
dismissing the overlay, keeping the `LaunchRequest` for the retry.

1. **Resolve** (`Command::ResolveUnlock`): `Runtime::resolve_unlock` shows "Authenticating"
   and runs the unlock loop of [Factor Architecture](../authentication/factor-architecture.md#the-unlock-loop):
   it asks `daemon-secrets` which factors the vault still requires (`VaultAuthQuery`,
   5-second `QUERY_TIMEOUT`), looks each one up (`AuthDispatcher::backend`), and submits
   every factor that needs no interaction (the SSH agent) as a `FactorSubmit` (30-second
   `FACTOR_TIMEOUT`) under the vault's keying (`core_auth::VaultMetadata::load_keying`). The
   platform keyring factor is submitted by daemon-launcher (`KeyringUnlockRequest`, 2-minute
   `KEYRING_TIMEOUT`: the keyring's own unlock prompt may wait for the user), because the
   credential store is on the session D-Bus bus, which this daemon's sandbox does not grant.
   `daemon-secrets` applies the vault's auth policy. The result is an `Event::UnlockStatus`:
   - `Unlocked` when a submission completed the unlock (or the vault already was unlocked);
   - `NeedsPassword` when a remaining factor is the password;
   - `Failed` when the vault requires a factor the overlay cannot provide (no backend, or a
     hardware touch), its metadata or enrollment is unreadable, or no factor is available. The
     overlay shows the message as a launch error.
2. **Password**: the controller enters `Password` and shows the prompt. Characters go to the
   runtime's `SecureVec` password buffer; the overlay receives only the length.
3. **Submission** (`Command::SubmitPasswordUnlock`): `Runtime::submit_password_unlock` shows
   "Verifying", moves the buffer into `core_auth::PasswordBackend` (the runtime keeps a fresh
   empty buffer), unwraps the master key, and submits it as a factor. A password that does not
   unwrap the key shows the prompt again with "Wrong password"; a factor `daemon-secrets`
   rejects shows its reason. An accepted password of a vault whose policy requires more
   factors resolves the remaining factors (step 1) instead of reporting a wrong password.
4. **Next profile**: after each unlock the next locked profile starts at step 1. A status for
   any profile but the one being unlocked is ignored.
5. **Retry**: with every profile unlocked, the controller emits `Command::ActivateProfiles`
   (`ProfileActivate` per profile, 10-second `ACTIVATE_TIMEOUT`) and `Command::LaunchApp` with
   the original request.

Escape in Unlocking clears the password buffer and dismisses the overlay. The password buffer
is pre-allocated and `mlock`ed (`SecureVec::for_password`) and never leaves the daemon thread.

## Keyboard Input

Key events arrive from two sources:

1. **The overlay keyboard**: the layer surface's SCTK `KeyboardHandler` while it holds
   exclusive focus, sent as `OverlayEvent`s.
2. **IPC `InputKeyEvent`**: `daemon-input` forwards evdev key events while this daemon holds a
   grab. `ipc_keys::map_ipc_key_to_event` maps X11 keysyms (`core_types::keysym`) to controller
   events; Tab is ignored (cycling comes from reactivation), and of releases only Alt/Meta
   count.

Both pass through one `KeyDeduplicator` (8 recent entries, 50 ms window, direction-aware), so
the first arrival of each keystroke is handled. `Command::ShowBorder` publishes
`InputGrabRequest`; hiding publishes `InputGrabRelease` (before the overlay hides). The first
IPC key event of an activation sends `ConfirmKeyboardInput`. A launcher activation with no
windows confirms IPC input at once: the compositor grants no focus without a toplevel.

## Window List

When `platform_linux::compositor::detect_compositor` finds a backend, the stack is seeded from
its first enumeration and the `wm-winlist-poll` thread re-enumerates every 2 seconds
(`POLL_INTERVAL`) and on request (`Refresh::fresh`); the compositor backend's synchronous
Wayland roundtrips would otherwise stall the single-threaded runtime. After 10 consecutive
failed enumerations (`MAX_FAILURES`) the compositor connection is dead: the thread reports it
(`Refresh::lost`), and the event loop stops the daemon with an error for a systemd restart.

Without a backend, `winlist::track_focus` builds the list from the wlr-foreign-toplevel focus
monitor (`platform_linux::focus_monitor`): each focused app ID is a window, removed when it
closes. Without that protocol the list stays empty.

Window activation (`Runtime::activate_window`) calls the backend's `activate_window` on the
blocking pool and, when the compositor accepts it, records the window in the MRU stack. Without
a backend, or when the compositor refuses, the activation fails (`WmActivateWindowResponse
{ success: false }`).

## IPC Interface

| Message | Response | Description |
| --- | --- | --- |
| `WmListWindows` | `WmListWindowsResponse { windows }` | The MRU-ordered window list |
| `WmActivateWindow { window_id }` | `WmActivateWindowResponse { success }` | Activates the window with that ID or app ID |
| `WmActivateOverlay` | -- | Forward activation |
| `WmActivateOverlayBackward` | -- | Backward activation |
| `WmActivateOverlayLauncher` | -- | Launcher activation |
| `WmActivateOverlayLauncherBackward` | -- | Launcher activation, backward |
| `InputKeyEvent` | -- | Key event from daemon-input (handled only while not idle) |

The daemon publishes `WmOverlayShown` on activation and `WmOverlayDismissed` when the overlay
closes.

## Process Hardening

- `platform_linux::security::harden_process()` and resource limits (`nofile = 4096`,
  `memlock_bytes = 0`).
- `core_types::init_secure_memory()` probes `memfd_secret` before the sandbox.
- `daemon_wm::sandbox::apply_sandbox` applies Landlock and seccomp on the only thread, before
  the runtime, configuration watcher, Wayland, and overlay threads start. The grants are the
  bus, the Wayland socket, configuration (read), SSH agent sockets, the systemd notification
  socket, the cache directory (MRU stack), COSMIC theme configuration, user data, and the system
  font, library, and XKB paths. There are no DRI or GPU grants (rendering is CPU `wl_shm`) and
  no D-Bus bus ([Sandbox Model](../architecture/sandbox-model.md)).
- `platform_linux::systemd::notify_ready()` at startup; the event loop sends watchdog
  notifications.

## Configuration

`WmConfig` (`core-config/src/schema_wm.rs`), from the configured default profile:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `hint_keys` | String | `"asdfghjkl"` | Hint keys for apps without a key binding or a letter in their name |
| `overlay_delay_ms` | u32 | 150 | Launcher dwell bound (the launcher dwell is `min(overlay_delay_ms, 100)`) |
| `quick_switch_threshold_ms` | u32 | 250 | Release within this time switches instantly; the switcher dwell |
| `border_color` | String | `"#89b4fa"` | Card outline color |
| `card_color` | String | `"#1e1e1ef0"` | Card background color |
| `text_color` | String | `"#ffffff"` | Text color |
| `hint_color` | String | `"#646464"` | Hint badge color |
| `hint_matched_color` | String | `"#4caf50"` | Matched hint badge color |
| `key_bindings` | BTreeMap | (see [Hints](hints.md)) | Per-key app bindings and launch commands |
| `show_title` | bool | true | Title column |
| `show_app_id` | bool | false | App name column |
| `max_visible_windows` | u32 | 20 | Windows in the picker |

On a configuration reload the daemon adopts the new `WmConfig`, sends the overlay its theme, and
announces `ConfigReloaded`.

## Dependencies

Workspace crates: `core-types`, `core-config`, `core-daemon`, `core-layout`, `core-ipc`,
`core-crypto`, `core-auth`. On Linux: `platform-linux` (with `cosmic`),
`smithay-client-toolkit`, `wayland-client`, `wayland-protocols`, `tiny-skia`, `cosmic-text`,
and `rustix`.
