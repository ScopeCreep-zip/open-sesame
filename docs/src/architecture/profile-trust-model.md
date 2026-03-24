# Profile Trust Model

Trust profiles are the fundamental isolation boundary in Open Sesame.
Every scoped resource -- secrets, clipboard content, frecency data,
snippets, audit entries, and launch configurations -- is partitioned
by trust profile.

## TrustProfileName Validation

The `TrustProfileName` type in `core-types/src/profile.rs` enforces
strict validation at construction time. It is impossible to hold an
invalid `TrustProfileName` value after construction.

**Invariants:**

- Non-empty.
- Maximum 64 bytes.
- Must start with an ASCII alphanumeric character: `[a-zA-Z0-9]`.
- Body characters restricted to: `[a-zA-Z0-9_-]`.
- Not `.` or `..` (path traversal prevention).
- No whitespace, path separators, or null bytes.

Invalid characters produce a detailed error message including the byte
value and position:
`"trust profile name contains invalid byte 0x{b:02x} at position {i}"`.

These rules make the name safe for direct use in filesystem paths
without additional sanitization.

**Filesystem mappings:**

| Resource | Path pattern |
|---|---|
| SQLCipher vault | `vaults/{name}.db` |
| BLAKE3 KDF context | `"pds v2 vault-key {name}"` |
| Frecency database | `launcher/{name}.frecency.db` |

`TrustProfileName` implements `TryFrom<String>` and `TryFrom<&str>`,
returning `Error::Validation` on failure. It serializes transparently
(via `#[serde(transparent)]`) as a plain string and deserializes with
validation. All boundary-facing code -- CLI argument parsers, IPC
message handlers, config file loaders -- validates at entry.

## Profile Scoping

Each trust profile isolates the following resources:

| Resource | Isolation mechanism |
|---|---|
| **Secrets** | Per-profile SQLCipher vault file. Vault keys are derived via BLAKE3 KDF with profile-specific context strings. |
| **Clipboard** | Cross-profile clipboard access is denied and logged as `AuditAction::IsolationViolationAttempt`. |
| **Frecency** | Per-profile SQLite database for launch frecency ranking. Profile switch in daemon-launcher triggers `engine.switch_profile()`. |
| **Extensions** | Extension data is scoped per profile via `IsolatedResource::Extensions`. |
| **Window list** | Window management state is scoped per profile via `IsolatedResource::WindowList`. |
| **Audit** | Audit entries record which profile was involved in each operation via `ProfileId` fields. |
| **Launch profiles** | Launch profile definitions live under `profiles.<name>.launch_profiles` in configuration. |

The `IsolatedResource` enum in `core-profile/src/lib.rs` defines the
five isolatable resource types: `Clipboard`, `Secrets`, `Frecency`,
`Extensions`, `WindowList`. It is serialized with
`#[serde(rename_all = "lowercase")]` for configuration and audit log
entries.

## Profile State Machine

Each profile has an independent lifecycle state, represented by the
`ProfileState` enum:

- **Inactive**: vault closed, no secrets served.
- **Active(ProfileId)**: vault open, serving secrets.
- **Transitioning(ProfileId)**: activation or deactivation in progress.

Multiple profiles may be active concurrently. There is no global "active
profile" singleton -- the system supports simultaneous active profiles
with independent vaults. The `active_profiles` set in daemon-profile is
a `HashSet<TrustProfileName>`.

## Context-Driven Activation

The `ContextEngine` in `core-profile/src/context.rs` evaluates system
signals against activation rules to determine the default profile for
new unscoped launches. Changing the default does not deactivate other
active profiles.

### Context Signals

Signals that trigger rule evaluation:

| Signal | Source |
|---|---|
| `SsidChanged(String)` | WiFi network change via D-Bus SSID monitor (`platform_linux::dbus::ssid_monitor`). |
| `AppFocused(AppId)` | Wayland compositor focus change via `platform_linux::compositor::focus_monitor`. |
| `UsbDeviceAttached(String)` | USB device insertion (vendor:product identifier). |
| `UsbDeviceDetached(String)` | USB device removal. |
| `HardwareKeyPresent(String)` | Hardware security key detection (e.g., YubiKey). |
| `TimeWindowEntered(String)` | Time-based rule trigger (cron-like expression). |
| `GeolocationChanged(f64, f64)` | Location change (latitude, longitude). |

Signal sources are spawned as long-lived tokio tasks in
`daemon-profile/src/main.rs`. They are conditionally compiled behind
`#[cfg(all(target_os = "linux", feature = "desktop"))]`.

### Activation Rules

Each profile's activation configuration (`ProfileActivation`) contains:

- **rules**: a `Vec<ActivationRule>`, each specifying a `RuleTrigger`
  type and a string value to match.
- **combinator**: `RuleCombinator::All` (every rule must match the
  signal) or `RuleCombinator::Any` (one matching rule suffices).
- **priority**: `u32` value. When multiple profiles match, the highest
  priority wins.
- **switch_delay_ms**: `u64` debounce interval in milliseconds. Prevents
  rapid oscillation when a signal fires repeatedly.

### Evaluation Algorithm

When `ContextEngine::evaluate(signal)` is called:

1. All profiles whose rules match the signal are collected. For `All`
   combinators, every rule in the profile must match; for `Any`, at
   least one rule must match.
2. Candidates are sorted by priority descending.
3. The highest-priority candidate is selected.
4. If it is already the current default, `None` is returned (no change).
5. Debounce check: if the candidate was last switched to within
   `switch_delay_ms` ago, `None` is returned.
6. Otherwise, the default is updated, the switch time is recorded, and
   the new `ProfileId` is returned.

Rule matching is type-strict: an `Ssid` trigger only matches
`SsidChanged` signals, an `AppFocus` trigger only matches `AppFocused`
signals, and so on. Mismatched trigger/signal pairs always return false.

## Default Profile

The default profile determines which trust profile is used for new
unscoped launches (launches without an explicit `--profile` flag). It
is set by:

1. **Configuration**: `global.default_profile` in the config file,
   loaded at startup.
2. **Context engine**: automatic switching based on runtime signals
   overrides the config default.
3. **Hot reload**: when config changes are detected by `ConfigWatcher`,
   the context engine is rebuilt with the new default and the
   `default_profile_name` is updated. The `config_profile_names` list
   is also refreshed so that `sesame profile list` reflects added or
   removed profiles.

Default profile changes are:

- Audited via `AuditAction::DefaultProfileChanged`.
- Broadcast on the IPC bus as `EventKind::DefaultProfileChanged`.
- Reported by `sesame status`.

## Profile Inheritance

There is no profile inheritance in the current implementation. Each
trust profile is an independent, self-contained configuration with its
own launch profiles, vault, and isolation boundaries. Cross-profile
interaction is limited to qualified tag references (e.g., `work:corp`)
in launch profile composition, which merge environment at launch time
without merging the profile definitions themselves.
