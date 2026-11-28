# Health Checks

Open Sesame provides daemon health monitoring through `sesame status` and systemd watchdog
integration.

## sesame status

The `sesame status` command in `open-sesame/src/status.rs` connects to the IPC bus and sends a
`StatusRequest` message to daemon-profile. The response (`StatusResponse`) includes:

- **Per-vault lock state** (`lock_state: Result<BTreeMap<TrustProfileName, bool>, String>`):
  daemon-secrets inventories persisted vault artifacts and held runtime state. Configuration
  profiles do not define this inventory. A successful inventory is displayed with profile names and
  lock indicators; acquisition and responder errors are displayed as unknown.
- **Default profile** (`default_profile: TrustProfileName`): the currently active default profile
  for new unscoped launches.
- **Active profiles** (`active_profiles: Vec<TrustProfileName>`): the list of profiles that are
  currently activated (vault open, serving secrets).
- **Global locked flag** (`locked: bool`): whether daemon-secrets holds no master keys. This flag
  cannot replace a failed inventory.

Example output:

```text
Vaults:
  personal  unlocked
  work      locked
Default profile: personal
Active profiles:
  - personal (default)
```

A successful empty inventory displays `none found`. An unavailable inventory displays `unknown` with
its cause, including before installation initialization.

### Configuration Convergence

```sh
sesame status --doctor config --output json --exit-code
```

The config category captures the local source revision, requests each daemon's configuration status
through its authenticated bus owner, and captures local sources again after the probe. Changing
sources during the probe fails the check rather than comparing inconsistent inputs.

Daemon and configuration checks always include profile, secrets, launcher, and snippets. WM,
clipboard, and input are included when the desktop target is active or transitioning, or when their
individual service is running, transitioning, or failed. Inactive desktop services on a headless
installation are not required. Failure to query the service manager is an explicit applicability
failure.

Source acceptance and consumer application are independent. Each response reports the last accepted
revision, last applied revision, latest observation result, watcher health, and application outcome.
Pending application, rejected or unreadable observations, failed resource application,
restart-required changes, and unavailable responders fail convergence. An applied current revision
with degraded native watches is a warning: timer reconciliation continues. Native watches with
accepted, applied current sources pass.

Only a consumer acknowledgement emits `ConfigReloaded`. Source acceptance alone emits no application
success. The WM waits for renderer settings adoption; the launcher prepares replacement portal
bindings before committing its configuration. Failed attempts retain the previously applied
snapshot. Authorization additionally requires an accepted observation matching the consumer's
acknowledged observation, so stale policy cannot authorize requests. Loss of an established launcher
shortcut stream rejects application and retries binding on reconciliation. A portal absent at
startup is optional; once adopted, it must recover before the launcher can report convergence.

Lock and deactivation use transport authentication without loading installation identity. A
malformed identity file therefore cannot prevent these authority-reducing operations.

### Consumer Application Policies

| Consumer | Application boundary | Failure behavior |
| --- | --- | --- |
| Profile | Rebuild profiles, default profile, and context engine; announce default changes after acknowledgement | Activation requires current acknowledged policy; deactivation and inventory remain available |
| Secrets | Adopt request-time ACL and profile policy | CRUD, factor submission, and activation fail closed; lock, deactivation, and inventory remain available |
| Launcher | Prepare replacement shortcut bindings, then commit launch configuration | Keep previous committed configuration when preparation fails; lost adopted bindings require recovery |
| WM | Renderer acknowledges theme and column settings | Reject failed application; resource loss prevents convergence until respawn and acknowledgement |
| Clipboard | Adopt clipboard settings and installation namespace | Retain previous applied settings when source observation fails |
| Input | Acknowledge observation; capture is controlled by XKB and CLI rather than profile input fields | Existing capture continues; source failures remain visible in configuration status |
| Snippets | Acknowledge observation; contents belong to the in-memory RPC store | Existing snippets remain available; source failures remain visible in configuration status |

The shared reload boundary classifies changes to sandbox requirements, IPC configuration,
cryptography, and an already-adopted installation identity as restart-required. The previous applied
snapshot remains available, but these changes cannot report convergence. First-time installation
identity adoption is supported without restarting pre-init daemons.

Clipboard retains the latest authenticated default-profile announcement across configuration
notifications. Recording pauses while that identity cannot be resolved in the applied configuration,
then resumes when its profile becomes available. A configuration notification does not overwrite an
already reported default.

### Liveness Check

The `sesame status` command implicitly tests daemon-profile liveness. If the IPC bus is unreachable
(daemon-profile is not running or the socket is missing), the `connect()` call fails with an error.
This makes `sesame status` usable as a basic health check in scripts and monitoring systems.

## systemd Integration

### Type=notify and sd_notify

Daemons use systemd's `Type=notify` service type. After completing initialization (config loaded,
IPC connected, indexes built), each daemon calls `platform_linux::systemd::notify_ready()`, which
sends `READY=1` to systemd. This tells systemd that the daemon is ready to accept requests.

Every sandboxed daemon's Landlock ruleset grants the `NOTIFY_SOCKET` path
(`core_daemon::sandbox::notify_rules`) so that `sd_notify` calls succeed after the sandbox is
applied: from Landlock ABI 9 a pathname socket is reachable only under a rule. The user service
manager's notification socket is a pathname socket (`$XDG_RUNTIME_DIR/systemd/notify`); an abstract
one (`@`-prefixed) would be unreachable under the abstract-socket scope every daemon runs with
([Sandbox Model](../architecture/sandbox-model.md)).

### WatchdogSec=30

Daemon-profile runs a tokio interval timer at half the watchdog interval (15 seconds) and calls
`platform_linux::systemd::notify_watchdog()` on each tick, which sends `WATCHDOG=1` to systemd.

If a daemon fails to send a watchdog notification within 30 seconds (two missed ticks), systemd
considers the daemon unresponsive and restarts it according to the unit's `Restart=` policy.

The watchdog tick in daemon-profile also serves as the reconciliation driver -- every other tick
(every 30 seconds), it reconciles state with daemon-secrets.

### Reconciliation

Daemon-profile reconciles with daemon-secrets every 30 seconds (every other watchdog tick). The
reconciliation RPC updates:

- The global `locked` flag.
- The `active_profiles` set.
- Per-profile lock state.

This ensures that `sesame status` reports current state even if an IPC event was lost or a daemon
restarted between reconciliation cycles.

## Crash-Restart Detection

Daemon-profile tracks daemon identities via `DaemonTracker` in `daemon-profile/src/main.rs`. The
tracker maintains a `HashMap<String, DaemonId>` mapping daemon names to their last known identity.

When a `DaemonStarted` event arrives from a daemon name that already has a registered `DaemonId`,
the `track()` method detects a crash-restart: the old ID differs from the new one. It returns
`Some(old_id)`, allowing daemon-profile to clean up stale state associated with the previous
instance.

## Watchdog Logging

Watchdog ticks are logged at `info` level for the first three ticks and then every 20th tick
(controlled by `watchdog_tick_count <= 3 || watchdog_tick_count.is_multiple_of(20)`). This provides
startup confirmation without flooding the journal during steady-state operation.
