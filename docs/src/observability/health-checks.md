# Health Checks

Open Sesame provides daemon health monitoring through `sesame status` and systemd watchdog
integration.

## sesame status

The `sesame status` command in `open-sesame/src/status.rs` connects to the IPC bus and sends a
`StatusRequest` message to daemon-profile. The response (`StatusResponse`) includes:

- **Per-vault lock state** (`lock_state: BTreeMap<TrustProfileName, bool>`): each trust
  profile's vault is reported as locked or unlocked. Displayed as a table with profile names
  and colored status indicators.
- **Default profile** (`default_profile: TrustProfileName`): the currently active default
  profile for new unscoped launches.
- **Active profiles** (`active_profiles: Vec<TrustProfileName>`): the list of profiles that
  are currently activated (vault open, serving secrets).
- **Global locked flag** (`locked: bool`): legacy fallback used when per-profile lock state is
  unavailable.

Example output:

```text
Vaults:
  personal  unlocked
  work      locked
Default profile: personal
Active profiles:
  - personal (default)
```

If the `lock_state` map is empty (daemon-secrets has not reported per-profile state), the
display falls back to a single global locked/unlocked indicator.

### Liveness Check

The `sesame status` command implicitly tests daemon-profile liveness. If the IPC bus is
unreachable (daemon-profile is not running or the socket is missing), the `connect()` call fails
with an error. This makes `sesame status` usable as a basic health check in scripts and
monitoring systems.

## systemd Integration

### Type=notify and sd_notify

Daemons use systemd's `Type=notify` service type. After completing initialization (config
loaded, IPC connected, indexes built), each daemon calls
`platform_linux::systemd::notify_ready()`, which sends `READY=1` to systemd. This tells systemd
that the daemon is ready to accept requests.

The `NOTIFY_SOCKET` path is included in daemon-profile's Landlock ruleset so that `sd_notify`
calls succeed after the filesystem sandbox is applied. Abstract sockets (prefixed with `@`)
bypass Landlock `AccessFs` rules and do not require explicit allowlisting.

### WatchdogSec=30

Daemon-profile runs a tokio interval timer at half the watchdog interval (15 seconds) and calls
`platform_linux::systemd::notify_watchdog()` on each tick, which sends `WATCHDOG=1` to systemd.

If a daemon fails to send a watchdog notification within 30 seconds (two missed ticks), systemd
considers the daemon unresponsive and restarts it according to the unit's `Restart=` policy.

The watchdog tick in daemon-profile also serves as the reconciliation driver -- every other tick
(every 30 seconds), it reconciles state with daemon-secrets.

### Reconciliation

Daemon-profile reconciles with daemon-secrets every 30 seconds (every other watchdog tick,
controlled by `watchdog_tick_count.is_multiple_of(2)`). The reconciliation RPC updates:

- The global `locked` flag.
- The `active_profiles` set.
- Per-profile lock state.

This ensures that `sesame status` reports current state even if an IPC event was lost or a
daemon restarted between reconciliation cycles.

## Crash-Restart Detection

Daemon-profile tracks daemon identities via `DaemonTracker` in `daemon-profile/src/main.rs`.
The tracker maintains a `HashMap<String, DaemonId>` mapping daemon names to their last known
identity.

When a `DaemonStarted` event arrives from a daemon name that already has a registered
`DaemonId`, the `track()` method detects a crash-restart: the old ID differs from the new one.
It returns `Some(old_id)`, allowing daemon-profile to clean up stale state associated with the
previous instance.

## Watchdog Logging

Watchdog ticks are logged at `info` level for the first three ticks and then every 20th tick
(controlled by `watchdog_tick_count <= 3 || watchdog_tick_count.is_multiple_of(20)`). This
provides startup confirmation without flooding the journal during steady-state operation.
