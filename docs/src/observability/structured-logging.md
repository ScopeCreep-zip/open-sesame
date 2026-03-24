# Structured Logging

All Open Sesame daemons use the `tracing` crate for structured, leveled logging. Log output is
configurable between JSON and human-readable formats, with journald integration on Linux.

## Tracing Integration

Every daemon initializes a `tracing-subscriber` stack at startup. The two supported output
formats are:

- **JSON** (`--log-format json`, default for daemon-profile): machine-parseable structured JSON,
  one object per line. Enabled via `tracing_subscriber::fmt().json().init()`.
- **Pretty** (`--log-format pretty`): human-readable colored output via
  `tracing_subscriber::fmt().init()`.

The format is selected via the `--log-format` CLI flag or the `PDS_LOG_FORMAT` environment
variable. The implementation is in `daemon-profile/src/sandbox.rs` (`init_logging`).

## RUST_LOG and Log Levels

All daemons read the `RUST_LOG` environment variable via
`tracing_subscriber::EnvFilter::try_from_default_env()`. If `RUST_LOG` is not set, the default
filter is `info`.

Standard tracing levels are used throughout:

| Level | Usage |
|---|---|
| `error` | IPC failures, secret fetch denials, audit chain verification failures, sandbox application failures. |
| `warn` | Non-fatal issues: systemd-run fallback, corrupt audit tail entry, HTTP git URL detected. |
| `info` | Daemon lifecycle (starting, ready, shutting down), launch execution, watchdog ticks, config reloads, key rotation, audit chain verification on startup. |
| `debug` | Child reaping status, context engine debounce suppression. |

## journald Integration

The `tracing-journald` crate is a Linux dependency of daemon-launcher and other daemons. When
running under systemd, structured log fields are forwarded to the journal as journal fields,
enabling filtering with `journalctl`:

```bash
journalctl --user -u daemon-launcher.service
journalctl --user -u daemon-profile.service
```

## Structured Fields

Tracing spans and events use structured key-value fields throughout the codebase. Notable
patterns:

- **Launch execution**: `entry_id`, `program`, `arg_count`, `scope_name`, `tags`, `devshell`,
  `env_count`, `secret_count`, `via_scope`, `pid` are attached to launch log lines in
  `daemon-launcher/src/launch.rs`.
- **Secret fetching**: `secret_count` and per-secret `reason` fields on denial.
- **Watchdog**: `watchdog_tick_count` tracks event loop health in `daemon-profile/src/main.rs`.
- **IPC messages**: `sender` and `msg_id` identify message origin.
- **Audit**: `path`, `sequence`, `entries` track audit log state at startup.
- **Security posture**: sandbox `status` is logged after Landlock and seccomp application.
- **Key rotation**: `daemon_name`, `generation`, `clearance` fields on rotation events.
- **Desktop entry resolution**: `entry_id`, `resolved_id` logged with the resolution strategy
  used.

## Daemon Startup Logging Sequence

Daemon-profile follows this startup sequence (other daemons follow a similar pattern):

1. `"daemon-profile starting"` -- logged immediately after CLI parsing.
2. `harden_process()` and `apply_resource_limits()` -- the platform layer hardens the process
   (RLIMIT_NOFILE, RLIMIT_MEMLOCK, etc.).
3. `init_secure_memory()` -- probes `memfd_secret(2)` availability and logs whether the kernel
   supports sealed anonymous memory for secret storage.
4. Sandbox application -- logs the Landlock and seccomp result via `?status` structured field.
5. IPC bus server bind -- logs `path` and confirms Noise IK encryption.
6. Per-daemon keypair generation -- logs `daemon`, `clearance` for each of the six known daemons.
7. Audit logger initialization -- logs `path` and `sequence` (chain head position).
8. Audit chain verification -- logs `entries` count if the chain is intact, or an error if
   verification fails.
9. Context engine initialization -- logs `profile` (the default ProfileId).
10. `platform_linux::systemd::notify_ready()` -- sends `READY=1` to systemd.
11. `"daemon-profile ready"` -- logged after readiness notification.
