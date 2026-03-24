# Metrics and Observability

This page describes the metrics and observability design for Open Sesame.
Structured logging is implemented today; metrics export and the
`sesame status --doctor` command are planned.

## Current State

All daemons emit structured log events via the `tracing` crate. Log output
includes span context (daemon ID, profile name, operation), timestamps, and
severity levels. Logs are written to `journald` when running under systemd,
or to stderr in development.

Metrics export (Prometheus, OpenTelemetry) is not yet implemented.

## Planned Metrics Export

### Prometheus

Each daemon will expose a `/metrics` endpoint on a local Unix socket (not a
TCP port) in Prometheus exposition format. A Prometheus instance or
`prometheus-node-exporter` textfile collector can scrape these.

### OpenTelemetry (OTLP)

For environments with an OTLP collector (Grafana Agent, OpenTelemetry
Collector), daemons will support OTLP export over gRPC or HTTP. This is
configured in `~/.config/pds/observability.toml`.

## Planned Metric Categories

### Daemon Health

| Metric | Type | Description |
|---|---|---|
| `pds_daemon_uptime_seconds` | Gauge | Seconds since daemon start |
| `pds_daemon_restart_count` | Counter | systemd restart count (from watchdog) |
| `pds_daemon_memory_rss_bytes` | Gauge | Resident set size |
| `pds_daemon_memory_locked_bytes` | Gauge | `mlock`'d memory |

### Vault Operations

| Metric | Type | Description |
|---|---|---|
| `pds_vault_unlock_total` | Counter | Unlock attempts (labeled by factor, result) |
| `pds_vault_unlock_duration_seconds` | Histogram | Time to complete unlock |
| `pds_vault_secret_read_total` | Counter | Secret read operations |
| `pds_vault_secret_write_total` | Counter | Secret write operations |
| `pds_vault_acl_denial_total` | Counter | ACL-denied operations |

### IPC Throughput

| Metric | Type | Description |
|---|---|---|
| `pds_ipc_messages_sent_total` | Counter | Messages sent (labeled by event kind) |
| `pds_ipc_messages_received_total` | Counter | Messages received |
| `pds_ipc_message_bytes_total` | Counter | Total bytes over the bus |
| `pds_ipc_request_duration_seconds` | Histogram | Request-response round-trip time |
| `pds_ipc_connections_active` | Gauge | Current connected clients |
| `pds_ipc_clearance_drop_total` | Counter | Messages dropped by clearance check |

### Memory Protection Posture

| Metric | Type | Description |
|---|---|---|
| `pds_mlock_limit_bytes` | Gauge | Configured `LimitMEMLOCK` |
| `pds_mlock_used_bytes` | Gauge | Currently locked memory |
| `pds_seccomp_active` | Gauge | 1 if seccomp filter is loaded, 0 otherwise |
| `pds_landlock_active` | Gauge | 1 if Landlock restrictions are active |

## sesame status --doctor

The `sesame status --doctor` command (tracked as issue #20) performs a
comprehensive system health check. The planned implementation runs 43
individual checks across 6 categories.

### Check Categories

#### 1. Daemon Liveness

Verifies each daemon process is running, its systemd unit is active, and it
responds to `StatusRequest` on the IPC bus.

#### 2. IPC Connectivity

Tests Noise IK handshake to the bus server, measures round-trip latency,
verifies the socket file exists with correct permissions.

#### 3. Vault Integrity

Checks SQLCipher database integrity, verifies enrolled auth factors match
configuration, tests that the vault salt is present and the correct length.

#### 4. Cryptographic Posture

Verifies Noise IK keypairs exist, checks key file permissions (0600),
validates that the ClearanceRegistry is populated, confirms `mlock` is
available for secret memory.

#### 5. Platform Integration

Checks Wayland session type, verifies COSMIC compositor protocol
availability, tests `xdg-desktop-portal` connectivity, confirms D-Bus
session bus access.

#### 6. Configuration

Validates TOML configuration against the schema, checks for deprecated keys,
verifies file permissions on sensitive config files.

### Output Formats

The `--doctor` command supports multiple output formats:

- **Text** (default) -- Human-readable output with pass/fail/warn indicators
  and remediation suggestions.
- **JSON** (`--format json`) -- Machine-parseable output for CI integration.
- **Prometheus exposition** (`--format prometheus`) -- Each check becomes a
  gauge metric (`pds_doctor_check{name="...",category="..."}` with value
  0, 1, or 2 for pass, fail, or warn).
- **OTLP** (`--format otlp`) -- Exports check results as OpenTelemetry
  metrics to a configured collector.

### Governance Profile Filtering

Checks can be filtered by governance profile to focus on compliance-relevant
items:

```bash
# Run only STIG-relevant checks
sesame status --doctor --governance stig

# Run PCI-DSS checks, output as JSON
sesame status --doctor --governance pci-dss --format json

# Run SOC2 checks
sesame status --doctor --governance soc2
```

Each check is tagged with the governance frameworks it is relevant to. For
example, the `mlock` availability check is relevant to STIG and PCI-DSS but
not SOC2; the audit log integrity check is relevant to all three.
