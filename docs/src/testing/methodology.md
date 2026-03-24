# Testing Methodology

Open Sesame uses a layered testing strategy spanning unit tests, integration tests, property-based
tests, and snapshot tests across the workspace.

## Test Categories

### Unit Tests

Unit tests are embedded in source files using `#[cfg(test)]` modules. They cover pure logic such as
hint assignment, configuration validation, cryptographic derivation, rate limiting, ACL enforcement,
audit logging, and type conversions. Approximately 576 test functions exist in `src/` modules across
55 source files in the workspace.

### Integration Tests

Integration tests live in `<crate>/tests/` directories and test cross-module behavior:

| File | Test Count | Scope |
|------|-----------|-------|
| `core-ipc/tests/socket_integration.rs` | 21 | Noise IK encrypted IPC: connect, pub/sub, request/response, clearance enforcement, identity binding, unicast routing |
| `daemon-wm/tests/wm_integration.rs` | 43 | Hint assignment, hint matching, overlay controller state machine, config validation |
| `open-sesame/tests/cli_integration.rs` | 18 | CLI argument parsing, help output, exit codes (no running daemon required) |
| `core-memory/tests/guard_page_sigsegv.rs` | 4 | Guard page SIGSEGV verification via subprocess harness |
| `core-ipc/tests/daemon_keypair.rs` | 1 | Keypair persistence, file permissions, tamper detection |

### Property-Based Tests (proptest)

The `proptest` crate is a dev-dependency in 10 workspace crates:

- `core-types`, `core-crypto`, `core-config`, `core-secrets`, `core-profile`, `core-fuzzy`
- `platform-linux`, `platform-macos`, `platform-windows`
- `extension-sdk`

Property-based tests generate random inputs to verify invariants such as serialization round-trips,
key derivation determinism, and type conversion totality.

### Snapshot Tests (insta)

The `insta` crate is declared as a workspace dependency with `yaml`, `json`, and `redactions`
features. Snapshot tests capture serialized output and compare against stored reference files,
detecting unintended changes to wire formats and configuration serialization.

## Test Isolation

### HOME Directory Isolation

Both Nix packages and the CI pipeline set `HOME=$(mktemp -d)` before running tests:

```bash
export HOME=$(mktemp -d)
```

This is configured as `preCheck` in `nix/package.nix` and `nix/package-desktop.nix`. Tests that
create configuration directories (`~/.config/pds/`), runtime directories
(`$XDG_RUNTIME_DIR/pds/`), or keypair files write to the temporary directory instead of the real
home.

For IPC integration tests, `core-ipc/tests/daemon_keypair.rs` uses
`noise::set_runtime_dir_override()` to redirect directory creation without mutating environment
variables, avoiding race conditions in parallel test execution.

### RLIMIT_MEMLOCK Requirement

The `ProtectedAlloc` allocator uses `mlock` to pin secret-holding pages in physical memory,
preventing swap exposure. This requires a sufficient `RLIMIT_MEMLOCK` limit.

In CI, `prlimit` raises the limit before test execution:

```bash
sudo prlimit --pid $$ --memlock=268435456:268435456
```

This sets both soft and hard limits to 256 MiB. The same `prlimit` invocation is used in the build
jobs for `.deb` packaging and Nix builds.

Tests that allocate `ProtectedAlloc` instances fail with `ENOMEM` if the memlock limit is
insufficient. The systemd service units set `LimitMEMLOCK=64M` for production use.

## Test Execution

### CI Pipeline

Tests run via `mise run ci:test` in the `test.yml` workflow on both `ubuntu-24.04` (amd64) and
`ubuntu-24.04-arm` (arm64). The mise task runner manages Rust toolchain installation and task
orchestration.

### Nix Builds

The Nix packages run cargo tests during the build phase:

- **Headless**: tests the five headless crates with `--no-default-features`
- **Desktop**: tests the entire workspace with `--workspace`

Both set `preCheck = "export HOME=$(mktemp -d)"` for isolation.

### Local Execution

Developers can run the full test suite with:

```bash
sudo prlimit --pid $$ --memlock=268435456:268435456
cargo test --workspace
```

The `prlimit` invocation is required for `core-memory` and any crate that transitively uses
`ProtectedAlloc`.
