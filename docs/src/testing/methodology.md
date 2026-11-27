# Testing Methodology

Open Sesame uses a layered testing strategy: unit tests beside the code they cover, integration
tests per crate, and property-based tests for wire and identifier types.

## Test Categories

### Unit Tests

Unit tests are embedded in source files using `#[cfg(test)]` modules. They cover pure logic such as
hint assignment, the overlay controller state machine, configuration validation, cryptographic
derivation, rate limiting, ACL enforcement, audit logging, IPC routing, and type conversions. About
1,180 test functions exist in `src/` modules across 127 source files in the workspace.

### Integration Tests

Integration tests live in `<crate>/tests/` directories and test cross-module behavior:

| File | Test Count | Scope |
| --- | --- | --- |
| `core-ipc/tests/socket_integration.rs` | 24 | Noise IK encrypted IPC: suites, connect, pub/sub, request/response, clearance enforcement, identity binding, unicast routing, key rotation |
| `open-sesame/tests/cli_integration.rs` | 18 | CLI argument parsing, help output, exit codes (no running daemon required) |
| `core-ipc/tests/daemon_keypair.rs` | 5 | Keypair persistence, file permissions, tamper detection, bus endpoint record |
| `core-memory/tests/guard_page_sigsegv.rs` | 4 | Guard page SIGSEGV verification via subprocess harness |

### Property-Based Tests (proptest)

`core-types` uses `proptest` to generate random inputs for serialization round-trips (postcard and
JSON) of identifiers (`ProfileId`, `WindowId`, `AgentId`, `AppId`, `TrustProfileName`), geometry, and
sensitivity classes.

## Test Isolation

### Filesystem Locations

Every location a daemon or the CLI uses comes from a `core_layout::Layout`. Tests build one with
`Layout::under(root)` over a temporary directory, so they never read or mutate the process
environment and run in parallel without races:

```rust
let root = tempfile::tempdir().unwrap();
let layout = core_layout::Layout::under(root.path());
```

The Nix packages additionally set `HOME=$(mktemp -d)` in `preCheck` (`nix/package.nix`,
`nix/package-desktop.nix`). The desktop package also points `XKB_CONFIG_ROOT` at `xkeyboard-config`
and `FONTCONFIG_FILE` at a DejaVu font configuration: daemon-input's tests compile the default XKB
keymap and daemon-wm's text tests shape with real fonts.

### RLIMIT_MEMLOCK Requirement

The `ProtectedAlloc` allocator uses `mlock` to pin secret-holding pages in physical memory,
preventing swap exposure. This requires a sufficient `RLIMIT_MEMLOCK` limit.

In CI, `prlimit` raises the limit before test execution:

```bash
sudo prlimit --pid $$ --memlock=268435456:268435456
```

This sets both soft and hard limits to 256 MiB.

Tests that allocate `ProtectedAlloc` instances fail with `ENOMEM` if the memlock limit is
insufficient. The systemd service units set `LimitMEMLOCK=64M` for production use.

## Test Execution

### CI Pipeline

Tests run via `mise run ci:test` in the `test.yml` workflow on both `ubuntu-24.04` (amd64) and
`ubuntu-24.04-arm` (arm64): format check, clippy with warnings denied, tests, and a debug build. The
`qa` job runs `mise run ci:qa` in the Nix devshell (TOML, Markdown, links, shell, workflows, and
`cargo deny`).

### Nix Builds

The Nix packages run cargo tests during the build phase:

- **Headless**: tests the five headless crates with `--no-default-features`
- **Desktop**: tests the entire workspace with `--workspace`

### Local Execution

Developers can run the full test suite with:

```bash
sudo prlimit --pid $$ --memlock=268435456:268435456
cargo test --workspace
```

The `prlimit` invocation is required for `core-memory` and any crate that transitively uses
`ProtectedAlloc`.
