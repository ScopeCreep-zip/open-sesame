//! End-to-end two-process integration test.
//!
//! Spawns two real `daemon-network` processes with separate config
//! directories, performs a Noise XX handshake via TCP dial, and verifies
//! TOFU pinning in both stores.
//!
//! Run with: `cargo nextest run -p daemon-network e2e_two_process -- --ignored`
//! Requires: `daemon-network` binary on PATH (build first with `cargo build`).
//!
//! This test is `#[ignore]` because it requires:
//! 1. The `daemon-network` binary built and on PATH
//! 2. IPC bus (daemon-profile) NOT running (we use standalone mode)
//! 3. Network ports available on localhost
//!
//! It validates that two independent daemon-network processes can:
//! - Start with separate TOFU stores
//! - Discover each other (via direct dial, not mDNS/BEP-44)
//! - Complete a Noise XX handshake
//! - Pin each other in their respective TOFU stores

// This test is a placeholder documenting the intended test flow.
// Full implementation requires standalone mode support in daemon-network
// (running without an IPC bus connection), which is not yet available.
// The daemon currently panics if it can't connect to daemon-profile's
// IPC bus, making isolated multi-process testing infeasible without
// also spawning daemon-profile instances.
//
// The in-process TestDaemon harness in tests/integration/common/ provides
// the closest approximation: it creates an in-process BusServer + BusClient,
// constructs DaemonState with real UDP sockets, and exercises the full
// handshake + session + TOFU flow. See two_peer.rs for these tests.
//
// When standalone mode is implemented (daemon-network can run without
// IPC for testing), this test will:
// 1. Create two tempdir config directories
// 2. Generate keypairs for each
// 3. Spawn `daemon-network --config-dir <dir1> --port <port1> --standalone`
// 4. Spawn `daemon-network --config-dir <dir2> --port <port2> --standalone`
// 5. Wait for both to report ready (sd_notify or port probe)
// 6. Send a dial command from process 1 to process 2
// 7. Verify TOFU stores contain each other's keys
// 8. Kill both processes

#[test]
#[ignore = "requires standalone mode support in daemon-network (not yet implemented)"]
fn e2e_two_process_handshake_and_tofu_pin() {
    // Placeholder — see module-level documentation for implementation plan.
    // The in-process two_peer tests in two_peer.rs exercise the same code
    // paths (Noise XX, TOFU, session table) without requiring process spawning.
}
