//! daemon-network library crate.
//!
//! All business logic lives here so integration tests can construct a
//! `DaemonState` and call dispatch/lifecycle functions directly without
//! running the full daemon process.
//!
//! The binary entry point (`main.rs`) handles process lifecycle: arg parsing,
//! tracing init, systemd notify, config loading, bus connection, and the
//! `tokio::select!` event loop.

// -- Core subsystems --
pub mod audit;
pub mod config;
pub mod control;
pub mod flood;
pub mod handshake;
pub mod handshake_ack;
pub mod metrics;
pub mod noise;
pub mod ratelimit;
pub mod sandbox;
pub mod send;
pub mod session;
pub mod tofu;
pub mod transport;

// -- Assembled state and dispatch (testable) --
pub mod dispatch;
pub mod lifecycle;
pub mod state;
