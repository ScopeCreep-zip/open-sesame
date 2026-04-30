//! Local IPC bus integration.
//!
//! `daemon-network` connects to `daemon-profile`'s `BusServer` as a `BusClient`
//! and communicates with `daemon-secrets` for network identity keypair retrieval.

pub mod bus;
