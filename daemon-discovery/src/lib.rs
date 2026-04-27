//! Peer discovery for Open Sesame network federation.
//!
//! Provides bootstrap.json seed list loading, DNS SRV resolution, and
//! RFC 6762/6763 multicast DNS for zero-configuration local-link discovery.
//!
//! Library crate consumed by `daemon-network`. Does not bind sockets itself —
//! feeds discovered addresses into a dial queue that `daemon-network` processes.
//!
//! Stub — Milestone 2 implements the full discovery subsystem.
