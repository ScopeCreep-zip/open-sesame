//! Peer discovery for Open Sesame network federation.
//!
//! Provides `bootstrap.json` seed list loading, DNS SRV resolution, and
//! RFC 6762/6763 multicast DNS for zero-configuration local-link discovery.
//!
//! Library crate consumed by `daemon-network`. Does not bind sockets itself —
//! feeds discovered addresses into a dial queue that `daemon-network` processes.
//!
//! ## Implemented
//!
//! - `bootstrap.json` static seed list loading and parsing
//!
//! ## Pending (Milestone 2)
//!
//! - mDNS LAN discovery (RFC 6762/6763)
//! - BEP-44 Mainline DHT internet discovery
//! - DNS SRV enterprise discovery
//! - Plumtree gossip peer-set dissemination

pub mod bootstrap;
