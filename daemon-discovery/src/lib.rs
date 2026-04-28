//! Peer discovery for Open Sesame network federation.
//!
//! Three discovery backends feed a unified `DialQueue`:
//!
//! 1. **mDNS** — LAN discovery via RFC 6762/6763, always-on
//! 2. **BEP-44** — Internet discovery via Mainline DHT (~15M nodes),
//!    Ed25519-signed mutable data items, default for personal/small-team
//! 3. **DNS SRV** — Enterprise discovery, `_opensesame._udp.<domain>`,
//!    disabled by default
//!
//! Plus a gossip layer (`foca` SWIM with Lifeguard) for peer-set
//! dissemination after initial connections are established.
//!
//! Library crate consumed by `daemon-network`. Does not bind sockets
//! itself for mDNS — provides the packet codec and announcement logic;
//! `daemon-network` owns the multicast socket lifecycle.

pub mod bep44;
pub mod bootstrap;
pub mod dns_srv;
pub mod gossip;
pub mod manager;
pub mod mdns;
pub mod queue;
