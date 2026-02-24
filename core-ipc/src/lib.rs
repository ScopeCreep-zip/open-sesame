//! IPC bus protocol, postcard framing, and BusServer/BusClient for PDS.
//!
//! The central nervous system of the Programmable Desktop Suite.
//! All inter-daemon communication uses postcard-encoded frames over Unix domain sockets.
#![forbid(unsafe_code)]
