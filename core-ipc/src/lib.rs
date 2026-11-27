//! IPC bus protocol, postcard framing, and BusServer/BusClient for PDS.
//!
//! The central nervous system of the Programmable Desktop Suite.
//! All inter-daemon communication uses postcard-encoded frames over Unix domain sockets.
//!
//! Wire format: `[4-byte BE length][postcard(Message<EventKind>)]`
#![forbid(unsafe_code)]

mod client;
mod framing;
mod message;
pub mod noise;
mod noise_keys;
mod registry;
mod server;
mod transport;

pub use client::{BusClient, RetryConfig};
pub use framing::{decode_frame, encode_frame};
pub use message::{Message, MessageContext, WIRE_VERSION};
pub use registry::{ClearanceRegistry, Registration};
pub use server::{BusServer, ConfirmationGuard, Requester};
