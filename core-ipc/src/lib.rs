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
pub mod registry;
mod server;
mod transport;

pub use client::BusClient;
pub use framing::{decode_frame, encode_frame};
pub use message::{Message, MessageContext, WIRE_VERSION};
pub use noise::{NoiseTransport, ZeroizingKeypair, generate_keypair};
pub use registry::ClearanceRegistry;
pub use server::{BusServer, ConfirmationGuard, SubscriptionFilter};
pub use transport::{PeerCredentials, extract_ucred, local_credentials, socket_path};
