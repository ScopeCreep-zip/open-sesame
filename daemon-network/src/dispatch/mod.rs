//! Frame and event dispatch functions.
//!
//! Each submodule handles one category of inbound event. All functions
//! take `&DaemonState` and are stateless — the state lives in `DaemonState`.

pub mod discovery;
pub mod ipc;
pub mod tcp;
pub mod udp;
