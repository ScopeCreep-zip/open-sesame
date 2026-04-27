//! TCP listener for Noise handshake and transport fallback.
//!
//! PQ hybrid handshake messages (ML-KEM-768 ciphertexts ~1088 bytes) can
//! exceed the IPv6 minimum MTU in a single UDP datagram. TCP provides
//! reliable, ordered delivery for the 3-message handshake. After handshake,
//! both parties can negotiate UDP for transport-phase Data frames.
//!
//! Each TCP connection gets its own Tokio task with a handshake timeout.

use crate::transport::frame::{self, Frame};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

/// A TCP inbound event.
#[derive(Debug)]
pub enum TcpInbound {
    /// A new TCP connection accepted (pre-handshake).
    NewConnection {
        stream: TcpStream,
        peer_addr: SocketAddr,
    },
    /// A frame read from an established TCP connection.
    Frame {
        frame: Frame,
        peer_addr: SocketAddr,
    },
}

/// Bind a TCP listener on the given port and accept connections.
///
/// Each accepted connection is sent to the channel for handshake processing.
///
/// # Errors
///
/// Returns `std::io::Error` if the TCP listener cannot bind.
///
/// # Panics
///
/// Panics if the listen address string cannot be parsed (should not happen
/// with valid port numbers).
pub async fn tcp_accept_loop(
    port: u16,
    tx: mpsc::Sender<TcpInbound>,
    _max_connections_per_addr: u32,
    _handshake_timeout_secs: u32,
) -> std::io::Result<()> {
    let addr: SocketAddr = format!("[::]:{port}").parse().unwrap();
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(port = port, "TCP listener bound");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(error = %e, "TCP accept error");
                continue;
            }
        };

        tracing::debug!(%peer_addr, "TCP connection accepted");

        let inbound = TcpInbound::NewConnection {
            stream,
            peer_addr,
        };
        if tx.try_send(inbound).is_err() {
            tracing::warn!(%peer_addr, "TCP dispatch channel full, dropping connection");
        }
    }
}

/// Read frames from a TCP stream until it closes or errors.
///
/// Wraps `tcp_read_frame` with a per-frame timeout.
pub async fn tcp_read_loop(
    mut stream: tokio::io::ReadHalf<TcpStream>,
    peer_addr: SocketAddr,
    tx: mpsc::Sender<TcpInbound>,
    read_timeout: Duration,
) {
    loop {
        match timeout(read_timeout, frame::tcp_read_frame(&mut stream)).await {
            Ok(Ok(Some(frame))) => {
                let inbound = TcpInbound::Frame { frame, peer_addr };
                if tx.try_send(inbound).is_err() {
                    tracing::warn!(%peer_addr, "TCP frame dispatch full");
                    break;
                }
            }
            Ok(Ok(None)) => {
                tracing::debug!(%peer_addr, "TCP connection closed");
                break;
            }
            Ok(Err(e)) => {
                tracing::warn!(%peer_addr, error = %e, "TCP read error");
                break;
            }
            Err(_) => {
                tracing::debug!(%peer_addr, "TCP read timeout");
                break;
            }
        }
    }
}
