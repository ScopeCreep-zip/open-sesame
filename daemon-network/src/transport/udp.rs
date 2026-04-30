//! UDP socket binding and receive loop.
//!
//! Dual-stack (IPv4-mapped IPv6) UDP socket. The receive loop runs in a
//! dedicated Tokio task and dispatches parsed frames via a bounded channel.

use crate::transport::frame::{Frame, HEADER_SIZE, MAX_UDP_BODY};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Bind a dual-stack UDP socket on the given port.
///
/// Accepts both IPv4 and IPv6 traffic via IPv4-mapped addresses.
///
/// # Errors
///
/// Returns `std::io::Error` if the UDP socket cannot bind.
///
/// # Panics
///
/// Panics if the listen address string cannot be parsed.
pub async fn bind_udp(port: u16) -> std::io::Result<UdpSocket> {
    let addr: SocketAddr = format!("[::]:{port}").parse().unwrap();
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!(port = port, "UDP socket bound");
    Ok(socket)
}

/// A received UDP frame with its source address.
#[derive(Debug)]
pub struct UdpInbound {
    pub frame: Frame,
    pub src_addr: SocketAddr,
}

/// Run the UDP receive loop, dispatching parsed frames to the channel.
///
/// Frames shorter than the header, with unknown version, or exceeding
/// `MAX_UDP_BODY` are silently dropped (no response to prevent information
/// leakage about our state).
pub async fn udp_receive_loop(socket: Arc<UdpSocket>, tx: tokio::sync::mpsc::Sender<UdpInbound>) {
    // 1280 bytes = IPv6 minimum MTU.
    let mut buf = vec![0u8; 1280];

    loop {
        let (len, src_addr) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(error = %e, "UDP recv_from error");
                continue;
            }
        };

        if len < HEADER_SIZE {
            tracing::trace!(len, %src_addr, "dropped: too short");
            continue;
        }

        if len > HEADER_SIZE + MAX_UDP_BODY {
            tracing::trace!(len, %src_addr, "dropped: too large for UDP");
            continue;
        }

        let Some(frame) = Frame::parse(&buf[..len]) else {
            tracing::trace!(len, %src_addr, "dropped: parse failed");
            continue;
        };

        let inbound = UdpInbound { frame, src_addr };
        if tx.try_send(inbound).is_err() {
            tracing::warn!(%src_addr, "UDP dispatch channel full, dropping frame");
        }
    }
}

/// Send a frame via UDP to a specific address.
///
/// # Errors
///
/// Returns `std::io::Error` if the send fails.
pub async fn udp_send(socket: &UdpSocket, frame: &Frame, addr: &SocketAddr) -> std::io::Result<()> {
    let bytes = frame.serialise();
    socket.send_to(&bytes, addr).await?;
    Ok(())
}
