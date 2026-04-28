//! Outbound data frame send path.
//!
//! Encrypts a plaintext payload through the peer's Noise transport,
//! constructs a wire `Frame` with the session's sequence number, and
//! transmits via UDP. Updates send metrics and per-peer counters.

use crate::metrics::Metrics;
use crate::session::table::PeerTable;
use crate::transport::frame::{Frame, WireSessionId};
use crate::transport::udp;
use core_types::FrameType;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Send an encrypted `Data` frame to a peer identified by session ID.
///
/// The `payload` is the application-layer plaintext (prefixed with a 2-byte
/// `NetworkMessageType` discriminant by the caller). It is encrypted through
/// the peer's Noise transport, wrapped in a wire `Frame`, and sent via UDP.
///
/// Header integrity: the frame header is NOT bound as AEAD associated data
/// because snow's Noise transport uses the internal nonce counter (derived
/// from the sequence number) for replay protection. Tampering with the
/// header's sequence number field causes the receiver's replay window to
/// reject the frame. This matches `WireGuard`'s approach — application-layer
/// framing is separate from Noise's AEAD construction.
///
/// Payloads exceeding `MAX_NOISE_PLAINTEXT` (65519 bytes) are split into
/// multiple Noise transport messages, each sent as a separate UDP frame
/// with incrementing sequence numbers.
///
/// # Errors
///
/// Returns an error string if the session is not found, encryption fails,
/// or the UDP send fails.
pub async fn send_data(
    session_id: &WireSessionId,
    payload: &[u8],
    peer_table: &Arc<PeerTable>,
    udp_socket: &Arc<UdpSocket>,
    metrics: &Arc<Metrics>,
) -> Result<(), String> {
    use crate::noise::state::MAX_NOISE_PLAINTEXT;

    // Split payload into chunks that fit within a single Noise transport message.
    let chunks: Vec<&[u8]> = if payload.len() <= MAX_NOISE_PLAINTEXT {
        vec![payload]
    } else {
        payload.chunks(MAX_NOISE_PLAINTEXT).collect()
    };

    // Hold the lock for the entire multi-chunk send to prevent session
    // removal between chunks causing a partial send.
    let mut peer = peer_table
        .get_mut(session_id)
        .ok_or_else(|| format!("session {session_id} not found"))?;

    let addr = peer.remote_addr;
    let mut frames = Vec::with_capacity(chunks.len());

    for chunk in &chunks {
        let ciphertext = peer
            .transport
            .encrypt(chunk)
            .map_err(|e| format!("encrypt failed: {e}"))?;
        let seq = peer.next_send_seq();
        #[allow(clippy::cast_possible_truncation)]
        peer.record_send(ciphertext.len() as u64);
        frames.push(Frame::new(FrameType::Data as u8, *session_id, seq, ciphertext));
    }
    // Release DashMap lock before async I/O.
    drop(peer);

    for frame in &frames {
        udp::udp_send(udp_socket, frame, &addr)
            .await
            .map_err(|e| format!("UDP send failed: {e}"))?;
        Metrics::inc(&metrics.frames_sent_total);
    }
    Ok(())
}

/// Send an encrypted `KeepAlive` frame to a peer (empty body, AEAD-sealed).
///
/// # Errors
///
/// Returns an error string if the session is not found, encryption fails,
/// or the UDP send fails.
pub async fn send_keepalive(
    session_id: &WireSessionId,
    peer_table: &Arc<PeerTable>,
    udp_socket: &Arc<UdpSocket>,
    metrics: &Arc<Metrics>,
) -> Result<(), String> {
    let (ciphertext, addr, seq) = {
        let mut peer = peer_table
            .get_mut(session_id)
            .ok_or_else(|| format!("session {session_id} not found"))?;

        let ciphertext = peer
            .transport
            .encrypt(&[])
            .map_err(|e| format!("encrypt keepalive failed: {e}"))?;

        let seq = peer.next_send_seq();
        peer.record_send(0);

        (ciphertext, peer.remote_addr, seq)
    };

    let frame = Frame::new(FrameType::KeepAlive as u8, *session_id, seq, ciphertext);

    udp::udp_send(udp_socket, &frame, &addr)
        .await
        .map_err(|e| format!("UDP send failed: {e}"))?;

    Metrics::inc(&metrics.frames_sent_total);
    Ok(())
}

/// Send a `Close` frame to a peer and remove the session from the table.
///
/// The close frame carries an empty encrypted body to prove session key
/// possession (prevents spoofed close attacks).
///
/// # Errors
///
/// Returns an error string if the session is not found or the send fails.
pub async fn send_close(
    session_id: &WireSessionId,
    peer_table: &Arc<PeerTable>,
    udp_socket: &Arc<UdpSocket>,
    metrics: &Arc<Metrics>,
) -> Result<(), String> {
    let (ciphertext, addr, seq) = {
        let mut peer = peer_table
            .get_mut(session_id)
            .ok_or_else(|| format!("session {session_id} not found"))?;

        let ciphertext = peer
            .transport
            .encrypt(&[])
            .map_err(|e| format!("encrypt close failed: {e}"))?;

        let seq = peer.next_send_seq();
        (ciphertext, peer.remote_addr, seq)
    };

    let frame = Frame::new(FrameType::Close as u8, *session_id, seq, ciphertext);

    udp::udp_send(udp_socket, &frame, &addr)
        .await
        .map_err(|e| format!("UDP send failed: {e}"))?;

    Metrics::inc(&metrics.frames_sent_total);
    peer_table.remove(session_id);
    Ok(())
}

/// Send a `RehandshakeRequest` frame to a peer.
///
/// Signals the peer that this side needs a fresh Noise XX handshake
/// (sequence exhaustion or age-based rekey). The peer initiates a new
/// TCP connection with XX. The current session remains active until
/// replaced or until the idle timeout fires.
///
/// # Errors
///
/// Returns an error string if the session is not found or the send fails.
pub async fn send_rehandshake_request(
    session_id: &WireSessionId,
    peer_table: &Arc<PeerTable>,
    udp_socket: &Arc<UdpSocket>,
    metrics: &Arc<Metrics>,
) -> Result<(), String> {
    let (ciphertext, addr, seq) = {
        let mut peer = peer_table
            .get_mut(session_id)
            .ok_or_else(|| format!("session {session_id} not found"))?;

        let ciphertext = peer
            .transport
            .encrypt(&[])
            .map_err(|e| format!("encrypt rehandshake request failed: {e}"))?;

        let seq = peer.next_send_seq();
        peer.record_send(0);

        (ciphertext, peer.remote_addr, seq)
    };

    let frame = Frame::new(FrameType::RehandshakeRequest as u8, *session_id, seq, ciphertext);

    udp::udp_send(udp_socket, &frame, &addr)
        .await
        .map_err(|e| format!("UDP send failed: {e}"))?;

    Metrics::inc(&metrics.frames_sent_total);
    Ok(())
}
