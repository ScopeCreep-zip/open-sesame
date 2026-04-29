//! Outbound frame send path.
//!
//! All outbound frames are encrypted through the peer's Noise transport,
//! wrapped in a wire `Frame`, and transmitted via UDP.

use crate::metrics::Metrics;
use crate::session::table::PeerTable;
use crate::transport::frame::{Frame, WireSessionId};
use crate::transport::udp;
use core_types::FrameType;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Data frames (non-empty payload, chunking)
// ---------------------------------------------------------------------------

/// Send an encrypted `Data` frame to a peer.
///
/// # Deviation: header NOT bound as AEAD AAD
///
/// The M1 spec calls for binding the 20-byte frame header as AEAD associated
/// data. This implementation does NOT do that because snow's Noise transport
/// uses an internal nonce counter for replay protection. When the transport
/// migrates from snow to a direct aws-lc-rs state machine, header-as-AAD
/// should be revisited.
///
/// Payloads exceeding `MAX_NOISE_PLAINTEXT` (65519 bytes) are split into
/// multiple Noise transport messages.
///
/// # Errors
///
/// Returns an error string if the session is not found, encryption fails,
/// or the UDP send fails.
pub async fn send_data(
    session_id: &WireSessionId,
    payload: &[u8],
    peer_table: &PeerTable,
    udp_socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<(), String> {
    use crate::noise::state::MAX_NOISE_PLAINTEXT;

    let chunks: Vec<&[u8]> = if payload.len() <= MAX_NOISE_PLAINTEXT {
        vec![payload]
    } else {
        payload.chunks(MAX_NOISE_PLAINTEXT).collect()
    };

    // Hold the DashMap shard lock for the entire multi-chunk encrypt pass.
    // DashMap::get_mut only locks the shard containing this session ID —
    // other sessions on different shards proceed concurrently.
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
    drop(peer);

    for frame in &frames {
        udp::udp_send(udp_socket, frame, &addr)
            .await
            .map_err(|e| format!("UDP send failed: {e}"))?;
        Metrics::inc(&metrics.frames_sent_total);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Control frames (empty body, single frame)
// ---------------------------------------------------------------------------

/// Encrypt an empty-body control frame and return it with the peer's address.
///
/// The session must exist in the peer table. The `DashMap` lock is held only
/// for encryption, then released before the caller does I/O.
fn encrypt_control_frame(
    frame_type: FrameType,
    session_id: &WireSessionId,
    peer_table: &PeerTable,
) -> Result<(Frame, SocketAddr), String> {
    let mut peer = peer_table
        .get_mut(session_id)
        .ok_or_else(|| format!("session {session_id} not found"))?;

    let ciphertext = peer
        .transport
        .encrypt(&[])
        .map_err(|e| format!("encrypt {frame_type:?} failed: {e}"))?;

    let seq = peer.next_send_seq();
    if frame_type != FrameType::Close {
        peer.record_send(0);
    }

    let addr = peer.remote_addr;
    drop(peer);

    Ok((Frame::new(frame_type as u8, *session_id, seq, ciphertext), addr))
}

/// Send an encrypted control frame via UDP (best-effort).
async fn send_control_frame(
    frame: &Frame,
    addr: &SocketAddr,
    udp_socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<(), String> {
    udp::udp_send(udp_socket, frame, addr)
        .await
        .map_err(|e| format!("UDP send failed: {e}"))?;
    Metrics::inc(&metrics.frames_sent_total);
    Ok(())
}

/// Send an encrypted `KeepAlive` frame to a peer.
///
/// # Errors
///
/// Returns an error if the session is not found, encryption fails,
/// or the UDP send fails.
pub async fn send_keepalive(
    session_id: &WireSessionId,
    peer_table: &PeerTable,
    udp_socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<(), String> {
    let (frame, addr) = encrypt_control_frame(FrameType::KeepAlive, session_id, peer_table)?;
    send_control_frame(&frame, &addr, udp_socket, metrics).await
}

/// Send a `RehandshakeRequest` frame to a peer.
///
/// Signals the peer that this side needs a fresh Noise XX handshake.
/// The current session remains active until replaced or timed out.
///
/// # Errors
///
/// Returns an error if the session is not found, encryption fails,
/// or the UDP send fails.
pub async fn send_rehandshake_request(
    session_id: &WireSessionId,
    peer_table: &PeerTable,
    udp_socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<(), String> {
    let (frame, addr) = encrypt_control_frame(FrameType::RehandshakeRequest, session_id, peer_table)?;
    send_control_frame(&frame, &addr, udp_socket, metrics).await
}

// ---------------------------------------------------------------------------
// Session close (encrypt → remove → best-effort send)
// ---------------------------------------------------------------------------

/// Close a session: encrypt a Close frame, remove from the peer table,
/// then send the frame as a best-effort courtesy to the peer.
///
/// The session is **always** removed from the table, regardless of whether
/// the UDP send succeeds. This prevents unreachable peers from becoming
/// immortal sessions that clog the peer table.
///
/// The Close frame is AEAD-sealed with an empty body to prove session key
/// possession (prevents spoofed close attacks).
///
/// # Why `Arc` parameters (unlike `send_keepalive`/`send_rehandshake_request`)
///
/// This function is synchronous — it encrypts and removes the session
/// inline, then spawns a `tokio::spawn` for the UDP send. The spawned
/// task needs `'static` ownership, so it `Arc::clone`s the socket and
/// metrics. The other send functions are `async` and the caller `.await`s
/// them, so they borrow directly with no spawn.
pub fn close_session(
    session_id: &WireSessionId,
    peer_table: &Arc<PeerTable>,
    udp_socket: &Arc<UdpSocket>,
    metrics: &Arc<Metrics>,
) {
    // Step 1: Encrypt while the session is still in the table.
    let frame_and_addr = encrypt_control_frame(FrameType::Close, session_id, peer_table);

    // Step 2: Remove unconditionally. The session is closed regardless of
    // whether we can notify the peer.
    peer_table.remove(session_id);
    Metrics::inc(&metrics.sessions_closed_total);

    // Step 3: Best-effort send (spawned — may fail for unreachable peers).
    if let Ok((frame, addr)) = frame_and_addr {
        let socket = Arc::clone(udp_socket);
        let m = Arc::clone(metrics);
        tokio::spawn(async move {
            let _ = send_control_frame(&frame, &addr, &socket, &m).await;
        });
    }
}
