//! Network wire frame codec.
//!
//! Every frame (handshake or transport) carries a 20-byte header:
//!
//! ```text
//! Offset  Size  Field
//! 0       1     Version (0x01)
//! 1       1     Frame Type (FrameType repr)
//! 2       2     Body Length (big-endian)
//! 4       12    Session ID (96-bit, assigned at dial time)
//! 16      4     Sequence Number (big-endian, per-direction monotonic)
//! ```
//!
//! Post-handshake Data frames bind the entire header as AEAD associated data.

use core_types::FrameType;

/// Current wire protocol version.
pub const WIRE_VERSION: u8 = 0x01;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 20;

/// Maximum UDP body size: 1280 (IPv6 min MTU) - 40 (IPv6) - 8 (UDP) - 20 (header) = 1212.
/// We use 1247 to leave room for tunnelling overhead.
pub const MAX_UDP_BODY: usize = 1247;

/// Maximum TCP body size (length-delimited, no MTU constraint).
pub const MAX_TCP_BODY: usize = 65535;

/// 12-byte wire session identifier carried in every network frame header.
///
/// Distinct from [`core_types::SessionId`] which is a UUID-based logical
/// identifier for IPC bus routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireSessionId(pub [u8; 12]);

impl WireSessionId {
    /// Generate a random session ID.
    #[must_use]
    pub fn random() -> Self {
        Self(core_crypto::network::random_bytes())
    }

    /// The zero session ID (used in `HandshakeInit` before assignment).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 12])
    }
}

impl std::fmt::Display for WireSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Parsed wire frame.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)] // frame_type is the canonical name from the wire spec
pub struct Frame {
    pub version: u8,
    pub frame_type: u8,
    pub body_len: u16,
    pub session_id: WireSessionId,
    pub sequence: u32,
    pub body: Vec<u8>,
}

impl Frame {
    /// Parse a frame from a byte buffer (header + body).
    ///
    /// Returns `None` if the buffer is too short or the version is unknown.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }

        let version = buf[0];
        if version != WIRE_VERSION {
            return None;
        }

        let frame_type = buf[1];
        let body_len = u16::from_be_bytes([buf[2], buf[3]]);
        let mut sid = [0u8; 12];
        sid.copy_from_slice(&buf[4..16]);
        let sequence = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);

        let expected_total = HEADER_SIZE + body_len as usize;
        if buf.len() < expected_total {
            return None;
        }

        let body = buf[HEADER_SIZE..expected_total].to_vec();

        Some(Frame {
            version,
            frame_type,
            body_len,
            session_id: WireSessionId(sid),
            sequence,
            body,
        })
    }

    /// Serialise the frame to bytes (header + body).
    #[must_use]
    pub fn serialise(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.body.len());
        buf.push(self.version);
        buf.push(self.frame_type);
        buf.extend_from_slice(&self.body_len.to_be_bytes());
        buf.extend_from_slice(&self.session_id.0);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Build a new frame.
    #[must_use]
    pub fn new(
        frame_type: u8,
        session_id: WireSessionId,
        sequence: u32,
        body: Vec<u8>,
    ) -> Self {
        #[allow(clippy::cast_possible_truncation)] // Body length validated by caller
        let body_len = body.len() as u16;
        Frame {
            version: WIRE_VERSION,
            frame_type,
            body_len,
            session_id,
            sequence,
            body,
        }
    }

    /// Extract the 20-byte header as a byte array (for AEAD AAD binding).
    #[must_use]
    #[allow(dead_code)] // Used by send.rs AEAD AAD construction and tests.
    pub fn header_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut h = [0u8; HEADER_SIZE];
        h[0] = self.version;
        h[1] = self.frame_type;
        h[2..4].copy_from_slice(&self.body_len.to_be_bytes());
        h[4..16].copy_from_slice(&self.session_id.0);
        h[16..20].copy_from_slice(&self.sequence.to_be_bytes());
        h
    }

    /// Check if this frame type matches a known `FrameType` variant.
    #[must_use]
    pub fn known_frame_type(&self) -> Option<FrameType> {
        match self.frame_type {
            0x01 => Some(FrameType::HandshakeInit),
            0x02 => Some(FrameType::HandshakeResponse),
            0x03 => Some(FrameType::HandshakeFinal),
            0x04 => Some(FrameType::CookieRequest),
            0x05 => Some(FrameType::CookieResponse),
            0x10 => Some(FrameType::Data),
            0x11 => Some(FrameType::KeepAlive),
            0x12 => Some(FrameType::Close),
            0x13 => Some(FrameType::RehandshakeRequest),
            _ => None,
        }
    }
}

/// Write a TCP length-delimited frame: `[4-byte BE length][frame bytes]`.
///
/// # Errors
///
/// Returns `std::io::Error` if writing to the stream fails.
#[allow(dead_code)] // Used by handshake TCP path and tests.
pub async fn tcp_write_frame(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    frame: &Frame,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = frame.serialise();
    #[allow(clippy::cast_possible_truncation)] // Frame size bounded by MAX_TCP_BODY
    let len = bytes.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

/// Read a TCP length-delimited frame: `[4-byte BE length][frame bytes]`.
///
/// # Errors
///
/// Returns `std::io::Error` on I/O failure or if the frame exceeds `MAX_TCP_BODY`.
/// Returns `Ok(None)` if the connection was closed cleanly.
pub async fn tcp_read_frame(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> std::io::Result<Option<Frame>> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    if reader.read_exact(&mut len_buf).await.is_err() {
        return Ok(None); // Connection closed
    }
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_TCP_BODY + HEADER_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TCP frame too large: {len} bytes"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    Ok(Frame::parse(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let sid = WireSessionId([0xAA; 12]);
        let frame = Frame::new(FrameType::Data as u8, sid, 42, vec![1, 2, 3, 4]);
        let bytes = frame.serialise();
        let parsed = Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.version, WIRE_VERSION);
        assert_eq!(parsed.frame_type, FrameType::Data as u8);
        assert_eq!(parsed.session_id, sid);
        assert_eq!(parsed.sequence, 42);
        assert_eq!(parsed.body, vec![1, 2, 3, 4]);
    }

    #[test]
    fn frame_too_short() {
        assert!(Frame::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn frame_wrong_version() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = 0xFF; // Unknown version
        assert!(Frame::parse(&bytes).is_none());
    }

    #[test]
    fn frame_body_length_mismatch() {
        let sid = WireSessionId([0; 12]);
        let frame = Frame::new(FrameType::KeepAlive as u8, sid, 0, vec![1, 2, 3]);
        let mut bytes = frame.serialise();
        bytes.truncate(HEADER_SIZE + 1); // Claim 3 bytes but only have 1
        assert!(Frame::parse(&bytes).is_none());
    }

    #[test]
    fn header_bytes_matches_serialise_prefix() {
        let sid = WireSessionId([0xBB; 12]);
        let frame = Frame::new(FrameType::Close as u8, sid, 99, vec![]);
        let serialised = frame.serialise();
        let header = frame.header_bytes();
        assert_eq!(&serialised[..HEADER_SIZE], &header);
    }

    #[test]
    fn known_frame_type_all_variants() {
        for (byte, expected) in [
            (0x01, FrameType::HandshakeInit),
            (0x02, FrameType::HandshakeResponse),
            (0x03, FrameType::HandshakeFinal),
            (0x04, FrameType::CookieRequest),
            (0x05, FrameType::CookieResponse),
            (0x10, FrameType::Data),
            (0x11, FrameType::KeepAlive),
            (0x12, FrameType::Close),
            (0x13, FrameType::RehandshakeRequest),
        ] {
            let sid = WireSessionId([0; 12]);
            let frame = Frame::new(byte, sid, 0, vec![]);
            assert_eq!(frame.known_frame_type(), Some(expected));
        }
    }

    #[test]
    fn unknown_frame_type() {
        let sid = WireSessionId([0; 12]);
        let frame = Frame::new(0xFF, sid, 0, vec![]);
        assert!(frame.known_frame_type().is_none());
    }

    #[test]
    fn session_id_display() {
        let sid = WireSessionId([0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01]);
        let s = format!("{sid}");
        assert_eq!(s, "abcdef0123456789abcdef01");
    }

    #[test]
    fn empty_body_frame() {
        let sid = WireSessionId::random();
        let frame = Frame::new(FrameType::KeepAlive as u8, sid, 0, vec![]);
        let bytes = frame.serialise();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = Frame::parse(&bytes).unwrap();
        assert!(parsed.body.is_empty());
    }

    #[tokio::test]
    async fn tcp_frame_round_trip() {
        let sid = WireSessionId([0xCC; 12]);
        let frame = Frame::new(FrameType::Data as u8, sid, 7, vec![10, 20, 30]);

        let (client, server) = tokio::io::duplex(4096);
        let (_cr, mut cw) = tokio::io::split(client);
        let (mut sr, _sw) = tokio::io::split(server);

        tcp_write_frame(&mut cw, &frame).await.unwrap();
        drop(cw); // Close write side

        let parsed = tcp_read_frame(&mut sr).await.unwrap().unwrap();
        assert_eq!(parsed.session_id, sid);
        assert_eq!(parsed.sequence, 7);
        assert_eq!(parsed.body, vec![10, 20, 30]);
    }
}
