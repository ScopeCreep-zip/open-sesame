//! Postcard serialization and length-prefixed wire framing.
//!
//! Two layers:
//! - **Serialization:** `encode_frame` / `decode_frame` convert between typed values
//!   and postcard byte payloads. These are symmetric: encode produces what decode consumes.
//! - **Wire I/O:** `write_frame` / `read_frame` add/strip a 4-byte big-endian length
//!   prefix for socket transport. The length prefix is a wire concern only — internal
//!   channels (bus routing, `BusServer::publish`, subscriber mpsc channels) carry raw
//!   postcard payloads without it.
//!
//! Wire format on the socket: `[4-byte BE length][postcard payload]`

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum frame payload size (16 MiB). Prevents OOM from malformed length prefixes.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Serialize a value to postcard bytes.
///
/// Symmetric with [`decode_frame`]: `decode_frame(encode_frame(v)) == v`.
///
/// The returned bytes are suitable for `BusServer::publish()`, internal channel
/// transport, and as input to `write_frame()` for socket I/O.
///
/// # Errors
///
/// Returns an error if postcard serialization fails.
pub fn encode_frame<T: Serialize>(value: &T) -> core_types::Result<Vec<u8>> {
    postcard::to_allocvec(value)
        .map_err(|e| core_types::Error::Ipc(format!("serialization failed: {e}")))
}

/// Deserialize a value from postcard bytes.
///
/// Symmetric with [`encode_frame`]: `decode_frame(encode_frame(v)) == v`.
///
/// # Errors
///
/// Returns an error if postcard deserialization fails.
pub fn decode_frame<T: DeserializeOwned>(payload: &[u8]) -> core_types::Result<T> {
    postcard::from_bytes(payload)
        .map_err(|e| core_types::Error::Ipc(format!("deserialization failed: {e}")))
}

/// Read a single length-prefixed frame from an async reader.
///
/// # Errors
///
/// Returns an error on I/O failure or if the frame size exceeds `MAX_FRAME_SIZE`.
pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> core_types::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(core_types::Error::Ipc(format!(
            "frame size {len} exceeds maximum {MAX_FRAME_SIZE}"
        )));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Write a single length-prefixed frame to an async writer.
///
/// # Errors
///
/// Returns an error on I/O failure.
pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> core_types::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| core_types::Error::Ipc("payload exceeds u32 length".into()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{DaemonId, EventKind, SecurityLevel};
    use uuid::Uuid;

    #[test]
    fn encode_decode_roundtrip() {
        let event = EventKind::DaemonStarted {
            daemon_id: DaemonId::from_uuid(Uuid::from_u128(1)),
            version: "0.1.0".into(),
            capabilities: vec!["test".into()],
        };
        let msg = crate::message::Message::new(
            DaemonId::from_uuid(Uuid::from_u128(1)),
            event,
            SecurityLevel::Internal,
            std::time::Instant::now(),
        );
        let payload = encode_frame(&msg).unwrap();
        let decoded: crate::message::Message<EventKind> = decode_frame(&payload).unwrap();
        assert!(matches!(decoded.payload, EventKind::DaemonStarted { .. }));
    }

    #[tokio::test]
    async fn async_read_write_roundtrip() {
        let payload = b"hello postcard";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).await.unwrap();
        let mut cursor = &buf[..];
        let decoded = read_frame(&mut cursor).await.unwrap();
        assert_eq!(decoded, payload);
    }

    // SECURITY INVARIANT: Frames exceeding MAX_FRAME_SIZE must be rejected on
    // read to prevent OOM from malformed or malicious length prefixes.
    #[tokio::test]
    async fn oversized_frame_rejected_on_read() {
        let oversized_len: u32 = MAX_FRAME_SIZE + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&oversized_len.to_be_bytes());
        // Don't need actual payload bytes — read_frame should reject at the length check.
        buf.extend(std::iter::repeat_n(0u8, 64));
        let mut cursor = &buf[..];
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err(), "frame exceeding MAX_FRAME_SIZE must be rejected");
    }

    // SECURITY INVARIANT: Zero-length frames must roundtrip correctly —
    // edge case that must not panic or produce garbage.
    #[tokio::test]
    async fn zero_length_frame_roundtrips() {
        let payload: &[u8] = &[];
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).await.unwrap();
        let mut cursor = &buf[..];
        let decoded = read_frame(&mut cursor).await.unwrap();
        assert!(decoded.is_empty());
    }
}
