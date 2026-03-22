//! Noise IK encrypted IPC transport (ADR-SEC-006).
//!
//! Provides forward-secret, mutually-authenticated encryption for all IPC
//! traffic using the Noise Protocol Framework (IK pattern) via `snow`.
//!
//! Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s`
//! - IK: initiator's static key transmitted, responder's static key pre-known
//! - X25519 DH, ChaCha20-Poly1305 AEAD, BLAKE2s hash
//! - 2-message handshake (1 round-trip), then forward-secret transport
//!
//! `UCred` (PID + UID) is bound into the Noise prologue so that both sides must
//! agree on the peer identity — cryptographically binding the OS-level transport
//! identity to the encrypted channel.
//!
//! Noise transport messages are limited to 65535 bytes. Application frames up to
//! 16 MiB are chunked into multiple Noise messages with a chunk-count header.
//!
//! Key management (generation, persistence, tamper detection) lives in
//! `noise_keys`.

use crate::framing::{MAX_FRAME_SIZE, read_frame, write_frame};
use crate::transport::PeerCredentials;
use tokio::io::{AsyncRead, AsyncWrite};

// Re-export key management API so downstream `use core_ipc::noise::*` paths remain stable.
pub use crate::noise_keys::{
    ZeroizingKeypair, create_keys_dir, generate_keypair, read_bus_public_key,
    read_bus_public_key_from, read_daemon_keypair, read_daemon_public_key,
    set_runtime_dir_override, write_bus_keypair, write_daemon_keypair,
};

/// Noise protocol parameter string.
pub(crate) const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext per Noise transport message: 65535 - 16 (AEAD tag) = 65519 bytes.
const MAX_NOISE_PLAINTEXT: usize = 65535 - 16;

/// Handshake timeout to prevent `DoS` via slow handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Build the prologue bytes from peer credentials.
///
/// Format: `PDS-IPC-v1:<local_pid>:<local_uid>:<remote_pid>:<remote_uid>`
///
/// Both sides must construct identical prologues for the handshake to succeed.
/// The server knows its own creds and the client's creds (from `UCred`), and vice
/// versa (the client knows its own PID/UID and the server's from `UCred` after connect).
///
/// For the prologue to match, we use a canonical ordering: lower PID first.
fn build_prologue(local: &PeerCredentials, remote: &PeerCredentials) -> Vec<u8> {
    // Canonical ordering: lower PID first to ensure both sides produce identical bytes.
    let (first, second) = if local.pid <= remote.pid {
        (local, remote)
    } else {
        (remote, local)
    };
    format!(
        "PDS-IPC-v1:{}:{}:{}:{}",
        first.pid, first.uid, second.pid, second.uid
    )
    .into_bytes()
}

/// Encrypted IPC transport wrapping a completed Noise session.
///
/// Provides chunked encrypted frame I/O over the Noise transport state.
/// Application frames are split into chunks of at most `MAX_NOISE_PLAINTEXT`
/// bytes, each encrypted as a separate Noise transport message.
///
/// The `TransportState` requires `&mut self` for both encrypt and decrypt,
/// so callers must coordinate access (e.g. via `Arc<Mutex<NoiseTransport>>`
/// when split into separate read/write tasks).
pub struct NoiseTransport {
    state: snow::TransportState,
}

impl NoiseTransport {
    /// Write an encrypted application frame.
    ///
    /// The payload is chunked into Noise transport messages of at most
    /// `MAX_NOISE_PLAINTEXT` bytes each. Wire format per frame:
    ///
    /// ```text
    /// [4-byte BE chunk_count][chunk_1][chunk_2]...[chunk_n]
    /// ```
    ///
    /// Each chunk is written as a length-prefixed frame via `write_frame`.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure or if the payload exceeds `MAX_FRAME_SIZE`.
    pub async fn write_encrypted_frame<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        payload: &[u8],
    ) -> core_types::Result<()> {
        if payload.len() > MAX_FRAME_SIZE as usize {
            return Err(core_types::Error::Ipc(format!(
                "payload size {} exceeds maximum {}",
                payload.len(),
                MAX_FRAME_SIZE
            )));
        }

        // Calculate number of chunks needed.
        let chunk_count = if payload.is_empty() {
            1 // Send one empty encrypted chunk for zero-length payloads.
        } else {
            payload.len().div_ceil(MAX_NOISE_PLAINTEXT)
        };

        // Write chunk count as a 4-byte BE header (plaintext — the count itself
        // is not sensitive and is needed to know how many chunks to read).
        let count_bytes = u32::try_from(chunk_count)
            .map_err(|_| core_types::Error::Ipc("too many chunks".into()))?;
        write_frame(writer, &count_bytes.to_be_bytes()).await?;

        // Write each chunk as an encrypted Noise message.
        // Output buffer: plaintext + 16-byte AEAD tag.
        let mut enc_buf = vec![0u8; MAX_NOISE_PLAINTEXT + 16];

        for chunk_idx in 0..chunk_count {
            let start = chunk_idx * MAX_NOISE_PLAINTEXT;
            let end = (start + MAX_NOISE_PLAINTEXT).min(payload.len());
            let chunk = &payload[start..end];

            let len = self
                .state
                .write_message(chunk, &mut enc_buf)
                .map_err(|e| core_types::Error::Ipc(format!("Noise encrypt failed: {e}")))?;

            write_frame(writer, &enc_buf[..len]).await?;
        }

        Ok(())
    }

    /// Read and decrypt an application frame.
    ///
    /// Reads the chunk count header, then reads and decrypts each chunk,
    /// reassembling the original plaintext payload.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure, decryption failure, or if the
    /// reassembled payload exceeds `MAX_FRAME_SIZE`.
    pub async fn read_encrypted_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> core_types::Result<Vec<u8>> {
        // Read chunk count header.
        let count_frame = read_frame(reader).await?;
        if count_frame.len() != 4 {
            return Err(core_types::Error::Ipc(format!(
                "invalid chunk count header: expected 4 bytes, got {}",
                count_frame.len()
            )));
        }
        let chunk_count = u32::from_be_bytes([
            count_frame[0],
            count_frame[1],
            count_frame[2],
            count_frame[3],
        ]) as usize;

        // Sanity check: max chunks for 16 MiB payload.
        let max_chunks = (MAX_FRAME_SIZE as usize).div_ceil(MAX_NOISE_PLAINTEXT);
        if chunk_count > max_chunks {
            return Err(core_types::Error::Ipc(format!(
                "chunk count {chunk_count} exceeds maximum {max_chunks}"
            )));
        }

        let mut payload = Vec::with_capacity(chunk_count * MAX_NOISE_PLAINTEXT);
        let mut dec_buf = vec![0u8; MAX_NOISE_PLAINTEXT];

        for _ in 0..chunk_count {
            let ciphertext = read_frame(reader).await?;
            let len = self
                .state
                .read_message(&ciphertext, &mut dec_buf)
                .map_err(|e| core_types::Error::Ipc(format!("Noise decrypt failed: {e}")))?;
            payload.extend_from_slice(&dec_buf[..len]);
        }

        // Zeroize intermediate decrypt buffer (may contain secret fragments).
        zeroize::Zeroize::zeroize(&mut dec_buf);

        if payload.len() > MAX_FRAME_SIZE as usize {
            return Err(core_types::Error::Ipc(format!(
                "decrypted payload {} exceeds maximum {}",
                payload.len(),
                MAX_FRAME_SIZE
            )));
        }

        Ok(payload)
    }

    /// Check if this transport was created by the initiator side.
    #[must_use]
    pub fn is_initiator(&self) -> bool {
        self.state.is_initiator()
    }

    /// Get the remote party's static public key.
    #[must_use]
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }
}

/// Perform the server-side (responder) Noise IK handshake.
///
/// Called after `stream.into_split()` and `extract_ucred()`, before the
/// read/write loops. The server's static keypair was generated at startup
/// and the client's identity is verified via the Noise handshake + `UCred`
/// prologue binding.
///
/// IK handshake (responder perspective):
/// 1. Read message 1 from initiator (contains initiator's ephemeral + encrypted static)
/// 2. Write message 2 to initiator (contains responder's ephemeral)
/// 3. Handshake complete — derive transport keys
///
/// # Errors
///
/// Returns an error if the handshake fails or times out.
pub async fn server_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    server_keypair: &snow::Keypair,
    local_creds: &PeerCredentials,
    remote_creds: &PeerCredentials,
) -> core_types::Result<NoiseTransport>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prologue = build_prologue(local_creds, remote_creds);

    let mut handshake = snow::Builder::new(
        NOISE_PARAMS
            .parse()
            .map_err(|e| core_types::Error::Platform(format!("invalid Noise params: {e}")))?,
    )
    .local_private_key(&server_keypair.private)
    .map_err(|e| core_types::Error::Ipc(format!("Noise builder error: {e}")))?
    .prologue(&prologue)
    .map_err(|e| core_types::Error::Ipc(format!("Noise prologue error: {e}")))?
    .build_responder()
    .map_err(|e| core_types::Error::Ipc(format!("Noise responder build failed: {e}")))?;

    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // IK responder: read msg1, write msg2.

        // Read message 1 from initiator.
        let msg1 = read_frame(reader).await?;
        let mut payload_buf = vec![0u8; 65535];
        handshake
            .read_message(&msg1, &mut payload_buf)
            .map_err(|e| {
                core_types::Error::Ipc(format!("Noise handshake msg1 read failed: {e}"))
            })?;

        // Write message 2 to initiator.
        let mut msg2_buf = vec![0u8; 65535];
        let msg2_len = handshake.write_message(&[], &mut msg2_buf).map_err(|e| {
            core_types::Error::Ipc(format!("Noise handshake msg2 write failed: {e}"))
        })?;
        write_frame(writer, &msg2_buf[..msg2_len]).await?;

        // Handshake complete — transition to transport mode.
        let transport = handshake
            .into_transport_mode()
            .map_err(|e| core_types::Error::Ipc(format!("Noise transport mode failed: {e}")))?;

        tracing::info!("Noise IK handshake completed (server)");
        Ok(NoiseTransport { state: transport })
    })
    .await
    .map_err(|_| core_types::Error::Ipc("Noise handshake timed out".into()))?
}

/// Perform the client-side (initiator) Noise IK handshake.
///
/// Called after `UnixStream::connect()` and `into_split()`, before the
/// read/write loops. The client generates an ephemeral static keypair and
/// pre-loads the server's public key (the "K" in IK).
///
/// IK handshake (initiator perspective):
/// 1. Write message 1 to responder (ephemeral + encrypted static)
/// 2. Read message 2 from responder (responder's ephemeral)
/// 3. Handshake complete — derive transport keys
///
/// # Errors
///
/// Returns an error if the handshake fails or times out.
pub async fn client_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    server_public_key: &[u8; 32],
    client_keypair: &snow::Keypair,
    local_creds: &PeerCredentials,
    remote_creds: &PeerCredentials,
) -> core_types::Result<NoiseTransport>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prologue = build_prologue(local_creds, remote_creds);

    let mut handshake = snow::Builder::new(
        NOISE_PARAMS
            .parse()
            .map_err(|e| core_types::Error::Platform(format!("invalid Noise params: {e}")))?,
    )
    .local_private_key(&client_keypair.private)
    .map_err(|e| core_types::Error::Ipc(format!("Noise builder error: {e}")))?
    .remote_public_key(server_public_key)
    .map_err(|e| core_types::Error::Ipc(format!("Noise remote key error: {e}")))?
    .prologue(&prologue)
    .map_err(|e| core_types::Error::Ipc(format!("Noise prologue error: {e}")))?
    .build_initiator()
    .map_err(|e| core_types::Error::Ipc(format!("Noise initiator build failed: {e}")))?;

    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // IK initiator: write msg1, read msg2.

        // Write message 1 to responder.
        let mut msg1_buf = vec![0u8; 65535];
        let msg1_len = handshake.write_message(&[], &mut msg1_buf).map_err(|e| {
            core_types::Error::Ipc(format!("Noise handshake msg1 write failed: {e}"))
        })?;
        write_frame(writer, &msg1_buf[..msg1_len]).await?;

        // Read message 2 from responder.
        let msg2 = read_frame(reader).await?;
        let mut payload_buf = vec![0u8; 65535];
        handshake
            .read_message(&msg2, &mut payload_buf)
            .map_err(|e| {
                core_types::Error::Ipc(format!("Noise handshake msg2 read failed: {e}"))
            })?;

        // Handshake complete — transition to transport mode.
        let transport = handshake
            .into_transport_mode()
            .map_err(|e| core_types::Error::Ipc(format!("Noise transport mode failed: {e}")))?;

        tracing::info!("Noise IK handshake completed (client)");
        Ok(NoiseTransport { state: transport })
    })
    .await
    .map_err(|_| core_types::Error::Ipc("Noise handshake timed out".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prologue_canonical_ordering() {
        let a = PeerCredentials {
            pid: 100,
            uid: 1000,
        };
        let b = PeerCredentials {
            pid: 200,
            uid: 1000,
        };

        // Both orderings produce the same prologue.
        assert_eq!(build_prologue(&a, &b), build_prologue(&b, &a));

        // Contains expected format.
        let p = String::from_utf8(build_prologue(&a, &b)).unwrap();
        assert_eq!(p, "PDS-IPC-v1:100:1000:200:1000");
    }

    #[tokio::test]
    async fn handshake_and_transport_roundtrip() {
        // Generate server and client keypairs.
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();

        let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

        // Simulated peer credentials (both sides must agree).
        let server_creds = PeerCredentials { pid: 1, uid: 1000 };
        let client_creds = PeerCredentials { pid: 2, uid: 1000 };

        // Create a duplex channel simulating a UDS pair.
        let (client_stream, server_stream) = tokio::io::duplex(65536);

        let (mut client_reader, mut client_writer) = tokio::io::split(client_stream);
        let (mut server_reader, mut server_writer) = tokio::io::split(server_stream);

        // Run handshake concurrently.
        let (client_result, server_result) = tokio::join!(
            client_handshake(
                &mut client_reader,
                &mut client_writer,
                &server_pub,
                client_kp.as_inner(),
                &client_creds,
                &server_creds,
            ),
            server_handshake(
                &mut server_reader,
                &mut server_writer,
                server_kp.as_inner(),
                &server_creds,
                &client_creds,
            ),
        );

        let mut client_transport = client_result.unwrap();
        let mut server_transport = server_result.unwrap();

        // Client sends encrypted message, server decrypts.
        let plaintext = b"hello encrypted world";

        client_transport
            .write_encrypted_frame(&mut client_writer, plaintext)
            .await
            .unwrap();

        let decrypted = server_transport
            .read_encrypted_frame(&mut server_reader)
            .await
            .unwrap();

        assert_eq!(decrypted, plaintext);

        // Server sends back, client decrypts.
        let response = b"acknowledged";
        server_transport
            .write_encrypted_frame(&mut server_writer, response)
            .await
            .unwrap();

        let decrypted_response = client_transport
            .read_encrypted_frame(&mut client_reader)
            .await
            .unwrap();

        assert_eq!(decrypted_response, response);
    }

    #[tokio::test]
    async fn large_frame_chunking() {
        // Test that frames larger than 65519 bytes are chunked correctly.
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();
        let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

        let server_creds = PeerCredentials { pid: 10, uid: 1000 };
        let client_creds = PeerCredentials { pid: 20, uid: 1000 };

        let (client_stream, server_stream) = tokio::io::duplex(1024 * 1024);
        let (mut cr, mut cw) = tokio::io::split(client_stream);
        let (mut sr, mut sw) = tokio::io::split(server_stream);

        let (mut ct, mut st) = tokio::join!(
            async {
                client_handshake(
                    &mut cr,
                    &mut cw,
                    &server_pub,
                    client_kp.as_inner(),
                    &client_creds,
                    &server_creds,
                )
                .await
                .unwrap()
            },
            async {
                server_handshake(
                    &mut sr,
                    &mut sw,
                    server_kp.as_inner(),
                    &server_creds,
                    &client_creds,
                )
                .await
                .unwrap()
            },
        );

        // 200 KiB payload — requires multiple chunks (200*1024 / 65519 = ~4 chunks).
        let large_payload = vec![0xABu8; 200 * 1024];

        ct.write_encrypted_frame(&mut cw, &large_payload)
            .await
            .unwrap();
        let decrypted = st.read_encrypted_frame(&mut sr).await.unwrap();
        assert_eq!(decrypted, large_payload);
    }

    #[tokio::test]
    async fn prologue_mismatch_fails_handshake() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();
        let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

        // Deliberately mismatched credentials — server thinks client is PID 99.
        let server_creds = PeerCredentials { pid: 1, uid: 1000 };
        let client_creds_real = PeerCredentials { pid: 2, uid: 1000 };
        let client_creds_fake = PeerCredentials { pid: 99, uid: 1000 };

        let (client_stream, server_stream) = tokio::io::duplex(65536);
        let (mut cr, mut cw) = tokio::io::split(client_stream);
        let (mut sr, mut sw) = tokio::io::split(server_stream);

        let (client_result, server_result) = tokio::join!(
            // Client uses real creds for prologue.
            client_handshake(
                &mut cr,
                &mut cw,
                &server_pub,
                client_kp.as_inner(),
                &client_creds_real,
                &server_creds,
            ),
            // Server uses WRONG creds for prologue (thinks client is PID 99).
            server_handshake(
                &mut sr,
                &mut sw,
                server_kp.as_inner(),
                &server_creds,
                &client_creds_fake,
            ),
        );

        // At least one side should fail due to prologue mismatch.
        assert!(
            client_result.is_err() || server_result.is_err(),
            "prologue mismatch should cause handshake failure"
        );
    }

    #[tokio::test]
    async fn empty_payload_roundtrip() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();
        let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();

        let sc = PeerCredentials { pid: 1, uid: 1000 };
        let cc = PeerCredentials { pid: 2, uid: 1000 };

        let (cs, ss) = tokio::io::duplex(65536);
        let (mut cr, mut cw) = tokio::io::split(cs);
        let (mut sr, mut sw) = tokio::io::split(ss);

        let (mut ct, mut st) = tokio::join!(
            async {
                client_handshake(
                    &mut cr,
                    &mut cw,
                    &server_pub,
                    client_kp.as_inner(),
                    &cc,
                    &sc,
                )
                .await
                .unwrap()
            },
            async {
                server_handshake(&mut sr, &mut sw, server_kp.as_inner(), &sc, &cc)
                    .await
                    .unwrap()
            },
        );

        ct.write_encrypted_frame(&mut cw, b"").await.unwrap();
        let decrypted = st.read_encrypted_frame(&mut sr).await.unwrap();
        assert!(decrypted.is_empty());
    }
}
