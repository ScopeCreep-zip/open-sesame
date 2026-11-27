//! Noise IK encrypted IPC transport (ADR-SEC-006).
//!
//! Provides forward-secret, mutually-authenticated encryption for all IPC
//! traffic using the Noise Protocol Framework (IK pattern) via `snow`.
//!
//! Protocol: `Noise_IK_25519_<cipher>_<hash>` ([`NoiseSuite`]), from
//! `[crypto] noise_cipher` (`ChaChaPoly` or `AESGCM`) and `noise_hash`
//! (`BLAKE2s` or `SHA256`)
//! - IK: initiator's static key transmitted, responder's static key pre-known
//! - X25519 DH
//! - 2-message handshake (1 round-trip), then forward-secret transport
//!
//! The bus server binds with one suite and publishes it with its public key
//! ([`BusEndpoint`]); clients handshake with the published suite.
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
use crate::transport::{PeerCredentials, local_credentials};
use core_types::{NoiseCipher, NoiseHash};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

pub use crate::noise_keys::{
    BusEndpoint, ZeroizingKeypair, create_keys_dir, generate_keypair, issue_daemon_keypair,
    publish_bus_endpoint, read_bus_endpoint, read_daemon_keypair, write_daemon_keypair,
};

/// The bus's Noise protocol: IK, X25519, and one AEAD cipher and hash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoiseSuite {
    pub cipher: NoiseCipher,
    pub hash: NoiseHash,
}

impl NoiseSuite {
    /// Every supported suite: each `[crypto] noise_cipher` and
    /// `noise_hash` combination.
    pub const ALL: [Self; 4] = [
        Self::new(NoiseCipher::ChaChaPoly, NoiseHash::Blake2s),
        Self::new(NoiseCipher::ChaChaPoly, NoiseHash::Sha256),
        Self::new(NoiseCipher::AesGcm, NoiseHash::Blake2s),
        Self::new(NoiseCipher::AesGcm, NoiseHash::Sha256),
    ];

    #[must_use]
    pub const fn new(cipher: NoiseCipher, hash: NoiseHash) -> Self {
        Self { cipher, hash }
    }

    /// The Noise protocol name, in snow's tokens (`ChaChaPoly`/`AESGCM`,
    /// `BLAKE2s`/`SHA256`).
    #[must_use]
    pub const fn protocol_name(self) -> &'static str {
        match (self.cipher, self.hash) {
            (NoiseCipher::ChaChaPoly, NoiseHash::Blake2s) => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
            (NoiseCipher::ChaChaPoly, NoiseHash::Sha256) => "Noise_IK_25519_ChaChaPoly_SHA256",
            (NoiseCipher::AesGcm, NoiseHash::Blake2s) => "Noise_IK_25519_AESGCM_BLAKE2s",
            (NoiseCipher::AesGcm, NoiseHash::Sha256) => "Noise_IK_25519_AESGCM_SHA256",
        }
    }

    /// The suite whose protocol name is `name`.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Ipc` naming `name` and the supported names when
    /// no suite has it.
    pub fn from_protocol_name(name: &str) -> core_types::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|suite| suite.protocol_name() == name)
            .ok_or_else(|| {
                let supported: Vec<&str> = Self::ALL.iter().map(|s| s.protocol_name()).collect();
                core_types::Error::Ipc(format!(
                    "unsupported Noise protocol {name:?}; supported: {}",
                    supported.join(", ")
                ))
            })
    }

    /// The snow parameters of this suite.
    pub(crate) fn params(self) -> snow::params::NoiseParams {
        self.protocol_name()
            .parse()
            .expect("every NoiseSuite protocol name is one snow's default resolver supports")
    }
}

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
/// so one task owns it and multiplexes reads and writes with
/// `tokio::select!` (`BusServer`, `BusClient`). Splitting it across tasks
/// behind a lock would let the reader hold the lock while it awaits the
/// socket and starve the writer.
///
/// [`read_encrypted_frame`](Self::read_encrypted_frame) is cancel-safe, as
/// a `select!` branch must be: received bytes accumulate in `inbox`, and a
/// frame is decrypted and removed from it only once all of its chunks have
/// arrived, so a read dropped at any await loses nothing.
pub(crate) struct NoiseTransport {
    state: snow::TransportState,
    /// Bytes received and not yet consumed as a complete frame.
    inbox: Vec<u8>,
}

/// Largest wire frame of one encrypted chunk: a Noise transport message.
const MAX_NOISE_MESSAGE: usize = 65535;

/// The range of the length-prefixed frame at `*at` in `inbox`, advancing
/// `*at` past it; `None` when it has not fully arrived. Frames longer than
/// `limit` are an error.
fn take_frame(
    inbox: &[u8],
    at: &mut usize,
    limit: usize,
) -> core_types::Result<Option<std::ops::Range<usize>>> {
    let Some(prefix) = inbox.get(*at..*at + 4) else {
        return Ok(None);
    };
    let len = u32::from_be_bytes(prefix.try_into().expect("the prefix is 4 bytes")) as usize;
    if len > limit {
        return Err(core_types::Error::Ipc(format!(
            "frame size {len} exceeds maximum {limit}"
        )));
    }
    let start = *at + 4;
    let end = start + len;
    if inbox.len() < end {
        return Ok(None);
    }
    *at = end;
    Ok(Some(start..end))
}

/// One complete encrypted application frame at the start of `inbox`: the
/// ranges of its ciphertext chunks and the bytes it spans; `None` when it
/// has not fully arrived.
fn complete_frame(
    inbox: &[u8],
) -> core_types::Result<Option<(Vec<std::ops::Range<usize>>, usize)>> {
    let mut at = 0;
    let Some(header) = take_frame(inbox, &mut at, MAX_FRAME_SIZE as usize)? else {
        return Ok(None);
    };
    let header: [u8; 4] = inbox[header.clone()].try_into().map_err(|_| {
        core_types::Error::Ipc(format!(
            "invalid chunk count header: expected 4 bytes, got {}",
            header.len()
        ))
    })?;
    let chunk_count = u32::from_be_bytes(header) as usize;
    let max_chunks = (MAX_FRAME_SIZE as usize).div_ceil(MAX_NOISE_PLAINTEXT);
    if chunk_count > max_chunks {
        return Err(core_types::Error::Ipc(format!(
            "chunk count {chunk_count} exceeds maximum {max_chunks}"
        )));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for _ in 0..chunk_count {
        let Some(chunk) = take_frame(inbox, &mut at, MAX_NOISE_MESSAGE)? else {
            return Ok(None);
        };
        chunks.push(chunk);
    }
    Ok(Some((chunks, at)))
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
    pub(crate) async fn write_encrypted_frame<W: AsyncWrite + Unpin>(
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

    /// Read and decrypt an application frame: the chunk count header and
    /// each chunk, reassembled into the original plaintext payload.
    ///
    /// Cancel-safe: the only await is `read_buf` into the transport's
    /// inbox, and the frame is decrypted and consumed only once it is
    /// complete, so a call dropped by `select!` loses no bytes and the next
    /// call resumes the same frame.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure (end of stream included), a
    /// malformed or oversized frame, decryption failure, or if the
    /// reassembled payload exceeds `MAX_FRAME_SIZE`.
    pub(crate) async fn read_encrypted_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> core_types::Result<Vec<u8>> {
        let (chunks, used) = loop {
            if let Some(frame) = complete_frame(&self.inbox)? {
                break frame;
            }
            self.inbox.reserve(8192);
            if reader.read_buf(&mut self.inbox).await? == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
        };

        // Both buffers hold decrypted plaintext (possibly secret values);
        // `Zeroizing` clears them on every return path, including errors.
        let mut payload =
            zeroize::Zeroizing::new(Vec::with_capacity(chunks.len() * MAX_NOISE_PLAINTEXT));
        let mut dec_buf = zeroize::Zeroizing::new(vec![0u8; MAX_NOISE_PLAINTEXT]);

        for chunk in chunks {
            let len = self
                .state
                .read_message(&self.inbox[chunk], &mut dec_buf)
                .map_err(|e| core_types::Error::Ipc(format!("Noise decrypt failed: {e}")))?;
            payload.extend_from_slice(&dec_buf[..len]);
        }
        self.inbox.drain(..used);

        if payload.len() > MAX_FRAME_SIZE as usize {
            return Err(core_types::Error::Ipc(format!(
                "decrypted payload {} exceeds maximum {}",
                payload.len(),
                MAX_FRAME_SIZE
            )));
        }

        // The caller owns the plaintext from here and zeroizes it.
        Ok(std::mem::take(&mut *payload))
    }

    /// Get the remote party's static public key.
    #[must_use]
    pub(crate) fn remote_static(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }
}

/// An established encrypted bus connection: the Noise transport and the
/// buffered halves of its socket, owned by one task.
pub(crate) struct Connection {
    pub(crate) transport: NoiseTransport,
    pub(crate) reader: BufReader<OwnedReadHalf>,
    pub(crate) writer: BufWriter<OwnedWriteHalf>,
}

/// The buffered halves of `stream`.
fn split(stream: UnixStream) -> (BufReader<OwnedReadHalf>, BufWriter<OwnedWriteHalf>) {
    let (reader, writer) = stream.into_split();
    (BufReader::new(reader), BufWriter::new(writer))
}

impl Connection {
    /// Handshake `stream` as the client `keypair` with the bus `server`
    /// (running with credentials `server_creds`).
    ///
    /// # Errors
    ///
    /// The [`client_handshake`] errors.
    pub(crate) async fn client(
        stream: UnixStream,
        server: &BusEndpoint,
        keypair: &snow::Keypair,
        server_creds: &PeerCredentials,
    ) -> core_types::Result<Self> {
        let (mut reader, mut writer) = split(stream);
        let transport = client_handshake(
            &mut reader,
            &mut writer,
            server,
            keypair,
            &local_credentials(),
            server_creds,
        )
        .await?;
        Ok(Self {
            transport,
            reader,
            writer,
        })
    }

    /// Handshake `stream` as the bus server `keypair` under `suite` with a
    /// client running with credentials `peer_creds`.
    ///
    /// # Errors
    ///
    /// The [`server_handshake`] errors.
    pub(crate) async fn server(
        stream: UnixStream,
        keypair: &snow::Keypair,
        suite: NoiseSuite,
        peer_creds: &PeerCredentials,
    ) -> core_types::Result<Self> {
        let (mut reader, mut writer) = split(stream);
        let transport = server_handshake(
            &mut reader,
            &mut writer,
            keypair,
            suite,
            &local_credentials(),
            peer_creds,
        )
        .await?;
        Ok(Self {
            transport,
            reader,
            writer,
        })
    }

    /// The peer's static public key, which the Noise IK pattern always
    /// transmits.
    ///
    /// # Panics
    ///
    /// Never: an IK handshake completes only with the initiator's
    /// 32-byte X25519 static key.
    pub(crate) fn remote_static_key(&self) -> [u8; 32] {
        self.transport
            .remote_static()
            .expect("the Noise IK pattern guarantees the remote static key after the handshake")
            .try_into()
            .expect("an X25519 public key is exactly 32 bytes")
    }
}

/// Perform the server-side (responder) Noise IK handshake.
///
/// Called by [`Connection::server`] after the accept loop extracted the
/// peer's `UCred`. The server's static keypair was generated at startup
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
pub(crate) async fn server_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    server_keypair: &snow::Keypair,
    suite: NoiseSuite,
    local_creds: &PeerCredentials,
    remote_creds: &PeerCredentials,
) -> core_types::Result<NoiseTransport>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prologue = build_prologue(local_creds, remote_creds);

    let mut handshake = snow::Builder::new(suite.params())
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
        Ok(NoiseTransport {
            state: transport,
            inbox: Vec::new(),
        })
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
pub(crate) async fn client_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    server: &BusEndpoint,
    client_keypair: &snow::Keypair,
    local_creds: &PeerCredentials,
    remote_creds: &PeerCredentials,
) -> core_types::Result<NoiseTransport>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let prologue = build_prologue(local_creds, remote_creds);

    let mut handshake = snow::Builder::new(server.suite.params())
        .local_private_key(&client_keypair.private)
        .map_err(|e| core_types::Error::Ipc(format!("Noise builder error: {e}")))?
        .remote_public_key(&server.public_key)
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
        Ok(NoiseTransport {
            state: transport,
            inbox: Vec::new(),
        })
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

    type Half = tokio::io::DuplexStream;
    type Reader = tokio::io::ReadHalf<Half>;
    type Writer = tokio::io::WriteHalf<Half>;

    /// One side of a completed handshake: its transport and stream halves.
    struct Side {
        transport: NoiseTransport,
        reader: Reader,
        writer: Writer,
    }

    /// The two outcomes of one handshake over an in-memory stream.
    struct Handshake {
        client: core_types::Result<NoiseTransport>,
        server: core_types::Result<NoiseTransport>,
        client_io: (Reader, Writer),
        server_io: (Reader, Writer),
    }

    const SERVER: PeerCredentials = PeerCredentials { pid: 1, uid: 1000 };
    const CLIENT: PeerCredentials = PeerCredentials { pid: 2, uid: 1000 };

    /// Handshake a client using `client_suite` with a server bound with
    /// `server_suite`, over an in-memory stream of `buffer` bytes. The
    /// client sees the server's true credentials; the server believes its
    /// peer is `server_sees`.
    async fn handshake(
        server_suite: NoiseSuite,
        client_suite: NoiseSuite,
        server_sees: &PeerCredentials,
        buffer: usize,
    ) -> Handshake {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();
        // The endpoint as the client read it: the server's key, and the
        // suite the client handshakes with.
        let endpoint = BusEndpoint {
            suite: client_suite,
            public_key: server_kp.public().try_into().unwrap(),
        };
        let (client_stream, server_stream) = tokio::io::duplex(buffer);
        let (mut cr, mut cw) = tokio::io::split(client_stream);
        let (mut sr, mut sw) = tokio::io::split(server_stream);
        let (client, server) = tokio::join!(
            client_handshake(
                &mut cr,
                &mut cw,
                &endpoint,
                client_kp.as_inner(),
                &CLIENT,
                &SERVER,
            ),
            server_handshake(
                &mut sr,
                &mut sw,
                server_kp.as_inner(),
                server_suite,
                &SERVER,
                server_sees,
            ),
        );
        Handshake {
            client,
            server,
            client_io: (cr, cw),
            server_io: (sr, sw),
        }
    }

    /// A completed handshake under `suite` with agreeing credentials.
    async fn connected(suite: NoiseSuite, buffer: usize) -> (Side, Side) {
        let h = handshake(suite, suite, &CLIENT, buffer).await;
        (
            Side {
                transport: h.client.unwrap(),
                reader: h.client_io.0,
                writer: h.client_io.1,
            },
            Side {
                transport: h.server.unwrap(),
                reader: h.server_io.0,
                writer: h.server_io.1,
            },
        )
    }

    #[tokio::test]
    async fn every_suite_handshakes_and_carries_frames_both_ways() {
        for suite in NoiseSuite::ALL {
            let (mut client, mut server) = connected(suite, 65536).await;
            client
                .transport
                .write_encrypted_frame(&mut client.writer, b"hello encrypted world")
                .await
                .unwrap();
            let decrypted = server
                .transport
                .read_encrypted_frame(&mut server.reader)
                .await
                .unwrap();
            assert_eq!(decrypted, b"hello encrypted world", "{suite:?}");
            server
                .transport
                .write_encrypted_frame(&mut server.writer, b"acknowledged")
                .await
                .unwrap();
            let decrypted = client
                .transport
                .read_encrypted_frame(&mut client.reader)
                .await
                .unwrap();
            assert_eq!(decrypted, b"acknowledged", "{suite:?}");
        }
    }

    #[tokio::test]
    async fn a_client_on_another_suite_fails_the_handshake() {
        for server_suite in NoiseSuite::ALL {
            for client_suite in NoiseSuite::ALL {
                if client_suite == server_suite {
                    continue;
                }
                let h = handshake(server_suite, client_suite, &CLIENT, 65536).await;
                assert!(
                    h.client.is_err() || h.server.is_err(),
                    "server {server_suite:?} accepted client {client_suite:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn large_frame_chunking() {
        // Frames larger than 65519 bytes are chunked: 200 KiB is ~4 chunks.
        let (mut client, mut server) = connected(NoiseSuite::default(), 1024 * 1024).await;
        let large_payload = vec![0xABu8; 200 * 1024];
        client
            .transport
            .write_encrypted_frame(&mut client.writer, &large_payload)
            .await
            .unwrap();
        let decrypted = server
            .transport
            .read_encrypted_frame(&mut server.reader)
            .await
            .unwrap();
        assert_eq!(decrypted, large_payload);
    }

    #[tokio::test]
    async fn prologue_mismatch_fails_handshake() {
        // The server believes its peer is PID 99; the client is PID 2.
        let fake_client = PeerCredentials { pid: 99, uid: 1000 };
        let suite = NoiseSuite::default();
        let h = handshake(suite, suite, &fake_client, 65536).await;
        assert!(
            h.client.is_err() || h.server.is_err(),
            "prologue mismatch should cause handshake failure"
        );
    }

    /// A read dropped by `select!` after the chunk count header arrived
    /// (another branch won) loses nothing: the next read returns the frame.
    #[tokio::test]
    async fn a_read_cancelled_mid_frame_resumes_it() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = connected(NoiseSuite::default(), 65536).await;
        let mut wire = Vec::new();
        client
            .transport
            .write_encrypted_frame(&mut wire, b"after the cancel")
            .await
            .unwrap();
        // [4-byte length][4-byte chunk count], then the chunk frame.
        let (header, chunk) = wire.split_at(8);
        client.writer.write_all(header).await.unwrap();
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            server.transport.read_encrypted_frame(&mut server.reader),
        )
        .await;
        assert!(cancelled.is_err(), "the read waits for the chunk");
        client.writer.write_all(chunk).await.unwrap();
        let payload = server
            .transport
            .read_encrypted_frame(&mut server.reader)
            .await
            .unwrap();
        assert_eq!(payload, b"after the cancel");
    }

    #[tokio::test]
    async fn empty_payload_roundtrip() {
        let (mut client, mut server) = connected(NoiseSuite::default(), 65536).await;
        client
            .transport
            .write_encrypted_frame(&mut client.writer, b"")
            .await
            .unwrap();
        let decrypted = server
            .transport
            .read_encrypted_frame(&mut server.reader)
            .await
            .unwrap();
        assert!(decrypted.is_empty());
    }
}
