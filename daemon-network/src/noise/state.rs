//! Noise XX state machine using `snow` with `aws-lc-rs` resolver.
//!
//! Implements both XX (first contact) and `IKpsk2` (reconnection with cached
//! static key + handshake-derived PSK) patterns.
//!
//! The state machine is consuming: each transition takes ownership of the
//! previous state, preventing reuse of handshake material.
//!
//! Protocol strings:
//! - XX: `Noise_XX_25519_ChaChaPoly_BLAKE2s`
//! - `IKpsk2`: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
//!
//! Note: snow uses BLAKE2s (not `BLAKE2b`). The milestone spec recommends
//! `BLAKE2b` for the leading-edge track, but snow's resolver only supports
//! BLAKE2s. A future iteration may implement the state machine directly
//! against aws-lc-rs + blake2 crate for `BLAKE2b` support. For now, snow
//! provides correctness, auditability, and published test vectors.

use snow::Builder;

/// Noise protocol parameter strings.
///
/// # Known gap: classical X25519 only
///
/// The M1 spec defaults to `NetworkKem::XWing` (X25519 + ML-KEM-768 hybrid).
/// Snow does not support PQ patterns, so we use classical X25519. The
/// `NetworkKem::XWing` enum in `core-types` is defined but not yet wired.
/// When the transport migrates from snow to a direct aws-lc-rs state machine,
/// PQ hybrid support should be implemented.
pub const NOISE_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_IKPSK2: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise transport message plaintext (65535 - 16 byte tag).
pub const MAX_NOISE_PLAINTEXT: usize = 65535 - 16;

/// Completed Noise transport with directional keys.
pub struct NoiseTransport {
    state: snow::TransportState,
    is_initiator: bool,
    /// Handshake hash captured before transition to transport mode.
    /// Used for PSK derivation on XX→IKpsk2 transition.
    cached_handshake_hash: [u8; 32],
}

impl NoiseTransport {
    /// Encrypt a plaintext message without additional authenticated data.
    ///
    /// Returns the ciphertext (plaintext + 16-byte AEAD tag).
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Snow` if the Noise transport encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.encrypt_with_aad(&[], plaintext)
    }

    /// Encrypt a plaintext message with additional authenticated data.
    ///
    /// The `aad` is mixed into the AEAD tag but NOT encrypted. The receiver
    /// must provide the same `aad` for decryption to succeed. Use this to
    /// bind frame headers to the ciphertext — an attacker who can observe
    /// plaintext headers cannot splice headers from different frames onto
    /// a valid ciphertext without breaking the AEAD tag.
    ///
    /// Uses snow's `write_message_with_additional_data` (pinned to git rev
    /// 295dc7b which adds this API to `TransportState`).
    pub fn encrypt_with_aad(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = self
            .state
            .write_message_with_additional_data(aad, plaintext, &mut buf)
            .map_err(NoiseError::Snow)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a ciphertext message without additional authenticated data.
    ///
    /// Returns the plaintext.
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Snow` if AEAD tag verification fails.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.decrypt_with_aad(&[], ciphertext)
    }

    /// Decrypt a ciphertext message with additional authenticated data.
    ///
    /// The `aad` must match what was provided during encryption.
    pub fn decrypt_with_aad(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .state
            .read_message_with_additional_data(aad, ciphertext, &mut buf)
            .map_err(NoiseError::Snow)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Get the remote party's static public key (32 bytes).
    #[must_use]
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.state.get_remote_static().map(|s| {
            let mut key = [0u8; 32];
            key.copy_from_slice(s);
            key
        })
    }

    /// Get the handshake hash (for PSK derivation on XX→IKpsk2 transition).
    ///
    /// Captured from the `HandshakeState` before transition to transport mode.
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.cached_handshake_hash
    }

    /// Whether this transport was created by the initiator.
    #[must_use]
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }
}

/// Perform a Noise XX handshake as initiator.
///
/// Three messages: initiator sends msg1, receives msg2, sends msg3.
/// Returns the transport state and the responder's static public key.
///
/// # Errors
///
/// Returns `NoiseError::Snow` on handshake failure, `NoiseError::Io` on I/O error,
/// or `NoiseError::InvalidParams` if the protocol string is malformed.
pub async fn xx_initiator<R, W>(
    reader: &mut R,
    writer: &mut W,
    local_keypair: &snow::Keypair,
) -> Result<NoiseTransport, NoiseError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut handshake = Builder::new(NOISE_XX.parse().map_err(|_| NoiseError::InvalidParams)?)
        .local_private_key(&local_keypair.private)
        .map_err(NoiseError::Snow)?
        .build_initiator()
        .map_err(NoiseError::Snow)?;

    // msg1: -> e
    let mut buf = vec![0u8; 65535];
    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(NoiseError::Snow)?;
    write_noise_msg(writer, &buf[..len]).await?;

    // msg2: <- e, ee, s, es
    let msg2 = read_noise_msg(reader).await?;
    handshake
        .read_message(&msg2, &mut buf)
        .map_err(NoiseError::Snow)?;

    // msg3: -> s, se
    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(NoiseError::Snow)?;
    write_noise_msg(writer, &buf[..len]).await?;

    // Capture handshake hash before transition (HandshakeState has it, TransportState doesn't).
    let hh = capture_handshake_hash(&handshake);

    let transport = handshake.into_transport_mode().map_err(NoiseError::Snow)?;

    Ok(NoiseTransport {
        state: transport,
        is_initiator: true,
        cached_handshake_hash: hh,
    })
}

/// Perform a Noise XX handshake as responder.
///
/// Three messages: responder receives msg1, sends msg2, receives msg3.
///
/// # Errors
///
/// Returns `NoiseError::Snow` on handshake failure, `NoiseError::Io` on I/O error.
pub async fn xx_responder<R, W>(
    reader: &mut R,
    writer: &mut W,
    local_keypair: &snow::Keypair,
) -> Result<NoiseTransport, NoiseError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut handshake = Builder::new(NOISE_XX.parse().map_err(|_| NoiseError::InvalidParams)?)
        .local_private_key(&local_keypair.private)
        .map_err(NoiseError::Snow)?
        .build_responder()
        .map_err(NoiseError::Snow)?;

    let mut buf = vec![0u8; 65535];

    // msg1: <- e
    let msg1 = read_noise_msg(reader).await?;
    handshake
        .read_message(&msg1, &mut buf)
        .map_err(NoiseError::Snow)?;

    // msg2: -> e, ee, s, es
    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(NoiseError::Snow)?;
    write_noise_msg(writer, &buf[..len]).await?;

    // msg3: <- s, se
    let msg3 = read_noise_msg(reader).await?;
    handshake
        .read_message(&msg3, &mut buf)
        .map_err(NoiseError::Snow)?;

    let hh = capture_handshake_hash(&handshake);
    let transport = handshake.into_transport_mode().map_err(NoiseError::Snow)?;

    Ok(NoiseTransport {
        state: transport,
        is_initiator: false,
        cached_handshake_hash: hh,
    })
}

/// Perform a Noise `IKpsk2` handshake as initiator (reconnection).
///
/// Requires the responder's cached static public key and a pre-shared key.
///
/// # Errors
///
/// Returns `NoiseError::Snow` on handshake failure, `NoiseError::Io` on I/O error.
pub async fn ikpsk2_initiator<R, W>(
    reader: &mut R,
    writer: &mut W,
    local_keypair: &snow::Keypair,
    remote_static: &[u8; 32],
    psk: &[u8; 32],
) -> Result<NoiseTransport, NoiseError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut handshake = Builder::new(
        NOISE_IKPSK2
            .parse()
            .map_err(|_| NoiseError::InvalidParams)?,
    )
    .local_private_key(&local_keypair.private)
    .map_err(NoiseError::Snow)?
    .remote_public_key(remote_static)
    .map_err(NoiseError::Snow)?
    .psk(2, psk)
    .map_err(NoiseError::Snow)?
    .build_initiator()
    .map_err(NoiseError::Snow)?;

    let mut buf = vec![0u8; 65535];

    // msg1: -> e, es, s, ss
    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(NoiseError::Snow)?;
    write_noise_msg(writer, &buf[..len]).await?;

    // msg2: <- e, ee, se, psk
    let msg2 = read_noise_msg(reader).await?;
    handshake
        .read_message(&msg2, &mut buf)
        .map_err(NoiseError::Snow)?;

    let hh = capture_handshake_hash(&handshake);
    let transport = handshake.into_transport_mode().map_err(NoiseError::Snow)?;

    Ok(NoiseTransport {
        state: transport,
        is_initiator: true,
        cached_handshake_hash: hh,
    })
}

/// Perform a Noise `IKpsk2` handshake as responder (reconnection).
///
/// # Errors
///
/// Returns `NoiseError::Snow` on handshake failure, `NoiseError::Io` on I/O error.
pub async fn ikpsk2_responder<R, W>(
    reader: &mut R,
    writer: &mut W,
    local_keypair: &snow::Keypair,
    psk: &[u8; 32],
) -> Result<NoiseTransport, NoiseError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut handshake = Builder::new(
        NOISE_IKPSK2
            .parse()
            .map_err(|_| NoiseError::InvalidParams)?,
    )
    .local_private_key(&local_keypair.private)
    .map_err(NoiseError::Snow)?
    .psk(2, psk)
    .map_err(NoiseError::Snow)?
    .build_responder()
    .map_err(NoiseError::Snow)?;

    let mut buf = vec![0u8; 65535];

    // msg1: <- e, es, s, ss
    let msg1 = read_noise_msg(reader).await?;
    handshake
        .read_message(&msg1, &mut buf)
        .map_err(NoiseError::Snow)?;

    // msg2: -> e, ee, se, psk
    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(NoiseError::Snow)?;
    write_noise_msg(writer, &buf[..len]).await?;

    let hh = capture_handshake_hash(&handshake);
    let transport = handshake.into_transport_mode().map_err(NoiseError::Snow)?;

    Ok(NoiseTransport {
        state: transport,
        is_initiator: false,
        cached_handshake_hash: hh,
    })
}

/// Derive a PSK from a completed XX handshake hash.
///
/// Both parties derive the same PSK from their shared handshake hash.
/// Used for XX→IKpsk2 transition on reconnection.
#[must_use]
pub fn derive_psk_from_handshake(handshake_hash: &[u8; 32]) -> [u8; 32] {
    let keys = core_crypto::network::hkdf_blake2b(handshake_hash, b"opensesame:psk:v1", 1);
    let mut psk = [0u8; 32];
    psk.copy_from_slice(keys[0].as_bytes());
    psk
}

/// Capture handshake hash from a `HandshakeState` before `into_transport_mode()`.
///
/// Snow's `TransportState` does not expose the handshake hash, so we must
/// capture it while the state machine is still in handshake phase.
///
/// The hash length depends on the cipher suite's hash function:
/// - BLAKE2s (current): 32 bytes -- full copy into [u8; 32]
/// - `BLAKE2b` (future): 64 bytes -- truncated to first 32 bytes
///
/// PSK derived from this hash is cipher-suite-dependent. Changing the
/// hash function changes the PSK, invalidating cached PSKs. A cipher
/// suite migration must clear all cached PSKs in the TOFU store.
fn capture_handshake_hash(hs: &snow::HandshakeState) -> [u8; 32] {
    let hash = hs.get_handshake_hash();
    let mut out = [0u8; 32];
    let len = hash.len().min(32);
    out[..len].copy_from_slice(&hash[..len]);
    out
}

// -- Wire helpers for length-prefixed Noise messages --

async fn write_noise_msg<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &[u8],
) -> Result<(), NoiseError> {
    use tokio::io::AsyncWriteExt;
    #[allow(clippy::cast_possible_truncation)] // Noise messages are < 65535 bytes
    let len = (msg.len() as u16).to_be_bytes();
    writer.write_all(&len).await.map_err(NoiseError::Io)?;
    writer.write_all(msg).await.map_err(NoiseError::Io)?;
    writer.flush().await.map_err(NoiseError::Io)?;
    Ok(())
}

async fn read_noise_msg<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, NoiseError> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(NoiseError::Io)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.map_err(NoiseError::Io)?;
    Ok(buf)
}

/// Errors from the Noise state machine.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("Noise protocol error: {0}")]
    Snow(#[from] snow::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid Noise parameters")]
    InvalidParams,
    #[error("Handshake timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> snow::Keypair {
        snow::Builder::new(NOISE_XX.parse().unwrap())
            .generate_keypair()
            .unwrap()
    }

    #[tokio::test]
    async fn xx_handshake_and_transport() {
        let initiator_kp = generate_keypair();
        let responder_kp = generate_keypair();

        let (client, server) = tokio::io::duplex(65536);
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut sw) = tokio::io::split(server);

        let (init_result, resp_result) = tokio::join!(
            xx_initiator(&mut cr, &mut cw, &initiator_kp),
            xx_responder(&mut sr, &mut sw, &responder_kp),
        );

        let mut init_transport = init_result.unwrap();
        let mut resp_transport = resp_result.unwrap();

        // Verify remote static keys.
        let init_sees = init_transport.remote_static().unwrap();
        let resp_sees = resp_transport.remote_static().unwrap();
        assert_eq!(init_sees, responder_kp.public.as_slice());
        assert_eq!(resp_sees, initiator_kp.public.as_slice());

        // Transport: initiator → responder.
        let ct = init_transport.encrypt(b"hello from initiator").unwrap();
        let pt = resp_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello from initiator");

        // Transport: responder → initiator.
        let ct = resp_transport.encrypt(b"hello from responder").unwrap();
        let pt = init_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello from responder");
    }

    #[tokio::test]
    async fn xx_then_ikpsk2_reconnection() {
        let initiator_kp = generate_keypair();
        let responder_kp = generate_keypair();

        // First: XX handshake.
        let (client, server) = tokio::io::duplex(65536);
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut sw) = tokio::io::split(server);

        let (init_result, resp_result) = tokio::join!(
            xx_initiator(&mut cr, &mut cw, &initiator_kp),
            xx_responder(&mut sr, &mut sw, &responder_kp),
        );

        let init_transport = init_result.unwrap();
        let resp_transport = resp_result.unwrap();

        // Derive PSK from handshake hash.
        let init_psk = derive_psk_from_handshake(&init_transport.handshake_hash());
        let resp_psk = derive_psk_from_handshake(&resp_transport.handshake_hash());
        assert_eq!(init_psk, resp_psk);

        // Cache responder's static key.
        let resp_static = init_transport.remote_static().unwrap();

        // Second: IKpsk2 reconnection.
        let (client2, server2) = tokio::io::duplex(65536);
        let (mut cr2, mut cw2) = tokio::io::split(client2);
        let (mut sr2, mut sw2) = tokio::io::split(server2);

        let (init2_result, resp2_result) = tokio::join!(
            ikpsk2_initiator(&mut cr2, &mut cw2, &initiator_kp, &resp_static, &init_psk),
            ikpsk2_responder(&mut sr2, &mut sw2, &responder_kp, &resp_psk),
        );

        let mut init2 = init2_result.unwrap();
        let mut resp2 = resp2_result.unwrap();

        // Verify transport works.
        let ct = init2.encrypt(b"reconnected").unwrap();
        let pt = resp2.decrypt(&ct).unwrap();
        assert_eq!(pt, b"reconnected");
    }

    #[test]
    fn psk_derivation_deterministic() {
        let hash = [0xAA; 32];
        let p1 = derive_psk_from_handshake(&hash);
        let p2 = derive_psk_from_handshake(&hash);
        assert_eq!(p1, p2);
    }

    #[test]
    fn psk_derivation_different_hashes() {
        let h1 = [0xAA; 32];
        let h2 = [0xBB; 32];
        assert_ne!(
            derive_psk_from_handshake(&h1),
            derive_psk_from_handshake(&h2)
        );
    }
}
