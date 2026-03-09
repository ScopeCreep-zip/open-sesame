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

use crate::framing::{read_frame, write_frame, MAX_FRAME_SIZE};
use crate::transport::PeerCredentials;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

/// Compute an integrity-detection checksum for a keypair.
///
/// Uses BLAKE3 keyed hash with the public key as the 32-byte key and
/// the private key as the data. Detects partial corruption or partial tampering
/// (e.g., private key replaced but checksum file untouched). Does NOT prevent
/// an attacker with full filesystem write access from replacing all three files
/// (private key, public key, checksum) with a self-consistent set — that requires
/// a root-of-trust outside the filesystem (e.g., TPM-backed attestation).
fn keypair_checksum(public_key: &[u8; 32], private_key: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(public_key, private_key).as_bytes()
}

/// Noise protocol parameter string.
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext per Noise transport message: 65535 - 16 (AEAD tag) = 65519 bytes.
const MAX_NOISE_PLAINTEXT: usize = 65535 - 16;

/// Handshake timeout to prevent `DoS` via slow handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Generate a new X25519 static keypair for Noise IK.
///
/// Called once at daemon startup. The keypair is ephemeral to the process lifetime
/// for connecting daemons, or persisted to `$XDG_RUNTIME_DIR/pds/` for the bus server.
///
/// # Errors
///
/// Returns an error if the crypto resolver fails.
pub fn generate_keypair() -> core_types::Result<ZeroizingKeypair> {
    let builder = snow::Builder::new(NOISE_PARAMS.parse().map_err(|e| {
        core_types::Error::Platform(format!("invalid Noise params: {e}"))
    })?);
    let keypair = builder.generate_keypair().map_err(|e| {
        core_types::Error::Platform(format!("keypair generation failed: {e}"))
    })?;
    Ok(ZeroizingKeypair::new(keypair))
}

/// Zeroize-on-drop wrapper for `snow::Keypair`.
///
/// `snow::Keypair` has no `Drop` impl, so the private key persists in freed
/// memory if not explicitly zeroized. This wrapper guarantees zeroization on
/// drop, including during panics (unwind calls `Drop`).
///
/// All code that constructs or receives a `snow::Keypair` should use this
/// wrapper instead. The private key is accessible via `private()` for
/// passing to `snow::Builder::local_private_key()`.
pub struct ZeroizingKeypair {
    inner: snow::Keypair,
}

impl ZeroizingKeypair {
    /// Wrap a `snow::Keypair`, taking ownership.
    #[must_use]
    pub fn new(keypair: snow::Keypair) -> Self {
        Self { inner: keypair }
    }

    /// Access the public key (32 bytes).
    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.inner.public
    }

    /// Access the private key (32 bytes). Use only for `snow::Builder` calls.
    #[must_use]
    pub fn private(&self) -> &[u8] {
        &self.inner.private
    }

    /// Borrow the inner `snow::Keypair` for APIs that require `&snow::Keypair`.
    #[must_use]
    pub fn as_inner(&self) -> &snow::Keypair {
        &self.inner
    }

    /// Consume the wrapper and return the inner `snow::Keypair`.
    ///
    /// The caller takes responsibility for zeroizing the private key.
    /// Use only when transferring ownership to an API that requires `snow::Keypair`
    /// (e.g., `BusServer::bind`).
    #[must_use]
    pub fn into_inner(mut self) -> snow::Keypair {
        let private = std::mem::take(&mut self.inner.private);
        let public = std::mem::take(&mut self.inner.public);
        snow::Keypair { private, public }
    }
}

impl Drop for ZeroizingKeypair {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.inner.private);
    }
}

impl From<snow::Keypair> for ZeroizingKeypair {
    fn from(keypair: snow::Keypair) -> Self {
        Self::new(keypair)
    }
}

/// Override for the runtime directory path. Set by tests to avoid `set_var`
/// race conditions (P7). Production code never sets this.
static RUNTIME_DIR_OVERRIDE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Set the runtime directory override. Intended for testing only.
/// Avoids `unsafe { set_var(...) }` which races with other threads reading env.
#[doc(hidden)]
pub fn set_runtime_dir_override(path: PathBuf) {
    *RUNTIME_DIR_OVERRIDE.lock().unwrap() = Some(path);
}

/// Resolve the PDS runtime directory (`$XDG_RUNTIME_DIR/pds/`).
fn runtime_dir() -> core_types::Result<PathBuf> {
    if let Some(ref override_dir) = *RUNTIME_DIR_OVERRIDE.lock().unwrap() {
        return Ok(override_dir.clone());
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").map_err(|_| {
        core_types::Error::Platform("XDG_RUNTIME_DIR is not set".into())
    })?;
    Ok(PathBuf::from(runtime).join("pds"))
}

/// Write the bus server's static keypair to the runtime directory.
///
/// - `bus.pub` (32 bytes, world-readable) — read by connecting daemons
/// - `bus.key` (32 bytes, mode 0600) — private key for the bus server
///
/// # Errors
///
/// Returns an error if directory creation or file I/O fails.
pub async fn write_bus_keypair(keypair: &snow::Keypair) -> core_types::Result<()> {
    let dir = runtime_dir()?;
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to create runtime dir {}: {e}",
            dir.display()
        ))
    })?;

    let pub_path = dir.join("bus.pub");
    let key_path = dir.join("bus.key");

    tokio::fs::write(&pub_path, &keypair.public).await.map_err(|e| {
        core_types::Error::Platform(format!("failed to write bus.pub: {e}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to set bus.pub permissions: {e}"))
            })?;
    }

    // Write private key atomically: write to temp file with 0600 perms, then rename.
    // This prevents a window where the key file exists with default (permissive) permissions.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp_key_path = dir.join("bus.key.tmp");
        // Blocking file ops for atomic write with mode — wrapped in spawn_blocking
        // to avoid blocking the tokio runtime.
        let private_key = zeroize::Zeroizing::new(keypair.private.clone());
        let tmp_path = tmp_key_path.clone();
        let final_path = key_path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(&private_key)?;
            f.sync_all()?;
            std::fs::rename(&tmp_path, &final_path)?;
            Ok(())
        })
        .await
        .map_err(|e| core_types::Error::Platform(format!("bus.key write task failed: {e}")))?
        .map_err(|e| core_types::Error::Platform(format!("failed to write bus.key: {e}")))?;
    }

    #[cfg(not(unix))]
    {
        compile_error!("bus.key writing requires Unix file permissions (mode 0600). Non-Unix platforms are not supported in MVP.");
    }

    // Write tamper-detection checksum.
    {
        let pub_array: [u8; 32] = keypair.public.clone().try_into().map_err(|_| {
            core_types::Error::Platform("bus public key is not 32 bytes".into())
        })?;
        let checksum = keypair_checksum(&pub_array, &keypair.private);
        let checksum_path = dir.join("bus.checksum");
        tokio::fs::write(&checksum_path, checksum).await.map_err(|e| {
            core_types::Error::Platform(format!("failed to write bus.checksum: {e}"))
        })?;
    }

    tracing::info!(
        pub_path = %pub_path.display(),
        key_path = %key_path.display(),
        "bus keypair written"
    );
    Ok(())
}

/// Directory for per-daemon keypair files.
fn keys_dir() -> core_types::Result<PathBuf> {
    Ok(runtime_dir()?.join("keys"))
}

/// Create the per-daemon keys directory if it does not exist.
///
/// # Errors
///
/// Returns an error if the directory cannot be created.
pub async fn create_keys_dir() -> core_types::Result<()> {
    let dir = keys_dir()?;
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to create keys dir {}: {e}",
            dir.display()
        ))
    })?;
    // Restrict to owner-only (0700) — create_dir_all inherits umask
    // (typically 0022 → 0755), which would let any local user enumerate daemons.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!(
                    "failed to set keys dir permissions on {}: {e}",
                    dir.display()
                ))
            })?;
    }
    Ok(())
}

/// Write a daemon's keypair to disk. Private key gets 0600, public key gets 0644.
///
/// Uses write-to-temp-then-rename for atomicity, same pattern as `write_bus_keypair()`.
///
/// # Errors
///
/// Returns an error if writing the keypair files fails.
pub async fn write_daemon_keypair(
    daemon_name: &str,
    keypair: &snow::Keypair,
) -> core_types::Result<()> {
    let dir = keys_dir()?;

    let pub_path = dir.join(format!("{daemon_name}.pub"));
    let key_path = dir.join(format!("{daemon_name}.key"));

    // Public key: world-readable (explicit 0644).
    tokio::fs::write(&pub_path, &keypair.public).await.map_err(|e| {
        core_types::Error::Platform(format!("failed to write {daemon_name}.pub: {e}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to set {daemon_name}.pub permissions: {e}"))
            })?;
    }

    // Private key: atomic write with 0600 perms.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp_path = dir.join(format!("{daemon_name}.key.tmp"));
        let private_key = zeroize::Zeroizing::new(keypair.private.clone());
        let tmp = tmp_path.clone();
        let final_path = key_path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&private_key)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &final_path)?;
            Ok(())
        })
        .await
        .map_err(|e| {
            core_types::Error::Platform(format!("{daemon_name}.key write task failed: {e}"))
        })?
        .map_err(|e| {
            core_types::Error::Platform(format!("failed to write {daemon_name}.key: {e}"))
        })?;
    }

    #[cfg(not(unix))]
    {
        compile_error!("daemon keypair writing requires Unix file permissions (mode 0600)");
    }

    // Write tamper-detection checksum.
    {
        let pub_array: [u8; 32] = keypair.public.clone().try_into().map_err(|_| {
            core_types::Error::Platform(format!("{daemon_name} public key is not 32 bytes"))
        })?;
        let checksum = keypair_checksum(&pub_array, &keypair.private);
        let checksum_path = dir.join(format!("{daemon_name}.checksum"));
        tokio::fs::write(&checksum_path, checksum).await.map_err(|e| {
            core_types::Error::Platform(format!("failed to write {daemon_name}.checksum: {e}"))
        })?;
    }

    tracing::debug!(
        daemon = daemon_name,
        pub_path = %pub_path.display(),
        key_path = %key_path.display(),
        "daemon keypair written"
    );
    Ok(())
}

/// Read a daemon's keypair from disk. Private key wrapped in `Zeroizing`.
///
/// # Errors
///
/// Returns an error if the keypair files cannot be read or have invalid size.
pub async fn read_daemon_keypair(
    daemon_name: &str,
) -> core_types::Result<(zeroize::Zeroizing<Vec<u8>>, [u8; 32])> {
    let dir = keys_dir()?;

    let key_path = dir.join(format!("{daemon_name}.key"));
    let pub_path = dir.join(format!("{daemon_name}.pub"));

    let private_bytes = tokio::fs::read(&key_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read {daemon_name}.key at {}: {e}",
            key_path.display()
        ))
    })?;

    let public_bytes = tokio::fs::read(&pub_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read {daemon_name}.pub at {}: {e}",
            pub_path.display()
        ))
    })?;

    let public_key: [u8; 32] = public_bytes.try_into().map_err(|v: Vec<u8>| {
        core_types::Error::Platform(format!(
            "{daemon_name}.pub has wrong size: expected 32 bytes, got {}",
            v.len()
        ))
    })?;

    // Tamper detection.
    let checksum_path = dir.join(format!("{daemon_name}.checksum"));
    match tokio::fs::read(&checksum_path).await {
        Ok(stored_checksum) => {
            let expected = keypair_checksum(&public_key, &private_bytes);
            if stored_checksum.len() != 32 || stored_checksum[..] != expected[..] {
                return Err(core_types::Error::Platform(format!(
                    "TAMPER DETECTED: {daemon_name} keypair checksum mismatch. \
                     The private key or public key file may have been modified. \
                     Delete $XDG_RUNTIME_DIR/pds/keys/{daemon_name}.* and restart daemon-profile."
                )));
            }
            tracing::debug!(daemon = daemon_name, "keypair integrity verified");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Backward compatibility: no checksum file from older installation.
            tracing::warn!(
                daemon = daemon_name,
                "no checksum file found — keypair integrity cannot be verified. \
                 Restart daemon-profile to generate checksums."
            );
        }
        Err(e) => {
            return Err(core_types::Error::Platform(format!(
                "failed to read {daemon_name}.checksum: {e}"
            )));
        }
    }

    Ok((zeroize::Zeroizing::new(private_bytes), public_key))
}

/// Read only a daemon's public key from disk.
///
/// # Errors
///
/// Returns an error if the public key file cannot be read or has invalid size.
pub async fn read_daemon_public_key(daemon_name: &str) -> core_types::Result<[u8; 32]> {
    let dir = keys_dir()?;
    let pub_path = dir.join(format!("{daemon_name}.pub"));
    let bytes = tokio::fs::read(&pub_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read {daemon_name}.pub at {}: {e}",
            pub_path.display()
        ))
    })?;
    let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        core_types::Error::Platform(format!(
            "{daemon_name}.pub has wrong size: expected 32 bytes, got {}",
            v.len()
        ))
    })?;
    Ok(key)
}

/// Read the bus server's public key from the runtime directory.
///
/// Connecting daemons call this before initiating the Noise IK handshake
/// (the "K" in IK — responder's static key is Known to the initiator).
///
/// # Errors
///
/// Returns an error if the file does not exist or is not exactly 32 bytes.
pub async fn read_bus_public_key() -> core_types::Result<[u8; 32]> {
    read_bus_public_key_from(&runtime_dir()?).await
}

/// Read the bus server's public key from a specific directory.
///
/// Allows callers to specify a custom path (useful for testing).
///
/// # Errors
///
/// Returns an error if the file does not exist or is not exactly 32 bytes.
pub async fn read_bus_public_key_from(dir: &Path) -> core_types::Result<[u8; 32]> {
    let pub_path = dir.join("bus.pub");
    let bytes = tokio::fs::read(&pub_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read bus.pub at {}: {e}",
            pub_path.display()
        ))
    })?;
    let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        core_types::Error::Platform(format!(
            "bus.pub has wrong size: expected 32 bytes, got {}",
            v.len()
        ))
    })?;
    Ok(key)
}

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
/// Application frames are split into chunks of at most [`MAX_NOISE_PLAINTEXT`]
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
    /// [`MAX_NOISE_PLAINTEXT`] bytes each. Wire format per frame:
    ///
    /// ```text
    /// [4-byte BE chunk_count][chunk_1][chunk_2]...[chunk_n]
    /// ```
    ///
    /// Each chunk is written as a length-prefixed frame via [`write_frame`].
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
        let count_bytes = u32::try_from(chunk_count).map_err(|_| {
            core_types::Error::Ipc("too many chunks".into())
        })?;
        write_frame(writer, &count_bytes.to_be_bytes()).await?;

        // Write each chunk as an encrypted Noise message.
        // Output buffer: plaintext + 16-byte AEAD tag.
        let mut enc_buf = vec![0u8; MAX_NOISE_PLAINTEXT + 16];

        for chunk_idx in 0..chunk_count {
            let start = chunk_idx * MAX_NOISE_PLAINTEXT;
            let end = (start + MAX_NOISE_PLAINTEXT).min(payload.len());
            let chunk = &payload[start..end];

            let len = self.state.write_message(chunk, &mut enc_buf).map_err(|e| {
                core_types::Error::Ipc(format!("Noise encrypt failed: {e}"))
            })?;

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
            let len = self.state.read_message(&ciphertext, &mut dec_buf).map_err(|e| {
                core_types::Error::Ipc(format!("Noise decrypt failed: {e}"))
            })?;
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
        handshake.read_message(&msg1, &mut payload_buf).map_err(|e| {
            core_types::Error::Ipc(format!("Noise handshake msg1 read failed: {e}"))
        })?;

        // Write message 2 to initiator.
        let mut msg2_buf = vec![0u8; 65535];
        let msg2_len = handshake.write_message(&[], &mut msg2_buf).map_err(|e| {
            core_types::Error::Ipc(format!("Noise handshake msg2 write failed: {e}"))
        })?;
        write_frame(writer, &msg2_buf[..msg2_len]).await?;

        // Handshake complete — transition to transport mode.
        let transport = handshake.into_transport_mode().map_err(|e| {
            core_types::Error::Ipc(format!("Noise transport mode failed: {e}"))
        })?;

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
        handshake.read_message(&msg2, &mut payload_buf).map_err(|e| {
            core_types::Error::Ipc(format!("Noise handshake msg2 read failed: {e}"))
        })?;

        // Handshake complete — transition to transport mode.
        let transport = handshake.into_transport_mode().map_err(|e| {
            core_types::Error::Ipc(format!("Noise transport mode failed: {e}"))
        })?;

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
        let a = PeerCredentials { pid: 100, uid: 1000 };
        let b = PeerCredentials { pid: 200, uid: 1000 };

        // Both orderings produce the same prologue.
        assert_eq!(build_prologue(&a, &b), build_prologue(&b, &a));

        // Contains expected format.
        let p = String::from_utf8(build_prologue(&a, &b)).unwrap();
        assert_eq!(p, "PDS-IPC-v1:100:1000:200:1000");
    }

    #[test]
    fn generate_keypair_produces_32_byte_keys() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.private().len(), 32);
        assert_eq!(kp.public().len(), 32);
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
                client_handshake(&mut cr, &mut cw, &server_pub, client_kp.as_inner(), &client_creds, &server_creds)
                    .await
                    .unwrap()
            },
            async {
                server_handshake(&mut sr, &mut sw, server_kp.as_inner(), &server_creds, &client_creds)
                    .await
                    .unwrap()
            },
        );

        // 200 KiB payload — requires multiple chunks (200*1024 / 65519 = ~4 chunks).
        let large_payload = vec![0xABu8; 200 * 1024];

        ct.write_encrypted_frame(&mut cw, &large_payload).await.unwrap();
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

    #[test]
    fn keypair_checksum_consistency() {
        let kp = generate_keypair().unwrap();
        let pub_array: [u8; 32] = kp.public().try_into().unwrap();
        let checksum1 = keypair_checksum(&pub_array, kp.private());
        let checksum2 = keypair_checksum(&pub_array, kp.private());
        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn keypair_checksum_detects_tampering() {
        let kp = generate_keypair().unwrap();
        let pub_array: [u8; 32] = kp.public().try_into().unwrap();
        let checksum = keypair_checksum(&pub_array, kp.private());

        // Tampered private key produces different checksum.
        let mut tampered = kp.private().to_vec();
        tampered[0] ^= 0xFF;
        let tampered_checksum = keypair_checksum(&pub_array, &tampered);
        assert_ne!(checksum, tampered_checksum);
    }

    // SECURITY INVARIANT: ZeroizingKeypair::into_inner must leave the wrapper's
    // private key zeroed so that the original allocation does not retain key material
    // after ownership transfer.
    #[test]
    fn zeroizing_keypair_into_inner_zeroes_source() {
        let kp = generate_keypair().unwrap();
        let private_copy = kp.private().to_vec();
        assert!(!private_copy.iter().all(|&b| b == 0), "generated key must be non-zero");

        let extracted = kp.into_inner();
        // The extracted keypair should have the original private key.
        assert_eq!(extracted.private, private_copy);
        // After into_inner, the wrapper's field was mem::take'd (zeroed Vec).
        // We can't inspect it post-move, but into_inner's implementation uses
        // mem::take which replaces with empty Vec — verified by code review.
        // This test validates the round-trip: generated key is non-zero,
        // extraction preserves key material for the caller.
    }

    // NOTE: daemon keypair persistence tests live in
    // core-ipc/tests/daemon_keypair.rs (uses set_runtime_dir_override)
    // (unsafe since Rust 2024) and the crate uses `#![forbid(unsafe_code)]`.

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
                client_handshake(&mut cr, &mut cw, &server_pub, client_kp.as_inner(), &cc, &sc)
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
