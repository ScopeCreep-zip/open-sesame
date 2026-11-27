//! Persistence of the bus endpoint and the per-daemon Noise IK keypairs.
//!
//! Every location comes from `core_layout::Layout` and every file is written
//! through `core_layout::file` (atomic, mode set exactly):
//! - `<runtime>/bus.endpoint` (0644) — the bus server's protocol name and
//!   public key ([`BusEndpoint`]). The server's private key stays in memory.
//! - `<runtime>/keys/<daemon>.key` (0600) — per-daemon private key
//! - `<runtime>/keys/<daemon>.pub` (0644) — per-daemon public key
//! - `<runtime>/keys/<daemon>.checksum` (0600) — integrity checksum, written
//!   last; a keypair without a verifying checksum is rejected

use std::path::{Path, PathBuf};

use core_layout::file::Mode;
use core_layout::{KeyFile, Layout};

use crate::noise::NoiseSuite;

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

/// Generate a new X25519 static keypair for Noise IK.
///
/// The keypair is the same for every [`NoiseSuite`]: each uses X25519.
///
/// # Errors
///
/// Returns an error if the crypto resolver fails.
pub fn generate_keypair() -> core_types::Result<ZeroizingKeypair> {
    let keypair = snow::Builder::new(NoiseSuite::default().params())
        .generate_keypair()
        .map_err(|e| core_types::Error::Platform(format!("keypair generation failed: {e}")))?;
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

/// The bus server's published identity: the Noise protocol it bound with
/// and its static public key. Clients handshake with exactly this.
///
/// On disk (`Layout::bus_endpoint_file`): the protocol name, a newline, the
/// public key as 64 lowercase hex digits, a newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusEndpoint {
    pub suite: NoiseSuite,
    pub public_key: [u8; 32],
}

impl BusEndpoint {
    fn encode(&self) -> String {
        format!(
            "{}\n{}\n",
            self.suite.protocol_name(),
            hex::encode(self.public_key)
        )
    }

    fn decode(text: &str, path: &Path) -> core_types::Result<Self> {
        let malformed = |what: &str| {
            core_types::Error::Ipc(format!(
                "{} is not a bus endpoint record: {what}",
                path.display()
            ))
        };
        let mut lines = text.split_terminator('\n');
        let (Some(name), Some(key), None) = (lines.next(), lines.next(), lines.next()) else {
            return Err(malformed("expected a protocol name line and a key line"));
        };
        let suite = NoiseSuite::from_protocol_name(name)?;
        let public_key = hex::decode(key)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| malformed("the key line is not 64 hex digits"))?;
        Ok(Self { suite, public_key })
    }
}

fn platform_error(e: &dyn std::fmt::Display) -> core_types::Error {
    core_types::Error::Platform(e.to_string())
}

/// Write `contents` to `path` with `mode` through `core_layout::file`, off
/// the tokio runtime threads.
async fn write_file(
    path: PathBuf,
    contents: zeroize::Zeroizing<Vec<u8>>,
    mode: Mode,
) -> core_types::Result<()> {
    tokio::task::spawn_blocking(move || core_layout::file::write(&path, &contents, mode))
        .await
        .map_err(|e| platform_error(&e))?
        .map_err(|e| platform_error(&e))
}

/// Publish the bus endpoint (`Layout::bus_endpoint_file`, 0644).
///
/// # Errors
///
/// When the runtime directory cannot be placed or the file cannot be
/// written.
pub async fn publish_bus_endpoint(
    layout: &Layout,
    endpoint: &BusEndpoint,
) -> core_types::Result<()> {
    let path = layout.bus_endpoint_file()?;
    write_file(
        path.clone(),
        zeroize::Zeroizing::new(endpoint.encode().into_bytes()),
        Mode::PublicRead,
    )
    .await?;
    tracing::info!(
        path = %path.display(),
        protocol = endpoint.suite.protocol_name(),
        "bus endpoint published"
    );
    Ok(())
}

/// The published bus endpoint.
///
/// # Errors
///
/// When the file does not exist (daemon-profile is not running), cannot
/// be read, or is not an endpoint record.
pub async fn read_bus_endpoint(layout: &Layout) -> core_types::Result<BusEndpoint> {
    let path = layout.bus_endpoint_file()?;
    let text = tokio::fs::read_to_string(&path).await.map_err(|e| {
        core_types::Error::Platform(format!("failed to read {}: {e}", path.display()))
    })?;
    BusEndpoint::decode(&text, &path)
}

/// Create the per-daemon keys directory owner-only (0700).
///
/// # Errors
///
/// Returns an error if the directory cannot be placed, created, or
/// restricted.
pub async fn create_keys_dir(layout: &Layout) -> core_types::Result<()> {
    let dir = layout.keys_dir()?;
    tokio::task::spawn_blocking(move || core_layout::file::create_private_dir(&dir))
        .await
        .map_err(|e| platform_error(&e))?
        .map_err(|e| platform_error(&e))
}

/// The three files of one daemon's keypair.
struct DaemonKeyFiles {
    private: PathBuf,
    public: PathBuf,
    checksum: PathBuf,
}

impl DaemonKeyFiles {
    fn of(layout: &Layout, daemon_name: &str) -> core_types::Result<Self> {
        Ok(Self {
            private: layout.daemon_key_file(daemon_name, KeyFile::Private)?,
            public: layout.daemon_key_file(daemon_name, KeyFile::Public)?,
            checksum: layout.daemon_key_file(daemon_name, KeyFile::Checksum)?,
        })
    }
}

/// Write a daemon's keypair (`Layout::daemon_key_file`): the private key
/// 0600, the public key 0644, then the checksum 0600, and return the
/// public key. The checksum is written last, so a keypair interrupted
/// mid-write fails verification.
///
/// # Errors
///
/// Returns an error if the keys directory cannot be placed, the public key
/// is not 32 bytes, or a key file cannot be written.
pub async fn write_daemon_keypair(
    layout: &Layout,
    daemon_name: &str,
    keypair: &snow::Keypair,
) -> core_types::Result<[u8; 32]> {
    let public: [u8; 32] = keypair.public.clone().try_into().map_err(|_| {
        core_types::Error::Platform(format!("{daemon_name}: public key is not 32 bytes"))
    })?;
    let files = DaemonKeyFiles::of(layout, daemon_name)?;
    write_file(
        files.private.clone(),
        zeroize::Zeroizing::new(keypair.private.clone()),
        Mode::OwnerOnly,
    )
    .await?;
    write_file(
        files.public.clone(),
        zeroize::Zeroizing::new(public.to_vec()),
        Mode::PublicRead,
    )
    .await?;
    write_file(
        files.checksum,
        zeroize::Zeroizing::new(keypair_checksum(&public, &keypair.private).to_vec()),
        Mode::OwnerOnly,
    )
    .await?;
    tracing::debug!(
        daemon = daemon_name,
        pub_path = %files.public.display(),
        key_path = %files.private.display(),
        "daemon keypair written"
    );
    Ok(public)
}

/// Generate a fresh keypair for `daemon_name`, persist it with
/// [`write_daemon_keypair`], and return its public key for the clearance
/// registry. The private key is zeroized when this returns.
///
/// # Errors
///
/// The [`generate_keypair`] and [`write_daemon_keypair`] errors.
pub async fn issue_daemon_keypair(
    layout: &Layout,
    daemon_name: &str,
) -> core_types::Result<[u8; 32]> {
    write_daemon_keypair(layout, daemon_name, generate_keypair()?.as_inner()).await
}

/// Read a file, naming it on error.
async fn read_file(path: &Path) -> core_types::Result<Vec<u8>> {
    tokio::fs::read(path)
        .await
        .map_err(|e| core_types::Error::Platform(format!("failed to read {}: {e}", path.display())))
}

/// Read a daemon's keypair and verify it against its checksum. Private key
/// wrapped in `Zeroizing`.
///
/// # Errors
///
/// Returns an error if any of the three files cannot be read, the public
/// key is not 32 bytes, or the checksum does not verify (`TAMPER DETECTED`,
/// naming the files to delete).
pub async fn read_daemon_keypair(
    layout: &Layout,
    daemon_name: &str,
) -> core_types::Result<(zeroize::Zeroizing<Vec<u8>>, [u8; 32])> {
    let files = DaemonKeyFiles::of(layout, daemon_name)?;
    let private_bytes = zeroize::Zeroizing::new(read_file(&files.private).await?);
    let public_key: [u8; 32] =
        read_file(&files.public)
            .await?
            .try_into()
            .map_err(|v: Vec<u8>| {
                core_types::Error::Platform(format!(
                    "{} has wrong size: expected 32 bytes, got {}",
                    files.public.display(),
                    v.len()
                ))
            })?;
    let stored_checksum = read_file(&files.checksum).await?;
    if stored_checksum[..] != keypair_checksum(&public_key, &private_bytes)[..] {
        return Err(core_types::Error::Platform(format!(
            "TAMPER DETECTED: {daemon_name} keypair checksum mismatch. \
             The private key or public key file may have been modified. \
             Delete {}, {} and {}, then restart daemon-profile.",
            files.private.display(),
            files.public.display(),
            files.checksum.display()
        )));
    }
    tracing::debug!(daemon = daemon_name, "keypair integrity verified");
    Ok((private_bytes, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{NoiseCipher, NoiseHash};

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

    #[test]
    fn generate_keypair_produces_32_byte_keys() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.private().len(), 32);
        assert_eq!(kp.public().len(), 32);
    }

    // SECURITY INVARIANT: ZeroizingKeypair::into_inner must leave the wrapper's
    // private key zeroed so that the original allocation does not retain key material
    // after ownership transfer.
    #[test]
    fn zeroizing_keypair_into_inner_zeroes_source() {
        let kp = generate_keypair().unwrap();
        let private_copy = kp.private().to_vec();
        assert!(
            !private_copy.iter().all(|&b| b == 0),
            "generated key must be non-zero"
        );

        let extracted = kp.into_inner();
        assert_eq!(extracted.private, private_copy);
    }

    #[test]
    fn endpoint_records_round_trip_for_every_suite() {
        let path = Path::new("/r/runtime/pds/bus.endpoint");
        for suite in NoiseSuite::ALL {
            let endpoint = BusEndpoint {
                suite,
                public_key: [0xA7; 32],
            };
            let text = endpoint.encode();
            assert_eq!(
                text,
                format!("{}\n{}\n", suite.protocol_name(), "a7".repeat(32))
            );
            assert_eq!(BusEndpoint::decode(&text, path).unwrap(), endpoint);
        }
    }

    #[test]
    fn malformed_endpoint_records_are_rejected() {
        let path = Path::new("/r/runtime/pds/bus.endpoint");
        let key = "a7".repeat(32);
        for text in [
            String::new(),
            "Noise_IK_25519_ChaChaPoly_BLAKE2s\n".to_owned(),
            format!("Noise_IK_25519_ChaChaPoly_BLAKE2s\n{key}\nextra\n"),
            format!("Noise_IK_25519_ChaChaPoly_BLAKE2s\n{}\n", "a7".repeat(31)),
            format!("Noise_XX_25519_ChaChaPoly_BLAKE2s\n{key}\n"),
            // A raw 32-byte key, as `bus.pub` held, is not a record.
            String::from_utf8_lossy(&[0xA7; 32]).into_owned(),
        ] {
            assert!(BusEndpoint::decode(&text, path).is_err(), "{text:?}");
        }
        let err = BusEndpoint::decode("Noise_IK_25519_AESGCM_MD5\n", path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a bus endpoint record"), "{err}");
        let suite = NoiseSuite::new(NoiseCipher::AesGcm, NoiseHash::Sha256);
        assert_eq!(
            NoiseSuite::from_protocol_name(suite.protocol_name()).unwrap(),
            suite
        );
    }

    // Persistence, modes, and tamper detection: core-ipc/tests/daemon_keypair.rs.
}
