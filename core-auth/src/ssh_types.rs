//! SSH enrollment blob types and serialization.
//!
//! Defines the binary format for SSH-agent enrollment blobs that store
//! an AES-256-GCM wrapped master key alongside the SSH key fingerprint
//! and type metadata.

use crate::AuthError;

/// Version of the enrollment blob format.
pub const ENROLLMENT_VERSION: u8 = 0x01;

/// Expected ciphertext length: 32-byte master key + 16-byte GCM tag.
const CIPHERTEXT_LEN: usize = 48;

/// Longest key fingerprint a blob holds. SHA-256 fingerprints are about
/// 50 bytes; the bound keeps a malformed blob from driving an allocation.
const MAX_FINGERPRINT_LEN: usize = 256;

/// Supported SSH key types for vault unlock.
///
/// Only key types that produce deterministic signatures are supported,
/// because the KEK is derived from the raw signature bytes — a different
/// signature on each unlock would produce a different KEK and fail to
/// unwrap the enrollment blob.
///
/// - **Ed25519**: deterministic by specification (RFC 8032).
/// - **RSA (PKCS#1 v1.5)**: deterministic — the padding scheme uses no
///   randomness. Sign requests for RSA keys always ask for `rsa-sha2-512`
///   (`agent::SSH_AGENT_RSA_SHA2_512`).
///
/// Excluded:
/// - **ECDSA**: non-deterministic — uses a random `k` value per signature.
/// - **RSA-PSS**: non-deterministic — uses a random salt per signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyType {
    Ed25519,
    Rsa,
}

impl SshKeyType {
    /// Parse from the SSH wire format key type string.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::UnsupportedKeyType` for key types with
    /// non-deterministic signatures (ECDSA, RSA-PSS) or unrecognized
    /// type strings.
    pub fn from_wire_name(name: &str) -> Result<Self, AuthError> {
        match name {
            "ssh-ed25519" => Ok(Self::Ed25519),
            "ssh-rsa" => Ok(Self::Rsa),
            other => Err(AuthError::UnsupportedKeyType(other.to_string())),
        }
    }

    /// Convert from `ssh_key::Algorithm`, accepting only deterministic types.
    ///
    /// Only Ed25519 (RFC 8032, deterministic) and RSA PKCS#1 v1.5
    /// (deterministic padding) are accepted. ECDSA (random k) and
    /// RSA-PSS (random salt) are rejected because their non-deterministic
    /// signatures would produce different KEKs on each unlock attempt.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::UnsupportedKeyType` for non-deterministic key types.
    pub fn from_algorithm(algo: &ssh_key::Algorithm) -> Result<Self, AuthError> {
        match algo {
            ssh_key::Algorithm::Ed25519 => Ok(Self::Ed25519),
            ssh_key::Algorithm::Rsa { .. } => Ok(Self::Rsa),
            other => Err(AuthError::UnsupportedKeyType(format!("{other:?}"))),
        }
    }

    /// SSH wire format key type string.
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::Rsa => "ssh-rsa",
        }
    }
}

/// Parsed enrollment blob.
///
/// Binary format:
/// ```text
/// Version byte (1 byte): 0x01
/// Key fingerprint length (2 bytes, BE): N
/// Key fingerprint (N bytes): SHA256:... (ASCII)
/// Key type length (1 byte): M
/// Key type (M bytes): "ssh-ed25519" or "ssh-rsa" (ASCII)
/// Nonce (12 bytes): random
/// Ciphertext + GCM tag (48 bytes): AES-256-GCM(kek, master_key)
/// ```
pub struct EnrollmentBlob {
    pub version: u8,
    pub key_fingerprint: String,
    pub key_type: SshKeyType,
    pub nonce: [u8; 12],
    /// 32 bytes master key + 16 bytes GCM tag = 48 bytes.
    pub ciphertext: Vec<u8>,
}

impl EnrollmentBlob {
    /// Serialize to the binary wire format.
    ///
    /// # Errors
    ///
    /// `AuthError::InvalidBlob` when the fingerprint exceeds
    /// `MAX_FINGERPRINT_LEN` bytes: [`Self::deserialize`] would reject it.
    pub fn serialize(&self) -> Result<Vec<u8>, AuthError> {
        let fp_bytes = self.key_fingerprint.as_bytes();
        let kt_bytes = self.key_type.wire_name().as_bytes();
        if fp_bytes.len() > MAX_FINGERPRINT_LEN {
            return Err(AuthError::InvalidBlob(format!(
                "fingerprint length {} exceeds maximum of {MAX_FINGERPRINT_LEN} bytes",
                fp_bytes.len()
            )));
        }
        let fp_len = u16::try_from(fp_bytes.len()).map_err(|_| {
            AuthError::InvalidBlob(format!("fingerprint length {} exceeds u16", fp_bytes.len()))
        })?;
        let kt_len = u8::try_from(kt_bytes.len()).map_err(|_| {
            AuthError::InvalidBlob(format!("key type length {} exceeds u8", kt_bytes.len()))
        })?;

        let mut buf = Vec::with_capacity(
            1 + 2 + fp_bytes.len() + 1 + kt_bytes.len() + 12 + self.ciphertext.len(),
        );
        buf.push(self.version);
        buf.extend_from_slice(&fp_len.to_be_bytes());
        buf.extend_from_slice(fp_bytes);
        buf.push(kt_len);
        buf.extend_from_slice(kt_bytes);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        Ok(buf)
    }

    /// Deserialize from the binary wire format.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidBlob` if the data is truncated, has an
    /// unsupported version, or contains an invalid key type.
    pub fn deserialize(data: &[u8]) -> Result<Self, AuthError> {
        if data.is_empty() {
            return Err(AuthError::InvalidBlob("empty data".into()));
        }

        let version = data[0];
        if version != ENROLLMENT_VERSION {
            return Err(AuthError::InvalidBlob(format!(
                "unsupported version {version:#04x}, expected {ENROLLMENT_VERSION:#04x}"
            )));
        }

        if data.len() < 4 {
            return Err(AuthError::InvalidBlob(
                "truncated: missing fingerprint length".into(),
            ));
        }

        let fp_len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if fp_len > MAX_FINGERPRINT_LEN {
            return Err(AuthError::InvalidBlob(format!(
                "fingerprint length {fp_len} exceeds maximum of {MAX_FINGERPRINT_LEN} bytes"
            )));
        }
        let fp_end = 3 + fp_len;
        if data.len() < fp_end + 1 {
            return Err(AuthError::InvalidBlob("truncated: fingerprint data".into()));
        }

        let key_fingerprint = std::str::from_utf8(&data[3..fp_end])
            .map_err(|e| AuthError::InvalidBlob(format!("invalid fingerprint UTF-8: {e}")))?
            .to_string();

        let kt_len = data[fp_end] as usize;
        let kt_start = fp_end + 1;
        let kt_end = kt_start + kt_len;
        if data.len() < kt_end + 12 + CIPHERTEXT_LEN {
            return Err(AuthError::InvalidBlob(
                "truncated: key type or crypto data".into(),
            ));
        }

        let kt_str = std::str::from_utf8(&data[kt_start..kt_end])
            .map_err(|e| AuthError::InvalidBlob(format!("invalid key type UTF-8: {e}")))?;
        let key_type = SshKeyType::from_wire_name(kt_str)?;

        let nonce_start = kt_end;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[nonce_start..nonce_start + 12]);

        let ct_start = nonce_start + 12;
        let ct_end = ct_start + CIPHERTEXT_LEN;
        if data.len() < ct_end {
            return Err(AuthError::InvalidBlob("truncated: ciphertext".into()));
        }

        let ciphertext = data[ct_start..ct_end].to_vec();

        Ok(Self {
            version,
            key_fingerprint,
            key_type,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_blob() -> EnrollmentBlob {
        EnrollmentBlob {
            version: ENROLLMENT_VERSION,
            key_fingerprint: "SHA256:abcdef1234567890".into(),
            key_type: SshKeyType::Ed25519,
            nonce: [0xAA; 12],
            ciphertext: vec![0xBB; CIPHERTEXT_LEN],
        }
    }

    #[test]
    fn oversized_fingerprint_is_not_serialized() {
        let mut blob = test_blob();
        blob.key_fingerprint = "A".repeat(MAX_FINGERPRINT_LEN + 1);
        assert!(matches!(blob.serialize(), Err(AuthError::InvalidBlob(_))));
        blob.key_fingerprint = "A".repeat(MAX_FINGERPRINT_LEN);
        let data = blob.serialize().unwrap();
        assert_eq!(
            EnrollmentBlob::deserialize(&data)
                .unwrap()
                .key_fingerprint
                .len(),
            MAX_FINGERPRINT_LEN
        );
    }

    #[test]
    fn round_trip_ed25519() {
        let blob = test_blob();
        let data = blob.serialize().unwrap();
        let parsed = EnrollmentBlob::deserialize(&data).unwrap();

        assert_eq!(parsed.version, ENROLLMENT_VERSION);
        assert_eq!(parsed.key_fingerprint, "SHA256:abcdef1234567890");
        assert_eq!(parsed.key_type, SshKeyType::Ed25519);
        assert_eq!(parsed.nonce, [0xAA; 12]);
        assert_eq!(parsed.ciphertext.len(), CIPHERTEXT_LEN);
    }

    #[test]
    fn round_trip_rsa() {
        let blob = EnrollmentBlob {
            version: ENROLLMENT_VERSION,
            key_fingerprint: "SHA256:rsafingerprint".into(),
            key_type: SshKeyType::Rsa,
            nonce: [0x11; 12],
            ciphertext: vec![0x22; CIPHERTEXT_LEN],
        };
        let data = blob.serialize().unwrap();
        let parsed = EnrollmentBlob::deserialize(&data).unwrap();
        assert_eq!(parsed.key_type, SshKeyType::Rsa);
        assert_eq!(parsed.key_fingerprint, "SHA256:rsafingerprint");
    }

    #[test]
    fn rejects_invalid_version() {
        let mut data = test_blob().serialize().unwrap();
        data[0] = 0xFF;
        let result = EnrollmentBlob::deserialize(&data);
        assert!(matches!(result, Err(AuthError::InvalidBlob(_))));
    }

    #[test]
    fn rejects_truncated_data() {
        let data = test_blob().serialize().unwrap();
        let result = EnrollmentBlob::deserialize(&data[..5]);
        assert!(matches!(result, Err(AuthError::InvalidBlob(_))));
    }

    #[test]
    fn rejects_empty_data() {
        let result = EnrollmentBlob::deserialize(&[]);
        assert!(matches!(result, Err(AuthError::InvalidBlob(_))));
    }

    #[test]
    fn ed25519_wire_name() {
        assert_eq!(SshKeyType::Ed25519.wire_name(), "ssh-ed25519");
    }

    #[test]
    fn rsa_wire_name() {
        assert_eq!(SshKeyType::Rsa.wire_name(), "ssh-rsa");
    }

    #[test]
    fn from_wire_name_ed25519() {
        assert_eq!(
            SshKeyType::from_wire_name("ssh-ed25519").unwrap(),
            SshKeyType::Ed25519
        );
    }

    #[test]
    fn from_wire_name_rsa() {
        assert_eq!(
            SshKeyType::from_wire_name("ssh-rsa").unwrap(),
            SshKeyType::Rsa
        );
    }

    #[test]
    fn from_wire_name_rejects_ecdsa() {
        assert!(matches!(
            SshKeyType::from_wire_name("ecdsa-sha2-nistp256"),
            Err(AuthError::UnsupportedKeyType(_))
        ));
    }

    #[test]
    fn rejects_oversized_fingerprint() {
        // Craft a blob with fingerprint length > 256
        let mut data = vec![ENROLLMENT_VERSION];
        let big_len: u16 = 300;
        data.extend_from_slice(&big_len.to_be_bytes());
        data.extend_from_slice(&vec![b'A'; 300]);
        // Pad enough for the rest of the blob
        data.extend_from_slice(&[0u8; 100]);
        let result = EnrollmentBlob::deserialize(&data);
        assert!(
            matches!(result, Err(AuthError::InvalidBlob(msg)) if msg.contains("exceeds maximum"))
        );
    }
}
