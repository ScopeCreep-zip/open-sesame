//! SSH-agent authentication backend.
//!
//! Connects to the user's SSH agent via `$SSH_AUTH_SOCK`, signs a
//! deterministic BLAKE3 challenge with the enrolled key, derives a KEK
//! from the signature, and unwraps the AES-256-GCM wrapped master key
//! from the enrollment blob.

use crate::AuthError;
use crate::backend::{AuthInteraction, IpcUnlockStrategy, UnlockOutcome, VaultAuthBackend};
use crate::ssh_types::{EnrollmentBlob, SshKeyType};
use core_crypto::SecureBytes;
use core_types::TrustProfileName;
use ssh_agent_client_rs::Identity;
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroize;

/// Get the fingerprint string for an identity.
fn identity_fingerprint(id: &Identity<'_>) -> String {
    match id {
        Identity::PublicKey(cow) => cow.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        Identity::Certificate(cow) => cow
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
    }
}

/// Get the algorithm for an identity.
fn identity_algorithm(id: &Identity<'_>) -> ssh_key::Algorithm {
    match id {
        Identity::PublicKey(cow) => cow.algorithm(),
        Identity::Certificate(cow) => cow.algorithm(),
    }
}

/// Connect to the SSH agent, trying multiple socket paths.
///
/// Resolution order:
/// 1. `$SSH_AUTH_SOCK` (may be a symlink to a forwarded agent socket)
/// 2. `~/.ssh/agent.sock` — stable symlink path created by the Konductor
///    profile.d propagation script for forwarded SSH agent sessions
///
/// Returns `None` if no connectable agent socket is found.
/// Intentionally synchronous — local Unix socket connect is sub-millisecond.
fn connect_agent() -> Option<ssh_agent_client_rs::Client> {
    // Primary: $SSH_AUTH_SOCK (set by ssh-agent, sshd forwarding, or systemd env)
    if let Some(sock_path) = std::env::var_os("SSH_AUTH_SOCK") {
        let path = std::path::Path::new(&sock_path);
        if let Ok(client) = ssh_agent_client_rs::Client::connect(path) {
            return Some(client);
        }
    }

    // Fallback: well-known stable symlink managed by profile.d hook.
    // On Konductor VMs, /etc/profile.d/konductor-ssh-agent.sh creates
    // ~/.ssh/agent.sock -> /tmp/ssh-XXXX/agent.PID on each SSH login,
    // giving systemd user services a stable path to the forwarded agent.
    if let Some(home) = std::env::var_os("HOME") {
        let fallback = std::path::Path::new(&home).join(".ssh/agent.sock");
        if let Ok(client) = ssh_agent_client_rs::Client::connect(&fallback) {
            return Some(client);
        }
    }

    None
}

/// SSH-agent backed vault authentication.
///
/// Connects to `$SSH_AUTH_SOCK`, signs a BLAKE3-derived challenge with
/// the enrolled key, derives a KEK from the deterministic signature,
/// and unwraps the master key from the enrollment blob.
pub struct SshAgentBackend;

impl SshAgentBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Path to the enrollment blob for a profile.
    fn enrollment_path(config_dir: &Path, profile: &TrustProfileName) -> std::path::PathBuf {
        config_dir
            .join("vaults")
            .join(format!("{profile}.ssh-enrollment"))
    }
}

impl Default for SshAgentBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl VaultAuthBackend for SshAgentBackend {
    fn name(&self) -> &str {
        "SSH Agent"
    }

    fn backend_id(&self) -> &str {
        "ssh-agent"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, config_dir: &Path) -> bool {
        Self::enrollment_path(config_dir, profile).exists()
    }

    async fn can_unlock(&self, profile: &TrustProfileName, config_dir: &Path) -> bool {
        if !self.is_enrolled(profile, config_dir) {
            return false;
        }

        let blob_path = Self::enrollment_path(config_dir, profile);
        let Ok(blob_data) = std::fs::read(&blob_path) else {
            return false;
        };
        let Ok(blob) = EnrollmentBlob::deserialize(&blob_data) else {
            return false;
        };

        let fingerprint = blob.key_fingerprint.clone();
        tokio::task::spawn_blocking(move || {
            let Some(mut agent) = connect_agent() else {
                return false;
            };
            let Ok(identities) = agent.list_all_identities() else {
                return false;
            };
            identities
                .iter()
                .any(|id| identity_fingerprint(id) == fingerprint)
        })
        .await
        .unwrap_or(false)
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::None
    }

    async fn unlock(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
        salt: &[u8],
    ) -> Result<UnlockOutcome, AuthError> {
        // 1. Read enrollment blob
        let blob_path = Self::enrollment_path(config_dir, profile);
        let blob_data =
            std::fs::read(&blob_path).map_err(|_| AuthError::NotEnrolled(profile.to_string()))?;
        let blob = EnrollmentBlob::deserialize(&blob_data)?;

        // 2. Derive challenge
        let profile_str = profile.to_string();
        let challenge_ctx = format!("pds v2 ssh-challenge {profile_str}");
        let challenge_bytes: [u8; 32] = blake3::derive_key(&challenge_ctx, salt);

        // 3. Connect to agent, find enrolled key, sign challenge.
        //    ssh-agent-client-rs is synchronous (Unix socket I/O), so all
        //    agent calls run inside spawn_blocking to avoid blocking the
        //    tokio runtime.
        let fingerprint = blob.key_fingerprint.clone();
        let challenge = challenge_bytes.to_vec();
        let sign_result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, AuthError> {
            let mut agent = connect_agent().ok_or_else(|| {
                AuthError::AgentUnavailable("SSH_AUTH_SOCK not set or agent not running".into())
            })?;

            let identities = agent.list_all_identities().map_err(|e| {
                AuthError::AgentProtocolError(format!("failed to list identities: {e}"))
            })?;

            let identity = identities
                .into_iter()
                .find(|id| identity_fingerprint(id) == fingerprint)
                .ok_or(AuthError::NoEligibleKey)?;

            let signature = agent
                .sign(identity, &challenge)
                .map_err(|e| AuthError::AgentProtocolError(format!("sign request failed: {e}")))?;

            // Immediately copy the signature bytes so the Vec is the only
            // unprotected holder; zeroized promptly after KEK derivation below.
            Ok(signature.as_bytes().to_vec())
        })
        .await
        .map_err(|e| AuthError::AgentUnavailable(format!("spawn_blocking failed: {e}")))??;

        // 4. Derive KEK from signature, then zeroize the raw signature bytes
        //    immediately. The signature is the sole input to KEK derivation —
        //    minimizing its lifetime reduces the exposure window.
        let kek_ctx = format!("pds v2 ssh-vault-kek {profile_str}");
        let mut kek_bytes: [u8; 32] = blake3::derive_key(&kek_ctx, &sign_result);
        let mut sig_bytes = sign_result;
        sig_bytes.zeroize();

        // 5. Unwrap master key
        let encryption_key = core_crypto::EncryptionKey::from_bytes(&kek_bytes)
            .map_err(|_| AuthError::UnwrapFailed)?;
        kek_bytes.zeroize();

        let master_key_bytes = encryption_key
            .decrypt(&blob.nonce, &blob.ciphertext)
            .map_err(|_| AuthError::UnwrapFailed)?;

        // 6. Build outcome
        let mut audit_metadata = BTreeMap::new();
        audit_metadata.insert("backend".into(), "ssh-agent".into());
        audit_metadata.insert("ssh_fingerprint".into(), blob.key_fingerprint.clone());
        audit_metadata.insert("key_type".into(), blob.key_type.wire_name().into());

        Ok(UnlockOutcome {
            master_key: master_key_bytes,
            audit_metadata,
            ipc_strategy: IpcUnlockStrategy::DirectMasterKey,
        })
    }

    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        config_dir: &Path,
        salt: &[u8],
        selected_key_index: Option<usize>,
    ) -> Result<(), AuthError> {
        // 1. Connect to agent, list eligible keys, sign challenge
        let profile_str = profile.to_string();
        let challenge_ctx = format!("pds v2 ssh-challenge {profile_str}");
        let challenge: [u8; 32] = blake3::derive_key(&challenge_ctx, salt);
        let challenge_vec = challenge.to_vec();

        // ssh-agent-client-rs is synchronous (Unix socket I/O), so all agent
        // calls run inside spawn_blocking to avoid blocking the tokio runtime.
        let (fingerprint, key_type, sig_bytes) = tokio::task::spawn_blocking(
            move || -> Result<(String, SshKeyType, Vec<u8>), AuthError> {
                let mut agent = connect_agent().ok_or_else(|| {
                    AuthError::AgentUnavailable("SSH_AUTH_SOCK not set or agent not running".into())
                })?;

                let identities = agent
                    .list_all_identities()
                    .map_err(|e| AuthError::AgentProtocolError(format!("list identities: {e}")))?;

                let eligible: Vec<_> = identities
                    .into_iter()
                    .filter(|id| SshKeyType::from_algorithm(&identity_algorithm(id)).is_ok())
                    .collect();

                if eligible.is_empty() {
                    return Err(AuthError::NoEligibleKey);
                }

                // Caller MUST provide an explicit key index. Silent default
                // selection is never acceptable — the user must declare which
                // key to use.
                let idx = selected_key_index.ok_or_else(|| {
                    AuthError::NoEligibleKey
                })?;
                if idx >= eligible.len() {
                    return Err(AuthError::NoEligibleKey);
                }
                let identity = eligible.into_iter().nth(idx).unwrap();
                let fp = identity_fingerprint(&identity);
                let algo = identity_algorithm(&identity);
                let kt = SshKeyType::from_algorithm(&algo)?;

                let sig = agent
                    .sign(identity, &challenge_vec)
                    .map_err(|e| AuthError::AgentProtocolError(format!("sign: {e}")))?;

                // Use a zeroizing container to minimize the window where raw
                // signature bytes (KEK input) sit unprotected in memory.
                let mut sig_vec = sig.as_bytes().to_vec();
                let result = (fp, kt, sig_vec.clone());
                sig_vec.zeroize();
                Ok(result)
            },
        )
        .await
        .map_err(|e| AuthError::AgentUnavailable(format!("spawn_blocking: {e}")))??;

        // 2. Derive KEK from signature
        let kek_ctx = format!("pds v2 ssh-vault-kek {profile_str}");
        let mut kek_bytes: [u8; 32] = blake3::derive_key(&kek_ctx, &sig_bytes);
        let mut sig_copy = sig_bytes;
        sig_copy.zeroize();

        // 3. Wrap master key
        let encryption_key = core_crypto::EncryptionKey::from_bytes(&kek_bytes)
            .map_err(|_| AuthError::UnwrapFailed)?;
        kek_bytes.zeroize();

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| AuthError::Io(std::io::Error::other(e)))?;

        let ciphertext = encryption_key
            .encrypt(&nonce_bytes, master_key.as_bytes())
            .map_err(|_| AuthError::UnwrapFailed)?;

        // 4. Write enrollment blob atomically
        let blob = EnrollmentBlob {
            version: crate::ENROLLMENT_VERSION,
            key_fingerprint: fingerprint.clone(),
            key_type,
            nonce: nonce_bytes,
            ciphertext,
        };

        let blob_path = Self::enrollment_path(config_dir, profile);
        let vaults_dir = config_dir.join("vaults");
        std::fs::create_dir_all(&vaults_dir)?;

        let tmp_path = blob_path.with_extension("ssh-enrollment.tmp");
        std::fs::write(&tmp_path, blob.serialize())?;

        // Set restrictive permissions (owner-only) before rename. The blob
        // contains an AES-256-GCM encrypted master key; do not rely on umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&tmp_path, &blob_path)?;

        tracing::info!(
            profile = %profile,
            fingerprint = %fingerprint,
            key_type = %key_type.wire_name(),
            "SSH enrollment created"
        );

        Ok(())
    }

    async fn revoke(&self, profile: &TrustProfileName, config_dir: &Path) -> Result<(), AuthError> {
        let path = Self::enrollment_path(config_dir, profile);
        if path.exists() {
            // Extract fingerprint for audit logging before deletion
            let fingerprint = std::fs::read(&path)
                .ok()
                .and_then(|data| EnrollmentBlob::deserialize(&data).ok())
                .map_or_else(|| "<unreadable>".into(), |blob| blob.key_fingerprint);

            // Overwrite with zeros before deletion to prevent casual recovery
            #[allow(clippy::cast_possible_truncation)]
            let file_len = std::fs::metadata(&path)
                .map(|m| m.len() as usize)
                .unwrap_or(256);
            let zeros = vec![0u8; file_len];
            let _ = std::fs::write(&path, &zeros);
            std::fs::remove_file(&path)?;

            tracing::info!(
                profile = %profile,
                fingerprint = %fingerprint,
                "SSH enrollment revoked"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> TrustProfileName {
        TrustProfileName::try_from("test-profile").unwrap()
    }

    #[test]
    fn is_enrolled_checks_file() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();

        assert!(!backend.is_enrolled(&profile, dir.path()));

        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        std::fs::write(vaults.join("test-profile.ssh-enrollment"), b"blob").unwrap();

        assert!(backend.is_enrolled(&profile, dir.path()));
    }

    #[tokio::test]
    async fn can_unlock_false_when_not_enrolled() {
        let backend = SshAgentBackend::new();
        let profile = test_profile();
        assert!(
            !backend
                .can_unlock(&profile, std::path::Path::new("/tmp"))
                .await
        );
    }

    #[tokio::test]
    async fn unlock_fails_no_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();
        let result = backend.unlock(&profile, dir.path(), &[0; 16]).await;
        assert!(matches!(result, Err(AuthError::NotEnrolled(_))));
    }

    #[tokio::test]
    async fn unlock_fails_invalid_blob() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();

        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        std::fs::write(vaults.join("test-profile.ssh-enrollment"), b"corrupt").unwrap();

        let result = backend.unlock(&profile, dir.path(), &[0; 16]).await;
        assert!(matches!(result, Err(AuthError::InvalidBlob(_))));
    }

    #[tokio::test]
    async fn revoke_removes_blob() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();

        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        let blob_path = vaults.join("test-profile.ssh-enrollment");
        std::fs::write(&blob_path, b"blob").unwrap();
        assert!(blob_path.exists());

        backend.revoke(&profile, dir.path()).await.unwrap();
        assert!(!blob_path.exists());
    }

    #[tokio::test]
    async fn revoke_noop_when_no_blob() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();
        backend.revoke(&profile, dir.path()).await.unwrap();
    }

    #[test]
    fn requires_no_interaction() {
        let backend = SshAgentBackend::new();
        assert_eq!(backend.requires_interaction(), AuthInteraction::None);
    }

    #[test]
    fn backend_id_is_ssh_agent() {
        let backend = SshAgentBackend::new();
        assert_eq!(backend.backend_id(), "ssh-agent");
    }

    /// Verify `connect_agent` handles nonexistent socket paths gracefully.
    /// We cannot mutate env vars (crate forbids unsafe), so this exercises
    /// the connect path with a known-bad socket via direct `Client::connect`.
    #[test]
    fn connect_to_nonexistent_socket_returns_error() {
        let bad_path = std::path::Path::new("/tmp/nonexistent-ssh-agent-test.sock");
        let result = ssh_agent_client_rs::Client::connect(bad_path);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_is_deterministic() {
        let salt = [0xAA; 16];
        let ctx = "pds v2 ssh-challenge test-profile";
        let c1: [u8; 32] = blake3::derive_key(ctx, &salt);
        let c2: [u8; 32] = blake3::derive_key(ctx, &salt);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_profiles_produce_different_challenges() {
        let salt = [0xAA; 16];
        let c1: [u8; 32] = blake3::derive_key("pds v2 ssh-challenge profile-a", &salt);
        let c2: [u8; 32] = blake3::derive_key("pds v2 ssh-challenge profile-b", &salt);
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_salts_produce_different_challenges() {
        let c1: [u8; 32] = blake3::derive_key("pds v2 ssh-challenge test", &[0xAA; 16]);
        let c2: [u8; 32] = blake3::derive_key("pds v2 ssh-challenge test", &[0xBB; 16]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn kek_derivation_is_deterministic() {
        let sig = [0x42u8; 64];
        let ctx = "pds v2 ssh-vault-kek test-profile";
        let k1: [u8; 32] = blake3::derive_key(ctx, &sig);
        let k2: [u8; 32] = blake3::derive_key(ctx, &sig);
        assert_eq!(k1, k2);
    }

    #[test]
    fn enrollment_blob_crypto_round_trip() {
        let master_key_data = vec![0x42u8; 32];

        // Simulate enrollment: derive KEK, wrap master key
        let sig_bytes = [0xDE; 64]; // simulated signature
        let kek: [u8; 32] = blake3::derive_key("pds v2 ssh-vault-kek test", &sig_bytes);
        let enc_key = core_crypto::EncryptionKey::from_bytes(&kek).unwrap();
        let nonce = [0x11u8; 12];
        let ciphertext = enc_key.encrypt(&nonce, &master_key_data).unwrap();

        let blob = EnrollmentBlob {
            version: crate::ENROLLMENT_VERSION,
            key_fingerprint: "SHA256:test".into(),
            key_type: SshKeyType::Ed25519,
            nonce,
            ciphertext: ciphertext.clone(),
        };

        // Serialize and deserialize
        let data = blob.serialize();
        let parsed = EnrollmentBlob::deserialize(&data).unwrap();

        // Simulate unlock: same KEK, unwrap
        let kek2: [u8; 32] = blake3::derive_key("pds v2 ssh-vault-kek test", &sig_bytes);
        let enc_key2 = core_crypto::EncryptionKey::from_bytes(&kek2).unwrap();
        let unwrapped = enc_key2.decrypt(&parsed.nonce, &parsed.ciphertext).unwrap();

        assert_eq!(unwrapped.as_bytes(), &master_key_data);
    }

    #[test]
    fn tampered_blob_fails_unwrap() {
        let master_key_data = vec![0x42u8; 32];
        let sig_bytes = [0xDE; 64];
        let kek: [u8; 32] = blake3::derive_key("pds v2 ssh-vault-kek test", &sig_bytes);
        let enc_key = core_crypto::EncryptionKey::from_bytes(&kek).unwrap();
        let nonce = [0x11u8; 12];
        let mut ciphertext = enc_key.encrypt(&nonce, &master_key_data).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0x01;

        let result = enc_key.decrypt(&nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let master_key_data = vec![0x42u8; 32];
        let sig_bytes = [0xDE; 64];
        let kek: [u8; 32] = blake3::derive_key("pds v2 ssh-vault-kek test", &sig_bytes);
        let enc_key = core_crypto::EncryptionKey::from_bytes(&kek).unwrap();
        let nonce = [0x11u8; 12];
        let ciphertext = enc_key.encrypt(&nonce, &master_key_data).unwrap();

        // Use wrong KEK (different signature)
        let wrong_sig = [0xAB; 64];
        let wrong_kek: [u8; 32] = blake3::derive_key("pds v2 ssh-vault-kek test", &wrong_sig);
        let wrong_enc_key = core_crypto::EncryptionKey::from_bytes(&wrong_kek).unwrap();
        let result = wrong_enc_key.decrypt(&nonce, &ciphertext);
        assert!(result.is_err());
    }

    /// Full enrollment + unlock cycle integration test (simulated agent).
    ///
    /// Exercises the complete crypto round-trip without a real SSH agent:
    /// generate challenge, derive KEK from simulated signature, wrap master
    /// key, write enrollment blob to disk, read it back, unwrap, and verify
    /// the recovered master key matches the original.
    #[test]
    fn full_enrollment_unlock_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();
        let salt = [0xBB; 16];
        let master_key_data = vec![0x42u8; 32];
        let simulated_sig = [0xAB; 64];

        // --- Enrollment phase ---

        // 1. Generate challenge (same as SshAgentBackend::enroll)
        let challenge_ctx = format!("pds v2 ssh-challenge {profile}");
        let challenge: [u8; 32] = blake3::derive_key(&challenge_ctx, &salt);

        // 2. Derive KEK from simulated signature
        let kek_ctx = format!("pds v2 ssh-vault-kek {profile}");
        let kek: [u8; 32] = blake3::derive_key(&kek_ctx, &simulated_sig);

        // 3. Wrap master key
        let enc_key = core_crypto::EncryptionKey::from_bytes(&kek).unwrap();
        let nonce = [0x33u8; 12];
        let ciphertext = enc_key.encrypt(&nonce, &master_key_data).unwrap();

        // 4. Build and write enrollment blob
        let blob = EnrollmentBlob {
            version: crate::ENROLLMENT_VERSION,
            key_fingerprint: "SHA256:test-round-trip".into(),
            key_type: SshKeyType::Ed25519,
            nonce,
            ciphertext,
        };
        let vaults_dir = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults_dir).unwrap();
        let blob_path = vaults_dir.join(format!("{profile}.ssh-enrollment"));
        std::fs::write(&blob_path, blob.serialize()).unwrap();

        // --- Unlock phase ---

        // 5. Read blob back from disk
        let blob_data = std::fs::read(&blob_path).unwrap();
        let parsed = EnrollmentBlob::deserialize(&blob_data).unwrap();
        assert_eq!(parsed.key_fingerprint, "SHA256:test-round-trip");
        assert_eq!(parsed.key_type, SshKeyType::Ed25519);

        // 6. Re-derive the same challenge (deterministic)
        let challenge2: [u8; 32] = blake3::derive_key(&challenge_ctx, &salt);
        assert_eq!(challenge, challenge2);

        // 7. Same signature -> same KEK -> successful unwrap
        let kek2: [u8; 32] = blake3::derive_key(&kek_ctx, &simulated_sig);
        assert_eq!(kek, kek2);
        let enc_key2 = core_crypto::EncryptionKey::from_bytes(&kek2).unwrap();
        let unwrapped = enc_key2.decrypt(&parsed.nonce, &parsed.ciphertext).unwrap();

        // 8. Verify recovered master key matches original
        assert_eq!(unwrapped.as_bytes(), &master_key_data);
    }
}
