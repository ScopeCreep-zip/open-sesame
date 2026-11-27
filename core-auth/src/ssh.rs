//! SSH-agent authentication backend.
//!
//! Connects to the user's SSH agent (`Layout::ssh_agent_sockets`), signs
//! the vault's deterministic challenge with the enrolled key, derives a
//! KEK from the signature, and unwraps the AES-256-GCM wrapped master key
//! from the enrollment blob. Challenge and KEK derive under the vault's
//! `hkdf` (`KeyContext::SshChallenge`, `KeyContext::SshVaultKek`).

use crate::AuthError;
use crate::agent::Agent;
use crate::backend::{AuthInteraction, UnlockOutcome, VaultAuthBackend};
use crate::ssh_types::{EnrollmentBlob, SshKeyType};
use crate::vault_meta::VaultKeying;
use core_crypto::{EncryptionKey, KeyContext, SecureBytes};
use core_layout::{Layout, VaultFile};
use core_types::AuthFactorId;
use core_types::TrustProfileName;
use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Whether two SHA-256 key fingerprints name the same key; the `SHA256:`
/// prefix (as `ssh-add -l` prints it) is optional on either side.
#[must_use]
pub fn same_fingerprint(a: &str, b: &str) -> bool {
    let bare = |fp: &str| fp.strip_prefix("SHA256:").unwrap_or(fp).to_owned();
    bare(a) == bare(b)
}

/// An SSH agent key that can be enrolled: its signatures are
/// deterministic (`SshKeyType`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKey {
    /// `SHA256:` fingerprint.
    pub fingerprint: String,
    pub key_type: SshKeyType,
    /// The agent's comment for the key (often the key file); may be empty.
    pub comment: String,
}

impl AgentKey {
    /// `fingerprint (comment)`, or the fingerprint alone without a comment.
    #[must_use]
    pub fn label(&self) -> String {
        if self.comment.is_empty() {
            self.fingerprint.clone()
        } else {
            format!("{} ({})", self.fingerprint, self.comment)
        }
    }
}

/// The enrollable keys of the first reachable agent among
/// `Layout::ssh_agent_sockets`, in agent order.
///
/// # Errors
///
/// `AuthError::AgentUnavailable` when no agent is reachable, and
/// `AuthError::AgentProtocolError` when the agent fails to list its keys.
pub async fn eligible_agent_keys(layout: &Layout) -> Result<Vec<AgentKey>, AuthError> {
    let candidates = layout.ssh_agent_sockets();
    tokio::task::spawn_blocking(move || {
        let identities = connect_agent(&candidates)?.identities()?;
        Ok(identities
            .iter()
            .filter_map(|id| {
                SshKeyType::from_algorithm(&id.algorithm())
                    .ok()
                    .map(|key_type| AgentKey {
                        fingerprint: id.fingerprint(),
                        key_type,
                        comment: id.comment().to_owned(),
                    })
            })
            .collect())
    })
    .await
    .map_err(|e| AuthError::AgentUnavailable(format!("agent query task failed: {e}")))?
}

/// Connect to the first reachable agent among `candidates`
/// (`Layout::ssh_agent_sockets`, in discovery order).
///
/// Intentionally synchronous — local Unix socket connect is sub-millisecond;
/// callers run it inside `spawn_blocking`.
///
/// # Errors
///
/// `AuthError::AgentUnavailable` naming every candidate and why it could
/// not be reached, or that no candidate input is set.
fn connect_agent(candidates: &[PathBuf]) -> Result<Agent<UnixStream>, AuthError> {
    if candidates.is_empty() {
        return Err(AuthError::AgentUnavailable(
            "neither $SSH_AUTH_SOCK nor $HOME is set".into(),
        ));
    }
    let mut failures = Vec::with_capacity(candidates.len());
    for path in candidates {
        match Agent::connect(path) {
            Ok(client) => return Ok(client),
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }
    Err(AuthError::AgentUnavailable(failures.join("; ")))
}

/// The challenge the agent signs for `profile`'s vault.
fn challenge(keying: &VaultKeying, profile: &TrustProfileName) -> SecureBytes {
    core_crypto::derive_key(
        keying.algorithms.hkdf,
        &KeyContext::SshChallenge(profile),
        &keying.salt,
    )
}

/// The enrollment KEK of `profile`'s vault, from the challenge signature.
fn kek(keying: &VaultKeying, profile: &TrustProfileName, signature: &[u8]) -> EncryptionKey {
    core_crypto::derive_encryption_key(
        keying.algorithms.hkdf,
        &KeyContext::SshVaultKek(profile),
        signature,
    )
}

/// The agent key that signed, and the KEK derived from its signature.
struct SignedKek {
    fingerprint: String,
    key_type: SshKeyType,
    kek: EncryptionKey,
}

/// Sign `profile`'s challenge with the agent key `fingerprint` names
/// (`SHA256:` optional) and derive the enrollment KEK from the signature.
/// The agent client is synchronous (Unix socket I/O), so the session runs
/// inside `spawn_blocking`; the signature is zeroized once the KEK exists.
async fn agent_kek(
    layout: &Layout,
    profile: &TrustProfileName,
    keying: &VaultKeying,
    fingerprint: &str,
) -> Result<SignedKek, AuthError> {
    let candidates = layout.ssh_agent_sockets();
    let (profile, keying, wanted) = (profile.clone(), *keying, fingerprint.to_owned());
    tokio::task::spawn_blocking(move || {
        let mut agent = connect_agent(&candidates)?;
        let identity = agent
            .identities()?
            .into_iter()
            .find(|id| same_fingerprint(&id.fingerprint(), &wanted))
            .ok_or(AuthError::KeyNotInAgent(wanted))?;
        let key_type = SshKeyType::from_algorithm(&identity.algorithm())?;
        let signature =
            Zeroizing::new(agent.sign(&identity, challenge(&keying, &profile).as_bytes())?);
        Ok(SignedKek {
            fingerprint: identity.fingerprint(),
            key_type,
            kek: kek(&keying, &profile, &signature),
        })
    })
    .await
    .map_err(|e| AuthError::AgentUnavailable(format!("agent signing task failed: {e}")))?
}

/// SSH-agent backed vault authentication.
///
/// Connects to the user's SSH agent, signs a BLAKE3-derived challenge with
/// the enrolled key, derives a KEK from the deterministic signature,
/// and unwraps the master key from the enrollment blob.
pub struct SshAgentBackend;

impl SshAgentBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Path to the enrollment blob for a profile.
    fn enrollment_path(layout: &Layout, profile: &TrustProfileName) -> Result<PathBuf, AuthError> {
        Ok(layout.vault_file(profile, VaultFile::SshEnrollment)?)
    }

    /// The enrollment blob, or `None` when the profile has no enrollment.
    ///
    /// # Errors
    ///
    /// The layout errors, an unreadable enrollment file, and
    /// `AuthError::InvalidBlob` for one that does not parse, each naming
    /// the file.
    pub fn read_enrollment(
        layout: &Layout,
        profile: &TrustProfileName,
    ) -> Result<Option<EnrollmentBlob>, AuthError> {
        let path = Self::enrollment_path(layout, profile)?;
        match std::fs::read(&path) {
            Ok(data) => EnrollmentBlob::deserialize(&data)
                .map(Some)
                .map_err(|e| e.in_file(&path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AuthError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read SSH enrollment {}: {e}", path.display()),
            ))),
        }
    }
}

impl Default for SshAgentBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl VaultAuthBackend for SshAgentBackend {
    fn factor_id(&self) -> AuthFactorId {
        AuthFactorId::SshAgent
    }

    fn name(&self) -> &'static str {
        "SSH Agent"
    }

    fn backend_id(&self) -> &'static str {
        "ssh-agent"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, layout: &Layout) -> Result<bool, AuthError> {
        Ok(core_layout::file::exists(&Self::enrollment_path(
            layout, profile,
        )?)?)
    }

    async fn can_unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
    ) -> Result<bool, AuthError> {
        let Some(blob) = Self::read_enrollment(layout, profile)? else {
            return Ok(false);
        };
        let fingerprint = blob.key_fingerprint.clone();
        let candidates = layout.ssh_agent_sockets();
        tokio::task::spawn_blocking(move || {
            // An unreachable agent: this factor cannot unlock now. An agent
            // that answers and fails the protocol: an error.
            let Ok(mut agent) = connect_agent(&candidates) else {
                return Ok(false);
            };
            Ok(agent
                .identities()?
                .iter()
                .any(|id| id.fingerprint() == fingerprint))
        })
        .await
        .map_err(|e| AuthError::AgentUnavailable(format!("agent query task failed: {e}")))?
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::None
    }

    async fn unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
        keying: &VaultKeying,
    ) -> Result<UnlockOutcome, AuthError> {
        let blob = Self::read_enrollment(layout, profile)?
            .ok_or_else(|| AuthError::NotEnrolled(profile.to_string()))?;
        let signed = agent_kek(layout, profile, keying, &blob.key_fingerprint).await?;
        let master_key = signed
            .kek
            .decrypt(&blob.nonce, &blob.ciphertext)
            .map_err(|_| AuthError::UnwrapFailed)?;
        Ok(UnlockOutcome {
            master_key,
            audit_metadata: BTreeMap::from([
                ("backend".into(), "ssh-agent".into()),
                ("ssh_fingerprint".into(), blob.key_fingerprint.clone()),
                ("key_type".into(), blob.key_type.wire_name().into()),
            ]),
            factor_id: AuthFactorId::SshAgent,
        })
    }

    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        layout: &Layout,
        keying: &VaultKeying,
        credential: Option<&str>,
    ) -> Result<(), AuthError> {
        let wanted = credential.ok_or_else(|| {
            AuthError::BackendNotApplicable(
                "SSH enrollment requires the key fingerprint to enroll".into(),
            )
        })?;
        let SignedKek {
            fingerprint,
            key_type,
            kek,
        } = agent_kek(layout, profile, keying, wanted).await?;
        let (nonce, ciphertext) = kek.seal(master_key.as_bytes())?;
        let blob = EnrollmentBlob {
            version: crate::ENROLLMENT_VERSION,
            key_fingerprint: fingerprint.clone(),
            key_type,
            nonce,
            ciphertext,
        };

        // The blob holds the AES-256-GCM wrapped master key: owner-only.
        core_layout::file::write(
            &Self::enrollment_path(layout, profile)?,
            &blob.serialize()?,
            core_layout::file::Mode::OwnerOnly,
        )?;

        tracing::info!(
            profile = %profile,
            fingerprint = %fingerprint,
            key_type = %key_type.wire_name(),
            "SSH enrollment created"
        );

        Ok(())
    }

    async fn revoke(&self, profile: &TrustProfileName, layout: &Layout) -> Result<(), AuthError> {
        // The fingerprint is for the revocation log only; an unreadable
        // enrollment is revoked and logged as such.
        let fingerprint = match Self::read_enrollment(layout, profile) {
            Ok(Some(blob)) => blob.key_fingerprint,
            Ok(None) => return Ok(()),
            Err(e) => {
                tracing::warn!(profile = %profile, error = %e, "revoking an unreadable SSH enrollment");
                "<unreadable>".into()
            }
        };
        if core_layout::file::destroy(&Self::enrollment_path(layout, profile)?)? {
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
    use crate::test_support::{layout, profile, test_profile};
    use core_types::{HkdfAlgorithm, KdfAlgorithm};

    fn keying(salt: u8, hkdf: HkdfAlgorithm) -> VaultKeying {
        crate::test_support::keying(salt, KdfAlgorithm::Argon2id, hkdf)
    }

    /// Write `contents` as the test profile's enrollment blob.
    fn write_enrollment(layout: &Layout, contents: &[u8]) -> PathBuf {
        let path = SshAgentBackend::enrollment_path(layout, &test_profile()).unwrap();
        core_layout::file::write(&path, contents, core_layout::file::Mode::OwnerOnly).unwrap();
        path
    }

    #[test]
    fn is_enrolled_checks_file() {
        let (_root, layout) = layout();
        let backend = SshAgentBackend::new();
        let profile = test_profile();

        assert!(!backend.is_enrolled(&profile, &layout).unwrap());
        write_enrollment(&layout, b"blob");
        assert!(backend.is_enrolled(&profile, &layout).unwrap());
    }

    #[tokio::test]
    async fn can_unlock_false_when_not_enrolled() {
        let (_root, layout) = layout();
        let backend = SshAgentBackend::new();
        assert!(!backend.can_unlock(&test_profile(), &layout).await.unwrap());
    }

    #[tokio::test]
    async fn can_unlock_reports_a_damaged_enrollment() {
        let (_root, layout) = layout();
        write_enrollment(&layout, b"corrupt");
        let result = SshAgentBackend::new()
            .can_unlock(&test_profile(), &layout)
            .await;
        assert!(
            matches!(result, Err(AuthError::InvalidBlob(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn unlock_fails_no_enrollment() {
        let (_root, layout) = layout();
        let result = SshAgentBackend::new()
            .unlock(&test_profile(), &layout, &keying(0, HkdfAlgorithm::Blake3))
            .await;
        assert!(matches!(result, Err(AuthError::NotEnrolled(_))));
    }

    #[tokio::test]
    async fn unlock_fails_invalid_blob() {
        let (_root, layout) = layout();
        let path = write_enrollment(&layout, b"corrupt");
        let result = SshAgentBackend::new()
            .unlock(&test_profile(), &layout, &keying(0, HkdfAlgorithm::Blake3))
            .await;
        assert!(
            matches!(&result, Err(AuthError::InvalidBlob(m)) if m.contains(&path.display().to_string())),
            "{:?}",
            result.err()
        );
    }

    #[test]
    fn unreachable_agents_are_named() {
        let (root, layout) = layout();
        let candidates = layout.ssh_agent_sockets();
        let Err(AuthError::AgentUnavailable(message)) = connect_agent(&candidates) else {
            panic!("expected AgentUnavailable");
        };
        for candidate in &candidates {
            assert!(
                message.contains(&candidate.display().to_string()),
                "{message}"
            );
        }
        drop(root);
        assert!(matches!(
            connect_agent(&[]),
            Err(AuthError::AgentUnavailable(m)) if m.contains("$SSH_AUTH_SOCK")
        ));
    }

    #[tokio::test]
    async fn revoke_removes_blob() {
        let (_root, layout) = layout();
        let blob_path = write_enrollment(&layout, b"blob");
        SshAgentBackend::new()
            .revoke(&test_profile(), &layout)
            .await
            .unwrap();
        assert!(!blob_path.exists());
    }

    #[tokio::test]
    async fn revoke_noop_when_no_blob() {
        let (_root, layout) = layout();
        SshAgentBackend::new()
            .revoke(&test_profile(), &layout)
            .await
            .unwrap();
    }

    #[test]
    fn fingerprints_match_with_or_without_prefix() {
        assert!(same_fingerprint("SHA256:abc", "abc"));
        assert!(same_fingerprint("abc", "SHA256:abc"));
        assert!(same_fingerprint("SHA256:abc", "SHA256:abc"));
        assert!(!same_fingerprint("SHA256:abc", "SHA256:abd"));
    }

    #[tokio::test]
    async fn enroll_requires_a_fingerprint() {
        let (_root, layout) = layout();
        let result = SshAgentBackend::new()
            .enroll(
                &test_profile(),
                &SecureBytes::new(vec![0; 32]),
                &layout,
                &keying(0, HkdfAlgorithm::Blake3),
                None,
            )
            .await;
        assert!(
            matches!(result, Err(AuthError::BackendNotApplicable(_))),
            "{result:?}"
        );
    }

    #[test]
    fn agent_key_label_includes_comment() {
        let key = AgentKey {
            fingerprint: "SHA256:abc".into(),
            key_type: SshKeyType::Ed25519,
            comment: String::new(),
        };
        assert_eq!(key.label(), "SHA256:abc");
        let commented = AgentKey {
            comment: "user@host".into(),
            ..key
        };
        assert_eq!(commented.label(), "SHA256:abc (user@host)");
    }

    #[test]
    fn identifies_as_the_non_interactive_agent_factor() {
        let backend = SshAgentBackend::new();
        assert_eq!(backend.requires_interaction(), AuthInteraction::None);
        assert_eq!(backend.backend_id(), "ssh-agent");
    }

    #[test]
    fn challenges_are_scoped_to_profile_salt_and_algorithm() {
        let (work, home) = (test_profile(), profile("home"));
        let base = challenge(&keying(0xAA, HkdfAlgorithm::Blake3), &work);
        assert_eq!(
            base.as_bytes(),
            challenge(&keying(0xAA, HkdfAlgorithm::Blake3), &work).as_bytes()
        );
        for other in [
            challenge(&keying(0xAA, HkdfAlgorithm::Blake3), &home),
            challenge(&keying(0xBB, HkdfAlgorithm::Blake3), &work),
            challenge(&keying(0xAA, HkdfAlgorithm::HkdfSha256), &work),
        ] {
            assert_ne!(base.as_bytes(), other.as_bytes());
        }
    }

    /// An enrollment wrapped under the KEK of one signature: written to
    /// disk, read back, and unwrapped by the KEK the same signature
    /// derives under the vault's algorithm, and by no other.
    #[test]
    fn enrollments_unwrap_only_under_the_same_signature_and_algorithm() {
        let (_root, layout) = layout();
        let profile = test_profile();
        let master_key = SecureBytes::from_slice(&[0x42; 32]);
        for hkdf in [HkdfAlgorithm::Blake3, HkdfAlgorithm::HkdfSha256] {
            let vault = keying(0xBB, hkdf);
            let (nonce, ciphertext) = kek(&vault, &profile, &[0xAB; 64])
                .seal(master_key.as_bytes())
                .unwrap();
            let blob = EnrollmentBlob {
                version: crate::ENROLLMENT_VERSION,
                key_fingerprint: "SHA256:test-round-trip".into(),
                key_type: SshKeyType::Ed25519,
                nonce,
                ciphertext,
            };
            write_enrollment(&layout, &blob.serialize().unwrap());
            let parsed = SshAgentBackend::read_enrollment(&layout, &profile)
                .unwrap()
                .unwrap();

            let unwrapped = kek(&vault, &profile, &[0xAB; 64])
                .decrypt(&parsed.nonce, &parsed.ciphertext)
                .unwrap();
            assert_eq!(unwrapped.as_bytes(), master_key.as_bytes());
            assert!(
                kek(&vault, &profile, &[0xAC; 64])
                    .decrypt(&parsed.nonce, &parsed.ciphertext)
                    .is_err()
            );
            let other = keying(
                0xBB,
                match hkdf {
                    HkdfAlgorithm::Blake3 => HkdfAlgorithm::HkdfSha256,
                    HkdfAlgorithm::HkdfSha256 => HkdfAlgorithm::Blake3,
                },
            );
            assert!(
                kek(&other, &profile, &[0xAB; 64])
                    .decrypt(&parsed.nonce, &parsed.ciphertext)
                    .is_err()
            );
        }
    }
}
