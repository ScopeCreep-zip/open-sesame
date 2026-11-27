//! Core trait and types for pluggable authentication backends.

use crate::AuthError;
use crate::vault_meta::VaultKeying;
use core_crypto::{KeyContext, SecureBytes};
use core_layout::Layout;
use core_types::{AuthFactorId, HkdfAlgorithm, TrustProfileName};
use std::collections::BTreeMap;

/// What kind of user interaction a backend requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthInteraction {
    /// No interaction -- backend can unlock silently (an SSH agent holding a software key).
    None,
    /// Password/PIN entry required (keyboard input).
    PasswordEntry,
    /// Physical touch on hardware token required (FIDO2, PIV with touch policy).
    HardwareTouch,
}

/// Which piece of the unlock this backend is providing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorContribution {
    /// This backend provides a complete master key (unwrapped independently).
    /// Used in `Any` and `Policy` modes.
    CompleteMasterKey,
    /// This backend provides a factor piece for combined derivation.
    /// Used in `All` mode where the master key is HKDF'd from all pieces.
    FactorPiece,
}

/// The master key of an `All`-policy vault: the vault's `hkdf` derivation
/// (`KeyContext::CombinedMasterKey`) over every factor's piece,
/// concatenated in `AuthFactorId` order. Vault creation and unlock both
/// derive it here, so they cannot disagree.
#[must_use]
pub fn combine_factor_pieces(
    profile: &TrustProfileName,
    hkdf: HkdfAlgorithm,
    pieces: &[(AuthFactorId, &[u8])],
) -> SecureBytes {
    let mut ordered = pieces.to_vec();
    ordered.sort_by_key(|(id, _)| *id);
    let mut combined = zeroize::Zeroizing::new(Vec::new());
    for (_, piece) in &ordered {
        combined.extend_from_slice(piece);
    }
    core_crypto::derive_key(hkdf, &KeyContext::CombinedMasterKey(profile), &combined)
}

/// Result of a successful backend unlock: the master key the backend
/// unwrapped, which daemon-secrets receives as one factor of the vault's
/// auth policy.
pub struct UnlockOutcome {
    /// The unwrapped 32-byte master key.
    pub master_key: SecureBytes,
    /// Backend-specific metadata for audit logging.
    pub audit_metadata: BTreeMap<String, String>,
    /// Which factor this outcome represents.
    pub factor_id: AuthFactorId,
}

impl UnlockOutcome {
    /// The `FactorSubmit` request carrying this outcome to daemon-secrets
    /// for `profile`. The master key moves into the request's protected
    /// allocation without a heap copy.
    #[must_use]
    pub fn into_factor_submit(self, profile: &TrustProfileName) -> core_types::EventKind {
        let (alloc, len) = self.master_key.into_protected_alloc();
        core_types::EventKind::FactorSubmit {
            factor_id: self.factor_id,
            key_material: core_types::SensitiveBytes::from_protected(alloc, len),
            profile: profile.clone(),
            audit_metadata: self.audit_metadata,
        }
    }
}

/// A pluggable authentication backend for vault unlock.
#[async_trait::async_trait]
pub trait VaultAuthBackend: Send + Sync {
    /// Which auth factor this backend provides.
    fn factor_id(&self) -> AuthFactorId;

    /// Human-readable name for audit logs and overlay display.
    fn name(&self) -> &'static str;

    /// Short identifier for IPC messages and config.
    fn backend_id(&self) -> &'static str;

    /// Whether this backend has an enrollment for the profile.
    ///
    /// # Errors
    ///
    /// When the enrollment's presence cannot be determined.
    fn is_enrolled(&self, profile: &TrustProfileName, layout: &Layout) -> Result<bool, AuthError>;

    /// Whether this backend can currently perform an unlock: enrolled, and
    /// its external dependency (agent, entered password) is present. Must
    /// be fast (< 100ms).
    ///
    /// # Errors
    ///
    /// When the enrollment exists but cannot be read or parsed.
    async fn can_unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
    ) -> Result<bool, AuthError>;

    /// What kind of user interaction this backend requires.
    fn requires_interaction(&self) -> AuthInteraction;

    /// Unwrap the master key of `profile`'s vault, deriving the KEK under
    /// the vault's `keying`.
    ///
    /// # Errors
    ///
    /// The backend's enrollment, derivation, and unwrap errors.
    async fn unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
        keying: &VaultKeying,
    ) -> Result<UnlockOutcome, AuthError>;

    /// Enroll this backend for a profile: wrap `master_key` under a KEK
    /// derived with the vault's `keying`.
    ///
    /// `credential` names which of the backend's credentials to enroll
    /// (SSH agent: the key fingerprint, with or without `SHA256:`); a
    /// backend with one credential ignores it.
    ///
    /// # Errors
    ///
    /// The backend's credential, derivation, wrap, and write errors.
    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        layout: &Layout,
        keying: &VaultKeying,
        credential: Option<&str>,
    ) -> Result<(), AuthError>;

    /// Remove enrollment for this backend: the enrollment file is
    /// zero-filled and removed. Absent enrollment is not an error.
    async fn revoke(&self, profile: &TrustProfileName, layout: &Layout) -> Result<(), AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::profile;

    #[test]
    fn outcome_becomes_the_factor_submission() {
        let outcome = UnlockOutcome {
            master_key: SecureBytes::new(vec![5; 32]),
            audit_metadata: BTreeMap::from([("backend".into(), "ssh-agent".into())]),
            factor_id: AuthFactorId::SshAgent,
        };
        match outcome.into_factor_submit(&profile("work")) {
            core_types::EventKind::FactorSubmit {
                factor_id,
                key_material,
                profile: submitted,
                audit_metadata,
            } => {
                assert_eq!(factor_id, AuthFactorId::SshAgent);
                assert_eq!(key_material.as_bytes(), &[5; 32]);
                assert_eq!(submitted.as_ref(), "work");
                assert_eq!(audit_metadata["backend"], "ssh-agent");
            }
            other => panic!("expected FactorSubmit, got {other:?}"),
        }
    }

    #[test]
    fn combined_key_derives_the_pieces_in_factor_order() {
        let work = profile("work");
        let (password, ssh) = ([1u8; 32], [2u8; 32]);
        let mut ordered = password.to_vec();
        ordered.extend_from_slice(&ssh);
        for hkdf in [HkdfAlgorithm::Blake3, HkdfAlgorithm::HkdfSha256] {
            let combined = combine_factor_pieces(
                &work,
                hkdf,
                &[
                    (AuthFactorId::SshAgent, &ssh),
                    (AuthFactorId::Password, &password),
                ],
            );
            let expected =
                core_crypto::derive_key(hkdf, &KeyContext::CombinedMasterKey(&work), &ordered);
            assert_eq!(combined.as_bytes(), expected.as_bytes());
        }
    }

    #[test]
    fn combined_key_ignores_submission_order_and_is_profile_and_algorithm_scoped() {
        let (a, b) = ([7u8; 32], [9u8; 32]);
        let combine = |name: &str, hkdf, pieces: &[(AuthFactorId, &[u8])]| {
            combine_factor_pieces(&profile(name), hkdf, pieces)
        };
        let forward = combine(
            "work",
            HkdfAlgorithm::Blake3,
            &[(AuthFactorId::Password, &a), (AuthFactorId::SshAgent, &b)],
        );
        let reverse = combine(
            "work",
            HkdfAlgorithm::Blake3,
            &[(AuthFactorId::SshAgent, &b), (AuthFactorId::Password, &a)],
        );
        assert_eq!(forward.as_bytes(), reverse.as_bytes());
        let other_profile = combine(
            "home",
            HkdfAlgorithm::Blake3,
            &[(AuthFactorId::Password, &a), (AuthFactorId::SshAgent, &b)],
        );
        assert_ne!(forward.as_bytes(), other_profile.as_bytes());
        let other_algorithm = combine(
            "work",
            HkdfAlgorithm::HkdfSha256,
            &[(AuthFactorId::Password, &a), (AuthFactorId::SshAgent, &b)],
        );
        assert_ne!(forward.as_bytes(), other_algorithm.as_bytes());
    }
}
