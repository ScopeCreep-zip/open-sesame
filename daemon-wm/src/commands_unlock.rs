//! Inline vault unlock: the factors a vault still requires, provided one
//! by one, and profile activation after unlock.
//!
//! daemon-secrets reports the factors a vault still requires
//! (`VaultAuthQuery`) and applies the vault's auth policy to each factor
//! submitted (`FactorSubmit`). For each required factor the overlay looks
//! up its backend (`core_auth::AuthDispatcher::backend`) and acts on what
//! the backend requires: a factor without interaction is submitted at once,
//! the password is asked for in the overlay.
//!
//! The platform keyring factor has no backend here: the credential store
//! is on the session D-Bus bus, which this daemon's sandbox does not grant.
//! daemon-launcher reads and submits it (`KeyringUnlockRequest`).

use crate::commands::Runtime;
use crate::controller::{Event, UnlockStatus};
use core_auth::{AuthInteraction, FactorProgress, VaultAuthBackend as _};
use core_types::{AuthFactorId, EventKind, ProfileId, SecurityLevel, TrustProfileName};

/// How long daemon-secrets may take to verify a submitted factor (vault
/// open with the derived key).
const FACTOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long daemon-secrets may take to report a vault's requirements.
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long daemon-launcher may take to submit the platform keyring factor:
/// the keyring's own unlock prompt may wait for the user, then
/// daemon-secrets verifies the factor ([`FACTOR_TIMEOUT`]).
const KEYRING_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

/// How long daemon-profile may take to activate an unlocked profile.
const ACTIVATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The progress shown while the factors without interaction are submitted.
fn authenticating(profile: &TrustProfileName) -> String {
    format!("Authenticating \u{201C}{profile}\u{201D}\u{2026}")
}

/// The progress shown while the password factor is verified.
fn verifying(profile: &TrustProfileName) -> String {
    format!("Verifying \u{201C}{profile}\u{201D}\u{2026}")
}

/// What follows the password factor's `progress`: the status to report, or
/// `None` when the vault's policy requires further factors, which are
/// resolved next.
fn after_password(progress: FactorProgress) -> Option<UnlockStatus> {
    match progress {
        FactorProgress::Unlocked | FactorProgress::AlreadyUnlocked => Some(UnlockStatus::Unlocked),
        FactorProgress::MoreRequired => None,
        FactorProgress::Rejected { reason } => Some(UnlockStatus::NeedsPassword {
            error: Some(match reason {
                Some(reason) => format!("Rejected: {reason}"),
                None => "Rejected by the secrets daemon".into(),
            }),
        }),
    }
}

/// The status of a vault whose remaining factors require `interaction`
/// from the overlay after every factor without interaction was submitted.
fn interactive_status(
    profile: &TrustProfileName,
    factor: AuthFactorId,
    interaction: AuthInteraction,
) -> UnlockStatus {
    match interaction {
        AuthInteraction::PasswordEntry => UnlockStatus::NeedsPassword { error: None },
        AuthInteraction::HardwareTouch => UnlockStatus::Failed {
            message: format!(
                "Vault \u{201C}{profile}\u{201D} requires the {factor} factor (a hardware \
                 touch), which the overlay does not support"
            ),
        },
        AuthInteraction::None => UnlockStatus::Failed {
            message: format!("Vault \u{201C}{profile}\u{201D}: the {factor} factor is unavailable"),
        },
    }
}

impl Runtime {
    /// Submit every factor `profile`'s vault still requires that needs no
    /// interaction, showing progress, and feed where the unlock stands to
    /// the controller.
    ///
    /// # Errors
    ///
    /// The [`Runtime::execute`] errors of the commands the status produces.
    pub(crate) async fn resolve_unlock(&mut self, profile: TrustProfileName) -> anyhow::Result<()> {
        tracing::info!(audit = "unlock-flow", event_type = "unlock-resolve", %profile, "resolving vault unlock factors");
        self.show_unlock_progress(authenticating(&profile));
        let status = self.resolve(&profile).await;
        Box::pin(self.handle(Event::UnlockStatus { profile, status })).await
    }

    /// Unwrap `profile`'s master key with the password buffer, submit it,
    /// and feed where the unlock stands to the controller; a vault whose
    /// policy requires more factors is resolved further.
    ///
    /// # Errors
    ///
    /// The [`Runtime::execute`] errors of the commands the status produces.
    pub(crate) async fn submit_password_unlock(
        &mut self,
        profile: TrustProfileName,
    ) -> anyhow::Result<()> {
        tracing::info!(audit = "unlock-flow", event_type = "password-unlock-submit", %profile, "submitting password unlock for vault");
        // Feedback before the password KDF runs.
        self.show_unlock_progress(verifying(&profile));
        // The buffer moves into the backend (mlock'd, zeroized on drop);
        // the runtime keeps a fresh empty buffer.
        let password = std::mem::replace(
            &mut self.password_buffer,
            core_crypto::SecureVec::for_password(),
        );
        let status = match self.password_factor(password, &profile).await {
            Ok(None) => self.resolve(&profile).await,
            Ok(Some(status)) | Err(status) => status,
        };
        Box::pin(self.handle(Event::UnlockStatus { profile, status })).await
    }

    /// The keying `profile`'s factors derive under.
    fn keying(&self, profile: &TrustProfileName) -> Result<core_auth::VaultKeying, UnlockStatus> {
        core_auth::VaultMetadata::load_keying(&self.layout, profile)
            .map(|(_, keying)| keying)
            .map_err(|e| {
                tracing::error!(%profile, audit = "unlock-flow", error = %e, "vault keying unavailable");
                UnlockStatus::Failed {
                    message: format!("Vault \u{201C}{profile}\u{201D} is unreadable: {e}"),
                }
            })
    }

    /// The factors `profile`'s vault still requires, from daemon-secrets.
    async fn remaining_factors(
        &self,
        profile: &TrustProfileName,
    ) -> Result<Vec<AuthFactorId>, UnlockStatus> {
        let failed = |message: String| {
            tracing::error!(%profile, audit = "unlock-flow", %message, "vault requirements unavailable");
            UnlockStatus::Failed { message }
        };
        let reply = self
            .client
            .request(
                EventKind::VaultAuthQuery {
                    profile: profile.clone(),
                },
                SecurityLevel::Internal,
                QUERY_TIMEOUT,
            )
            .await
            .map_err(|e| {
                failed(format!(
                    "Vault \u{201C}{profile}\u{201D}: query failed: {e}"
                ))
            })?;
        core_auth::remaining_factors(reply.payload)
            .map_err(|e| failed(format!("Vault \u{201C}{profile}\u{201D}: {e}")))
    }

    /// Submit every factor `profile`'s vault still requires that needs no
    /// interaction: unlocked when one completes the unlock; otherwise the
    /// interaction the first remaining interactive factor requires. A
    /// factor without interaction that is unavailable or fails is logged
    /// and the next one is tried.
    async fn resolve(&self, profile: &TrustProfileName) -> UnlockStatus {
        let keying = match self.keying(profile) {
            Ok(keying) => keying,
            Err(status) => return status,
        };
        let remaining = match self.remaining_factors(profile).await {
            Ok(remaining) => remaining,
            Err(status) => return status,
        };
        let auth = core_auth::AuthDispatcher::new(None);
        let mut interactive = None;
        let mut unavailable = None;
        for factor in remaining {
            if factor == AuthFactorId::PlatformKeyring {
                match self.keyring_factor(profile).await {
                    Some(progress) if progress.is_unlocked() => return UnlockStatus::Unlocked,
                    Some(FactorProgress::MoreRequired) => {}
                    Some(progress) => {
                        tracing::warn!(%profile, %factor, audit = "unlock-flow", ?progress, "factor rejected by daemon-secrets");
                        unavailable.get_or_insert(factor);
                    }
                    None => {
                        unavailable.get_or_insert(factor);
                    }
                }
                continue;
            }
            let Some(backend) = auth.backend(factor) else {
                return UnlockStatus::Failed {
                    message: format!(
                        "Vault \u{201C}{profile}\u{201D} requires the {factor} factor, which \
                         the overlay cannot provide"
                    ),
                };
            };
            let interaction = backend.requires_interaction();
            if interaction != AuthInteraction::None {
                interactive.get_or_insert((factor, interaction));
                continue;
            }
            match backend.can_unlock(profile, &self.layout).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!(%profile, %factor, audit = "unlock-flow", "factor unavailable (not enrolled, or its agent cannot answer)");
                    unavailable.get_or_insert(factor);
                    continue;
                }
                Err(e) => {
                    tracing::error!(%profile, %factor, audit = "unlock-flow", error = %e, "factor enrollment unreadable");
                    return UnlockStatus::Failed {
                        message: format!(
                            "Vault \u{201C}{profile}\u{201D}: {factor} enrollment unreadable: {e}"
                        ),
                    };
                }
            }
            let outcome = match backend.unlock(profile, &self.layout, &keying).await {
                Ok(outcome) => outcome,
                Err(e) => {
                    tracing::warn!(%profile, %factor, audit = "unlock-flow", error = %e, "factor unlock failed");
                    unavailable.get_or_insert(factor);
                    continue;
                }
            };
            match self.submit_factor(outcome, profile).await {
                Ok(progress) if progress.is_unlocked() => return UnlockStatus::Unlocked,
                Ok(FactorProgress::MoreRequired) => {}
                Ok(progress) => {
                    tracing::warn!(%profile, %factor, audit = "unlock-flow", ?progress, "factor rejected by daemon-secrets");
                    unavailable.get_or_insert(factor);
                }
                Err(status) => return status,
            }
        }
        match (interactive, unavailable) {
            (Some((factor, interaction)), _) => interactive_status(profile, factor, interaction),
            (None, Some(factor)) => interactive_status(profile, factor, AuthInteraction::None),
            (None, None) => UnlockStatus::Failed {
                message: format!(
                    "Vault \u{201C}{profile}\u{201D} requires no factor yet is locked"
                ),
            },
        }
    }

    /// Have daemon-launcher read and submit `profile`'s platform keyring
    /// factor: daemon-secrets' answer, or `None` when the factor could not
    /// be submitted (no credential store, the keyring locked or its prompt
    /// dismissed, no KEK, or daemon-launcher unreachable), which the unlock
    /// loop treats as an unavailable factor.
    async fn keyring_factor(&self, profile: &TrustProfileName) -> Option<FactorProgress> {
        let request = EventKind::KeyringUnlockRequest {
            profile: profile.clone(),
        };
        let reply = match self
            .client
            .request(request, SecurityLevel::Internal, KEYRING_TIMEOUT)
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                tracing::warn!(%profile, audit = "unlock-flow", error = %e, "keyring unlock request to daemon-launcher failed");
                return None;
            }
        };
        if let EventKind::KeyringUnlockFailed { reason, .. } = &reply.payload {
            tracing::info!(%profile, audit = "unlock-flow", %reason, "platform keyring factor unavailable");
            return None;
        }
        match FactorProgress::from_response(reply.payload) {
            Ok(progress) => {
                tracing::info!(%profile, audit = "unlock-flow", ?progress, "platform keyring factor submitted by daemon-launcher");
                Some(progress)
            }
            Err(e) => {
                tracing::error!(%profile, audit = "unlock-flow", error = %e, "unexpected answer to the keyring unlock request");
                None
            }
        }
    }

    /// Submit `outcome` as a factor of `profile`'s vault.
    async fn submit_factor(
        &self,
        outcome: core_auth::UnlockOutcome,
        profile: &TrustProfileName,
    ) -> Result<FactorProgress, UnlockStatus> {
        let factor = outcome.factor_id;
        let failed = |message: String| {
            tracing::error!(%profile, %factor, audit = "unlock-flow", %message, "factor submission failed");
            UnlockStatus::Failed { message }
        };
        let reply = self
            .client
            .request(
                outcome.into_factor_submit(profile),
                SecurityLevel::Internal,
                FACTOR_TIMEOUT,
            )
            .await
            .map_err(|e| {
                failed(format!(
                    "Vault \u{201C}{profile}\u{201D}: submission failed: {e}"
                ))
            })?;
        let progress = FactorProgress::from_response(reply.payload)
            .map_err(|e| failed(format!("Vault \u{201C}{profile}\u{201D}: {e}")))?;
        tracing::info!(%profile, %factor, audit = "unlock-flow", ?progress, "factor submitted");
        Ok(progress)
    }

    /// Unwrap and submit the password factor: the status it settles, or
    /// `None` when the vault requires further factors.
    async fn password_factor(
        &self,
        password: core_crypto::SecureVec,
        profile: &TrustProfileName,
    ) -> Result<Option<UnlockStatus>, UnlockStatus> {
        if password.is_empty() {
            return Ok(Some(UnlockStatus::NeedsPassword {
                error: Some("Enter the password".into()),
            }));
        }
        let keying = self.keying(profile)?;
        let backend = core_auth::PasswordBackend::new().with_password(password);
        let outcome = match backend.unlock(profile, &self.layout, &keying).await {
            Ok(outcome) => outcome,
            Err(core_auth::AuthError::UnwrapFailed) => {
                tracing::info!(%profile, audit = "unlock-flow", "wrong password");
                return Ok(Some(UnlockStatus::NeedsPassword {
                    error: Some("Wrong password".into()),
                }));
            }
            Err(e) => {
                tracing::error!(%profile, audit = "unlock-flow", error = %e, "password unlock failed");
                return Err(UnlockStatus::Failed {
                    message: format!(
                        "Vault \u{201C}{profile}\u{201D}: password unlock failed: {e}"
                    ),
                });
            }
        };
        Ok(after_password(self.submit_factor(outcome, profile).await?))
    }

    /// Ask daemon-profile to activate each of `profiles` after unlock.
    pub(crate) async fn activate_profiles(&self, profiles: &[TrustProfileName]) {
        for profile_name in profiles {
            tracing::info!(audit = "unlock-flow", event_type = "profile-activate", %profile_name, "activating profile after vault unlock");
            let request = EventKind::ProfileActivate {
                target: ProfileId::new(),
                profile_name: profile_name.clone(),
            };
            match self
                .client
                .request(request, SecurityLevel::Internal, ACTIVATE_TIMEOUT)
                .await
            {
                Ok(msg) => match msg.payload {
                    EventKind::ProfileActivateResponse { success: true } => {
                        tracing::info!(audit = "unlock-flow", event_type = "profile-activated", %profile_name, "profile activated successfully");
                    }
                    EventKind::ProfileActivateResponse { success: false } => {
                        tracing::error!(audit = "unlock-flow", event_type = "profile-activate-failed", %profile_name, "profile activation rejected by daemon-profile");
                    }
                    other => {
                        tracing::warn!(?other, %profile_name, "unexpected response to ProfileActivate");
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, %profile_name, "profile activation IPC failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work() -> TrustProfileName {
        TrustProfileName::try_from("work").unwrap()
    }

    #[test]
    fn an_accepted_password_of_a_multi_factor_vault_continues_to_the_next_factor() {
        assert_eq!(after_password(FactorProgress::MoreRequired), None);
        assert_eq!(
            after_password(FactorProgress::Unlocked),
            Some(UnlockStatus::Unlocked)
        );
        assert_eq!(
            after_password(FactorProgress::AlreadyUnlocked),
            Some(UnlockStatus::Unlocked)
        );
    }

    #[test]
    fn a_rejected_password_factor_shows_the_reason() {
        assert_eq!(
            after_password(FactorProgress::Rejected {
                reason: Some("partial unlock expired".into())
            }),
            Some(UnlockStatus::NeedsPassword {
                error: Some("Rejected: partial unlock expired".into())
            })
        );
    }

    #[test]
    fn each_interaction_maps_to_what_the_overlay_does() {
        assert_eq!(
            interactive_status(
                &work(),
                AuthFactorId::Password,
                AuthInteraction::PasswordEntry
            ),
            UnlockStatus::NeedsPassword { error: None }
        );
        assert!(matches!(
            interactive_status(&work(), AuthFactorId::Fido2, AuthInteraction::HardwareTouch),
            UnlockStatus::Failed { message } if message.contains("fido2")
        ));
        assert!(matches!(
            interactive_status(&work(), AuthFactorId::SshAgent, AuthInteraction::None),
            UnlockStatus::Failed { message } if message.contains("unavailable")
        ));
    }
}
