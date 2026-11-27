//! What daemon-secrets answers about an unlock: the progress after one
//! submitted factor, and the factors a vault still requires. Every client
//! that unlocks a vault (the CLI, the overlay) reads the answers here.

use core_types::{AuthFactorId, EventKind, UnlockRejectedReason};

/// Where an unlock stands after one `FactorSubmit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactorProgress {
    /// The factor completed the unlock.
    Unlocked,
    /// The vault was already unlocked; the factor was not needed.
    AlreadyUnlocked,
    /// The factor was accepted; the vault's policy requires more factors.
    MoreRequired,
    /// daemon-secrets refused the factor; `reason` when it gave one.
    Rejected { reason: Option<String> },
}

/// A daemon-secrets answer that carries no unlock progress.
#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    /// daemon-secrets could not read the vault's requirements.
    #[error("vault requirements unavailable: {0}")]
    Requirements(String),
    /// The answer is not a response to the request (its redacted form).
    #[error("unexpected response: {0}")]
    Unexpected(String),
}

impl ResponseError {
    fn unexpected(response: &EventKind) -> Self {
        Self::Unexpected(format!("{response:?}"))
    }
}

impl FactorProgress {
    /// The progress `response` to a `FactorSubmit` reports.
    ///
    /// # Errors
    ///
    /// `ResponseError::Unexpected` for any answer other than a
    /// `FactorResponse` or an already-unlocked `UnlockRejected`.
    pub fn from_response(response: EventKind) -> Result<Self, ResponseError> {
        match response {
            EventKind::FactorResponse {
                accepted: true,
                unlock_complete: true,
                ..
            } => Ok(Self::Unlocked),
            EventKind::FactorResponse {
                accepted: true,
                unlock_complete: false,
                ..
            } => Ok(Self::MoreRequired),
            EventKind::FactorResponse {
                accepted: false,
                error,
                ..
            } => Ok(Self::Rejected { reason: error }),
            EventKind::UnlockRejected {
                reason: UnlockRejectedReason::AlreadyUnlocked,
                ..
            } => Ok(Self::AlreadyUnlocked),
            other => Err(ResponseError::unexpected(&other)),
        }
    }

    /// Whether the vault is unlocked after this factor.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked | Self::AlreadyUnlocked)
    }
}

/// The factors a vault still requires, in enrollment order, from the
/// `VaultAuthQueryResponse` `response`: its enrolled factors less those a
/// partial unlock has received.
///
/// # Errors
///
/// `ResponseError::Requirements` when daemon-secrets could not read the
/// vault's metadata; `ResponseError::Unexpected` for any other answer.
pub fn remaining_factors(response: EventKind) -> Result<Vec<AuthFactorId>, ResponseError> {
    match response {
        EventKind::VaultAuthQueryResponse {
            error: Some(error), ..
        } => Err(ResponseError::Requirements(error)),
        EventKind::VaultAuthQueryResponse {
            enrolled_factors,
            partial_in_progress,
            received_factors,
            error: None,
            ..
        } => Ok(enrolled_factors
            .into_iter()
            .filter(|factor| !(partial_in_progress && received_factors.contains(factor)))
            .collect()),
        other => Err(ResponseError::unexpected(&other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::profile;
    use core_types::AuthCombineMode;

    fn factor_response(accepted: bool, unlock_complete: bool, error: Option<&str>) -> EventKind {
        EventKind::FactorResponse {
            accepted,
            unlock_complete,
            remaining_factors: vec![],
            remaining_additional: 0,
            profile: profile("work"),
            error: error.map(str::to_owned),
        }
    }

    fn query(partial: bool, received: Vec<AuthFactorId>, error: Option<&str>) -> EventKind {
        EventKind::VaultAuthQueryResponse {
            profile: profile("work"),
            enrolled_factors: vec![AuthFactorId::Password, AuthFactorId::SshAgent],
            auth_policy: AuthCombineMode::All,
            partial_in_progress: partial,
            received_factors: received,
            error: error.map(str::to_owned),
        }
    }

    #[test]
    fn factor_responses_map_to_their_progress() {
        let progress = |response| FactorProgress::from_response(response).unwrap();
        assert_eq!(
            progress(factor_response(true, true, None)),
            FactorProgress::Unlocked
        );
        assert_eq!(
            progress(factor_response(true, false, None)),
            FactorProgress::MoreRequired
        );
        assert_eq!(
            progress(factor_response(false, false, Some("expired"))),
            FactorProgress::Rejected {
                reason: Some("expired".into())
            }
        );
        let already = EventKind::UnlockRejected {
            reason: UnlockRejectedReason::AlreadyUnlocked,
            profile: Some(profile("work")),
        };
        assert_eq!(progress(already), FactorProgress::AlreadyUnlocked);
        assert!(FactorProgress::AlreadyUnlocked.is_unlocked());
        assert!(!FactorProgress::MoreRequired.is_unlocked());
    }

    #[test]
    fn an_answer_to_another_request_is_unexpected() {
        assert!(matches!(
            FactorProgress::from_response(EventKind::StatusRequest),
            Err(ResponseError::Unexpected(_))
        ));
        assert!(matches!(
            remaining_factors(EventKind::StatusRequest),
            Err(ResponseError::Unexpected(_))
        ));
    }

    #[test]
    fn remaining_factors_exclude_those_a_partial_unlock_received() {
        assert_eq!(
            remaining_factors(query(false, vec![], None)).unwrap(),
            [AuthFactorId::Password, AuthFactorId::SshAgent]
        );
        assert_eq!(
            remaining_factors(query(true, vec![AuthFactorId::Password], None)).unwrap(),
            [AuthFactorId::SshAgent]
        );
        assert!(matches!(
            remaining_factors(query(false, vec![], Some("unreadable"))),
            Err(ResponseError::Requirements(e)) if e == "unreadable"
        ));
    }
}
