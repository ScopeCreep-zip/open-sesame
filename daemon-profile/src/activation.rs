//! Profile activation and deactivation, and the confirmed RPC to
//! daemon-secrets they are made of.
//!
//! A transition changes one piece of state: whether daemon-secrets serves
//! the profile's vault. daemon-profile announces the transition, asks
//! daemon-secrets to apply it through a confirmed RPC (unicast, then wait
//! for the correlated response), and announces and audits the outcome.
//!
//! The RPC ends in one of three ways:
//! - confirmed: daemon-secrets applied the transition;
//! - rejected: daemon-secrets answered that it did not, and its state is
//!   unchanged;
//! - unconfirmed: no valid answer arrived (daemon-secrets not connected, a
//!   timeout, an answer of another kind), so daemon-secrets may or may not
//!   have applied it. The caller reconciles its shadow state with
//!   daemon-secrets' authoritative state; a compensating request could
//!   undo a transition that never happened.

use std::time::{Duration, Instant};

use anyhow::Context;
use core_ipc::Message;
use core_profile::AuditAction;
use core_types::{Daemon, EventKind, ProfileId, SecurityLevel, TrustProfileName};

use crate::dispatch::Hub;

/// How long a confirmed RPC waits for its response.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

/// Unicast attempts to daemon-secrets: after a restart it is unreachable
/// until it has completed its handshake and announced itself.
const SEND_ATTEMPTS: u32 = 5;

/// The delay before the second attempt, doubled before each later one.
const SEND_BACKOFF: Duration = Duration::from_millis(100);

/// A change of whether daemon-secrets serves a profile's vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition {
    Activate,
    Deactivate,
}

impl Transition {
    /// The request daemon-secrets applies.
    fn request(self, target: ProfileId, profile_name: &TrustProfileName) -> EventKind {
        let profile_name = profile_name.clone();
        match self {
            Self::Activate => EventKind::ProfileActivate {
                target,
                profile_name,
            },
            Self::Deactivate => EventKind::ProfileDeactivate {
                target,
                profile_name,
            },
        }
    }

    /// The announcement that the transition began.
    fn begun(self, target: ProfileId, profile_name: &TrustProfileName) -> EventKind {
        match self {
            Self::Activate => EventKind::ProfileActivationBegun {
                target,
                trigger: format!("explicit activation of {profile_name}"),
            },
            Self::Deactivate => EventKind::ProfileDeactivationBegun { target },
        }
    }

    /// Whether `response` answers this transition's request, and if so
    /// whether daemon-secrets applied it.
    fn applied(self, response: &EventKind) -> Option<bool> {
        match (self, response) {
            (Self::Activate, EventKind::ProfileActivateResponse { success })
            | (Self::Deactivate, EventKind::ProfileDeactivateResponse { success }) => {
                Some(*success)
            }
            _ => None,
        }
    }

    /// The announcement and audit entry of a completed transition.
    fn completed(self, target: ProfileId, duration_ms: u32) -> (EventKind, AuditAction) {
        match self {
            Self::Activate => (
                EventKind::ProfileActivated {
                    target,
                    duration_ms,
                },
                AuditAction::ProfileActivated {
                    target,
                    duration_ms,
                },
            ),
            Self::Deactivate => (
                EventKind::ProfileDeactivated {
                    target,
                    duration_ms,
                },
                AuditAction::ProfileDeactivated {
                    target,
                    duration_ms,
                },
            ),
        }
    }

    /// The announcement and audit entry of a failed transition.
    fn failed(self, target: ProfileId, reason: &str) -> (EventKind, AuditAction) {
        let reason = reason.to_owned();
        match self {
            Self::Activate => (
                EventKind::ProfileActivationFailed {
                    target,
                    reason: reason.clone(),
                },
                AuditAction::ProfileActivationFailed { target, reason },
            ),
            Self::Deactivate => (
                EventKind::ProfileDeactivationFailed {
                    target,
                    reason: reason.clone(),
                },
                AuditAction::ProfileDeactivationFailed { target, reason },
            ),
        }
    }
}

/// Why a transition did not complete.
#[derive(Debug)]
pub(crate) enum TransitionError {
    /// daemon-secrets answered that it did not apply the transition: its
    /// state is unchanged.
    Rejected,
    /// No valid answer arrived: daemon-secrets' state is unknown until
    /// reconciled.
    Unconfirmed(anyhow::Error),
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secrets = Daemon::Secrets;
        match self {
            Self::Rejected => write!(f, "{secrets} rejected the request"),
            Self::Unconfirmed(e) => write!(f, "{secrets} did not confirm the request: {e:#}"),
        }
    }
}

impl std::error::Error for TransitionError {}

/// `elapsed` in whole milliseconds, saturating at `u32::MAX` (the wire and
/// audit fields are `u32`; a transition is bounded by the RPC timeouts).
fn millis(elapsed: Duration) -> u32 {
    u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX)
}

impl Hub {
    /// Apply `transition` to `profile_name` (`target`) in daemon-secrets,
    /// announcing and auditing it: the elapsed milliseconds on success.
    ///
    /// # Errors
    ///
    /// [`TransitionError::Rejected`] when daemon-secrets refuses it, and
    /// [`TransitionError::Unconfirmed`] when no valid answer arrives. Both
    /// are announced and audited before they are returned.
    pub(crate) async fn transition(
        &mut self,
        transition: Transition,
        target: ProfileId,
        profile_name: &TrustProfileName,
    ) -> Result<u32, TransitionError> {
        let start = Instant::now();
        self.announce(transition.begun(target, profile_name)).await;
        let outcome = match self
            .confirmed_rpc(transition.request(target, profile_name))
            .await
        {
            Ok(response) => match transition.applied(&response.payload) {
                Some(true) => Ok(()),
                Some(false) => Err(TransitionError::Rejected),
                None => Err(TransitionError::Unconfirmed(anyhow::anyhow!(
                    "unexpected response {:?}",
                    response.payload
                ))),
            },
            Err(e) => Err(TransitionError::Unconfirmed(e)),
        };
        let duration_ms = millis(start.elapsed());
        let (event, action) = match &outcome {
            Ok(()) => transition.completed(target, duration_ms),
            Err(e) => transition.failed(target, &e.to_string()),
        };
        self.announce(event).await;
        self.record(&action);
        outcome.map(|()| duration_ms)
    }

    /// Send `event` to daemon-secrets and wait for its correlated response.
    ///
    /// A response to an earlier request whose wait ended is discarded.
    ///
    /// # Errors
    ///
    /// When the request cannot be encoded, daemon-secrets cannot be reached
    /// after [`SEND_ATTEMPTS`] attempts, no correlated response arrives
    /// within [`CONFIRM_TIMEOUT`], or the response cannot be decoded.
    pub(crate) async fn confirmed_rpc(
        &mut self,
        event: EventKind,
    ) -> anyhow::Result<Message<EventKind>> {
        let mut msg = Message::new(
            &self.ctx,
            event,
            SecurityLevel::SecretsOnly,
            self.bus.epoch(),
        );
        // Unicast past the server's routing, which stamps every other
        // frame with its sender's registry name.
        msg.verified_sender_name = Some(Daemon::Profile.name().into());
        let msg_id = msg.msg_id;
        let frame = core_ipc::encode_frame(&msg).context("failed to encode the request")?;

        // Routed here until dropped.
        let _route = self
            .bus
            .register_confirmation(msg_id, self.confirm_tx.clone())
            .await;
        while self.confirm_rx.try_recv().is_ok() {}
        self.send_to_secrets(&frame).await?;

        let deadline = tokio::time::Instant::now() + CONFIRM_TIMEOUT;
        loop {
            let raw = tokio::time::timeout_at(deadline, self.confirm_rx.recv())
                .await
                .map_err(|_| {
                    anyhow::anyhow!("no response within {}ms", CONFIRM_TIMEOUT.as_millis())
                })?
                .context("the confirmation channel closed")?;
            let response: Message<EventKind> =
                core_ipc::decode_frame(&raw).context("failed to decode the response")?;
            if response.correlation_id == Some(msg_id) {
                return Ok(response);
            }
            tracing::debug!(
                expected = %msg_id,
                got = ?response.correlation_id,
                "discarding a response to an earlier request"
            );
        }
    }

    /// Unicast `frame` to daemon-secrets, retrying while it is not
    /// connected.
    async fn send_to_secrets(&self, frame: &[u8]) -> anyhow::Result<()> {
        let mut backoff = SEND_BACKOFF;
        let mut attempt = 1;
        loop {
            match self.bus.send_to_named(Daemon::Secrets.name(), frame).await {
                Ok(()) => return Ok(()),
                Err(e) if attempt == SEND_ATTEMPTS => {
                    return Err(e).with_context(|| format!("after {SEND_ATTEMPTS} attempts"));
                }
                Err(e) => {
                    tracing::warn!(
                        attempt,
                        max_attempts = SEND_ATTEMPTS,
                        backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                        error = %e,
                        "{} not reachable, retrying",
                        Daemon::Secrets
                    );
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                    attempt += 1;
                }
            }
        }
    }

    /// Publish `event` to every connection with Internal clearance, from
    /// daemon-profile's message context. An event that cannot be encoded
    /// is logged.
    pub(crate) async fn announce(&self, event: EventKind) {
        let msg = Message::new(&self.ctx, event, SecurityLevel::Internal, self.bus.epoch());
        match core_ipc::encode_frame(&msg) {
            Ok(frame) => self.bus.publish(&frame, SecurityLevel::Internal).await,
            Err(e) => {
                tracing::error!(error = %e, event = ?msg.payload, "failed to encode an announcement");
            }
        }
    }

    /// Append `action` to the audit log. A failed append is logged with
    /// the action: the daemon keeps running, and the chain stays verifiable
    /// up to the last written entry.
    pub(crate) fn record(&mut self, action: &AuditAction) {
        if let Err(e) = self.audit.append(action.clone()) {
            tracing::error!(error = %e, ?action, "failed to write an audit entry");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ProfileId {
        ProfileId::from_uuid(uuid::Uuid::from_u128(7))
    }

    fn work() -> TrustProfileName {
        TrustProfileName::try_from("work").unwrap()
    }

    #[test]
    fn each_transition_accepts_only_its_own_response() {
        let activated = EventKind::ProfileActivateResponse { success: true };
        let refused = EventKind::ProfileDeactivateResponse { success: false };
        assert_eq!(Transition::Activate.applied(&activated), Some(true));
        assert_eq!(Transition::Deactivate.applied(&activated), None);
        assert_eq!(Transition::Deactivate.applied(&refused), Some(false));
        assert_eq!(Transition::Activate.applied(&refused), None);
        assert_eq!(
            Transition::Activate.applied(&EventKind::StatusRequest),
            None
        );
    }

    #[test]
    fn a_failed_deactivation_is_recorded_as_a_deactivation_failure() {
        let (event, action) = Transition::Deactivate.failed(target(), "timed out");
        assert!(matches!(
            event,
            EventKind::ProfileDeactivationFailed { reason, .. } if reason == "timed out"
        ));
        assert!(matches!(
            action,
            AuditAction::ProfileDeactivationFailed { reason, .. } if reason == "timed out"
        ));
        let (event, action) = Transition::Activate.failed(target(), "rejected");
        assert!(matches!(event, EventKind::ProfileActivationFailed { .. }));
        assert!(matches!(
            action,
            AuditAction::ProfileActivationFailed { .. }
        ));
    }

    #[test]
    fn requests_name_their_profile() {
        assert!(matches!(
            Transition::Activate.request(target(), &work()),
            EventKind::ProfileActivate { profile_name, .. } if profile_name == work()
        ));
        assert!(matches!(
            Transition::Deactivate.request(target(), &work()),
            EventKind::ProfileDeactivate { profile_name, .. } if profile_name == work()
        ));
    }

    #[test]
    fn durations_saturate() {
        assert_eq!(millis(Duration::from_millis(42)), 42);
        assert_eq!(millis(Duration::from_secs(u64::MAX)), u32::MAX);
    }
}
