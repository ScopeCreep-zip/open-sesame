//! IPC message dispatch: routes inbound events to handler modules and sends
//! every handler's response through one path.

use crate::crud;
use crate::rate_limit::SecretRateLimiter;
use crate::unlock;
use crate::vault::VaultState;

use core_ipc::{BusClient, Message};
use core_types::{EventKind, SecurityLevel};

/// What a handler draws on: the bus connection, the vault state, the rate
/// limiter, and the configuration.
pub(crate) struct MessageContext<'a> {
    pub(crate) client: &'a mut BusClient,
    pub(crate) vault_state: &'a mut VaultState,
    pub(crate) rate_limiter: &'a mut SecretRateLimiter,
    pub(crate) config: &'a core_daemon::ConfigApplicationState,
}

/// Handle one inbound IPC message: the handler's response, when it has
/// one, is sent correlated to `msg` after the lock-state announcement it
/// implies.
pub(crate) async fn handle_message(msg: &Message<EventKind>, ctx: &mut MessageContext<'_>) {
    // Unlock and activation increase authority. Lock, deactivation, and
    // inventory remain available while configuration is rejected.
    if matches!(
        msg.payload,
        EventKind::FactorSubmit { .. } | EventKind::ProfileActivate { .. }
    ) && let Err(error) = ctx.config.policy()
    {
        let response = match &msg.payload {
            EventKind::FactorSubmit { profile, .. } => EventKind::FactorResponse {
                accepted: false,
                unlock_complete: false,
                remaining_factors: vec![],
                remaining_additional: 0,
                profile: profile.clone(),
                error: Some(format!("authorization policy unavailable: {error}")),
            },
            EventKind::ProfileActivate { .. } => {
                EventKind::ProfileActivateResponse { success: false }
            }
            _ => unreachable!("only authority-increasing requests enter policy admission"),
        };
        tracing::warn!(%error, "authority-increasing request denied: policy unavailable");
        respond(ctx, msg, response).await;
        return;
    }
    let response = match &msg.payload {
        EventKind::FactorSubmit {
            factor_id,
            key_material,
            profile,
            audit_metadata,
        } => Some(
            unlock::handle_factor_submit(
                msg,
                ctx,
                *factor_id,
                key_material,
                profile,
                audit_metadata,
            )
            .await,
        ),
        EventKind::VaultAuthQuery { profile } => {
            Some(unlock::vault_auth_requirements(ctx.vault_state, profile))
        }
        EventKind::LockRequest { profile } => {
            Some(unlock::handle_lock_request(msg, ctx, profile.as_ref()).await)
        }
        EventKind::SecretGet { profile, key } => {
            Some(crud::handle_secret_get(msg, ctx, profile, key).await)
        }
        EventKind::SecretSet {
            profile,
            key,
            value,
        } => Some(crud::handle_secret_set(msg, ctx, profile, key, value).await),
        EventKind::SecretDelete { profile, key } => {
            Some(crud::handle_secret_delete(msg, ctx, profile, key).await)
        }
        EventKind::SecretList { profile } => {
            Some(crud::handle_secret_list(msg, ctx, profile).await)
        }
        EventKind::ProfileActivate { profile_name, .. } => {
            crud::handle_profile_activate(msg, ctx, profile_name).await
        }
        EventKind::ProfileDeactivate { profile_name, .. } => {
            crud::handle_profile_deactivate(msg, ctx, profile_name).await
        }
        EventKind::SecretsStateRequest => Some(crud::secrets_state(ctx)),
        // StatusRequest is daemon-profile's (it reconciles with
        // SecretsStateRequest); every other event is not addressed here.
        _ => None,
    };
    if let Some(event) = response {
        respond(ctx, msg, event).await;
    }
}

/// The lock-state announcement `response` implies: a completed unlock
/// announces `VaultUnlocked`, a successful lock `VaultsLocked`.
fn lock_state_announcement(response: &EventKind) -> Option<EventKind> {
    match response {
        EventKind::FactorResponse {
            accepted: true,
            unlock_complete: true,
            profile,
            ..
        } => Some(EventKind::VaultUnlocked {
            profile: profile.clone(),
        }),
        EventKind::LockResponse {
            success: true,
            profiles_locked,
        } => Some(EventKind::VaultsLocked {
            profiles: profiles_locked.clone(),
        }),
        _ => None,
    }
}

/// Announce the lock-state change `response` implies, then send it
/// correlated to `request`. The announcement goes first, so daemon-profile
/// sees the state change even if the daemon dies before the response.
async fn respond(ctx: &MessageContext<'_>, request: &Message<EventKind>, response: EventKind) {
    if let Some(announcement) = lock_state_announcement(&response)
        && let Err(e) = ctx
            .client
            .publish(announcement, SecurityLevel::Internal)
            .await
    {
        tracing::error!(
            audit = "security",
            error = %e,
            "lock/unlock broadcast failed — daemon-profile may have stale state"
        );
    }
    core_daemon::reply(ctx.client, request, response).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::TrustProfileName;

    fn work() -> TrustProfileName {
        crate::test_support::profile("work")
    }

    fn factor_response(accepted: bool, unlock_complete: bool) -> EventKind {
        EventKind::FactorResponse {
            accepted,
            unlock_complete,
            remaining_factors: vec![],
            remaining_additional: 0,
            profile: work(),
            error: None,
        }
    }

    #[test]
    fn only_completed_unlocks_and_successful_locks_are_announced() {
        assert!(matches!(
            lock_state_announcement(&factor_response(true, true)),
            Some(EventKind::VaultUnlocked { profile }) if profile == work()
        ));
        assert!(lock_state_announcement(&factor_response(true, false)).is_none());
        assert!(lock_state_announcement(&factor_response(false, false)).is_none());
        assert!(matches!(
            lock_state_announcement(&EventKind::LockResponse {
                success: true,
                profiles_locked: vec![work()],
            }),
            Some(EventKind::VaultsLocked { profiles }) if profiles == [work()]
        ));
        assert!(
            lock_state_announcement(&EventKind::LockResponse {
                success: false,
                profiles_locked: vec![],
            })
            .is_none()
        );
    }
}
