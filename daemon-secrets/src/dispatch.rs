//! IPC message dispatch: routes inbound events to handler modules.

use crate::crud;
use crate::rate_limit::SecretRateLimiter;
use crate::unlock;
use crate::vault::VaultState;

use anyhow::Context;
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::path::Path;

/// Grouped context for `handle_message` to avoid parameter explosion.
pub(crate) struct MessageContext<'a> {
    pub(crate) client: &'a mut BusClient,
    pub(crate) vault_state: &'a mut VaultState,
    pub(crate) config_dir: &'a Path,
    pub(crate) default_profile: &'a TrustProfileName,
    pub(crate) daemon_id: DaemonId,
    pub(crate) rate_limiter: &'a mut SecretRateLimiter,
    pub(crate) config: &'a core_config::Config,
    pub(crate) socket_path: &'a Path,
    pub(crate) server_pub: &'a [u8; 32],
}

/// Handle a single inbound IPC message. Returns false if the daemon should exit.
///
/// Dual audit strategy for secret operations:
/// 1. tracing (always local, journal-based) -- structured logs for each operation.
/// 2. IPC event (SecretOperationAudit, fire-and-forget to daemon-profile) -- persisted
///    in the hash-chained audit log by daemon-profile. Best-effort: delivery failure
///    must not block or fail secret operations.
///
/// Both paths are required. Do not remove one assuming the other is sufficient.
pub(crate) async fn handle_message(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
) -> anyhow::Result<bool> {
    let response_event = match &msg.payload {
        // Daemon announcements — verified identity comes from msg.verified_sender_name
        // stamped by the bus server.
        EventKind::DaemonStarted { .. } => None,

        // Key rotation — reconnect with new keypair via shared handler.
        EventKind::KeyRotationPending {
            daemon_name,
            new_pubkey,
            grace_period_s,
        } if daemon_name == "daemon-secrets" => {
            tracing::info!(
                grace_period_s,
                "key rotation pending, will reconnect with new keypair"
            );
            match BusClient::handle_key_rotation(
                "daemon-secrets",
                ctx.daemon_id,
                ctx.socket_path,
                ctx.server_pub,
                new_pubkey,
                vec!["secrets".into(), "keylocker".into()],
                env!("CARGO_PKG_VERSION"),
            )
            .await
            {
                Ok(new_client) => {
                    *ctx.client = new_client;
                    tracing::info!("reconnected with rotated keypair");
                }
                Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
            }
            None
        }

        // -- Unlock (per-profile) --
        EventKind::UnlockRequest { password, profile } => {
            return match unlock::handle_unlock_request(msg, ctx, password, profile).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- SSH-agent unlock (pre-derived master key) --
        EventKind::SshUnlockRequest {
            master_key,
            profile,
            ssh_fingerprint,
        } => {
            return match unlock::handle_ssh_unlock(msg, ctx, master_key, profile, ssh_fingerprint)
                .await
            {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Multi-factor: submit a single factor --
        EventKind::FactorSubmit {
            factor_id,
            key_material,
            profile,
            audit_metadata,
        } => {
            return match unlock::handle_factor_submit(
                msg,
                ctx,
                factor_id,
                key_material,
                profile,
                audit_metadata,
            )
            .await
            {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Multi-factor: query vault auth requirements --
        EventKind::VaultAuthQuery { profile } => unlock::handle_vault_auth_query(ctx, profile),

        // -- Lock (per-profile or all) --
        EventKind::LockRequest { profile } => {
            let event = unlock::handle_lock_request(msg, ctx, profile).await;
            match event {
                Some(ev) => {
                    return handle_post_dispatch(ctx, msg, ev).await;
                }
                None => return Ok(true),
            }
        }

        // StatusRequest is handled exclusively by daemon-profile, which queries
        // daemon-secrets via SecretsStateRequest for authoritative state.
        EventKind::StatusRequest => None,

        // -- Secret Get (profile-scoped) --
        EventKind::SecretGet { profile, key } => {
            return match crud::handle_secret_get(msg, ctx, profile, key).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Secret Set (profile-scoped) --
        EventKind::SecretSet {
            profile,
            key,
            value,
        } => {
            return match crud::handle_secret_set(msg, ctx, profile, key, value).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Secret Delete (profile-scoped) --
        EventKind::SecretDelete { profile, key } => {
            return match crud::handle_secret_delete(msg, ctx, profile, key).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Secret List (profile-scoped) --
        EventKind::SecretList { profile } => {
            return match crud::handle_secret_list(msg, ctx, profile).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Profile Activate (authorize + open vault) --
        EventKind::ProfileActivate { profile_name, .. } => {
            return match crud::handle_profile_activate(msg, ctx, profile_name).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Profile Deactivate (deauthorize, flush JIT, close vault) --
        EventKind::ProfileDeactivate { profile_name, .. } => {
            crud::handle_profile_deactivate(msg, ctx, profile_name).await
        }

        // -- State reconciliation: daemon-profile queries authoritative state --
        EventKind::SecretsStateRequest => crud::handle_secrets_state_request(ctx),

        // -- Ignore other events --
        _ => None,
    };

    if let Some(event) = response_event {
        return handle_post_dispatch(ctx, msg, event).await;
    }

    Ok(true)
}

/// Post-dispatch: broadcast lock state changes, then send correlated response.
async fn handle_post_dispatch(
    ctx: &mut MessageContext<'_>,
    msg: &Message<EventKind>,
    event: EventKind,
) -> anyhow::Result<bool> {
    // Broadcast lock state changes BEFORE the correlated unicast response.
    // This ensures daemon-profile sees the state change even if a crash occurs
    // between the broadcast and the CLI response.
    let broadcast = match &event {
        EventKind::UnlockResponse { success, profile } => Some(EventKind::UnlockResponse {
            success: *success,
            profile: profile.clone(),
        }),
        EventKind::LockResponse {
            success,
            profiles_locked,
        } => Some(EventKind::LockResponse {
            success: *success,
            profiles_locked: profiles_locked.clone(),
        }),
        _ => None,
    };

    if let Some(notify) = broadcast
        && let Err(e) = ctx.client.publish(notify, SecurityLevel::Internal).await
    {
        tracing::error!(
            audit = "security",
            error = %e,
            "lock/unlock broadcast failed — daemon-profile may have stale state"
        );
    }

    send_response(ctx.client, msg, event, ctx.daemon_id).await?;

    Ok(true)
}

/// Send a correlated response and return `Ok(None)` for use in handler
/// functions that return `Result<Option<EventKind>>`. This is the early-return
/// path: the response is sent directly and the dispatch layer has nothing to do.
pub(crate) async fn send_response_early(
    client: &mut BusClient,
    request: &Message<EventKind>,
    response_event: EventKind,
    daemon_id: DaemonId,
) -> anyhow::Result<Option<EventKind>> {
    send_response(client, request, response_event, daemon_id).await?;
    Ok(None)
}

/// Send a correlated response to an inbound request.
pub(crate) async fn send_response(
    client: &mut BusClient,
    request: &Message<EventKind>,
    response_event: EventKind,
    daemon_id: DaemonId,
) -> anyhow::Result<bool> {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    let response = Message::new(
        &msg_ctx,
        response_event,
        request.security_level,
        client.epoch(),
    )
    .with_correlation(request.msg_id);

    client
        .send(&response)
        .await
        .context("failed to send response")?;
    Ok(true)
}
