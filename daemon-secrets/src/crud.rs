//! Secret CRUD operations (Get, Set, Delete, List) with 6-gate security
//! pipeline, profile activation/deactivation, and state reconciliation.

use crate::acl::{
    audit_secret_access, check_secret_access, check_secret_list_access, check_secret_requester,
};
use crate::dispatch::{MessageContext, send_response_early};

use core_ipc::{BusClient, Message};
use core_secrets::SecretsStore;
use core_types::{
    DaemonId, EventKind, SecretDenialReason, SecurityLevel, SensitiveBytes, TrustProfileName,
};
use zeroize::Zeroize;

/// Validate a secret key name (defense-in-depth).
/// Delegates to the canonical implementation in core-types.
fn validate_secret_key(key: &str) -> core_types::Result<()> {
    core_types::validate_secret_key(key)
}

/// Emit a secret operation audit event on the IPC bus for persistent logging
/// by daemon-profile. Fire-and-forget: audit event delivery failure must not
/// block or fail secret operations.
///
/// SECURITY: This function must NEVER receive or emit secret values.
/// Only metadata (action, profile, key name, requester, outcome).
async fn emit_audit_event(
    client: &BusClient,
    action: &str,
    profile: &TrustProfileName,
    key: Option<&str>,
    requester: DaemonId,
    requester_name: Option<&str>,
    outcome: &str,
) {
    let event = EventKind::SecretOperationAudit {
        action: action.to_owned(),
        profile: profile.clone(),
        key: key.map(ToOwned::to_owned),
        requester,
        requester_name: requester_name.map(ToOwned::to_owned),
        outcome: outcome.to_owned(),
    };
    if let Err(e) = client.publish(event, SecurityLevel::Internal).await {
        tracing::warn!(error = %e, action, "failed to emit secret audit event");
    }
}

/// Run the 6-gate security pipeline (gates 1-5.5) shared by Get/Set/Delete.
///
/// Returns `Ok(requester_name)` if all gates pass, or `Err(early_response)` if
/// a gate denied the request (response already sent to the caller).
///
/// Gates: 1) lock check, 2) active profile, 3) identity, 4) rate limit,
/// 5) ACL, 5.5) key validation.
async fn secret_gate_pipeline(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    action: &str,
    profile: &TrustProfileName,
    key: &str,
    deny_event: fn(&str, SecretDenialReason) -> EventKind,
) -> Result<(), anyhow::Result<Option<EventKind>>> {
    // 1. LOCK CHECK (cheapest, most restrictive).
    if ctx.vault_state.master_keys.is_empty() {
        audit_secret_access(action, msg.sender, profile, Some(key), "denied-locked");
        emit_audit_event(
            ctx.client,
            action,
            profile,
            Some(key),
            msg.sender,
            msg.verified_sender_name.as_deref(),
            "denied-locked",
        )
        .await;
        return Err(send_response_early(
            ctx.client,
            msg,
            deny_event(key, SecretDenialReason::Locked),
            ctx.daemon_id,
        )
        .await);
    }

    // 2. ACTIVE PROFILE CHECK.
    if !ctx.vault_state.active_profiles.contains(profile) {
        audit_secret_access(
            action,
            msg.sender,
            profile,
            Some(key),
            "denied-profile-not-active",
        );
        emit_audit_event(
            ctx.client,
            action,
            profile,
            Some(key),
            msg.sender,
            msg.verified_sender_name.as_deref(),
            "denied-profile-not-active",
        )
        .await;
        return Err(send_response_early(
            ctx.client,
            msg,
            deny_event(key, SecretDenialReason::ProfileNotActive),
            ctx.daemon_id,
        )
        .await);
    }

    // 3. IDENTITY CHECK (server-verified sender name).
    let requester_name = msg.verified_sender_name.as_deref();
    check_secret_requester(msg.sender, requester_name);

    // 4. RATE LIMIT CHECK.
    if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
        tracing::warn!(
            audit = "rate-limit",
            requester = %msg.sender,
            profile = %profile,
            key,
            "secret request rate limit exceeded"
        );
        audit_secret_access(action, msg.sender, profile, Some(key), "rate-limited");
        emit_audit_event(
            ctx.client,
            action,
            profile,
            Some(key),
            msg.sender,
            requester_name,
            "rate-limited",
        )
        .await;
        return Err(send_response_early(
            ctx.client,
            msg,
            deny_event(key, SecretDenialReason::RateLimited),
            ctx.daemon_id,
        )
        .await);
    }

    // 5. ACL CHECK (per-secret access control).
    if !check_secret_access(ctx.config, profile, requester_name, key) {
        tracing::warn!(
            audit = "access-denied",
            requester = %msg.sender,
            daemon_name = requester_name.unwrap_or("unknown"),
            profile = %profile,
            key,
            "secret access denied by per-profile ACL"
        );
        audit_secret_access(action, msg.sender, profile, Some(key), "denied-acl");
        emit_audit_event(
            ctx.client,
            action,
            profile,
            Some(key),
            msg.sender,
            requester_name,
            "denied-acl",
        )
        .await;
        return Err(send_response_early(
            ctx.client,
            msg,
            deny_event(key, SecretDenialReason::AccessDenied),
            ctx.daemon_id,
        )
        .await);
    }

    // 5.5. KEY VALIDATION (defense-in-depth).
    if let Err(e) = validate_secret_key(key) {
        audit_secret_access(action, msg.sender, profile, Some(key), "denied-invalid-key");
        emit_audit_event(
            ctx.client,
            action,
            profile,
            Some(key),
            msg.sender,
            requester_name,
            "denied-invalid-key",
        )
        .await;
        return Err(send_response_early(
            ctx.client,
            msg,
            deny_event(key, SecretDenialReason::VaultError(e.to_string())),
            ctx.daemon_id,
        )
        .await);
    }

    Ok(())
}

/// Denial event builder for `SecretGetResponse`.
fn deny_get(key: &str, reason: SecretDenialReason) -> EventKind {
    EventKind::SecretGetResponse {
        key: key.to_owned(),
        value: SensitiveBytes::new(vec![]),
        denial: Some(reason),
    }
}

/// Denial event builder for `SecretSetResponse`.
fn deny_set(_key: &str, reason: SecretDenialReason) -> EventKind {
    EventKind::SecretSetResponse {
        success: false,
        denial: Some(reason),
    }
}

/// Denial event builder for `SecretDeleteResponse`.
fn deny_delete(_key: &str, reason: SecretDenialReason) -> EventKind {
    EventKind::SecretDeleteResponse {
        success: false,
        denial: Some(reason),
    }
}

/// Handle `SecretGet` event.
pub(crate) async fn handle_secret_get(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
) -> anyhow::Result<Option<EventKind>> {
    // Gates 1-5.5: lock, active profile, identity, rate limit, ACL, key validation.
    if let Err(early) = secret_gate_pipeline(msg, ctx, "get", profile, key, deny_get).await {
        return early;
    }
    let requester_name = msg.verified_sender_name.as_deref();
    let state = &mut ctx.vault_state;

    // 6. VAULT ACCESS.
    match state.vault_for(profile).await {
        Ok(vault) => match vault.resolve(key).await {
            Ok(secret) => {
                #[cfg(feature = "ipc-field-encryption")]
                let (value, denial) = match state.encrypt_for_ipc(profile, secret.as_bytes()) {
                    Ok(v) => (SensitiveBytes::new(v), None),
                    Err(e) => {
                        tracing::error!(profile = %profile, key, error = %e, "IPC encryption failed");
                        (
                            SensitiveBytes::new(vec![]),
                            Some(SecretDenialReason::VaultError(format!(
                                "IPC encryption failed: {e}"
                            ))),
                        )
                    }
                };
                #[cfg(not(feature = "ipc-field-encryption"))]
                let (value, denial): (SensitiveBytes, Option<SecretDenialReason>) =
                    (SensitiveBytes::new(secret.as_bytes().to_vec()), None);

                audit_secret_access("get", msg.sender, profile, Some(key), "success");
                emit_audit_event(
                    ctx.client,
                    "get",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "success",
                )
                .await;
                Ok(Some(EventKind::SecretGetResponse {
                    key: key.to_owned(),
                    value,
                    denial,
                }))
            }
            Err(e) => {
                tracing::warn!(profile = %profile, key, error = %e, "secret get failed");
                audit_secret_access("get", msg.sender, profile, Some(key), "not-found");
                emit_audit_event(
                    ctx.client,
                    "get",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "not-found",
                )
                .await;
                Ok(Some(EventKind::SecretGetResponse {
                    key: key.to_owned(),
                    value: SensitiveBytes::new(vec![]),
                    denial: Some(SecretDenialReason::NotFound),
                }))
            }
        },
        Err(e) => {
            tracing::error!(profile = %profile, error = %e, "vault access failed");
            audit_secret_access("get", msg.sender, profile, Some(key), "vault-error");
            emit_audit_event(
                ctx.client,
                "get",
                profile,
                Some(key),
                msg.sender,
                requester_name,
                "vault-error",
            )
            .await;
            Ok(Some(EventKind::SecretGetResponse {
                key: key.to_owned(),
                value: SensitiveBytes::new(vec![]),
                denial: Some(SecretDenialReason::VaultError(e.to_string())),
            }))
        }
    }
}

/// Handle `SecretSet` event.
pub(crate) async fn handle_secret_set(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
    value: &SensitiveBytes,
) -> anyhow::Result<Option<EventKind>> {
    // Gates 1-5.5: lock, active profile, identity, rate limit, ACL, key validation.
    if let Err(early) = secret_gate_pipeline(msg, ctx, "set", profile, key, deny_set).await {
        return early;
    }
    let requester_name = msg.verified_sender_name.as_deref();
    let state = &mut ctx.vault_state;

    // 6. VAULT ACCESS (IPC field decryption runs here, after all gates pass).
    #[cfg(feature = "ipc-field-encryption")]
    let mut store_value = match state.decrypt_from_ipc(profile, value.as_bytes()) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::error!(profile = %profile, key, error = %e, "IPC decryption of secret value failed");
            audit_secret_access("set", msg.sender, profile, Some(key), "decrypt-error");
            return send_response_early(
                ctx.client,
                msg,
                EventKind::SecretSetResponse {
                    success: false,
                    denial: Some(SecretDenialReason::VaultError(format!(
                        "IPC decryption failed: {e}"
                    ))),
                },
                ctx.daemon_id,
            )
            .await;
        }
    };
    #[cfg(not(feature = "ipc-field-encryption"))]
    let mut store_value = value.as_bytes().to_vec();

    let (success, denial) = match state.vault_for(profile).await {
        Ok(vault) => match vault.store().set(key, &store_value).await {
            Ok(()) => {
                vault.flush().await;
                (true, None)
            }
            Err(e) => {
                tracing::error!(profile = %profile, key, error = %e, "secret set failed");
                (false, Some(SecretDenialReason::VaultError(e.to_string())))
            }
        },
        Err(e) => {
            tracing::error!(profile = %profile, error = %e, "vault access failed");
            (false, Some(SecretDenialReason::VaultError(e.to_string())))
        }
    };
    // Zeroize the intermediate plaintext copy.
    store_value.zeroize();
    let outcome = if success { "success" } else { "failed" };
    audit_secret_access("set", msg.sender, profile, Some(key), outcome);
    emit_audit_event(
        ctx.client,
        "set",
        profile,
        Some(key),
        msg.sender,
        requester_name,
        outcome,
    )
    .await;
    Ok(Some(EventKind::SecretSetResponse { success, denial }))
}

/// Handle `SecretDelete` event.
pub(crate) async fn handle_secret_delete(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
) -> anyhow::Result<Option<EventKind>> {
    // Gates 1-5.5: lock, active profile, identity, rate limit, ACL, key validation.
    if let Err(early) = secret_gate_pipeline(msg, ctx, "delete", profile, key, deny_delete).await {
        return early;
    }
    let requester_name = msg.verified_sender_name.as_deref();
    let state = &mut ctx.vault_state;

    // 6. VAULT ACCESS.
    let (success, denial) = match state.vault_for(profile).await {
        Ok(vault) => match vault.store().delete(key).await {
            Ok(()) => {
                vault.flush().await;
                (true, None)
            }
            Err(e) => {
                tracing::warn!(profile = %profile, key, error = %e, "secret delete failed");
                (false, Some(SecretDenialReason::VaultError(e.to_string())))
            }
        },
        Err(e) => {
            tracing::error!(profile = %profile, error = %e, "vault access failed");
            (false, Some(SecretDenialReason::VaultError(e.to_string())))
        }
    };
    let outcome = if success { "success" } else { "failed" };
    audit_secret_access("delete", msg.sender, profile, Some(key), outcome);
    emit_audit_event(
        ctx.client,
        "delete",
        profile,
        Some(key),
        msg.sender,
        requester_name,
        outcome,
    )
    .await;
    Ok(Some(EventKind::SecretDeleteResponse { success, denial }))
}

/// Handle `SecretList` event.
pub(crate) async fn handle_secret_list(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
) -> anyhow::Result<Option<EventKind>> {
    // 1. LOCK CHECK.
    let Some(state) = Some(&mut ctx.vault_state).filter(|s| !s.master_keys.is_empty()) else {
        audit_secret_access("list", msg.sender, profile, None, "denied-locked");
        emit_audit_event(
            ctx.client,
            "list",
            profile,
            None,
            msg.sender,
            msg.verified_sender_name.as_deref(),
            "denied-locked",
        )
        .await;
        return send_response_early(
            ctx.client,
            msg,
            EventKind::SecretListResponse {
                keys: vec![],
                denial: Some(SecretDenialReason::Locked),
            },
            ctx.daemon_id,
        )
        .await;
    };

    // 2. ACTIVE PROFILE CHECK.
    if !state.active_profiles.contains(profile) {
        audit_secret_access(
            "list",
            msg.sender,
            profile,
            None,
            "denied-profile-not-active",
        );
        emit_audit_event(
            ctx.client,
            "list",
            profile,
            None,
            msg.sender,
            msg.verified_sender_name.as_deref(),
            "denied-profile-not-active",
        )
        .await;
        return send_response_early(
            ctx.client,
            msg,
            EventKind::SecretListResponse {
                keys: vec![],
                denial: Some(SecretDenialReason::ProfileNotActive),
            },
            ctx.daemon_id,
        )
        .await;
    }

    // 3. IDENTITY CHECK.
    let requester_name = msg.verified_sender_name.as_deref();
    check_secret_requester(msg.sender, requester_name);

    // 4. RATE LIMIT CHECK.
    if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
        audit_secret_access("list", msg.sender, profile, None, "rate-limited");
        emit_audit_event(
            ctx.client,
            "list",
            profile,
            None,
            msg.sender,
            requester_name,
            "rate-limited",
        )
        .await;
        return send_response_early(
            ctx.client,
            msg,
            EventKind::SecretListResponse {
                keys: vec![],
                denial: Some(SecretDenialReason::RateLimited),
            },
            ctx.daemon_id,
        )
        .await;
    }

    // 5. ACL CHECK (deny list if daemon has explicit empty ACL).
    if !check_secret_list_access(ctx.config, profile, requester_name) {
        tracing::warn!(
            audit = "access-denied",
            requester = %msg.sender,
            daemon_name = requester_name.unwrap_or("unknown"),
            profile = %profile,
            "secret list denied by per-profile ACL"
        );
        audit_secret_access("list", msg.sender, profile, None, "denied-acl");
        emit_audit_event(
            ctx.client,
            "list",
            profile,
            None,
            msg.sender,
            requester_name,
            "denied-acl",
        )
        .await;
        return send_response_early(
            ctx.client,
            msg,
            EventKind::SecretListResponse {
                keys: vec![],
                denial: Some(SecretDenialReason::AccessDenied),
            },
            ctx.daemon_id,
        )
        .await;
    }

    // 6. VAULT ACCESS.
    let (keys, denial) = match state.vault_for(profile).await {
        Ok(vault) => (vault.store().list_keys().await.unwrap_or_default(), None),
        Err(e) => {
            tracing::error!(profile = %profile, error = %e, "vault access failed");
            (vec![], Some(SecretDenialReason::VaultError(e.to_string())))
        }
    };
    let outcome = if denial.is_some() {
        "failed"
    } else if keys.is_empty() {
        "empty"
    } else {
        "success"
    };
    audit_secret_access("list", msg.sender, profile, None, outcome);
    emit_audit_event(
        ctx.client,
        "list",
        profile,
        None,
        msg.sender,
        requester_name,
        outcome,
    )
    .await;
    Ok(Some(EventKind::SecretListResponse { keys, denial }))
}

/// Handle `ProfileActivate` event.
pub(crate) async fn handle_profile_activate(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile_name: &TrustProfileName,
) -> anyhow::Result<Option<EventKind>> {
    if msg.verified_sender_name.as_deref() != Some("daemon-profile") {
        tracing::debug!(sender = ?msg.verified_sender_name, "ignoring profile lifecycle event from non-profile sender");
        return Ok(None);
    }
    // Per-vault check: reject if this specific profile's vault is not unlocked.
    if !ctx.vault_state.master_keys.contains_key(profile_name) {
        tracing::warn!(profile = %profile_name, "profile activate rejected: vault not unlocked");
        return send_response_early(
            ctx.client,
            msg,
            EventKind::ProfileActivateResponse { success: false },
            ctx.daemon_id,
        )
        .await;
    }
    let state = &mut ctx.vault_state;
    // Authorize first, then open vault (vault_for gates on active_profiles).
    state.activate_profile(profile_name);
    let success = match state.vault_for(profile_name).await {
        Ok(_) => {
            tracing::info!(profile = %profile_name, "profile activated");
            true
        }
        Err(e) => {
            // Vault open failed — revoke authorization.
            state.active_profiles.remove(profile_name);
            tracing::error!(profile = %profile_name, error = %e, "profile activation failed");
            false
        }
    };
    Ok(Some(EventKind::ProfileActivateResponse { success }))
}

/// Handle `ProfileDeactivate` event.
pub(crate) async fn handle_profile_deactivate(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile_name: &TrustProfileName,
) -> Option<EventKind> {
    if msg.verified_sender_name.as_deref() != Some("daemon-profile") {
        tracing::debug!(sender = ?msg.verified_sender_name, "ignoring profile lifecycle event from non-profile sender");
        return None;
    }
    // Deactivation is idempotent and doesn't require vault to be unlocked.
    ctx.vault_state.deactivate_profile(profile_name).await;
    Some(EventKind::ProfileDeactivateResponse { success: true })
}

/// Handle `SecretsStateRequest` event.
pub(crate) fn handle_secrets_state_request(ctx: &mut MessageContext<'_>) -> Option<EventKind> {
    let state = &ctx.vault_state;
    let all_locked = state.master_keys.is_empty();
    let active_profiles = state.active_profiles();
    // Build per-profile lock state from config profile names.
    let lock_state: std::collections::BTreeMap<TrustProfileName, bool> = ctx
        .config
        .profiles
        .keys()
        .filter_map(|name| TrustProfileName::try_from(name.as_str()).ok())
        .map(|name| {
            let is_locked = !state.master_keys.contains_key(&name);
            (name, is_locked)
        })
        .collect();
    Some(EventKind::SecretsStateResponse {
        locked: all_locked,
        active_profiles,
        lock_state,
    })
}
