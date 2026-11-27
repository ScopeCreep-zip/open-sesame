//! Secret CRUD operations (Get, Set, Delete, List) behind the security
//! gates, profile activation/deactivation, and state reconciliation.

use crate::acl::{Request, audit_secret_access, check_access, check_secret_requester};
use crate::dispatch::MessageContext;
use crate::vault::VaultState;

use core_crypto::SecureBytes;
use core_ipc::Message;
use core_secrets::SecretsStore;
use core_types::{EventKind, SecretDenialReason, SecurityLevel, SensitiveBytes, TrustProfileName};

/// Record the `outcome` of secret operation `action`: a local audit log
/// entry, and an audit event on the bus that daemon-profile persists in
/// the hash-chained audit log. Both are required; bus delivery is
/// best-effort and never fails the operation.
///
/// SECURITY: only metadata (action, profile, key name, requester,
/// outcome) — never a secret value.
async fn audit(
    ctx: &MessageContext<'_>,
    msg: &Message<EventKind>,
    action: &str,
    profile: &TrustProfileName,
    key: Option<&str>,
    outcome: &str,
) {
    audit_secret_access(action, msg.sender, profile, key, outcome);
    let event = EventKind::SecretOperationAudit {
        action: action.to_owned(),
        profile: profile.clone(),
        key: key.map(ToOwned::to_owned),
        requester: msg.sender,
        requester_name: msg.verified_sender_name.clone(),
        outcome: outcome.to_owned(),
    };
    if let Err(e) = ctx.client.publish(event, SecurityLevel::Internal).await {
        tracing::warn!(error = %e, action, "failed to emit secret audit event");
    }
}

/// The security gates, in order: 1) vault lock, 2) active profile,
/// 3) identity, 4) rate limit, 5) ACL, 6) key validation (key requests).
/// The denial of the first gate that fails, audited; `None` when every
/// gate passes.
async fn gate(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    action: &str,
    profile: &TrustProfileName,
    request: Request<'_>,
) -> Option<SecretDenialReason> {
    let key = match request {
        Request::Key(key) => Some(key),
        Request::List => None,
    };
    let requester = msg.verified_sender_name.as_deref();
    let (outcome, reason) = if ctx.vault_state.master_keys.is_empty() {
        ("denied-locked", SecretDenialReason::Locked)
    } else if !ctx.vault_state.active_profiles.contains(profile) {
        (
            "denied-profile-not-active",
            SecretDenialReason::ProfileNotActive,
        )
    } else {
        check_secret_requester(msg.sender, requester);
        if !ctx.rate_limiter.check(requester) {
            tracing::warn!(audit = "rate-limit", requester = %msg.sender, %profile, ?request, "secret request rate limit exceeded");
            ("rate-limited", SecretDenialReason::RateLimited)
        } else if !check_access(ctx.config, profile, requester, request) {
            tracing::warn!(audit = "access-denied", requester = %msg.sender, daemon_name = requester.unwrap_or("unknown"), %profile, ?request, "secret request denied by per-profile ACL");
            ("denied-acl", SecretDenialReason::AccessDenied)
        } else if let Some(Err(e)) = key.map(core_types::validate_secret_key) {
            (
                "denied-invalid-key",
                SecretDenialReason::VaultError(e.to_string()),
            )
        } else {
            return None;
        }
    };
    audit(ctx, msg, action, profile, key, outcome).await;
    Some(reason)
}

/// The audit outcome and denial of a failed secret operation: an absent
/// key is `NotFound`, every other failure a `VaultError` carrying it.
fn failure(e: core_types::Error) -> (&'static str, SecretDenialReason) {
    match e {
        core_types::Error::NotFound(_) => ("not-found", SecretDenialReason::NotFound),
        other => ("failed", SecretDenialReason::VaultError(other.to_string())),
    }
}

/// Audit the `result` of secret operation `action` and return its value,
/// or its [`failure`] denial.
async fn settle<T>(
    ctx: &MessageContext<'_>,
    msg: &Message<EventKind>,
    action: &str,
    profile: &TrustProfileName,
    key: Option<&str>,
    result: core_types::Result<T>,
) -> Result<T, SecretDenialReason> {
    let (outcome, settled) = match result {
        Ok(value) => ("success", Ok(value)),
        Err(e) => {
            tracing::error!(%profile, action, key, error = %e, "secret operation failed");
            let (outcome, reason) = failure(e);
            (outcome, Err(reason))
        }
    };
    audit(ctx, msg, action, profile, key, outcome).await;
    settled
}

/// A stored secret as it crosses the bus: sealed under the profile's IPC
/// key (ADR-SEC-006).
#[cfg(feature = "ipc-field-encryption")]
fn bus_value(
    state: &VaultState,
    profile: &TrustProfileName,
    secret: &SecureBytes,
) -> core_types::Result<SensitiveBytes> {
    let sealed = zeroize::Zeroizing::new(state.encrypt_for_ipc(profile, secret.as_bytes())?);
    Ok(SensitiveBytes::from_slice(&sealed))
}

/// A stored secret as it crosses the bus: as stored (Noise transport
/// encryption is the boundary).
#[cfg(not(feature = "ipc-field-encryption"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature with the ipc-field-encryption variant"
)]
fn bus_value(
    _state: &VaultState,
    _profile: &TrustProfileName,
    secret: &SecureBytes,
) -> core_types::Result<SensitiveBytes> {
    Ok(SensitiveBytes::from_slice(secret.as_bytes()))
}

/// A secret value from the bus as it is stored: opened from the profile's
/// IPC key seal (ADR-SEC-006).
#[cfg(feature = "ipc-field-encryption")]
fn stored_value(
    state: &VaultState,
    profile: &TrustProfileName,
    value: &SensitiveBytes,
) -> core_types::Result<SecureBytes> {
    state.decrypt_from_ipc(profile, value.as_bytes())
}

/// A secret value from the bus as it is stored: as sent.
#[cfg(not(feature = "ipc-field-encryption"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature with the ipc-field-encryption variant"
)]
fn stored_value(
    _state: &VaultState,
    _profile: &TrustProfileName,
    value: &SensitiveBytes,
) -> core_types::Result<SecureBytes> {
    Ok(SecureBytes::from_slice(value.as_bytes()))
}

/// Handle `SecretGet`.
pub(crate) async fn handle_secret_get(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
) -> EventKind {
    let denied = |reason| EventKind::SecretGetResponse {
        key: key.to_owned(),
        value: SensitiveBytes::from_slice(&[]),
        denial: Some(reason),
    };
    if let Some(reason) = gate(msg, ctx, "get", profile, Request::Key(key)).await {
        return denied(reason);
    }
    let result = async {
        let secret = ctx
            .vault_state
            .vault_for(profile)
            .await?
            .resolve(key)
            .await?;
        bus_value(ctx.vault_state, profile, &secret)
    }
    .await;
    match settle(ctx, msg, "get", profile, Some(key), result).await {
        Ok(value) => EventKind::SecretGetResponse {
            key: key.to_owned(),
            value,
            denial: None,
        },
        Err(reason) => denied(reason),
    }
}

/// Handle `SecretSet`.
pub(crate) async fn handle_secret_set(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
    value: &SensitiveBytes,
) -> EventKind {
    if let Some(reason) = gate(msg, ctx, "set", profile, Request::Key(key)).await {
        return EventKind::SecretSetResponse {
            success: false,
            denial: Some(reason),
        };
    }
    let result = async {
        let stored = stored_value(ctx.vault_state, profile, value)?;
        let vault = ctx.vault_state.vault_for(profile).await?;
        vault.store().set(key, stored.as_bytes()).await?;
        vault.flush().await;
        Ok(())
    }
    .await;
    let denial = settle(ctx, msg, "set", profile, Some(key), result)
        .await
        .err();
    EventKind::SecretSetResponse {
        success: denial.is_none(),
        denial,
    }
}

/// Handle `SecretDelete`.
pub(crate) async fn handle_secret_delete(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
) -> EventKind {
    if let Some(reason) = gate(msg, ctx, "delete", profile, Request::Key(key)).await {
        return EventKind::SecretDeleteResponse {
            success: false,
            denial: Some(reason),
        };
    }
    let result = async {
        let vault = ctx.vault_state.vault_for(profile).await?;
        vault.store().delete(key).await?;
        vault.flush().await;
        Ok(())
    }
    .await;
    let denial = settle(ctx, msg, "delete", profile, Some(key), result)
        .await
        .err();
    EventKind::SecretDeleteResponse {
        success: denial.is_none(),
        denial,
    }
}

/// Handle `SecretList`.
pub(crate) async fn handle_secret_list(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
) -> EventKind {
    if let Some(reason) = gate(msg, ctx, "list", profile, Request::List).await {
        return EventKind::SecretListResponse {
            keys: vec![],
            denial: Some(reason),
        };
    }
    let result = async {
        ctx.vault_state
            .vault_for(profile)
            .await?
            .store()
            .list_keys()
            .await
    }
    .await;
    match settle(ctx, msg, "list", profile, None, result).await {
        Ok(keys) => EventKind::SecretListResponse { keys, denial: None },
        Err(reason) => EventKind::SecretListResponse {
            keys: vec![],
            denial: Some(reason),
        },
    }
}

/// Whether `msg` comes from daemon-profile, the only sender of profile
/// lifecycle events; any other sender's is ignored.
fn from_daemon_profile(msg: &Message<EventKind>) -> bool {
    let from_profile =
        msg.verified_sender_name.as_deref() == Some(core_types::Daemon::Profile.name());
    if !from_profile {
        tracing::debug!(sender = ?msg.verified_sender_name, "ignoring profile lifecycle event from non-profile sender");
    }
    from_profile
}

/// Handle `ProfileActivate`: authorize the profile and open its vault.
pub(crate) async fn handle_profile_activate(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile_name: &TrustProfileName,
) -> Option<EventKind> {
    if !from_daemon_profile(msg) {
        return None;
    }
    let state = &mut *ctx.vault_state;
    let success = if state.master_keys.contains_key(profile_name) {
        // Authorize first, then open the vault (vault_for gates on
        // active_profiles); a failed open revokes the authorization.
        state.activate_profile(profile_name);
        match state.vault_for(profile_name).await {
            Ok(_) => {
                tracing::info!(profile = %profile_name, "profile activated");
                true
            }
            Err(e) => {
                state.active_profiles.remove(profile_name);
                tracing::error!(profile = %profile_name, error = %e, "profile activation failed");
                false
            }
        }
    } else {
        tracing::warn!(profile = %profile_name, "profile activate rejected: vault not unlocked");
        false
    };
    Some(EventKind::ProfileActivateResponse { success })
}

/// Handle `ProfileDeactivate`. Idempotent; the vault need not be unlocked.
pub(crate) async fn handle_profile_deactivate(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile_name: &TrustProfileName,
) -> Option<EventKind> {
    if !from_daemon_profile(msg) {
        return None;
    }
    ctx.vault_state.deactivate_profile(profile_name).await;
    Some(EventKind::ProfileDeactivateResponse { success: true })
}

/// The `SecretsStateResponse`: whether every vault is locked, the active
/// profiles, and the lock state of every configured profile. An invalid
/// configured name has no vault; it is logged and left out.
pub(crate) fn secrets_state(ctx: &MessageContext<'_>) -> EventKind {
    let state = &ctx.vault_state;
    let lock_state = ctx
        .config
        .profiles
        .keys()
        .filter_map(|name| match TrustProfileName::try_from(name.as_str()) {
            Ok(profile) => Some(profile),
            Err(e) => {
                tracing::error!(profile = %name, error = %e, "invalid profile name in config, excluded from lock state");
                None
            }
        })
        .map(|profile| {
            let locked = !state.master_keys.contains_key(&profile);
            (profile, locked)
        })
        .collect();
    EventKind::SecretsStateResponse {
        locked: state.master_keys.is_empty(),
        active_profiles: state.active_profiles(),
        lock_state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_absent_key_is_not_found() {
        assert_eq!(
            failure(core_types::Error::NotFound("secret key: k".into())),
            ("not-found", SecretDenialReason::NotFound)
        );
        let (outcome, reason) = failure(core_types::Error::Secrets(
            "database disk image is malformed".into(),
        ));
        assert_eq!(outcome, "failed");
        assert!(
            matches!(&reason, SecretDenialReason::VaultError(m) if m.contains("malformed")),
            "{reason:?}"
        );
    }
}
