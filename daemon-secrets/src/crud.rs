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

/// Validate a secret key name (defense-in-depth).
/// Delegates to the canonical implementation in core-types.
fn validate_secret_key(key: &str) -> core_types::Result<()> {
    core_types::validate_secret_key(key)
}

/// Check whether a secret key access should be blocked by the system key
/// ACL. System keys (underscore prefix) are only accessible from callers
/// with `SecurityLevel::Internal` or higher.
///
/// Returns `true` if the access is **denied** (caller lacks clearance).
fn is_system_key_denied(key: &str, security_level: SecurityLevel) -> bool {
    key.starts_with('_') && security_level < SecurityLevel::Internal
}

/// Filter system keys from a key list for non-Internal callers.
fn filter_system_keys(keys: &mut Vec<String>, security_level: SecurityLevel) {
    if security_level < SecurityLevel::Internal {
        keys.retain(|k| !k.starts_with('_'));
    }
}

/// Global vault log handle, initialised from `main.rs` at startup.
///
/// Uses `OnceLock` to avoid threading the `Arc<VaultLog>` through every
/// CRUD function signature. The vault log is set once and read many times.
static VAULT_LOG: std::sync::OnceLock<std::sync::Arc<crate::vault_log::VaultLog>> =
    std::sync::OnceLock::new();

/// Cached installation ID to avoid re-reading installation.toml on every write.
pub static INSTALL_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Signing seed for vault log entry signing.
/// `RwLock` (not `OnceLock`) because the seed lifecycle is:
/// unavailable (startup) → available (vault unlock) → unavailable (vault lock).
/// `OnceLock` can't be cleared on lock or re-set after init ceremony creates the seed.
/// `Zeroizing` wrapper ensures the old value is zeroized when replaced or cleared.
static SIGNING_SEED: std::sync::RwLock<Option<zeroize::Zeroizing<[u8; 32]>>> =
    std::sync::RwLock::new(None);

/// Network identity private key for replication re-encryption decryption.
/// Same lifecycle as `SIGNING_SEED`.
static NETWORK_PRIVATE_KEY: std::sync::RwLock<Option<zeroize::Zeroizing<[u8; 32]>>> =
    std::sync::RwLock::new(None);

/// Set the signing seed. Takes `Zeroizing` to avoid unzeroized boundary copies.
/// Called after vault unlock delivers `_signing-seed`.
pub fn set_signing_seed(seed: Option<zeroize::Zeroizing<[u8; 32]>>) {
    let mut guard = SIGNING_SEED.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = seed;
}

/// Clear the signing seed. Called on vault lock.
/// Uses `into_inner` on poisoned locks — zeroization must not be blocked by poisoning.
pub fn clear_signing_seed() {
    let mut guard = SIGNING_SEED.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Set the network identity private key. Takes `Zeroizing` to avoid boundary copies.
pub fn set_network_private_key(key: Option<zeroize::Zeroizing<[u8; 32]>>) {
    let mut guard = NETWORK_PRIVATE_KEY.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = key;
}

/// Clear the network private key. Called on vault lock.
pub fn clear_network_private_key() {
    let mut guard = NETWORK_PRIVATE_KEY.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Check if the signing seed is available without copying it.
/// Use this for predicate checks instead of `with_signing_seed(..).is_some()`.
pub fn signing_seed_is_set() -> bool {
    SIGNING_SEED
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
}

/// Check if the network private key is available without copying it.
#[allow(dead_code)] // API symmetry with signing_seed_is_set; used when predicates are needed.
pub fn network_private_key_is_set() -> bool {
    NETWORK_PRIVATE_KEY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
}

/// Access the signing seed inside a closure. The seed never leaves the lock
/// scope — no stack copies, no `Zeroize` burden on callers.
pub fn with_signing_seed<R>(f: impl FnOnce(&[u8; 32]) -> R) -> Option<R> {
    let guard = SIGNING_SEED.read().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_deref().map(f)
}

/// Access the network private key inside a closure.
pub fn with_network_private_key<R>(f: impl FnOnce(&[u8; 32]) -> R) -> Option<R> {
    let guard = NETWORK_PRIVATE_KEY.read().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_deref().map(f)
}

/// Set the global vault log instance. Called once from `main.rs`.
///
/// Accepts the installation ID as a pre-validated parameter from the caller
/// instead of re-reading `installation.toml` from disk. The caller (main.rs)
/// loads the installation config once and passes the ID — no redundant disk
/// reads, no divergence between what main.rs and the vault log think the
/// installation ID is.
///
/// # Errors
///
/// Returns an error if `installation_id` is not a valid non-nil UUID. The
/// vault log requires a stable installation ID for per-author hash chain
/// semantics — running without one is a misconfiguration that must be loud.
pub fn set_vault_log(
    log: std::sync::Arc<crate::vault_log::VaultLog>,
    installation_id: &str,
) -> Result<(), String> {
    // Validate FIRST, set INSTALL_ID only after success.
    // This prevents the OnceLock from being poisoned with an invalid value
    // if validation fails — the expect() in write_local_entry relies on
    // INSTALL_ID being a valid non-nil UUID when set.
    let parsed = uuid::Uuid::parse_str(installation_id)
        .map_err(|e| format!("installation ID '{installation_id}' is not a valid UUID: {e}"))?;
    if parsed.is_nil() {
        return Err(
            "installation ID is nil UUID — vault log requires a non-nil installation ID. \
             Run `sesame init` to create one."
                .into(),
        );
    }
    // Only NOW set the OnceLock — validation passed.
    let _ = INSTALL_ID.set(installation_id.to_string());
    let _ = VAULT_LOG.set(log);
    Ok(())
}

/// Get a reference to the global vault log (for dispatch handlers).
pub fn vault_log_ref() -> Option<&'static std::sync::Arc<crate::vault_log::VaultLog>> {
    VAULT_LOG.get()
}

/// Vault-log hook: writes a log entry after every successful secret mutation.
///
/// System keys (underscore prefix) are skipped — they are per-installation
/// infrastructure (signing seed, network private key) that don't replicate.
/// The init ceremony stores these before the signing seed is available,
/// creating a bootstrapping chicken-and-egg. The audit log in daemon-profile
/// provides ops visibility for system key writes.
///
/// If the vault log is not initialised or the signing seed is unavailable,
/// the hook silently skips. Secret mutations succeed regardless — the vault
/// log is for replication, not for gating CRUD operations.
fn vault_log_hook(
    profile: &TrustProfileName,
    operation: core_types::VaultLogOp,
    key: &str,
    value_bytes: &[u8],
) {
    // System keys don't replicate — skip logging.
    if key.starts_with('_') {
        return;
    }

    let Some(log) = VAULT_LOG.get() else {
        return;
    };

    // If the signing seed isn't available yet, skip silently.
    // This happens between daemon start and vault unlock.
    if !signing_seed_is_set() {
        return;
    }

    let install_id = INSTALL_ID.get().map_or("", |s| s.as_str());

    if let Err(e) = log.write_local_entry(profile, operation, key, install_id, value_bytes) {
        tracing::warn!(error = %e, "vault log write failed (non-fatal)");
    }
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
        value: SensitiveBytes::from_slice(&[]),
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
pub async fn handle_secret_get(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
) -> anyhow::Result<Option<EventKind>> {
    if is_system_key_denied(key, msg.security_level) {
        return Ok(Some(EventKind::SecretGetResponse {
            key: key.to_string(),
            value: SensitiveBytes::from_slice(&[]),
            denial: Some(SecretDenialReason::AccessDenied),
        }));
    }
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
                    Ok(mut v) => {
                        let sb = SensitiveBytes::from_slice(&v);
                        zeroize::Zeroize::zeroize(&mut v);
                        (sb, None)
                    }
                    Err(e) => {
                        tracing::error!(profile = %profile, key, error = %e, "IPC encryption failed");
                        (
                            SensitiveBytes::from_slice(&[]),
                            Some(SecretDenialReason::VaultError(format!(
                                "IPC encryption failed: {e}"
                            ))),
                        )
                    }
                };
                #[cfg(not(feature = "ipc-field-encryption"))]
                let (value, denial): (SensitiveBytes, Option<SecretDenialReason>) =
                    (SensitiveBytes::from_slice(secret.as_bytes()), None);

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
                    value: SensitiveBytes::from_slice(&[]),
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
                value: SensitiveBytes::from_slice(&[]),
                denial: Some(SecretDenialReason::VaultError(e.to_string())),
            }))
        }
    }
}

/// Handle `SecretSet` event.
pub async fn handle_secret_set(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
    value: &SensitiveBytes,
) -> anyhow::Result<Option<EventKind>> {
    if is_system_key_denied(key, msg.security_level) {
        return Ok(Some(EventKind::SecretSetResponse {
            success: false,
            denial: Some(SecretDenialReason::AccessDenied),
        }));
    }
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
    // Pass secret bytes directly from SensitiveBytes' ProtectedAlloc to the vault
    // store — no heap copy. For IPC-encrypted mode, the decrypted Vec is used instead.
    #[cfg(not(feature = "ipc-field-encryption"))]
    let store_bytes: &[u8] = value.as_bytes();
    #[cfg(feature = "ipc-field-encryption")]
    let store_bytes: &[u8] = &store_value;

    let default_profile = ctx.default_profile.clone();
    let (success, denial) = match state.vault_for(profile).await {
        Ok(vault) => match vault.store().set(key, store_bytes).await {
            Ok(()) => {
                vault.flush().await;
                // H-03: After sesame init writes _signing-seed or _network-identity-private
                // to the default profile vault, reactively cache them so vault log
                // signing and replication decryption work without a lock+unlock cycle.
                if profile == &default_profile {
                    if key == "_signing-seed" {
                        if store_bytes.len() == 32 {
                            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
                            seed.copy_from_slice(store_bytes);
                            set_signing_seed(Some(seed));
                            tracing::info!("signing seed reactively cached after vault write");
                        } else {
                            // M-02: wrong-length value invalidates the cache.
                            set_signing_seed(None);
                            tracing::warn!(len = store_bytes.len(), "signing seed wrong length, cache invalidated");
                        }
                    } else if key == "_network-identity-private" {
                        if store_bytes.len() == 32 {
                            let mut pk = zeroize::Zeroizing::new([0u8; 32]);
                            pk.copy_from_slice(store_bytes);
                            set_network_private_key(Some(pk));
                            tracing::info!("network private key reactively cached after vault write");
                        } else {
                            set_network_private_key(None);
                            tracing::warn!(len = store_bytes.len(), "network private key wrong length, cache invalidated");
                        }
                    }
                }
                vault_log_hook(profile, core_types::VaultLogOp::Set, key, store_bytes);
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
    // Zeroize the IPC-decrypted intermediate (only exists with ipc-field-encryption).
    #[cfg(feature = "ipc-field-encryption")]
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
pub async fn handle_secret_delete(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    key: &str,
) -> anyhow::Result<Option<EventKind>> {
    if is_system_key_denied(key, msg.security_level) {
        return Ok(Some(EventKind::SecretDeleteResponse {
            success: false,
            denial: Some(SecretDenialReason::AccessDenied),
        }));
    }
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
                vault_log_hook(profile, core_types::VaultLogOp::Delete, key, &[]);
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
pub async fn handle_secret_list(
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
        Ok(vault) => {
            let mut all_keys = vault.store().list_keys().await.unwrap_or_default();
            filter_system_keys(&mut all_keys, msg.security_level);
            (all_keys, None)
        }
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
pub async fn handle_profile_activate(
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
pub async fn handle_profile_deactivate(
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
pub fn handle_secrets_state_request(ctx: &mut MessageContext<'_>) -> Option<EventKind> {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================
    // System key ACL: is_system_key_denied
    // ================================================================

    #[test]
    fn system_key_denied_for_open_clearance() {
        assert!(is_system_key_denied("_signing-seed", SecurityLevel::Open));
        assert!(is_system_key_denied("_network-identity-private", SecurityLevel::Open));
    }

    #[test]
    fn system_key_allowed_for_internal_clearance() {
        assert!(!is_system_key_denied("_signing-seed", SecurityLevel::Internal));
    }

    #[test]
    fn system_key_allowed_for_secrets_only_clearance() {
        // SecretsOnly > Internal in the SecurityLevel ordering.
        assert!(!is_system_key_denied("_signing-seed", SecurityLevel::SecretsOnly));
    }

    #[test]
    fn non_system_key_allowed_for_all_clearance_levels() {
        assert!(!is_system_key_denied("api-key", SecurityLevel::Open));
        assert!(!is_system_key_denied("api-key", SecurityLevel::Internal));
        assert!(!is_system_key_denied("github-token", SecurityLevel::SecretsOnly));
    }

    #[test]
    fn empty_key_is_not_system_key() {
        assert!(!is_system_key_denied("", SecurityLevel::Open));
    }

    #[test]
    fn single_underscore_is_system_key() {
        assert!(is_system_key_denied("_", SecurityLevel::Open));
    }

    // ================================================================
    // System key ACL: filter_system_keys
    // ================================================================

    #[test]
    fn filter_hides_system_keys_for_open_clearance() {
        let mut keys = vec![
            "api-key".into(),
            "_signing-seed".into(),
            "github-token".into(),
            "_network-identity-private".into(),
        ];
        filter_system_keys(&mut keys, SecurityLevel::Open);
        assert_eq!(keys, vec!["api-key", "github-token"]);
    }

    #[test]
    fn filter_preserves_system_keys_for_internal_clearance() {
        let mut keys = vec![
            "api-key".into(),
            "_signing-seed".into(),
            "github-token".into(),
        ];
        filter_system_keys(&mut keys, SecurityLevel::Internal);
        assert_eq!(keys, vec!["api-key", "_signing-seed", "github-token"]);
    }

    #[test]
    fn filter_preserves_all_keys_for_secrets_only() {
        let mut keys = vec!["_a".into(), "_b".into(), "c".into()];
        filter_system_keys(&mut keys, SecurityLevel::SecretsOnly);
        assert_eq!(keys, vec!["_a", "_b", "c"]);
    }

    #[test]
    fn filter_empty_list_is_noop() {
        let mut keys: Vec<String> = vec![];
        filter_system_keys(&mut keys, SecurityLevel::Open);
        assert!(keys.is_empty());
    }

    #[test]
    fn filter_all_system_keys_produces_empty() {
        let mut keys = vec!["_a".into(), "_b".into()];
        filter_system_keys(&mut keys, SecurityLevel::Open);
        assert!(keys.is_empty());
    }
}
