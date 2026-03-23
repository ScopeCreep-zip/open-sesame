//! Vault unlock/lock lifecycle: password unlock, SSH unlock, multi-factor,
//! vault auth query, lock, and salt/key derivation helpers.

use crate::acl::audit_secret_access;
use crate::dispatch::{MessageContext, send_response_early};
use crate::rate_limit::SecretRateLimiter;
use crate::vault::{ALL_MODE_KDF_CONTEXT, PARTIAL_UNLOCK_TIMEOUT_SECS, PartialUnlock};

use core_crypto::SecureBytes;
use core_ipc::Message;
use core_secrets::{JitDelivery, SqlCipherStore};
use core_types::{AuthCombineMode, AuthFactorId, EventKind, TrustProfileName};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroize;

use crate::vault::UnlockResult;

/// Per-profile salt file path: `{config_dir}/vaults/{profile}.salt`
pub(crate) fn profile_salt_path(config_dir: &Path, profile: &TrustProfileName) -> PathBuf {
    config_dir.join("vaults").join(format!("{profile}.salt"))
}

/// Derive the master key from password + salt via Argon2id.
pub(crate) fn derive_master_key(
    password: &[u8],
    salt: &[u8; 16],
) -> core_types::Result<SecureBytes> {
    core_crypto::derive_key_argon2(password, salt)
}

/// Generate a new per-profile salt and persist to disk.
pub(crate) fn generate_profile_salt(salt_path: &Path) -> core_types::Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| core_types::Error::Crypto(format!("getrandom failed: {e}")))?;
    if let Some(parent) = salt_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            core_types::Error::Config(format!("failed to create vault directory: {e}"))
        })?;
    }
    std::fs::write(salt_path, salt)
        .map_err(|e| core_types::Error::Config(format!("failed to write profile salt: {e}")))?;
    Ok(salt)
}

/// Load a salt file from disk.
pub(crate) fn load_salt(path: &Path) -> core_types::Result<[u8; 16]> {
    let salt_bytes = std::fs::read(path).map_err(|e| {
        core_types::Error::Config(format!("failed to read salt from {}: {e}", path.display()))
    })?;
    salt_bytes
        .try_into()
        .map_err(|_| core_types::Error::Config("salt file is not 16 bytes".into()))
}

/// Unlock a specific profile's vault by deriving its master key from a
/// per-profile salt via Argon2id. Fast path uses platform keyring.
///
/// Each profile has its own salt at `{config_dir}/vaults/{profile}.salt`.
/// First unlock generates the salt. Subsequent unlocks read existing salt.
/// If a vault DB exists, the derived key is verified against it and the
/// opened store is returned for caching.
pub(crate) async fn unlock_profile(
    password: &[u8],
    profile: &TrustProfileName,
    config_dir: &Path,
) -> core_types::Result<UnlockResult> {
    let salt_file = profile_salt_path(config_dir, profile);

    // Fast path: try per-profile keyring retrieval (avoids Argon2id).
    #[cfg(target_os = "linux")]
    if salt_file.exists() {
        let salt_bytes = std::fs::read(&salt_file)
            .map_err(|e| core_types::Error::Config(format!("failed to read profile salt: {e}")))?;
        if let Some(master_key) =
            crate::keyring::keyring_retrieve_profile(password, &salt_bytes, profile).await
        {
            return Ok(UnlockResult {
                master_key,
                verified_store: None,
            });
        }
    }

    // Derive master key: load existing salt or generate new one.
    let master_key = if salt_file.exists() {
        let salt = load_salt(&salt_file)?;
        derive_master_key(password, &salt)?
    } else {
        let new_salt = generate_profile_salt(&salt_file)?;
        tracing::info!(profile = %profile, path = %salt_file.display(), "per-profile salt generated");
        derive_master_key(password, &new_salt)?
    };

    // Verify against existing vault DB if it exists.
    let vault_path = config_dir.join("vaults").join(format!("{profile}.db"));
    let verified_store = if vault_path.exists() {
        let vault_key = core_crypto::derive_vault_key(master_key.as_bytes(), profile);
        let vp = vault_path;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::task::spawn_blocking(move || SqlCipherStore::open(&vp, &vault_key)),
        )
        .await
        .map_err(|_| {
            core_types::Error::Secrets(
                "vault open timed out (10s) — possible seccomp violation on blocking thread".into(),
            )
        })?
        .map_err(|e| core_types::Error::Secrets(format!("spawn_blocking: {e}")))?;

        match result {
            Ok(store) => {
                tracing::info!(profile = %profile, "vault key verified");
                Some(store)
            }
            Err(e) => {
                tracing::warn!(error = %e, profile = %profile, "vault key verification failed — wrong password");
                return Err(core_types::Error::Secrets(
                    "wrong password: vault key verification failed".into(),
                ));
            }
        }
    } else {
        None
    };

    Ok(UnlockResult {
        master_key,
        verified_store,
    })
}

/// Handle `UnlockRequest` event.
pub(crate) async fn handle_unlock_request(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    password: &core_types::SensitiveBytes,
    profile: &Option<TrustProfileName>,
) -> anyhow::Result<Option<EventKind>> {
    let target = profile
        .clone()
        .unwrap_or_else(|| ctx.default_profile.clone());

    if ctx.vault_state.master_keys.contains_key(&target) {
        tracing::warn!(audit = "security", profile = %target, "unlock request for already-unlocked profile — rejected");
        audit_secret_access(
            "unlock",
            msg.sender,
            &target,
            None,
            "rejected-already-unlocked",
        );
        return send_response_early(
            ctx.client,
            msg,
            EventKind::UnlockRejected {
                reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
                profile: Some(target),
            },
            ctx.daemon_id,
        )
        .await;
    }
    let outcome = match unlock_profile(password.as_bytes(), &target, ctx.config_dir).await {
        Ok(result) => {
            // Store per-profile keyring entry BEFORE transferring ownership
            // to the map — avoids retrieving from map and eliminates unwrap.
            #[cfg(target_os = "linux")]
            {
                let salt_path = profile_salt_path(ctx.config_dir, &target);
                if let Ok(salt_bytes) = std::fs::read(&salt_path) {
                    crate::keyring::keyring_store_profile(
                        &result.master_key,
                        password.as_bytes(),
                        &salt_bytes,
                        &target,
                    )
                    .await;
                }
            }

            ctx.vault_state
                .master_keys
                .insert(target.clone(), result.master_key);

            // Cache verified store to avoid redundant SQLCipher open on ProfileActivate.
            if let Some(store) = result.verified_store {
                let jit = JitDelivery::new(store, ctx.vault_state.ttl);
                ctx.vault_state.vaults.insert(target.clone(), jit);
            }

            tracing::info!(profile = %target, "vault unlocked");
            "success"
        }
        Err(e) => {
            tracing::error!(error = %e, profile = %target, "unlock failed");
            "failed"
        }
    };
    audit_secret_access("unlock", msg.sender, &target, None, outcome);
    Ok(Some(EventKind::UnlockResponse {
        success: outcome == "success",
        profile: target,
    }))
}

/// Handle `SshUnlockRequest` event.
pub(crate) async fn handle_ssh_unlock(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    master_key: &core_types::SensitiveBytes,
    profile: &TrustProfileName,
    ssh_fingerprint: &str,
) -> anyhow::Result<Option<EventKind>> {
    let target = profile.clone();

    if ctx.vault_state.master_keys.contains_key(&target) {
        tracing::warn!(audit = "security", profile = %target, "SSH unlock request for already-unlocked profile — rejected");
        audit_secret_access(
            "ssh-unlock",
            msg.sender,
            &target,
            None,
            "rejected-already-unlocked",
        );
        return send_response_early(
            ctx.client,
            msg,
            EventKind::UnlockRejected {
                reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
                profile: Some(target),
            },
            ctx.daemon_id,
        )
        .await;
    }

    // Copy directly from SensitiveBytes' ProtectedAlloc into SecureBytes' ProtectedAlloc.
    // No heap intermediate — both sides are page-aligned, mlock'd memory.
    let secure_master_key = SecureBytes::from_slice(master_key.as_bytes());

    // Verify against existing vault DB if it exists.
    let vault_path = ctx.config_dir.join("vaults").join(format!("{target}.db"));
    let (success, verified_store) = if vault_path.exists() {
        let vault_key = core_crypto::derive_vault_key(secure_master_key.as_bytes(), &target);
        let vp = vault_path;
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::task::spawn_blocking(move || SqlCipherStore::open(&vp, &vault_key)),
        )
        .await
        {
            Ok(Ok(Ok(store))) => {
                tracing::info!(profile = %target, ssh_fingerprint = %ssh_fingerprint, "vault key verified via SSH");
                (true, Some(store))
            }
            Ok(Ok(Err(e))) => {
                tracing::warn!(error = %e, profile = %target, "SSH unlock vault key verification failed");
                (false, None)
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, profile = %target, "SSH unlock spawn_blocking failed");
                (false, None)
            }
            Err(_) => {
                tracing::error!(profile = %target, "SSH unlock vault open timed out (10s) — possible seccomp violation");
                (false, None)
            }
        }
    } else {
        // No vault DB yet — accept the master key on faith.
        (true, None)
    };

    if success {
        ctx.vault_state
            .master_keys
            .insert(target.clone(), secure_master_key);
        if let Some(store) = verified_store {
            let jit = JitDelivery::new(store, ctx.vault_state.ttl);
            ctx.vault_state.vaults.insert(target.clone(), jit);
        }
        tracing::info!(profile = %target, ssh_fingerprint = %ssh_fingerprint, "vault unlocked via SSH");
    }

    audit_secret_access(
        "ssh-unlock",
        msg.sender,
        &target,
        None,
        if success { "success" } else { "failed" },
    );
    Ok(Some(EventKind::UnlockResponse {
        success,
        profile: target,
    }))
}

/// Handle `FactorSubmit` event.
pub(crate) async fn handle_factor_submit(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    factor_id: &AuthFactorId,
    key_material: &core_types::SensitiveBytes,
    profile: &TrustProfileName,
    audit_metadata: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<Option<EventKind>> {
    let target = profile.clone();

    if ctx.vault_state.master_keys.contains_key(&target) {
        return send_response_early(
            ctx.client,
            msg,
            EventKind::FactorResponse {
                accepted: false,
                unlock_complete: false,
                remaining_factors: vec![],
                remaining_additional: 0,
                profile: target,
                error: Some("already unlocked".into()),
            },
            ctx.daemon_id,
        )
        .await;
    }

    // Load vault metadata.
    let meta = match core_auth::VaultMetadata::load(&ctx.vault_state.config_dir, &target) {
        Ok(m) => m,
        Err(e) => {
            return send_response_early(
                ctx.client,
                msg,
                EventKind::FactorResponse {
                    accepted: false,
                    unlock_complete: false,
                    remaining_factors: vec![],
                    remaining_additional: 0,
                    profile: target,
                    error: Some(format!("vault metadata error: {e}")),
                },
                ctx.daemon_id,
            )
            .await;
        }
    };

    // Verify factor is enrolled.
    if !meta.has_factor(*factor_id) {
        return send_response_early(
            ctx.client,
            msg,
            EventKind::FactorResponse {
                accepted: false,
                unlock_complete: false,
                remaining_factors: vec![],
                remaining_additional: 0,
                profile: target,
                error: Some(format!("factor {factor_id} not enrolled")),
            },
            ctx.daemon_id,
        )
        .await;
    }

    // Copy directly from SensitiveBytes' ProtectedAlloc into SecureBytes' ProtectedAlloc.
    let secure_key = SecureBytes::from_slice(key_material.as_bytes());

    // For any/policy mode: verify the key against the vault DB.
    let vault_path = ctx
        .vault_state
        .config_dir
        .join("vaults")
        .join(format!("{target}.db"));
    if vault_path.exists()
        && meta.contribution_type() == core_auth::FactorContribution::CompleteMasterKey
    {
        let vault_key = core_crypto::derive_vault_key(secure_key.as_bytes(), &target);
        let vp = vault_path;
        let verify_ok = matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::task::spawn_blocking(move || SqlCipherStore::open(&vp, &vault_key)),
            )
            .await,
            Ok(Ok(Ok(_store)))
        );
        if !verify_ok {
            audit_secret_access(
                "factor-submit",
                msg.sender,
                &target,
                None,
                "factor-verification-failed",
            );
            return send_response_early(
                ctx.client,
                msg,
                EventKind::FactorResponse {
                    accepted: false,
                    unlock_complete: false,
                    remaining_factors: vec![],
                    remaining_additional: 0,
                    profile: target,
                    error: Some("factor key verification failed".into()),
                },
                ctx.daemon_id,
            )
            .await;
        }
    }

    // Determine required factors based on policy.
    let (remaining_required, remaining_additional) = match &meta.auth_policy {
        AuthCombineMode::Any => {
            // Any single factor suffices — no partial state needed.
            (HashSet::new(), 0u32)
        }
        AuthCombineMode::All => {
            let all_factors: HashSet<AuthFactorId> =
                meta.enrolled_factors.iter().map(|f| f.factor_id).collect();
            (all_factors, 0)
        }
        AuthCombineMode::Policy(policy) => {
            let required: HashSet<AuthFactorId> = policy.required.iter().copied().collect();
            (required, policy.additional_required)
        }
    };

    // Get or create partial unlock state.
    let partial = ctx
        .vault_state
        .partial_unlocks
        .entry(target.clone())
        .or_insert_with(|| PartialUnlock {
            received_factors: HashMap::new(),
            remaining_required: remaining_required.clone(),
            remaining_additional,
            deadline: tokio::time::Instant::now()
                + Duration::from_secs(PARTIAL_UNLOCK_TIMEOUT_SECS),
        });

    // Check if expired.
    if partial.is_expired() {
        ctx.vault_state.partial_unlocks.remove(&target);
        return send_response_early(
            ctx.client,
            msg,
            EventKind::FactorResponse {
                accepted: false,
                unlock_complete: false,
                remaining_factors: vec![],
                remaining_additional: 0,
                profile: target,
                error: Some("partial unlock expired".into()),
            },
            ctx.daemon_id,
        )
        .await;
    }

    // Record factor.
    let partial = ctx.vault_state.partial_unlocks.get_mut(&target).unwrap();
    partial
        .received_factors
        .insert(*factor_id, secure_key.clone());
    partial.remaining_required.remove(factor_id);

    // For policy mode: check if this factor counts as an additional.
    if !remaining_required.contains(factor_id) && partial.remaining_additional > 0 {
        partial.remaining_additional -= 1;
    }

    // For "any" mode: one factor is enough.
    if matches!(meta.auth_policy, AuthCombineMode::Any) {
        partial.remaining_required.clear();
        partial.remaining_additional = 0;
    }

    let complete = partial.is_complete();
    let remaining_factors_list: Vec<AuthFactorId> =
        partial.remaining_required.iter().copied().collect();
    let remaining_add = partial.remaining_additional;

    if complete {
        // Promote to unlocked.
        let partial = ctx.vault_state.partial_unlocks.remove(&target).unwrap();

        // For "all" mode: combine factor pieces via HKDF.
        let master_key = if meta.contribution_type() == core_auth::FactorContribution::FactorPiece {
            let mut pieces: Vec<_> = partial.received_factors.into_iter().collect();
            pieces.sort_by_key(|(id, _)| *id);
            let mut combined = Vec::new();
            for (_id, piece) in &pieces {
                combined.extend_from_slice(piece.as_bytes());
            }
            let ctx_str = format!("{ALL_MODE_KDF_CONTEXT} {target}");
            let derived: [u8; 32] = blake3::derive_key(&ctx_str, &combined);
            combined.zeroize();
            SecureBytes::new(derived.to_vec())
        } else {
            // Any/policy mode: all factors unwrap to the same key.
            // Use the first one.
            partial
                .received_factors
                .into_values()
                .next()
                .expect("at least one factor received")
        };

        ctx.vault_state
            .master_keys
            .insert(target.clone(), master_key);

        let fp = audit_metadata
            .get("ssh_fingerprint")
            .cloned()
            .unwrap_or_default();
        tracing::info!(
            profile = %target,
            factor = %factor_id,
            ssh_fingerprint = %fp,
            "vault unlocked via multi-factor"
        );
        audit_secret_access("factor-unlock", msg.sender, &target, None, "success");
    } else {
        tracing::info!(
            profile = %target,
            factor = %factor_id,
            remaining = ?remaining_factors_list,
            remaining_additional = remaining_add,
            "factor accepted, awaiting more"
        );
        audit_secret_access(
            "factor-submit",
            msg.sender,
            &target,
            None,
            "accepted-partial",
        );
    }

    Ok(Some(EventKind::FactorResponse {
        accepted: true,
        unlock_complete: complete,
        remaining_factors: remaining_factors_list,
        remaining_additional: remaining_add,
        profile: target,
        error: None,
    }))
}

/// Handle `VaultAuthQuery` event.
pub(crate) fn handle_vault_auth_query(
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
) -> Option<EventKind> {
    let target = profile.clone();
    let meta = core_auth::VaultMetadata::load(&ctx.vault_state.config_dir, &target);

    match meta {
        Ok(m) => {
            let enrolled: Vec<AuthFactorId> =
                m.enrolled_factors.iter().map(|f| f.factor_id).collect();
            let partial_in_progress = ctx.vault_state.partial_unlocks.contains_key(&target);
            let received: Vec<AuthFactorId> = ctx
                .vault_state
                .partial_unlocks
                .get(&target)
                .map(|p| p.received_factors.keys().copied().collect())
                .unwrap_or_default();
            Some(EventKind::VaultAuthQueryResponse {
                profile: target,
                enrolled_factors: enrolled,
                auth_policy: m.auth_policy,
                partial_in_progress,
                received_factors: received,
            })
        }
        Err(e) => {
            tracing::warn!(
                profile = %target,
                error = %e,
                "vault auth query failed"
            );
            Some(EventKind::VaultAuthQueryResponse {
                profile: target,
                enrolled_factors: vec![],
                auth_policy: AuthCombineMode::Any,
                partial_in_progress: false,
                received_factors: vec![],
            })
        }
    }
}

/// Handle `LockRequest` event.
pub(crate) async fn handle_lock_request(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &Option<TrustProfileName>,
) -> Option<EventKind> {
    let profiles_locked: Vec<TrustProfileName> = match profile {
        Some(target) => {
            // Lock single profile.
            ctx.vault_state.active_profiles.remove(target);
            if let Some(vault) = ctx.vault_state.vaults.remove(target) {
                vault.flush().await;
                vault.store().pragma_rekey_clear();
                drop(vault);
            }
            ctx.vault_state.master_keys.remove(target); // zeroizes on drop
            ctx.vault_state.partial_unlocks.remove(target); // zeroizes on drop
            #[cfg(target_os = "linux")]
            crate::keyring::keyring_delete_profile(target).await;
            tracing::info!(profile = %target, "vault locked, key material zeroized");
            vec![target.clone()]
        }
        None => {
            // Lock all profiles.
            let locked: Vec<TrustProfileName> =
                ctx.vault_state.master_keys.keys().cloned().collect();
            ctx.vault_state.active_profiles.clear();
            for (_profile, vault) in ctx.vault_state.vaults.drain() {
                vault.flush().await;
                vault.store().pragma_rekey_clear();
                drop(vault);
            }
            ctx.vault_state.master_keys.clear(); // each SecureBytes zeroizes on drop
            ctx.vault_state.partial_unlocks.clear(); // each SecureBytes zeroizes on drop
            #[cfg(target_os = "linux")]
            crate::keyring::keyring_delete_all(&locked).await;
            tracing::info!("all vaults locked, key material zeroized");
            locked
        }
    };
    *ctx.rate_limiter = SecretRateLimiter::new();
    audit_secret_access("lock", msg.sender, "-", None, "success");
    Some(EventKind::LockResponse {
        success: true,
        profiles_locked,
    })
}
