//! Vault unlock/lock lifecycle: factor submission under the vault's auth
//! policy, vault auth query, and lock.
//!
//! Every unlock is a sequence of `FactorSubmit` requests. Clients unwrap
//! the master key with a core-auth backend (password, SSH agent) and submit
//! it as one factor; this module enforces the vault's policy (`Any`, `All`,
//! `Policy`) over the factors received and verifies the resulting key
//! against the vault database before it is installed.

use crate::acl::audit_secret_access;
use crate::dispatch::MessageContext;
use crate::rate_limit::SecretRateLimiter;
use crate::vault::{
    MasterKey, PARTIAL_UNLOCK_TIMEOUT, PartialUnlock, VaultState, existing_vault, open_vault,
};

use core_auth::{FactorContribution, VaultMetadata};
use core_crypto::SecureBytes;
use core_ipc::Message;
use core_layout::Layout;
use core_secrets::{JitDelivery, SqlCipherStore};
use core_types::{AuthCombineMode, AuthFactorId, EventKind, TrustProfileName};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Open `profile`'s vault database with `key` when it exists: the store
/// (cached for the first activation), `None` when there is no database yet
/// (the first open after unlock creates it under `key`).
async fn verify_key(
    layout: &Layout,
    key: &MasterKey,
    profile: &TrustProfileName,
) -> core_types::Result<Option<SqlCipherStore>> {
    match existing_vault(layout, profile)? {
        Some(path) => Ok(Some(open_vault(path, key, profile).await?)),
        None => Ok(None),
    }
}

/// A rejected `FactorResponse` for `profile`, carrying `error`.
fn factor_rejected(profile: &TrustProfileName, error: String) -> EventKind {
    EventKind::FactorResponse {
        accepted: false,
        unlock_complete: false,
        remaining_factors: vec![],
        remaining_additional: 0,
        profile: profile.clone(),
        error: Some(error),
    }
}

/// The factors the vault's policy requires, and how many additional
/// factors beyond them.
fn requirements(meta: &VaultMetadata) -> (HashSet<AuthFactorId>, u32) {
    match &meta.auth_policy {
        // Any single factor suffices.
        AuthCombineMode::Any => (HashSet::new(), 0),
        AuthCombineMode::All => (
            meta.enrolled_factors.iter().map(|f| f.factor_id).collect(),
            0,
        ),
        AuthCombineMode::Policy(policy) => (
            policy.required.iter().copied().collect(),
            policy.additional_required,
        ),
    }
}

/// Where a vault's unlock stands after a factor.
enum Progress {
    /// The policy is satisfied: every factor received.
    Complete(HashMap<AuthFactorId, SecureBytes>),
    /// The factors still required and how many additional ones.
    Partial {
        remaining: Vec<AuthFactorId>,
        additional: u32,
    },
}

/// Record `factor_id`'s `key` in `profile`'s partial unlock (created on
/// the first factor). `None` when the partial unlock has expired; it is
/// discarded.
fn record_factor(
    state: &mut VaultState,
    profile: &TrustProfileName,
    factor_id: AuthFactorId,
    key: &SecureBytes,
    meta: &VaultMetadata,
) -> Option<Progress> {
    let (required, additional) = requirements(meta);
    let partial = state
        .partial_unlocks
        .entry(profile.clone())
        .or_insert_with(|| PartialUnlock {
            received_factors: HashMap::new(),
            remaining_required: required.clone(),
            remaining_additional: additional,
            deadline: tokio::time::Instant::now() + PARTIAL_UNLOCK_TIMEOUT,
        });
    if partial.is_expired() {
        state.partial_unlocks.remove(profile);
        return None;
    }
    partial.received_factors.insert(factor_id, key.clone());
    partial.remaining_required.remove(&factor_id);
    // A factor outside the required set counts as an additional one.
    if !required.contains(&factor_id) && partial.remaining_additional > 0 {
        partial.remaining_additional -= 1;
    }
    // Any mode: one factor is enough.
    if matches!(meta.auth_policy, AuthCombineMode::Any) {
        partial.remaining_required.clear();
        partial.remaining_additional = 0;
    }
    if partial.is_complete() {
        let received = std::mem::take(&mut partial.received_factors);
        state.partial_unlocks.remove(profile);
        Some(Progress::Complete(received))
    } else {
        Some(Progress::Partial {
            remaining: partial.remaining_required.iter().copied().collect(),
            additional: partial.remaining_additional,
        })
    }
}

/// What a submitted factor's key proved against the vault database.
enum Submission {
    /// A factor piece of an `All` vault: not a key on its own.
    Piece,
    /// A complete master key that opens the vault: its store, `None` when
    /// no database exists yet.
    Verified(Option<Box<SqlCipherStore>>),
}

/// Install `profile`'s master key once its policy is satisfied: the
/// combined key of an `All` vault is derived from the `received` pieces
/// and verified here, the first point it exists; any/policy keys were
/// verified on submission.
async fn complete_unlock(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: &TrustProfileName,
    meta: &VaultMetadata,
    received: HashMap<AuthFactorId, SecureBytes>,
    submitted: MasterKey,
    submission: Submission,
) -> Result<(), String> {
    let master_key = if meta.contribution_type() == FactorContribution::FactorPiece {
        let pieces: Vec<(AuthFactorId, &[u8])> = received
            .iter()
            .map(|(id, piece)| (*id, piece.as_bytes()))
            .collect();
        let hkdf = meta.algorithms.hkdf;
        MasterKey {
            key: core_auth::combine_factor_pieces(profile, hkdf, &pieces),
            hkdf,
        }
    } else {
        // Every factor unwraps to the same master key; this factor's key is
        // the one verified against the vault.
        submitted
    };
    let verified_store = match submission {
        Submission::Verified(store) => store.map(|store| *store),
        Submission::Piece => verify_key(&ctx.vault_state.layout, &master_key, profile)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, %profile, "combined key verification failed");
                audit_secret_access(
                    "factor-unlock",
                    msg.sender,
                    profile,
                    None,
                    "combined-key-rejected",
                );
                format!("the submitted factors do not open the vault: {e}")
            })?,
    };
    if let Some(store) = verified_store {
        let jit = JitDelivery::new(store, ctx.vault_state.ttl);
        ctx.vault_state.vaults.insert(profile.clone(), jit);
    }
    ctx.vault_state
        .master_keys
        .insert(profile.clone(), master_key);
    Ok(())
}

/// Handle `FactorSubmit`: verify and record the factor under the vault's
/// policy, installing the master key once the policy is satisfied.
pub(crate) async fn handle_factor_submit(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    factor_id: AuthFactorId,
    key_material: &core_types::SensitiveBytes,
    profile: &TrustProfileName,
    audit_metadata: &BTreeMap<String, String>,
) -> EventKind {
    if ctx.vault_state.master_keys.contains_key(profile) {
        audit_secret_access(
            "factor-submit",
            msg.sender,
            profile,
            None,
            "rejected-already-unlocked",
        );
        return EventKind::UnlockRejected {
            reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
            profile: Some(profile.clone()),
        };
    }
    let meta = match VaultMetadata::load(&ctx.vault_state.layout, profile) {
        Ok(meta) => meta,
        Err(e) => return factor_rejected(profile, format!("vault metadata error: {e}")),
    };
    if !meta.has_factor(factor_id) {
        return factor_rejected(profile, format!("factor {factor_id} not enrolled"));
    }

    // Copied from SensitiveBytes' protected allocation into SecureBytes';
    // every key of the vault derives under its metadata's algorithm.
    let submitted = MasterKey {
        key: SecureBytes::from_slice(key_material.as_bytes()),
        hkdf: meta.algorithms.hkdf,
    };
    // Any/policy mode: every factor unwraps the master key itself, so it is
    // verified against the vault database now (the opened store is kept
    // for the unlock it may complete). All mode: a piece is not a key.
    let submission = if meta.contribution_type() == FactorContribution::CompleteMasterKey {
        match verify_key(&ctx.vault_state.layout, &submitted, profile).await {
            Ok(store) => Submission::Verified(store.map(Box::new)),
            Err(e) => {
                tracing::warn!(error = %e, %profile, factor = %factor_id, "factor key verification failed");
                audit_secret_access(
                    "factor-submit",
                    msg.sender,
                    profile,
                    None,
                    "factor-verification-failed",
                );
                return factor_rejected(profile, "factor key verification failed".into());
            }
        }
    } else {
        Submission::Piece
    };

    let Some(progress) = record_factor(ctx.vault_state, profile, factor_id, &submitted.key, &meta)
    else {
        return factor_rejected(profile, "partial unlock expired".into());
    };
    let (complete, remaining_factors, remaining_additional) = match progress {
        Progress::Complete(received) => {
            if let Err(error) =
                complete_unlock(msg, ctx, profile, &meta, received, submitted, submission).await
            {
                return factor_rejected(profile, error);
            }
            tracing::info!(
                %profile,
                factor = %factor_id,
                ssh_fingerprint = audit_metadata.get("ssh_fingerprint").map(String::as_str),
                "vault unlocked"
            );
            audit_secret_access("factor-unlock", msg.sender, profile, None, "success");
            (true, vec![], 0)
        }
        Progress::Partial {
            remaining,
            additional,
        } => {
            tracing::info!(%profile, factor = %factor_id, ?remaining, additional, "factor accepted, awaiting more");
            audit_secret_access(
                "factor-submit",
                msg.sender,
                profile,
                None,
                "accepted-partial",
            );
            (false, remaining, additional)
        }
    };
    EventKind::FactorResponse {
        accepted: true,
        unlock_complete: complete,
        remaining_factors,
        remaining_additional,
        profile: profile.clone(),
        error: None,
    }
}

/// The `VaultAuthQueryResponse` for `profile`: its enrolled factors and
/// policy, and the factors a partial unlock has received; or the reason
/// its metadata cannot be read.
pub(crate) fn vault_auth_requirements(state: &VaultState, profile: &TrustProfileName) -> EventKind {
    match VaultMetadata::load(&state.layout, profile) {
        Ok(meta) => {
            let partial = state.partial_unlocks.get(profile);
            EventKind::VaultAuthQueryResponse {
                profile: profile.clone(),
                enrolled_factors: meta.enrolled_factors.iter().map(|f| f.factor_id).collect(),
                auth_policy: meta.auth_policy,
                partial_in_progress: partial.is_some(),
                received_factors: partial
                    .map(|p| p.received_factors.keys().copied().collect())
                    .unwrap_or_default(),
                error: None,
            }
        }
        Err(e) => {
            tracing::warn!(%profile, error = %e, "vault auth query failed");
            EventKind::VaultAuthQueryResponse {
                profile: profile.clone(),
                enrolled_factors: vec![],
                auth_policy: AuthCombineMode::Any,
                partial_in_progress: false,
                received_factors: vec![],
                error: Some(format!("vault metadata error: {e}")),
            }
        }
    }
}

/// Handle `LockRequest`: lock `profile`, or every vault.
pub(crate) async fn handle_lock_request(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
    profile: Option<&TrustProfileName>,
) -> EventKind {
    let profiles_locked = match profile {
        Some(target) => {
            ctx.vault_state.lock(target).await;
            vec![target.clone()]
        }
        None => ctx.vault_state.lock_all().await,
    };
    *ctx.rate_limiter = SecretRateLimiter::new();
    audit_secret_access("lock", msg.sender, "-", None, "success");
    EventKind::LockResponse {
        success: true,
        profiles_locked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{empty_vault_state, profile};
    use core_types::{AuthPolicy, CryptoConfig};

    fn vault(policy: AuthCombineMode) -> VaultMetadata {
        VaultMetadata::new(
            vec![
                (AuthFactorId::Password, "master password".into()),
                (AuthFactorId::SshAgent, "SHA256:abc".into()),
            ],
            policy,
            &CryptoConfig::default(),
        )
        .unwrap()
    }

    /// Submit `factors` in order; the progress after each.
    fn submit(meta: &VaultMetadata, factors: &[AuthFactorId]) -> Vec<Option<Progress>> {
        let dir = tempfile::tempdir().unwrap();
        let mut state = empty_vault_state(dir.path());
        factors
            .iter()
            .map(|&factor| {
                let key = SecureBytes::from_slice(&[factor as u8; 32]);
                record_factor(&mut state, &profile("work"), factor, &key, meta)
            })
            .collect()
    }

    fn is_complete(progress: Option<&Progress>, factors: usize) -> bool {
        matches!(progress, Some(Progress::Complete(received)) if received.len() == factors)
    }

    #[test]
    fn any_completes_on_the_first_factor() {
        let progress = submit(&vault(AuthCombineMode::Any), &[AuthFactorId::SshAgent]);
        assert!(is_complete(progress[0].as_ref(), 1));
    }

    #[test]
    fn all_completes_once_every_factor_is_received() {
        let progress = submit(
            &vault(AuthCombineMode::All),
            &[AuthFactorId::Password, AuthFactorId::SshAgent],
        );
        assert!(matches!(
            &progress[0],
            Some(Progress::Partial { remaining, additional: 0 }) if remaining == &[AuthFactorId::SshAgent]
        ));
        assert!(is_complete(progress[1].as_ref(), 2));
    }

    #[test]
    fn a_policy_counts_factors_outside_the_required_set_as_additional() {
        let policy = AuthCombineMode::Policy(AuthPolicy {
            required: vec![AuthFactorId::Password],
            additional_required: 1,
        });
        let progress = submit(
            &vault(policy),
            &[AuthFactorId::SshAgent, AuthFactorId::Password],
        );
        assert!(matches!(
            &progress[0],
            Some(Progress::Partial { remaining, additional: 0 }) if remaining == &[AuthFactorId::Password]
        ));
        assert!(is_complete(progress[1].as_ref(), 2));
    }

    #[test]
    fn an_expired_partial_unlock_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = empty_vault_state(dir.path());
        let meta = vault(AuthCombineMode::All);
        let work = profile("work");
        let key = SecureBytes::from_slice(&[1; 32]);
        record_factor(&mut state, &work, AuthFactorId::Password, &key, &meta);
        state.partial_unlocks.get_mut(&work).unwrap().deadline = tokio::time::Instant::now();
        assert!(record_factor(&mut state, &work, AuthFactorId::SshAgent, &key, &meta).is_none());
        assert!(!state.partial_unlocks.contains_key(&work));
    }
}
