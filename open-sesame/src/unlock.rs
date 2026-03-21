use anyhow::Context;
use core_auth::VaultAuthBackend as _;
use core_ipc::BusClient;
use core_types::{AuthFactorId, EventKind, SecurityLevel, SensitiveBytes, TrustProfileName};
use owo_colors::OwoColorize;
use zeroize::Zeroize;

use crate::ipc::{connect, resolve_profile_specs, rpc};

/// Submit a single factor via `FactorSubmit` IPC and handle the response.
///
/// Returns `Ok(true)` if the vault is now fully unlocked, `Ok(false)` if more
/// factors are still needed (partial unlock accepted), or an error on rejection.
async fn submit_factor(
    client: &BusClient,
    factor_id: AuthFactorId,
    outcome: core_auth::UnlockOutcome,
    profile: &TrustProfileName,
) -> anyhow::Result<bool> {
    let event = EventKind::FactorSubmit {
        factor_id,
        key_material: SensitiveBytes::new(outcome.master_key.into_vec()),
        profile: profile.clone(),
        audit_metadata: outcome.audit_metadata,
    };

    match rpc(client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::FactorResponse {
            accepted: true,
            unlock_complete: true,
            profile: p,
            ..
        } => {
            println!(
                "{}",
                format!("Vault '{p}' unlocked via {factor_id}.").green()
            );
            Ok(true)
        }
        EventKind::FactorResponse {
            accepted: true,
            unlock_complete: false,
            remaining_factors,
            remaining_additional,
            ..
        } => {
            let remaining_names: Vec<String> =
                remaining_factors.iter().map(|f| f.to_string()).collect();
            tracing::debug!(
                remaining = ?remaining_names,
                additional = remaining_additional,
                "factor accepted, more required"
            );
            Ok(false)
        }
        EventKind::FactorResponse {
            accepted: false,
            error,
            ..
        } => {
            let msg = error.unwrap_or_else(|| "unknown error".into());
            anyhow::bail!("factor {factor_id} rejected: {msg}");
        }
        EventKind::UnlockRejected {
            reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
            profile: p,
        } => {
            println!(
                "{}",
                format!(
                    "Vault '{}' already unlocked.",
                    p.as_ref().map_or("unknown", |v| v.as_ref())
                )
                .yellow()
            );
            Ok(true)
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// Try to submit a non-interactive factor (SSH agent).
/// Returns `Ok(Some(true))` if vault is unlocked, `Ok(Some(false))` if partial,
/// `Ok(None)` if factor was not attempted, or `Err` on hard failure.
async fn try_auto_factor(
    client: &BusClient,
    factor_id: AuthFactorId,
    meta: &core_auth::VaultMetadata,
    profile: &TrustProfileName,
    config_dir: &std::path::Path,
    salt: &[u8],
) -> anyhow::Result<Option<bool>> {
    if !meta.has_factor(factor_id) {
        return Ok(None);
    }

    match factor_id {
        AuthFactorId::SshAgent => {
            let backend = core_auth::SshAgentBackend::new();
            if !backend.can_unlock(profile, config_dir).await {
                return Ok(None);
            }
            match core_auth::VaultAuthBackend::unlock(&backend, profile, config_dir, salt).await {
                Ok(outcome) => match submit_factor(client, factor_id, outcome, profile).await {
                    Ok(complete) => Ok(Some(complete)),
                    Err(e) => {
                        tracing::debug!(error = %e, "SSH factor rejected");
                        Ok(None)
                    }
                },
                Err(e) => {
                    tracing::debug!(error = %e, "SSH auto-unlock failed");
                    Ok(None)
                }
            }
        }
        _ => Ok(None),
    }
}

/// Prompt for password and submit as a factor.
/// Returns `Ok(true)` if vault is unlocked, `Ok(false)` if partial.
async fn prompt_password_factor(
    client: &BusClient,
    profile: &TrustProfileName,
    profile_name: &str,
    config_dir: &std::path::Path,
    salt: &[u8],
) -> anyhow::Result<bool> {
    let mut password = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        dialoguer::Password::new()
            .with_prompt(format!("Password for vault '{profile_name}'"))
            .interact()
            .context("failed to read password")?
    } else {
        let mut buf = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buf)
            .context("failed to read password from stdin")?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            anyhow::bail!(
                "empty password from stdin for vault '{profile_name}' — refusing to unlock"
            );
        }
        buf
    };

    let mut password_sv = core_crypto::SecureVec::new();
    for ch in password.chars() {
        password_sv.push_char(ch);
    }
    password.zeroize();

    let pw_backend = core_auth::PasswordBackend::new().with_password(password_sv);
    let outcome = core_auth::VaultAuthBackend::unlock(&pw_backend, profile, config_dir, salt)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "password unlock failed for vault '{profile_name}': {e}\n\
                 Check your password or re-initialize the vault."
            )
        })?;

    submit_factor(client, AuthFactorId::Password, outcome, profile).await
}

pub(crate) async fn cmd_unlock(profile_arg: Option<String>) -> anyhow::Result<()> {
    let client = connect().await?;

    let specs = resolve_profile_specs(profile_arg.as_deref());
    let config_dir = core_config::config_dir();

    for spec in &specs {
        let profile_name = &spec.vault;
        let target_profile = TrustProfileName::try_from(profile_name.as_str())
            .map_err(|e| anyhow::anyhow!("invalid profile name '{profile_name}': {e}"))?;

        let salt_path = config_dir
            .join("vaults")
            .join(format!("{target_profile}.salt"));
        let salt = std::fs::read(&salt_path)
            .context("failed to read vault salt — is the vault initialized?")?;

        let meta = core_auth::VaultMetadata::load(&config_dir, &target_profile)
            .context("failed to load vault metadata — is the vault initialized?")?;

        // Collect enrolled factor IDs for iteration.
        let enrolled: Vec<AuthFactorId> =
            meta.enrolled_factors.iter().map(|f| f.factor_id).collect();

        // Phase 1: Submit all non-interactive factors (SSH agent).
        let mut unlocked = false;
        for &factor in &enrolled {
            if unlocked {
                break;
            }
            match try_auto_factor(&client, factor, &meta, &target_profile, &config_dir, &salt)
                .await?
            {
                Some(true) => {
                    unlocked = true;
                }
                Some(false) => {
                    tracing::debug!(
                        factor = %factor,
                        "auto factor accepted, more factors needed"
                    );
                }
                None => {}
            }
        }

        if unlocked {
            continue;
        }

        // Phase 2: Query daemon for remaining factors.
        let remaining = match rpc(
            &client,
            EventKind::VaultAuthQuery {
                profile: target_profile.clone(),
            },
            SecurityLevel::SecretsOnly,
        )
        .await?
        {
            EventKind::VaultAuthQueryResponse {
                enrolled_factors: ef,
                partial_in_progress,
                received_factors,
                ..
            } => {
                if partial_in_progress {
                    // Filter out already-received factors.
                    ef.iter()
                        .filter(|f| !received_factors.contains(f))
                        .copied()
                        .collect::<Vec<_>>()
                } else {
                    ef
                }
            }
            _ => enrolled.clone(),
        };

        // Phase 3: Submit interactive factors.
        for &factor in &remaining {
            if unlocked {
                break;
            }
            match factor {
                AuthFactorId::Password => {
                    if !meta.has_factor(AuthFactorId::Password) {
                        continue;
                    }
                    match prompt_password_factor(
                        &client,
                        &target_profile,
                        profile_name,
                        &config_dir,
                        &salt,
                    )
                    .await
                    {
                        Ok(true) => {
                            unlocked = true;
                        }
                        Ok(false) => {
                            tracing::debug!("password factor accepted, more factors needed");
                        }
                        Err(e) => {
                            anyhow::bail!(
                                "password unlock failed for vault '{profile_name}': {e}\n\
                                 Check your password or re-initialize the vault."
                            );
                        }
                    }
                }
                other => {
                    // Future factors (FIDO2, TPM, etc.) are not yet implemented.
                    anyhow::bail!(
                        "vault '{profile_name}' requires factor '{other}' which is not \
                         yet supported in this CLI version.\n\
                         Enrolled factors: {enrolled:?}"
                    );
                }
            }
        }

        if !unlocked {
            anyhow::bail!(
                "failed to unlock vault '{profile_name}' — all available factors exhausted.\n\
                 Ensure your SSH key is loaded (ssh-add -l) or check your vault auth policy."
            );
        }
    }

    Ok(())
}

pub(crate) async fn cmd_lock(profile_arg: Option<String>) -> anyhow::Result<()> {
    let client = connect().await?;

    let target_profile = profile_arg
        .map(|p| TrustProfileName::try_from(p.as_str()))
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid profile name: {e}"))?;

    let event = EventKind::LockRequest {
        profile: target_profile,
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::LockResponse {
            success: true,
            profiles_locked,
        } => {
            if profiles_locked.is_empty() {
                println!("{}", "All vaults locked. Key material zeroized.".green());
            } else {
                for p in &profiles_locked {
                    println!(
                        "{}",
                        format!("Vault '{}' locked. Key material zeroized.", p).green()
                    );
                }
            }
        }
        EventKind::LockResponse { success: false, .. } => {
            anyhow::bail!("lock failed");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}
