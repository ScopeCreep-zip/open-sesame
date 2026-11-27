use anyhow::Context;
use core_auth::{AuthInteraction, FactorProgress, VaultAuthBackend, VaultKeying};
use core_ipc::BusClient;
use core_layout::Layout;
use core_types::{EventKind, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::helpers::unexpected;
use crate::ipc::{connect, rpc};
use open_sesame::cli::ProfileSpecs;

/// Submit one factor's key material: whether the vault is now unlocked
/// ([`FactorProgress::is_unlocked`]) or needs more factors.
///
/// # Errors
///
/// The request errors, a factor daemon-secrets refused, and any answer
/// that is not a factor response.
pub(crate) async fn submit_factor(
    client: &BusClient,
    outcome: core_auth::UnlockOutcome,
    profile: &TrustProfileName,
) -> anyhow::Result<FactorProgress> {
    let factor_id = outcome.factor_id;
    let event = outcome.into_factor_submit(profile);
    let progress =
        FactorProgress::from_response(rpc(client, event, SecurityLevel::SecretsOnly).await?)?;
    match &progress {
        FactorProgress::Unlocked => println!(
            "{}",
            format!("Vault '{profile}' unlocked via {factor_id}.").green()
        ),
        FactorProgress::AlreadyUnlocked => println!(
            "{}",
            format!("Vault '{profile}' already unlocked.").yellow()
        ),
        FactorProgress::MoreRequired => {
            tracing::debug!(%profile, %factor_id, "factor accepted, more required");
        }
        FactorProgress::Rejected { reason } => anyhow::bail!(
            "factor {factor_id} rejected: {}",
            reason.as_deref().unwrap_or("daemon-secrets gave no reason")
        ),
    }
    Ok(progress)
}

/// Submit the non-interactive factor `backend` provides when it can unlock
/// now. `None` when it cannot, or it failed: the failure is printed and
/// the other factors are tried.
async fn non_interactive_factor(
    client: &BusClient,
    layout: &Layout,
    profile: &TrustProfileName,
    keying: &VaultKeying,
    backend: &dyn VaultAuthBackend,
) -> anyhow::Result<Option<FactorProgress>> {
    if !backend.can_unlock(profile, layout).await? {
        return Ok(None);
    }
    let name = backend.name();
    match backend.unlock(profile, layout, keying).await {
        Ok(outcome) => match submit_factor(client, outcome, profile).await {
            Ok(progress) => Ok(Some(progress)),
            Err(e) => {
                eprintln!("{} {name} factor rejected: {e:#}", "WARN:".yellow().bold());
                Ok(None)
            }
        },
        Err(e) => {
            eprintln!("{} {name} unlock failed: {e}", "WARN:".yellow().bold());
            Ok(None)
        }
    }
}

/// Prompt for the vault password and submit it as a factor.
async fn password_factor(
    client: &BusClient,
    layout: &Layout,
    profile: &TrustProfileName,
    keying: &VaultKeying,
) -> anyhow::Result<FactorProgress> {
    let password = crate::prompt::password(&format!("Password for vault '{profile}'"))?;
    let backend = core_auth::PasswordBackend::new().with_password(password);
    let outcome = backend.unlock(profile, layout, keying).await.map_err(|e| {
        anyhow::anyhow!(
            "password unlock failed for vault '{profile}': {e}\n\
             Check your password or re-initialize the vault."
        )
    })?;
    submit_factor(client, outcome, profile).await
}

/// The factors `profile`'s vault still requires, from daemon-secrets.
async fn remaining_factors(
    client: &BusClient,
    profile: &TrustProfileName,
) -> anyhow::Result<Vec<core_types::AuthFactorId>> {
    let event = EventKind::VaultAuthQuery {
        profile: profile.clone(),
    };
    let response = rpc(client, event, SecurityLevel::SecretsOnly).await?;
    core_auth::remaining_factors(response).with_context(|| format!("vault '{profile}'"))
}

/// Unlock one vault: every factor it still requires, the non-interactive
/// ones first, then the password; after a password the vault's remaining
/// factors are read again.
pub(crate) async fn unlock_profile(
    client: &BusClient,
    layout: &Layout,
    profile: &TrustProfileName,
) -> anyhow::Result<()> {
    let (_, keying) = core_auth::VaultMetadata::load_keying(layout, profile)?;
    let auth = core_auth::AuthDispatcher::new(core_daemon::credential_store().await);
    let mut password_submitted = false;
    loop {
        let mut needs_password = false;
        for factor in remaining_factors(client, profile).await? {
            let backend = auth.backend(factor).ok_or_else(|| {
                anyhow::anyhow!(
                    "vault '{profile}' requires factor '{factor}', which this CLI cannot provide"
                )
            })?;
            match backend.requires_interaction() {
                AuthInteraction::None => {
                    let progress =
                        non_interactive_factor(client, layout, profile, &keying, backend).await?;
                    if progress.is_some_and(|p| p.is_unlocked()) {
                        return Ok(());
                    }
                }
                AuthInteraction::PasswordEntry => needs_password = true,
                AuthInteraction::HardwareTouch => anyhow::bail!(
                    "vault '{profile}' requires the {factor} factor (a hardware touch), \
                     which this CLI does not support"
                ),
            }
        }
        if !needs_password || password_submitted {
            anyhow::bail!(
                "failed to unlock vault '{profile}': every available factor was submitted.\n\
                 Ensure your SSH key is loaded (ssh-add -l), your login keyring is unlocked, \
                 or check your vault auth policy."
            );
        }
        password_submitted = true;
        if password_factor(client, layout, profile, &keying)
            .await?
            .is_unlocked()
        {
            return Ok(());
        }
    }
}

pub(crate) async fn cmd_unlock(layout: &Layout, specs: &ProfileSpecs) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    for spec in specs {
        unlock_profile(&client, layout, &spec.vault).await?;
    }
    Ok(())
}

pub(crate) async fn cmd_lock(
    layout: &Layout,
    profile: Option<TrustProfileName>,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(
        &client,
        EventKind::LockRequest { profile },
        SecurityLevel::SecretsOnly,
    )
    .await?
    {
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
                        format!("Vault '{p}' locked. Key material zeroized.").green()
                    );
                }
            }
            Ok(())
        }
        EventKind::LockResponse { success: false, .. } => anyhow::bail!("lock failed"),
        other => Err(unexpected(&other)),
    }
}
