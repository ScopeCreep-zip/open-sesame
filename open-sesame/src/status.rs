use core_layout::Layout;
use core_types::{EventKind, SecurityLevel};
use owo_colors::OwoColorize;

use crate::helpers::unexpected;
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_status(layout: &Layout) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let response = rpc(&client, EventKind::StatusRequest, SecurityLevel::Internal).await?;
    let EventKind::StatusResponse {
        active_profiles,
        default_profile,
        lock_state,
        ..
    } = response
    else {
        return Err(unexpected(&response));
    };

    match lock_state {
        None => println!(
            "Vaults: {}",
            "unknown (daemon-secrets is not answering; every vault is treated as locked)"
                .red()
                .bold()
        ),
        Some(lock_state) if lock_state.is_empty() => {
            println!("Vaults: {}", "none configured".dimmed());
        }
        Some(lock_state) => print_vaults(&lock_state),
    }

    println!("Default profile: {}", default_profile.as_ref().bold());
    if active_profiles.is_empty() {
        println!("Active profiles: {}", "none".dimmed());
    } else {
        println!("Active profiles:");
        for p in &active_profiles {
            let marker = if p == &default_profile {
                " (default)"
            } else {
                ""
            };
            println!("  - {p}{marker}");
        }
    }
    Ok(())
}

/// Each vault of `lock_state` with whether it is locked.
fn print_vaults(lock_state: &std::collections::BTreeMap<core_types::TrustProfileName, bool>) {
    println!("Vaults:");
    let width = lock_state.keys().map(|k| k.len()).max().unwrap_or_default();
    for (profile, locked) in lock_state {
        let state = if *locked {
            "locked".red().bold().to_string()
        } else {
            "unlocked".green().bold().to_string()
        };
        println!("  {:width$}  {state}", profile.as_ref());
    }
}

/// `sesame status --rotate-keys`: start a Noise IK key rotation.
pub(crate) async fn cmd_rotate_keys(layout: &Layout) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(
        &client,
        EventKind::KeyRotationRequest,
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::KeyRotationRequestResponse { success: true, .. } => {
            println!(
                "{} Key rotation initiated. Phase 2 completes in 30 seconds.",
                "✓".green().bold()
            );
            Ok(())
        }
        EventKind::KeyRotationRequestResponse {
            success: false,
            error,
        } => anyhow::bail!(
            "key rotation failed: {}",
            error.as_deref().unwrap_or("daemon-profile gave no reason")
        ),
        other => Err(unexpected(&other)),
    }
}
