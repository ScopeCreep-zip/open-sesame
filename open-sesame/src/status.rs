use core_types::{EventKind, SecurityLevel};
use owo_colors::OwoColorize;

use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_status() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::StatusRequest, SecurityLevel::Internal).await? {
        EventKind::StatusResponse {
            active_profiles,
            default_profile,
            locked,
            lock_state,
            ..
        } => {
            // Per-profile lock state display.
            if lock_state.is_empty() {
                // Fallback: daemon didn't return per-profile state, use global locked flag.
                let lock_status = if locked {
                    "locked".red().bold().to_string()
                } else {
                    "unlocked".green().bold().to_string()
                };
                println!("Secrets daemon: {lock_status}");
            } else {
                println!("Vaults:");
                let max_name_len = lock_state
                    .keys()
                    .map(|k| k.as_ref().len())
                    .max()
                    .unwrap_or(0);
                for (profile, is_locked) in &lock_state {
                    let status = if *is_locked {
                        "locked".red().bold().to_string()
                    } else {
                        "unlocked".green().bold().to_string()
                    };
                    println!(
                        "  {:width$}  {status}",
                        profile.as_ref(),
                        width = max_name_len
                    );
                }
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
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}
