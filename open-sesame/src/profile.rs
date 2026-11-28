use anyhow::Context;
use core_layout::Layout;
use core_types::{EventKind, ProfileId, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::helpers::{table, unexpected};
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_profile_list(layout: &Layout) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(&client, EventKind::ProfileList, SecurityLevel::Internal).await? {
        EventKind::ProfileListResponse { profiles } if profiles.is_empty() => {
            println!("{}", "No profiles configured.".dimmed());
        }
        EventKind::ProfileListResponse { profiles } => {
            let mut table = table(&["Name", "Active", "Default"]);
            for p in &profiles {
                let active = if p.is_active {
                    "yes".green().to_string()
                } else {
                    "no".dimmed().to_string()
                };
                let default = if p.is_default {
                    "yes".green().to_string()
                } else {
                    String::new()
                };
                table.add_row(vec![p.name.to_string(), active, default]);
            }
            println!("{table}");
        }
        other => return Err(unexpected(&other)),
    }
    Ok(())
}

pub(crate) async fn cmd_profile_activate(
    layout: &Layout,
    profile_name: TrustProfileName,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let name = profile_name.clone();
    let event = EventKind::ProfileActivate {
        target: ProfileId::new(),
        profile_name,
    };
    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileActivateResponse { success: true } => {
            println!("Profile '{}' activated.", name.green());
            Ok(())
        }
        EventKind::ProfileActivateResponse { success: false } => {
            anyhow::bail!("failed to activate profile '{name}'")
        }
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_profile_deactivate(
    layout: &Layout,
    profile_name: TrustProfileName,
) -> anyhow::Result<()> {
    let client = crate::ipc::connect_transport(layout).await?;
    let name = profile_name.clone();
    let event = EventKind::ProfileDeactivate {
        target: ProfileId::new(),
        profile_name,
    };
    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileDeactivateResponse { success: true } => {
            println!("Profile '{}' deactivated.", name.green());
            Ok(())
        }
        EventKind::ProfileDeactivateResponse { success: false } => {
            anyhow::bail!("failed to deactivate profile '{name}' — not active?")
        }
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_profile_default(
    layout: &Layout,
    profile_name: TrustProfileName,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let name = profile_name.clone();
    match rpc(
        &client,
        EventKind::SetDefaultProfile { profile_name },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::SetDefaultProfileResponse { success: true } => {
            println!("Default profile set to '{}'.", name.green());
            Ok(())
        }
        EventKind::SetDefaultProfileResponse { success: false } => {
            anyhow::bail!("failed to set default profile to '{name}'")
        }
        other => Err(unexpected(&other)),
    }
}

pub(crate) fn cmd_profile_show(layout: &Layout, name: &TrustProfileName) -> anyhow::Result<()> {
    let config = core_config::load_config(layout)?;
    let profile = config
        .profiles
        .get(name.as_ref())
        .ok_or_else(|| anyhow::anyhow!("profile '{name}' not found in config"))?;
    let toml_str = toml::to_string_pretty(profile).context("failed to serialize profile config")?;

    println!("Profile: {}", name.bold());
    if *name == config.global.default_profile {
        println!("(default profile)");
    }
    println!();
    println!("{toml_str}");
    Ok(())
}
