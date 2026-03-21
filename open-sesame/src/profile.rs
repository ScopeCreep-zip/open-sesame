use anyhow::Context;
use comfy_table::{Table, presets::UTF8_FULL};
use core_types::{EventKind, ProfileId, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_profile_list() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::ProfileList, SecurityLevel::Internal).await? {
        EventKind::ProfileListResponse { profiles } => {
            if profiles.is_empty() {
                println!("{}", "No profiles configured.".dimmed());
                return Ok(());
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Name", "Active", "Default"]);

            for p in &profiles {
                let active = if p.is_active {
                    "yes".green().to_string()
                } else {
                    "no".dimmed().to_string()
                };
                let default = if p.is_default {
                    "yes".green().to_string()
                } else {
                    "".to_string()
                };
                let name_str = p.name.to_string();
                table.add_row(vec![&name_str, &active, &default]);
            }

            println!("{table}");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_profile_activate(name: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile_name = TrustProfileName::try_from(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::ProfileActivate {
        target: ProfileId::new(),
        profile_name,
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileActivateResponse { success: true } => {
            println!("Profile '{}' activated.", name.green());
        }
        EventKind::ProfileActivateResponse { success: false } => {
            anyhow::bail!("failed to activate profile '{name}'");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_profile_deactivate(name: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile_name = TrustProfileName::try_from(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::ProfileDeactivate {
        target: ProfileId::new(),
        profile_name,
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileDeactivateResponse { success: true } => {
            println!("Profile '{}' deactivated.", name.green());
        }
        EventKind::ProfileDeactivateResponse { success: false } => {
            anyhow::bail!("failed to deactivate profile '{name}' — not active?");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_profile_default(name: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile_name = TrustProfileName::try_from(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SetDefaultProfile { profile_name };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SetDefaultProfileResponse { success: true } => {
            println!("Default profile set to '{}'.", name.green());
        }
        EventKind::SetDefaultProfileResponse { success: false } => {
            anyhow::bail!("failed to set default profile to '{name}'");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) fn cmd_profile_show(name: &str) -> anyhow::Result<()> {
    let config = core_config::load_config(None).context("failed to load config")?;

    let profile = config
        .profiles
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("profile '{name}' not found in config"))?;

    let toml_str = toml::to_string_pretty(profile).context("failed to serialize profile config")?;

    println!("Profile: {}", name.bold());
    if name == config.global.default_profile.as_ref() {
        println!("(default profile)");
    }
    println!();
    println!("{toml_str}");

    Ok(())
}
