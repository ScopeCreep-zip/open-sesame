use std::io::Write;

use anyhow::Context;
use core_layout::Layout;
use core_types::{EventKind, SecurityLevel, SensitiveBytes, TrustProfileName, validate_secret_key};
use owo_colors::OwoColorize;

use crate::helpers::{format_denial_reason, unexpected, validate_profile_in_config};
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_secret_set(
    layout: &Layout,
    profile: &TrustProfileName,
    key: &str,
) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(layout, profile)?;
    let client = connect(layout).await?;
    let value = crate::prompt::secret_value(&format!("Value for '{key}'"))?;
    let event = EventKind::SecretSet {
        profile: profile.clone(),
        key: key.to_owned(),
        value: SensitiveBytes::from_slice(value.as_bytes()),
    };
    drop(value);

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretSetResponse {
            success: true,
            denial: None,
        } => {
            println!("Secret '{key}' stored in profile '{profile}'.");
            Ok(())
        }
        EventKind::SecretSetResponse {
            denial: Some(reason),
            ..
        } => anyhow::bail!("{}", format_denial_reason(&reason, key, profile)),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_secret_get(
    layout: &Layout,
    profile: &TrustProfileName,
    key: &str,
) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(layout, profile)?;
    let client = connect(layout).await?;
    let event = EventKind::SecretGet {
        profile: profile.clone(),
        key: key.to_owned(),
    };
    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretGetResponse {
            key,
            denial: Some(reason),
            ..
        } => anyhow::bail!("{}", format_denial_reason(&reason, &key, profile)),
        // The value is written byte-exact; a trailing newline follows it
        // on a terminal only, so piped output is the secret itself.
        EventKind::SecretGetResponse {
            value,
            denial: None,
            ..
        } => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(value.as_bytes())
                .context("failed to write the secret to stdout")?;
            if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                writeln!(stdout).context("failed to write to stdout")?;
            }
            stdout.flush().context("failed to write to stdout")
        }
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_secret_delete(
    layout: &Layout,
    profile: &TrustProfileName,
    key: &str,
    skip_confirm: bool,
) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(layout, profile)?;
    if !skip_confirm
        && !crate::prompt::confirm(&format!("Delete secret '{key}' from profile '{profile}'?"))?
    {
        println!("Cancelled.");
        return Ok(());
    }
    let client = connect(layout).await?;
    let event = EventKind::SecretDelete {
        profile: profile.clone(),
        key: key.to_owned(),
    };
    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretDeleteResponse {
            success: true,
            denial: None,
        } => {
            println!("Secret '{key}' deleted from profile '{profile}'.");
            Ok(())
        }
        EventKind::SecretDeleteResponse {
            denial: Some(reason),
            ..
        } => anyhow::bail!("{}", format_denial_reason(&reason, key, profile)),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_secret_list(
    layout: &Layout,
    profile: &TrustProfileName,
) -> anyhow::Result<()> {
    validate_profile_in_config(layout, profile)?;
    let client = connect(layout).await?;
    let event = EventKind::SecretList {
        profile: profile.clone(),
    };
    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretListResponse {
            denial: Some(reason),
            ..
        } => anyhow::bail!("{}", format_denial_reason(&reason, "", profile)),
        EventKind::SecretListResponse { keys, denial: None } if keys.is_empty() => {
            println!("{}", "No secrets in this profile.".dimmed());
            Ok(())
        }
        EventKind::SecretListResponse { keys, denial: None } => {
            println!("Secrets in profile '{}':", profile.as_ref().bold());
            for k in &keys {
                println!("  - {k}");
            }
            Ok(())
        }
        other => Err(unexpected(&other)),
    }
}
