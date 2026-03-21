use anyhow::Context;
use core_types::{EventKind, SecurityLevel, SensitiveBytes, TrustProfileName};
use owo_colors::OwoColorize;
use zeroize::Zeroize;

use crate::helpers::{format_denial_reason, validate_profile_in_config, validate_secret_key};
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_secret_set(profile: &str, key: &str) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut value = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        dialoguer::Password::new()
            .with_prompt(format!("Value for '{key}'"))
            .interact()
            .context("failed to read secret value")?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("failed to read secret value from stdin")?;
        // Trim trailing newline from piped input.
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    };

    let mut value_bytes = value.as_bytes().to_vec();
    value.zeroize();

    let event = EventKind::SecretSet {
        profile: profile.clone(),
        key: key.to_owned(),
        value: SensitiveBytes::new(std::mem::take(&mut value_bytes)),
    };
    value_bytes.zeroize();

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretSetResponse { success: true, .. } => {
            println!("Secret '{key}' stored in profile '{profile}'.");
        }
        EventKind::SecretSetResponse {
            success: false,
            denial,
        } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, key, &profile));
            }
            anyhow::bail!("failed to store secret");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_secret_get(profile: &str, key: &str) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SecretGet {
        profile: profile.clone(),
        key: key.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretGetResponse {
            key: k,
            value,
            denial,
        } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, &k, &profile));
            }
            if value.is_empty() {
                anyhow::bail!("secret '{k}' not found in profile '{profile}'");
            }
            // With default config (ipc-field-encryption off), value is
            // plaintext over Noise-encrypted transport. Print as UTF-8
            // if valid, hex otherwise. Zeroize all copies after printing.
            match String::from_utf8(value.as_bytes().to_vec()) {
                Ok(mut s) => {
                    println!("{s}");
                    s.zeroize();
                }
                Err(_) => {
                    let mut hex: String = value
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    println!("{hex}");
                    hex.zeroize();
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_secret_delete(
    profile: &str,
    key: &str,
    skip_confirm: bool,
) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Confirm deletion with TTY and non-TTY support.
    if !skip_confirm {
        let confirmed = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            dialoguer::Confirm::new()
                .with_prompt(format!("Delete secret '{key}' from profile '{profile}'?"))
                .default(false)
                .interact()
                .context("failed to read confirmation")?
        } else {
            // Non-TTY: read a line from stdin and check for "y" or "yes".
            eprintln!("Delete secret '{key}' from profile '{profile}'? [y/N]");
            let mut buf = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(std::io::stdin()), &mut buf)
                .context("failed to read confirmation from stdin")?;
            let answer = buf.trim().to_lowercase();
            answer == "y" || answer == "yes"
        };

        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let event = EventKind::SecretDelete {
        profile: profile.clone(),
        key: key.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretDeleteResponse { success: true, .. } => {
            println!("Secret '{key}' deleted from profile '{profile}'.");
        }
        EventKind::SecretDeleteResponse {
            success: false,
            denial,
        } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, key, &profile));
            }
            anyhow::bail!("failed to delete secret");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_secret_list(profile: &str) -> anyhow::Result<()> {
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SecretList {
        profile: profile.clone(),
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretListResponse { keys, denial } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, "", &profile));
            }
            if keys.is_empty() {
                println!("{}", "No secrets in this profile.".dimmed());
            } else {
                println!("Secrets in profile '{}':", profile.as_ref().bold());
                for k in &keys {
                    println!("  - {k}");
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}
