use comfy_table::{Table, presets::UTF8_FULL};
use core_types::{EventKind, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_clipboard_history(profile: &str, limit: u32) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::ClipboardHistory { profile, limit };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ClipboardHistoryResponse { entries } => {
            if entries.is_empty() {
                println!("{}", "No clipboard history.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["ID", "Type", "Sensitivity", "Preview"]);

                for e in &entries {
                    table.add_row(vec![
                        &e.entry_id.to_string(),
                        &e.content_type,
                        &format!("{:?}", e.sensitivity),
                        &e.preview,
                    ]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_clipboard_clear(profile: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    match rpc(
        &client,
        EventKind::ClipboardClear { profile },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::ClipboardClearResponse { success: true } => {
            println!("{}", "Clipboard history cleared.".green());
        }
        EventKind::ClipboardClearResponse { success: false } => {
            anyhow::bail!("failed to clear clipboard history");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_clipboard_get(entry_id: &str) -> anyhow::Result<()> {
    let client = connect().await?;

    let uuid = entry_id.strip_prefix("clip-").unwrap_or(entry_id);
    let uuid: uuid::Uuid = uuid
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid clipboard entry ID: {entry_id}"))?;
    let entry_id_parsed = core_types::ClipboardEntryId::from_uuid(uuid);

    match rpc(
        &client,
        EventKind::ClipboardGet {
            entry_id: entry_id_parsed,
        },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::ClipboardGetResponse {
            content: Some(c),
            content_type,
        } => {
            if let Some(ct) = content_type {
                eprintln!("Content-Type: {ct}");
            }
            println!("{c}");
        }
        EventKind::ClipboardGetResponse { content: None, .. } => {
            anyhow::bail!("clipboard entry not found or expired");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}
