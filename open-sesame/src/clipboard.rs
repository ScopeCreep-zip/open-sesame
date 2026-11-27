use core_layout::Layout;
use core_types::{ClipboardEntryId, EventKind, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::helpers::{table, unexpected};
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_clipboard_history(
    layout: &Layout,
    profile: TrustProfileName,
    limit: u32,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(
        &client,
        EventKind::ClipboardHistory { profile, limit },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::ClipboardHistoryResponse { entries } if entries.is_empty() => {
            println!("{}", "No clipboard history.".dimmed());
        }
        EventKind::ClipboardHistoryResponse { entries } => {
            let mut table = table(&["ID", "Type", "Sensitivity", "Preview"]);
            for e in &entries {
                table.add_row(vec![
                    e.entry_id.to_string(),
                    e.content_type.clone(),
                    format!("{:?}", e.sensitivity),
                    e.preview.clone(),
                ]);
            }
            println!("{table}");
        }
        other => return Err(unexpected(&other)),
    }
    Ok(())
}

pub(crate) async fn cmd_clipboard_clear(
    layout: &Layout,
    profile: TrustProfileName,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(
        &client,
        EventKind::ClipboardClear { profile },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::ClipboardClearResponse { success: true } => {
            println!("{}", "Clipboard history cleared.".green());
            Ok(())
        }
        EventKind::ClipboardClearResponse { success: false } => {
            anyhow::bail!("failed to clear clipboard history")
        }
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_clipboard_get(
    layout: &Layout,
    entry_id: ClipboardEntryId,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(
        &client,
        EventKind::ClipboardGet { entry_id },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::ClipboardGetResponse {
            content: Some(content),
            content_type,
        } => {
            if let Some(ct) = content_type {
                eprintln!("Content-Type: {ct}");
            }
            println!("{content}");
            Ok(())
        }
        EventKind::ClipboardGetResponse { content: None, .. } => {
            anyhow::bail!("clipboard entry {entry_id} not found or expired")
        }
        other => Err(unexpected(&other)),
    }
}
