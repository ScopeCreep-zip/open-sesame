use comfy_table::{Table, presets::UTF8_FULL};
use core_types::{EventKind, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_snippet_list(profile: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    match rpc(
        &client,
        EventKind::SnippetList { profile },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::SnippetListResponse { snippets } => {
            if snippets.is_empty() {
                println!("{}", "No snippets configured.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Trigger", "Template Preview"]);

                for s in &snippets {
                    table.add_row(vec![&s.trigger, &s.template_preview]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_snippet_expand(profile: &str, trigger: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SnippetExpand {
        profile,
        trigger: trigger.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SnippetExpandResponse {
            expanded: Some(text),
        } => {
            println!("{text}");
        }
        EventKind::SnippetExpandResponse { expanded: None } => {
            anyhow::bail!("snippet trigger '{trigger}' not found");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_snippet_add(
    profile: &str,
    trigger: &str,
    template: &str,
) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SnippetAdd {
        profile,
        trigger: trigger.to_owned(),
        template: template.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SnippetAddResponse { success: true } => {
            println!("Snippet '{}' added.", trigger.green());
        }
        EventKind::SnippetAddResponse { success: false } => {
            anyhow::bail!("failed to add snippet");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}
