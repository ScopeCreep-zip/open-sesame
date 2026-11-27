use core_layout::Layout;
use core_types::{EventKind, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::helpers::{table, unexpected};
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_snippet_list(
    layout: &Layout,
    profile: TrustProfileName,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(
        &client,
        EventKind::SnippetList { profile },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::SnippetListResponse { snippets } if snippets.is_empty() => {
            println!("{}", "No snippets configured.".dimmed());
        }
        EventKind::SnippetListResponse { snippets } => {
            let mut table = table(&["Trigger", "Template Preview"]);
            for s in &snippets {
                table.add_row(vec![s.trigger.clone(), s.template_preview.clone()]);
            }
            println!("{table}");
        }
        other => return Err(unexpected(&other)),
    }
    Ok(())
}

pub(crate) async fn cmd_snippet_expand(
    layout: &Layout,
    profile: TrustProfileName,
    trigger: &str,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let event = EventKind::SnippetExpand {
        profile,
        trigger: trigger.to_owned(),
    };
    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SnippetExpandResponse {
            expanded: Some(text),
        } => {
            println!("{text}");
            Ok(())
        }
        EventKind::SnippetExpandResponse { expanded: None } => {
            anyhow::bail!("snippet trigger '{trigger}' not found")
        }
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_snippet_add(
    layout: &Layout,
    profile: TrustProfileName,
    trigger: &str,
    template: &str,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let event = EventKind::SnippetAdd {
        profile,
        trigger: trigger.to_owned(),
        template: template.to_owned(),
    };
    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SnippetAddResponse { success: true } => {
            println!("Snippet '{}' added.", trigger.green());
            Ok(())
        }
        EventKind::SnippetAddResponse { success: false } => anyhow::bail!("failed to add snippet"),
        other => Err(unexpected(&other)),
    }
}
