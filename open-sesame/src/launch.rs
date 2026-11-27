use core_layout::Layout;
use core_types::{EventKind, LaunchOutcome, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::helpers::{table, unexpected};
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_launch_search(
    layout: &Layout,
    query: &str,
    max_results: u32,
    profile: Option<TrustProfileName>,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let event = EventKind::LaunchQuery {
        query: query.to_owned(),
        max_results,
        profile,
    };
    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::LaunchQueryResponse { results } if results.is_empty() => {
            println!("{}", "No results.".dimmed());
        }
        EventKind::LaunchQueryResponse { results } => {
            let mut table = table(&["Name", "ID", "Score"]);
            for r in &results {
                table.add_row(vec![
                    r.name.clone(),
                    r.entry_id.clone(),
                    format!("{:.2}", r.score),
                ]);
            }
            println!("{table}");
        }
        other => return Err(unexpected(&other)),
    }
    Ok(())
}

pub(crate) async fn cmd_launch_run(
    layout: &Layout,
    entry_id: &str,
    profile: Option<TrustProfileName>,
) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let event = EventKind::LaunchExecute {
        entry_id: entry_id.to_owned(),
        profile,
        tags: Vec::new(),
        launch_args: Vec::new(),
    };
    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::LaunchExecuteResponse {
            outcome: LaunchOutcome::Launched { pid },
        } => {
            println!("Launched {} (PID {pid})", entry_id.green());
            Ok(())
        }
        EventKind::LaunchExecuteResponse {
            outcome: LaunchOutcome::Denied(denial),
        } => anyhow::bail!("launch denied: {denial}"),
        EventKind::LaunchExecuteResponse {
            outcome: LaunchOutcome::Failed { reason },
        } => anyhow::bail!("launch failed: {reason}"),
        other => Err(unexpected(&other)),
    }
}
