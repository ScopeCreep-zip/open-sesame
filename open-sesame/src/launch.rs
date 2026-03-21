use comfy_table::{Table, presets::UTF8_FULL};
use core_types::{EventKind, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;

use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_launch_search(
    query: &str,
    max_results: u32,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = profile
        .map(|s| TrustProfileName::try_from(s).map_err(|e| anyhow::anyhow!("{e}")))
        .transpose()?;

    let event = EventKind::LaunchQuery {
        query: query.to_owned(),
        max_results,
        profile,
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::LaunchQueryResponse { results } => {
            if results.is_empty() {
                println!("{}", "No results.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Name", "ID", "Score"]);

                for r in &results {
                    table.add_row(vec![&r.name, &r.entry_id, &format!("{:.2}", r.score)]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_launch_run(entry_id: &str, profile: Option<&str>) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = profile
        .map(|s| TrustProfileName::try_from(s).map_err(|e| anyhow::anyhow!("{e}")))
        .transpose()?;

    let event = EventKind::LaunchExecute {
        entry_id: entry_id.to_owned(),
        profile,
        tags: Vec::new(),
        launch_args: Vec::new(),
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::LaunchExecuteResponse { pid, error, .. } => {
            if pid == 0 {
                let detail = error.as_deref().unwrap_or("unknown error");
                anyhow::bail!("launch failed: {detail}");
            }
            println!("Launched {} (PID {})", entry_id.green(), pid);
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}
