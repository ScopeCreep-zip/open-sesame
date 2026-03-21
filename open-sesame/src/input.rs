use comfy_table::{Table, presets::UTF8_FULL};
use core_types::{EventKind, SecurityLevel};
use owo_colors::OwoColorize;

use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_input_layers() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::InputLayersList, SecurityLevel::Internal).await? {
        EventKind::InputLayersListResponse { layers } => {
            if layers.is_empty() {
                println!("{}", "No input layers configured.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Layer", "Active", "Remaps"]);

                for l in &layers {
                    let active = if l.is_active {
                        "yes".green().to_string()
                    } else {
                        "no".dimmed().to_string()
                    };
                    table.add_row(vec![&l.name, &active, &l.remap_count.to_string()]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_input_status() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::InputStatus, SecurityLevel::Internal).await? {
        EventKind::InputStatusResponse {
            active_layer,
            grabbed_devices,
            remapping_active,
        } => {
            let status = if remapping_active {
                "active".green().to_string()
            } else {
                "inactive".yellow().to_string()
            };

            println!("Remapping: {status}");
            println!("Active layer: {}", active_layer.bold());
            if grabbed_devices.is_empty() {
                println!("Grabbed devices: {}", "none".dimmed());
            } else {
                println!("Grabbed devices:");
                for d in &grabbed_devices {
                    println!("  - {d}");
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}
