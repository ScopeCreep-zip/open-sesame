use core_layout::Layout;
use core_types::{EventKind, SecurityLevel};
use owo_colors::OwoColorize;

use crate::helpers::{table, unexpected};
use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_input_layers(layout: &Layout) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    match rpc(&client, EventKind::InputLayersList, SecurityLevel::Internal).await? {
        EventKind::InputLayersListResponse { layers } if layers.is_empty() => {
            println!("{}", "No input layers configured.".dimmed());
        }
        EventKind::InputLayersListResponse { layers } => {
            let mut table = table(&["Layer", "Active", "Remaps"]);
            for l in &layers {
                let active = if l.is_active {
                    "yes".green().to_string()
                } else {
                    "no".dimmed().to_string()
                };
                table.add_row(vec![l.name.clone(), active, l.remap_count.to_string()]);
            }
            println!("{table}");
        }
        other => return Err(unexpected(&other)),
    }
    Ok(())
}

pub(crate) async fn cmd_input_status(layout: &Layout) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let response = rpc(&client, EventKind::InputStatus, SecurityLevel::Internal).await?;
    let EventKind::InputStatusResponse {
        active_layer,
        grabbed_devices,
        remapping_active,
    } = response
    else {
        return Err(unexpected(&response));
    };
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
    Ok(())
}
