use anyhow::Context;
use comfy_table::{Table, presets::UTF8_FULL};
use core_types::{EventKind, SecurityLevel};
use owo_colors::OwoColorize;
use std::time::Duration;

use crate::ipc::{connect, rpc};

pub(crate) async fn cmd_wm_list() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::WmListWindows, SecurityLevel::Internal).await? {
        EventKind::WmListWindowsResponse { windows } => {
            if windows.is_empty() {
                println!("{}", "No windows tracked.".dimmed());
                return Ok(());
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["ID", "App", "Title", "Focused"]);

            for w in &windows {
                let focused = if w.is_focused {
                    "yes".green().to_string()
                } else {
                    "".to_string()
                };
                table.add_row(vec![
                    &w.id.to_string(),
                    &w.app_id.to_string(),
                    &w.title,
                    &focused,
                ]);
            }

            println!("{table}");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_wm_switch(backward: bool) -> anyhow::Result<()> {
    let client = connect().await?;

    // List windows, pick next/previous in MRU order.
    let windows = match rpc(&client, EventKind::WmListWindows, SecurityLevel::Internal).await? {
        EventKind::WmListWindowsResponse { windows } => windows,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    if windows.is_empty() {
        println!("{}", "No windows to switch to.".dimmed());
        return Ok(());
    }

    // The WmListWindowsResponse returns windows in MRU order (most recent first).
    // Index 0 = currently focused (MRU top). Forward = index 1 (previous window).
    // Backward = last index (least recently used).
    if windows.len() <= 1 {
        tracing::debug!("only one window open, nothing to switch to");
        return Ok(());
    }
    let target_idx = if backward { windows.len() - 1 } else { 1 };

    let target_id = windows[target_idx].id.to_string();

    match rpc(
        &client,
        EventKind::WmActivateWindow {
            window_id: target_id.clone(),
        },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::WmActivateWindowResponse { success: true } => {
            println!(
                "Switched to: {} ({})",
                windows[target_idx].title.green(),
                windows[target_idx].app_id,
            );
        }
        EventKind::WmActivateWindowResponse { success: false } => {
            anyhow::bail!("failed to activate window '{target_id}'");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_wm_focus(window_id: &str) -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(
        &client,
        EventKind::WmActivateWindow {
            window_id: window_id.to_owned(),
        },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::WmActivateWindowResponse { success: true } => {
            println!("Focused window: {}", window_id.green());
        }
        EventKind::WmActivateWindowResponse { success: false } => {
            anyhow::bail!("window '{window_id}' not found");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

pub(crate) async fn cmd_wm_overlay(launcher: bool, backward: bool) -> anyhow::Result<()> {
    let variant = match (launcher, backward) {
        (true, true) => "overlay-launcher-backward",
        (true, false) => "overlay-launcher",
        (false, true) => "overlay-backward",
        (false, false) => "overlay",
    };

    // Fast path: send datagram to resident process (~2ms).
    if try_send_fast_path(variant) {
        return Ok(());
    }

    // Slow path: full Noise IK connect + publish.
    let client = connect().await?;
    let event = match variant {
        "overlay-launcher" => EventKind::WmActivateOverlayLauncher,
        "overlay-launcher-backward" => EventKind::WmActivateOverlayLauncherBackward,
        "overlay-backward" => EventKind::WmActivateOverlayBackward,
        _ => EventKind::WmActivateOverlay,
    };
    client
        .publish(event, SecurityLevel::Internal)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Spawn resident in background for next invocation.
    spawn_resident();

    client.shutdown().await;
    Ok(())
}

/// Send an overlay command to the resident fast-path process via Unix datagram.
///
/// Returns `true` if the datagram was sent (resident is alive).
fn try_send_fast_path(variant: &str) -> bool {
    let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") else {
        return false;
    };
    let pid_path = format!("{runtime_dir}/pds/wm-fast.pid");
    let sock_path = format!("{runtime_dir}/pds/wm-fast.sock");

    // Check PID file for liveness.
    let Ok(pid_content) = std::fs::read_to_string(&pid_path) else {
        return false;
    };
    let Ok(pid) = pid_content.trim().parse::<i32>() else {
        return false;
    };

    // Verify process is alive via kill(pid, 0).
    if unsafe { libc::kill(pid, 0) } != 0 {
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&sock_path);
        return false;
    }

    // Send datagram (blocking — this is a ~0.1ms operation).
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return false;
    };
    sock.send_to(variant.as_bytes(), &sock_path).is_ok()
}

/// Fork a resident fast-path process in the background.
fn spawn_resident() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = std::process::Command::new(exe)
        .args(["wm", "overlay-resident"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Resident fast-path daemon: holds an IPC connection, listens for datagrams.
///
/// Exits on IPC disconnect, datagram error, or 5-minute idle timeout.
pub(crate) async fn cmd_wm_overlay_resident() -> anyhow::Result<()> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR not set")?;
    let pds_dir = format!("{runtime_dir}/pds");
    let pid_path = format!("{pds_dir}/wm-fast.pid");
    let sock_path = format!("{pds_dir}/wm-fast.sock");

    // Check if another resident is already running.
    if let Ok(existing_pid) = std::fs::read_to_string(&pid_path)
        && let Ok(pid) = existing_pid.trim().parse::<i32>()
        && unsafe { libc::kill(pid, 0) } == 0
    {
        return Ok(());
    }

    // Write PID file.
    std::fs::write(&pid_path, std::process::id().to_string())?;

    // Bind datagram socket with 0600 permissions.
    let _ = std::fs::remove_file(&sock_path);
    let dgram = tokio::net::UnixDatagram::bind(&sock_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Establish IPC connection (full Noise IK handshake — done once).
    let client = connect().await?;

    // Event loop: receive datagrams, publish to IPC bus.
    let idle_timeout = Duration::from_secs(300);
    let mut buf = [0u8; 64];

    loop {
        match tokio::time::timeout(idle_timeout, dgram.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let variant = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let event = match variant {
                    "overlay" => EventKind::WmActivateOverlay,
                    "overlay-backward" => EventKind::WmActivateOverlayBackward,
                    "overlay-launcher" => EventKind::WmActivateOverlayLauncher,
                    "overlay-launcher-backward" => EventKind::WmActivateOverlayLauncherBackward,
                    _ => continue,
                };
                if client
                    .publish(event, SecurityLevel::Internal)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break, // Idle timeout.
        }
    }

    // Cleanup.
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
    client.shutdown().await;
    Ok(())
}
