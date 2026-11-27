use anyhow::Context;
use core_layout::Layout;
use core_types::{EventKind, OverlayRequest, SecurityLevel, Window};
use owo_colors::OwoColorize;
use std::time::Duration;

use crate::helpers::{table, unexpected};
use crate::ipc::{connect, rpc};

/// The windows daemon-wm tracks, most recently used first.
async fn list_windows(client: &core_ipc::BusClient) -> anyhow::Result<Vec<Window>> {
    match rpc(client, EventKind::WmListWindows, SecurityLevel::Internal).await? {
        EventKind::WmListWindowsResponse { windows } => Ok(windows),
        other => Err(unexpected(&other)),
    }
}

/// Ask daemon-wm to activate `window_id` (a window ID or app ID).
async fn activate(client: &core_ipc::BusClient, window_id: &str) -> anyhow::Result<()> {
    let event = EventKind::WmActivateWindow {
        window_id: window_id.to_owned(),
    };
    match rpc(client, event, SecurityLevel::Internal).await? {
        EventKind::WmActivateWindowResponse { success: true } => Ok(()),
        EventKind::WmActivateWindowResponse { success: false } => {
            anyhow::bail!("daemon-wm could not activate window '{window_id}'")
        }
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn cmd_wm_list(layout: &Layout) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let windows = list_windows(&client).await?;
    if windows.is_empty() {
        println!("{}", "No windows tracked.".dimmed());
        return Ok(());
    }
    let mut table = table(&["ID", "App", "Title", "Focused"]);
    for w in &windows {
        let focused = if w.is_focused {
            "yes".green().to_string()
        } else {
            String::new()
        };
        table.add_row(vec![
            w.id.to_string(),
            w.app_id.to_string(),
            w.title.clone(),
            focused,
        ]);
    }
    println!("{table}");
    Ok(())
}

/// The window `sesame wm switch` targets in the most-recently-used list:
/// the previous window forward, the least recently used backward. `None`
/// with fewer than two windows (index 0 is the focused window).
fn switch_target(windows: &[Window], backward: bool) -> Option<&Window> {
    match windows.len() {
        0 | 1 => None,
        len if backward => windows.get(len - 1),
        _ => windows.get(1),
    }
}

pub(crate) async fn cmd_wm_switch(layout: &Layout, backward: bool) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    let windows = list_windows(&client).await?;
    let Some(target) = switch_target(&windows, backward) else {
        println!("{}", "No other window to switch to.".dimmed());
        return Ok(());
    };
    activate(&client, &target.id.to_string()).await?;
    println!("Switched to: {} ({})", target.title.green(), target.app_id);
    Ok(())
}

pub(crate) async fn cmd_wm_focus(layout: &Layout, window_id: &str) -> anyhow::Result<()> {
    let client = connect(layout).await?;
    activate(&client, window_id).await?;
    println!("Focused window: {}", window_id.green());
    Ok(())
}

/// The activation a fast-path datagram requests: its payload is the
/// request's id; any other payload, UTF-8 or not, is `None`.
fn datagram_request(payload: &[u8]) -> Option<OverlayRequest> {
    std::str::from_utf8(payload)
        .ok()
        .and_then(OverlayRequest::from_id)
}

/// Remove `path`; an already-absent file is not an error.
fn remove_if_present(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// The PID recorded in `pid_path` when that process is alive; `None` when
/// the file is absent or the process is gone (`ESRCH`), or the PID now
/// belongs to another user's process (`EPERM`).
fn live_resident_pid(pid_path: &std::path::Path) -> anyhow::Result<Option<rustix::process::Pid>> {
    let content = match std::fs::read_to_string(pid_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", pid_path.display())),
    };
    let raw: i32 = content
        .trim()
        .parse()
        .with_context(|| format!("corrupt PID file {}", pid_path.display()))?;
    let pid = (raw > 0)
        .then(|| rustix::process::Pid::from_raw(raw))
        .flatten()
        .ok_or_else(|| anyhow::anyhow!("corrupt PID file {}: {raw}", pid_path.display()))?;
    // kill(pid, 0) probes liveness without sending a signal.
    match rustix::process::test_kill_process(pid) {
        Ok(()) => Ok(Some(pid)),
        Err(rustix::io::Errno::SRCH | rustix::io::Errno::PERM) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to probe resident PID {pid}")),
    }
}

pub(crate) async fn cmd_wm_overlay(
    layout: &Layout,
    launcher: bool,
    backward: bool,
) -> anyhow::Result<()> {
    let request = OverlayRequest::new(launcher, backward);

    // Fast path: send datagram to resident process (~2ms). The slow path
    // below is always correct; a fast-path error is reported, not fatal.
    match try_send_fast_path(layout, request) {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => eprintln!(
            "{} overlay fast path unavailable: {e:#}",
            "WARN:".yellow().bold()
        ),
    }

    // Slow path: full Noise IK connect + publish.
    let client = connect(layout).await?;
    client
        .publish(request.event(), SecurityLevel::Internal)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Spawn resident in background for next invocation.
    if let Err(e) = spawn_resident() {
        eprintln!(
            "{} overlay fast path not started: {e:#}",
            "WARN:".yellow().bold()
        );
    }

    client.shutdown().await;
    Ok(())
}

/// Send an overlay command to the resident fast-path process via Unix datagram.
///
/// `Ok(true)` when sent; `Ok(false)` when no resident is running (stale
/// PID and socket files are removed).
fn try_send_fast_path(layout: &Layout, request: OverlayRequest) -> anyhow::Result<bool> {
    let (pid_path, sock_path) = layout.wm_fast_path_files()?;
    if live_resident_pid(&pid_path)?.is_none() {
        remove_if_present(&pid_path)?;
        remove_if_present(&sock_path)?;
        return Ok(false);
    }

    // Send datagram (blocking — this is a ~0.1ms operation).
    let sock =
        std::os::unix::net::UnixDatagram::unbound().context("failed to create datagram socket")?;
    sock.send_to(request.id().as_bytes(), &sock_path)
        .with_context(|| format!("failed to send to {}", sock_path.display()))?;
    Ok(true)
}

/// Fork a resident fast-path process in the background.
fn spawn_resident() -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("failed to resolve the sesame executable")?;
    std::process::Command::new(exe)
        .args(["wm", "overlay-resident"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("failed to spawn overlay resident")?;
    Ok(())
}

/// Resident fast-path daemon: holds an IPC connection, listens for datagrams.
///
/// Exits on IPC disconnect, datagram error, or 5-minute idle timeout.
pub(crate) async fn cmd_wm_overlay_resident(layout: &Layout) -> anyhow::Result<()> {
    let (pid_path, sock_path) = layout.wm_fast_path_files()?;

    // Check if another resident is already running.
    if live_resident_pid(&pid_path)?.is_some() {
        return Ok(());
    }

    // Write PID file.
    std::fs::write(&pid_path, std::process::id().to_string())
        .with_context(|| format!("failed to write {}", pid_path.display()))?;

    // Bind datagram socket with 0600 permissions.
    remove_if_present(&sock_path)?;
    let dgram = tokio::net::UnixDatagram::bind(&sock_path)
        .with_context(|| format!("failed to bind {}", sock_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Establish IPC connection (full Noise IK handshake — done once).
    let client = connect(layout).await?;

    // Event loop: receive datagrams, publish to IPC bus.
    let idle_timeout = Duration::from_mins(5);
    let mut buf = [0u8; 64];

    loop {
        match tokio::time::timeout(idle_timeout, dgram.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let Some(request) = datagram_request(&buf[..n]) else {
                    tracing::warn!(len = n, "unknown overlay datagram ignored");
                    continue;
                };
                if let Err(e) = client
                    .publish(request.event(), SecurityLevel::Internal)
                    .await
                {
                    tracing::warn!(error = %e, "bus publish failed, resident exiting");
                    break;
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "datagram receive failed, resident exiting");
                break;
            }
            Err(_) => break, // Idle timeout.
        }
    }

    // Cleanup.
    let sock_cleanup = remove_if_present(&sock_path);
    let pid_cleanup = remove_if_present(&pid_path);
    client.shutdown().await;
    sock_cleanup?;
    pid_cleanup
}

#[cfg(test)]
mod tests {
    use super::{OverlayRequest, datagram_request, live_resident_pid, switch_target};

    fn window(title: &str) -> core_types::Window {
        core_types::Window::new(
            core_types::WindowId::new(),
            core_types::AppId::new(title),
            title.into(),
            false,
        )
    }

    #[test]
    fn switch_targets_previous_forward_and_oldest_backward() {
        let windows = [window("focused"), window("previous"), window("oldest")];
        assert_eq!(switch_target(&windows, false).unwrap().title, "previous");
        assert_eq!(switch_target(&windows, true).unwrap().title, "oldest");
        assert!(switch_target(&windows[..1], false).is_none());
        assert!(switch_target(&[], true).is_none());
    }

    #[test]
    fn resident_pid_file_states() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wm-fast.pid");
        assert_eq!(live_resident_pid(&path).unwrap(), None);
        std::fs::write(&path, std::process::id().to_string()).unwrap();
        assert!(
            live_resident_pid(&path).unwrap().is_some(),
            "this process is alive"
        );
        for corrupt in ["0", "-4", "pid"] {
            std::fs::write(&path, corrupt).unwrap();
            assert!(live_resident_pid(&path).is_err(), "{corrupt}");
        }
    }

    #[test]
    fn datagrams_carry_request_ids() {
        for request in OverlayRequest::ALL {
            assert_eq!(datagram_request(request.id().as_bytes()), Some(request));
        }
        assert_eq!(datagram_request(b""), None);
        assert_eq!(datagram_request(b"overlay-sideways"), None);
        assert_eq!(datagram_request(&[0xFF, 0xFE]), None);
    }
}
