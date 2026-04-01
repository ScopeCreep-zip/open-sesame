//! Command executor — dumb switch, no decisions.
//!
//! Translates [`Command`] variants into side effects: overlay draws,
//! IPC publishes, compositor calls, and recursive sub-command execution.

use crate::controller::{Command, Event, OverlayController};
use crate::overlay::{OverlayCmd, OverlayEvent};
use core_crypto::SecureVec;
use core_ipc::BusClient;
use core_types::{EventKind, SecurityLevel};
use std::sync::Arc;
use tokio::sync::Mutex;

#[allow(clippy::too_many_arguments)]
pub async fn execute_commands(
    commands: Vec<Command>,
    overlay_cmd_tx: &std::sync::mpsc::Sender<OverlayCmd>,
    overlay_event_rx: &mut tokio::sync::mpsc::Receiver<OverlayEvent>,
    #[cfg(target_os = "linux")] backend: &Option<
        Arc<Box<dyn platform_linux::compositor::CompositorBackend>>,
    >,
    client: &mut BusClient,
    config_state: &std::sync::Arc<std::sync::RwLock<core_config::Config>>,
    controller: &mut OverlayController,
    windows: &Arc<Mutex<Vec<core_types::Window>>>,
    wm_config: &Arc<Mutex<core_config::WmConfig>>,
    ipc_keyboard_confirmed: &mut bool,
    password_buffer: &mut SecureVec,
) {
    for cmd in commands {
        match cmd {
            Command::ShowBorder {
                zero_window_launcher,
            } => {
                // Reset IPC keyboard confirmation for new activation cycle.
                *ipc_keyboard_confirmed = false;
                if overlay_cmd_tx.send(OverlayCmd::ShowBorder).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
                if zero_window_launcher {
                    *ipc_keyboard_confirmed = true;
                    let _ = overlay_cmd_tx.send(OverlayCmd::ConfirmKeyboardInput);
                }
                // Request keyboard event forwarding from daemon-input.
                client
                    .publish(
                        EventKind::InputGrabRequest {
                            requester: client.daemon_id(),
                        },
                        SecurityLevel::Internal,
                    )
                    .await
                    .ok();
            }
            Command::ShowPicker { windows, hints } => {
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowFull { windows, hints })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::UpdatePicker { input, selection } => {
                if overlay_cmd_tx
                    .send(OverlayCmd::UpdateInput { input, selection })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::HideAndSync => {
                // Release keyboard grab BEFORE hiding — daemon-input stops forwarding.
                client
                    .publish(
                        EventKind::InputGrabRelease {
                            requester: client.daemon_id(),
                        },
                        SecurityLevel::Internal,
                    )
                    .await
                    .ok();

                if overlay_cmd_tx.send(OverlayCmd::HideAndSync).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                    continue;
                }
                let sync_deadline =
                    tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        while let Some(ev) = overlay_event_rx.recv().await {
                            if matches!(ev, OverlayEvent::SurfaceUnmapped) {
                                return;
                            }
                        }
                    });
                if sync_deadline.await.is_err() {
                    tracing::error!("timed out waiting for SurfaceUnmapped from overlay thread");
                    // Recovery: force-hide the overlay. Even if the overlay thread is
                    // stuck, this queues a Hide command that will be processed when
                    // the thread resumes. If the thread has died, the send fails
                    // silently and the channel is already disconnected.
                    let _ = overlay_cmd_tx.send(OverlayCmd::Hide);
                }
            }
            Command::Hide => {
                client
                    .publish(
                        EventKind::InputGrabRelease {
                            requester: client.daemon_id(),
                        },
                        SecurityLevel::Internal,
                    )
                    .await
                    .ok();

                if overlay_cmd_tx.send(OverlayCmd::Hide).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ActivateWindow { window, .. } => {
                let target_id = window.id.to_string();
                crate::mru::save(&target_id);

                #[cfg(target_os = "linux")]
                let activate_ok = if let Some(backend) = backend {
                    match backend.activate_window(&window.id).await {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::warn!(error = %e, target = %target_id, "compositor activate_window failed");
                            false
                        }
                    }
                } else {
                    true
                };

                #[cfg(not(target_os = "linux"))]
                let activate_ok = true;

                if activate_ok {
                    tracing::info!(target = %target_id, app_id = %window.app_id, "window activated via overlay");
                }
            }
            Command::LaunchApp {
                command,
                tags,
                launch_args,
            } => {
                tracing::info!(command = %command, ?tags, ?launch_args, "launch-or-focus: launching app");

                // Release keyboard grab — no more key forwarding needed.
                client
                    .publish(
                        EventKind::InputGrabRelease {
                            requester: client.daemon_id(),
                        },
                        SecurityLevel::Internal,
                    )
                    .await
                    .ok();

                // Keep the "Launching..." toast visible during the IPC request.
                // The overlay runs on a separate SCTK thread so it keeps rendering
                // while tokio blocks on the launch request. This gives the user
                // visual feedback that the action was received.
                // (ShowLaunching was already sent by the controller before this command.)

                // Capture retry context before moving into IPC request.
                let retry_command = command.clone();
                let retry_tags = tags.clone();
                let retry_launch_args = launch_args.clone();

                let active_profile = {
                    let cfg_guard = config_state.read().ok();
                    cfg_guard.and_then(|c| {
                        core_types::TrustProfileName::try_from(c.global.default_profile.as_ref())
                            .ok()
                    })
                };
                let result = client
                    .request(
                        EventKind::LaunchExecute {
                            entry_id: command,
                            profile: active_profile,
                            tags,
                            launch_args,
                        },
                        SecurityLevel::Internal,
                        std::time::Duration::from_secs(10),
                    )
                    .await;

                let launch_event = match result {
                    Ok(msg) => match msg.payload {
                        EventKind::LaunchExecuteResponse { pid, error, denial } => {
                            if pid > 0 && error.is_none() && denial.is_none() {
                                Event::LaunchResult {
                                    success: true,
                                    error: None,
                                    denial: None,
                                    original_command: None,
                                    original_tags: None,
                                    original_launch_args: None,
                                }
                            } else {
                                Event::LaunchResult {
                                    success: false,
                                    error: error.or_else(|| Some("launch failed".into())),
                                    denial,
                                    original_command: Some(retry_command.clone()),
                                    original_tags: Some(retry_tags.clone()),
                                    original_launch_args: Some(retry_launch_args.clone()),
                                }
                            }
                        }
                        _ => Event::LaunchResult {
                            success: false,
                            error: Some("unexpected response from launcher".into()),
                            denial: None,
                            original_command: None,
                            original_tags: None,
                            original_launch_args: None,
                        },
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "launch request failed");
                        Event::LaunchResult {
                            success: false,
                            error: Some(format!("IPC error: {e}")),
                            denial: None,
                            original_command: None,
                            original_tags: None,
                            original_launch_args: None,
                        }
                    }
                };

                let win_list = windows.lock().await;
                let cfg = wm_config.lock().await;
                let result_cmds = controller.handle(launch_event, &win_list, &cfg);
                drop(cfg);
                drop(win_list);
                // Process launch result commands via the full command executor.
                // This handles all command variants including unlock flow
                // commands (AttemptAutoUnlock, ShowPasswordPrompt, etc.)
                // emitted when the launcher returns VaultsLocked denial.
                Box::pin(execute_commands(
                    result_cmds,
                    overlay_cmd_tx,
                    overlay_event_rx,
                    #[cfg(target_os = "linux")]
                    backend,
                    client,
                    config_state,
                    controller,
                    windows,
                    wm_config,
                    ipc_keyboard_confirmed,
                    password_buffer,
                ))
                .await;
            }
            Command::ShowLaunchStaged { command } => {
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowLaunchStaged { command })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ResetGrace => {
                if overlay_cmd_tx.send(OverlayCmd::ResetGrace).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowLaunching => {
                if overlay_cmd_tx.send(OverlayCmd::ShowLaunching).is_err() {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowLaunchError { message, .. } => {
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowLaunchError { message })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::Publish(event, level) => {
                client.publish(event, level).await.ok();
            }
            // -- Unlock flow commands --
            //
            // The AttemptAutoUnlock handler cannot be unit-tested in isolation
            // because it requires a live IPC bus (BusClient), a running
            // daemon-secrets for the request/response cycle, and filesystem
            // access for salt files and enrollment blobs. The underlying
            // crypto round-trip is covered by core-auth's
            // `full_enrollment_unlock_round_trip` test. The controller's
            // state machine transitions for AutoUnlockResult are covered
            // by the controller unit tests in controller.rs.
            Command::AttemptAutoUnlock { profile } => {
                crate::commands_unlock::attempt_auto_unlock(
                    profile,
                    overlay_cmd_tx,
                    overlay_event_rx,
                    #[cfg(target_os = "linux")]
                    backend,
                    client,
                    config_state,
                    controller,
                    windows,
                    wm_config,
                    ipc_keyboard_confirmed,
                    password_buffer,
                )
                .await;
            }
            Command::ShowPasswordPrompt { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "password-prompt-shown",
                    %profile,
                    "showing password prompt for vault unlock"
                );
                // Re-acquire keyboard grab for password input. The LaunchApp
                // handler releases the grab before the IPC request, but the
                // VaultsLocked fallback needs keyboard input for password entry.
                *ipc_keyboard_confirmed = false;
                client
                    .publish(
                        EventKind::InputGrabRequest {
                            requester: client.daemon_id(),
                        },
                        SecurityLevel::Internal,
                    )
                    .await
                    .ok();
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowUnlockPrompt {
                        profile: profile.to_string(),
                        password_len: 0,
                        error: None,
                    })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowTouchPrompt { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "touch-prompt-shown",
                    %profile,
                    "showing touch prompt for vault unlock"
                );
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowUnlockProgress {
                        profile: profile.to_string(),
                        message: format!(
                            "Touch your security key for \u{201C}{profile}\u{201D}\u{2026}"
                        ),
                    })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowAutoUnlockProgress { profile } => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "auto-unlock-progress",
                    %profile,
                    "showing auto-unlock progress"
                );
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowUnlockProgress {
                        profile: profile.to_string(),
                        message: format!("Authenticating \u{201C}{profile}\u{201D}\u{2026}"),
                    })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::ShowVerifying => {
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "verifying",
                    "showing verification progress for vault unlock"
                );
                let profile = controller
                    .current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowUnlockProgress {
                        profile,
                        message: "Verifying\u{2026}".into(),
                    })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::PasswordChar(ch) => {
                password_buffer.push_char(ch);
                let profile = controller
                    .current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowUnlockPrompt {
                        profile,
                        password_len: password_buffer.char_count(),
                        error: None,
                    })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::PasswordBackspace => {
                password_buffer.pop_char();
                let profile = controller
                    .current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowUnlockPrompt {
                        profile,
                        password_len: password_buffer.char_count(),
                        error: None,
                    })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
            Command::SubmitPasswordUnlock { profile } => {
                crate::commands_unlock::submit_password_unlock(
                    profile,
                    overlay_cmd_tx,
                    overlay_event_rx,
                    #[cfg(target_os = "linux")]
                    backend,
                    client,
                    config_state,
                    controller,
                    windows,
                    wm_config,
                    ipc_keyboard_confirmed,
                    password_buffer,
                )
                .await;
            }
            Command::ClearPasswordBuffer => {
                password_buffer.clear();
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "password-buffer-cleared",
                    "password buffer cleared and zeroized"
                );
            }
            Command::ActivateProfiles { profiles } => {
                crate::commands_unlock::activate_profiles(profiles, client).await;
            }
            Command::ShowUnlockError { message } => {
                tracing::warn!(
                    audit = "unlock-flow",
                    event_type = "unlock-error",
                    %message,
                    "unlock error displayed to user"
                );
                let profile = controller
                    .current_unlock_profile()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "vault".into());
                if overlay_cmd_tx
                    .send(OverlayCmd::ShowUnlockPrompt {
                        profile,
                        password_len: password_buffer.char_count(),
                        error: Some(message),
                    })
                    .is_err()
                {
                    tracing::error!("overlay thread has exited unexpectedly");
                }
            }
        }
    }
}
