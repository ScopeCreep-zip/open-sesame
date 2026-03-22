//! Vault unlock command handlers extracted from the command executor.
//!
//! These async helpers implement the heavy unlock-flow arms of the command
//! executor: auto-unlock via SSH agent, password-based unlock, and profile
//! activation after successful unlock.

use crate::controller::{Event, OverlayController};
use crate::overlay::{OverlayCmd, OverlayEvent};
use core_crypto::SecureVec;
use core_ipc::BusClient;
use core_types::{EventKind, ProfileId, SecurityLevel, TrustProfileName, UnlockRejectedReason};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Execute the AttemptAutoUnlock flow: read salt, try SSH agent unlock,
/// send master key to daemon-secrets, then feed result back through controller.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn attempt_auto_unlock(
    profile: TrustProfileName,
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
    tracing::info!(
        audit = "unlock-flow",
        event_type = "auto-unlock-attempt",
        %profile,
        "attempting auto-unlock for vault"
    );

    let config_dir = core_config::config_dir();
    let salt_path = config_dir.join("vaults").join(format!("{profile}.salt"));
    let salt = tokio::fs::read(&salt_path).await.ok();

    let (success, needs_touch) = if let Some(salt_bytes) = &salt {
        let auth = core_auth::AuthDispatcher::new();
        if let Some(auto_backend) = auth.find_auto_backend(&profile, &config_dir).await {
            match auto_backend.unlock(&profile, &config_dir, salt_bytes).await {
                Ok(outcome) => {
                    let fp = outcome
                        .audit_metadata
                        .get("ssh_fingerprint")
                        .cloned()
                        .unwrap_or_default();
                    let event = core_types::EventKind::SshUnlockRequest {
                        master_key: {
                            let (alloc, len) = outcome.master_key.into_protected_alloc();
                            core_types::SensitiveBytes::from_protected(alloc, len)
                        },
                        profile: profile.clone(),
                        ssh_fingerprint: fp.clone(),
                    };
                    match client
                        .request(
                            event,
                            core_types::SecurityLevel::Internal,
                            std::time::Duration::from_secs(30),
                        )
                        .await
                    {
                        Ok(msg) => match msg.payload {
                            EventKind::UnlockResponse { success: true, .. } => {
                                tracing::info!(%profile, %fp, "SSH auto-unlock accepted by daemon-secrets");
                                (true, false)
                            }
                            EventKind::UnlockRejected {
                                reason: UnlockRejectedReason::AlreadyUnlocked,
                                ..
                            } => {
                                tracing::info!(%profile, "vault already unlocked, treating as success");
                                (true, false)
                            }
                            EventKind::UnlockResponse { success: false, .. } => {
                                tracing::warn!(%profile, "SSH auto-unlock rejected by daemon-secrets");
                                (false, false)
                            }
                            other => {
                                tracing::warn!(%profile, ?other, "unexpected response to SshUnlockRequest");
                                (false, false)
                            }
                        },
                        Err(e) => {
                            tracing::error!(error = %e, %profile, "SshUnlockRequest IPC failed");
                            (false, false)
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, %profile, audit = "unlock-flow", "auto-unlock backend failed, falling back to password");
                    (false, false)
                }
            }
        } else {
            tracing::info!(%profile, audit = "unlock-flow", "no auto-unlock backend available (not enrolled or agent unavailable)");
            (false, false)
        }
    } else {
        tracing::warn!(%profile, audit = "unlock-flow", "no salt file found, cannot attempt auto-unlock");
        (false, false)
    };

    let win_list = windows.lock().await;
    let cfg = wm_config.lock().await;
    let sub_cmds = controller.handle(
        Event::AutoUnlockResult {
            success,
            profile,
            needs_touch,
        },
        &win_list,
        &cfg,
    );
    drop(cfg);
    drop(win_list);
    Box::pin(super::commands::execute_commands(
        sub_cmds,
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

/// Execute the SubmitPasswordUnlock flow: take the password buffer, send
/// UnlockRequest to daemon-secrets, feed result back through controller.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_password_unlock(
    profile: TrustProfileName,
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
    tracing::info!(
        audit = "unlock-flow",
        event_type = "password-unlock-submit",
        %profile,
        "submitting password unlock for vault"
    );

    // Show "Verifying..." overlay BEFORE the IPC round-trip so the
    // user sees immediate feedback.
    if overlay_cmd_tx
        .send(OverlayCmd::ShowUnlockProgress {
            profile: profile.to_string(),
            message: "Verifying\u{2026}".into(),
        })
        .is_err()
    {
        tracing::error!("overlay thread has exited unexpectedly");
    }

    if password_buffer.is_empty() {
        tracing::warn!(%profile, "empty password buffer on submit");
        let win_list = windows.lock().await;
        let cfg = wm_config.lock().await;
        let sub_cmds = controller.handle(
            Event::UnlockResult {
                success: false,
                profile,
            },
            &win_list,
            &cfg,
        );
        drop(cfg);
        drop(win_list);
        Box::pin(super::commands::execute_commands(
            sub_cmds,
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
        return;
    }

    // Copy password directly from protected SecureVec into SensitiveBytes.
    // from_slice reads from mlock'd ProtectedAlloc and copies into a new
    // ProtectedAlloc — no heap exposure. SecureVec is cleared afterward.
    let unlock_event = EventKind::UnlockRequest {
        password: core_types::SensitiveBytes::from_slice(password_buffer.as_bytes()),
        profile: Some(profile.clone()),
    };
    password_buffer.clear();

    // 30s timeout accommodates Argon2id KDF with high memory parameters.
    let result = client
        .request(
            unlock_event,
            SecurityLevel::Internal,
            std::time::Duration::from_secs(30),
        )
        .await;

    let unlock_result = match result {
        Ok(msg) => match msg.payload {
            EventKind::UnlockResponse {
                success,
                profile: resp_profile,
            } => Event::UnlockResult {
                success,
                profile: resp_profile,
            },
            EventKind::UnlockRejected {
                reason,
                profile: resp_profile,
            } => {
                let already = reason == UnlockRejectedReason::AlreadyUnlocked;
                if already {
                    tracing::info!(?resp_profile, "vault already unlocked, treating as success");
                } else {
                    tracing::info!(?reason, ?resp_profile, "unlock rejected");
                }
                Event::UnlockResult {
                    success: already,
                    profile: resp_profile.unwrap_or(profile),
                }
            }
            other => {
                tracing::warn!(?other, "unexpected response to UnlockRequest");
                Event::UnlockResult {
                    success: false,
                    profile,
                }
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "unlock request failed");
            Event::UnlockResult {
                success: false,
                profile,
            }
        }
    };

    let win_list = windows.lock().await;
    let cfg = wm_config.lock().await;
    let sub_cmds = controller.handle(unlock_result, &win_list, &cfg);
    drop(cfg);
    drop(win_list);
    Box::pin(super::commands::execute_commands(
        sub_cmds,
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

/// Activate profiles after successful vault unlock.
pub(crate) async fn activate_profiles(profiles: Vec<TrustProfileName>, client: &mut BusClient) {
    for profile_name in &profiles {
        let target = ProfileId::new();
        let activate_event = EventKind::ProfileActivate {
            target,
            profile_name: profile_name.clone(),
        };
        tracing::info!(
            audit = "unlock-flow",
            event_type = "profile-activate",
            %profile_name,
            "activating profile after vault unlock"
        );
        match client
            .request(
                activate_event,
                SecurityLevel::Internal,
                std::time::Duration::from_secs(10),
            )
            .await
        {
            Ok(msg) => match msg.payload {
                EventKind::ProfileActivateResponse { success: true } => {
                    tracing::info!(
                        audit = "unlock-flow",
                        event_type = "profile-activated",
                        %profile_name,
                        "profile activated successfully"
                    );
                }
                EventKind::ProfileActivateResponse { success: false } => {
                    tracing::error!(
                        audit = "unlock-flow",
                        event_type = "profile-activate-failed",
                        %profile_name,
                        "profile activation rejected by daemon-profile"
                    );
                }
                other => {
                    tracing::warn!(?other, %profile_name, "unexpected response to ProfileActivate");
                }
            },
            Err(e) => {
                tracing::error!(
                    error = %e,
                    %profile_name,
                    "profile activation IPC failed"
                );
            }
        }
    }
}
