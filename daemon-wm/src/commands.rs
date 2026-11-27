//! Command executor — dumb switch, no decisions.
//!
//! [`Runtime`] owns the daemon's side-effect endpoints: the overlay thread,
//! the bus client, the compositor backend, the MRU store, and the password
//! buffer. [`Runtime::execute`] translates controller [`Command`]s into
//! effects on them; results the controller must see are fed back through
//! [`Runtime::handle`].

use crate::controller::{Command, Event, LaunchRequest, OverlayController};
use crate::ipc_keys::KeyDeduplicator;
use crate::mru::MruStore;
use crate::surface::wayland::{OverlayCmd, OverlayEvent};
use crate::winlist::{Refresh, Windows};
use anyhow::Context;
use core_config::{Config, WmConfig};
use core_crypto::SecureVec;
use core_ipc::BusClient;
use core_layout::Layout;
use core_types::{EventKind, LaunchOutcome, SecurityLevel, Window};
use std::sync::{Arc, RwLock};

/// Longest wait for the overlay to unmap before a window is activated.
const UNMAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long daemon-launcher may take to answer a launch.
const LAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The compositor backend, when one was detected.
#[cfg(target_os = "linux")]
pub type Backend = Option<Arc<dyn platform_linux::compositor::CompositorBackend>>;

/// The daemon's side-effect endpoints and the controller they serve.
pub struct Runtime {
    /// Vault salts and enrollments for inline unlock.
    pub layout: Layout,
    /// The MRU stack window activations are recorded in.
    pub mru: MruStore,
    /// Commands to the overlay render thread.
    pub overlay_cmd_tx: std::sync::mpsc::Sender<OverlayCmd>,
    /// Keyboard and surface events from the overlay render thread.
    pub overlay_event_rx: tokio::sync::mpsc::Receiver<OverlayEvent>,
    #[cfg(target_os = "linux")]
    pub backend: Backend,
    pub client: BusClient,
    /// The live configuration (default profile for launches).
    pub config_state: Arc<RwLock<Config>>,
    pub controller: OverlayController,
    /// The compositor's window list.
    pub windows: Windows,
    /// On-demand refresh of `windows`; `None` when they are tracked by
    /// focus alone.
    pub refresh: Option<Refresh>,
    /// The default profile's window-manager settings.
    pub wm_config: WmConfig,
    /// Key events already handled from the overlay or IPC.
    pub dedup: KeyDeduplicator,
    /// Whether keyboard input arrived over IPC this activation cycle.
    pub ipc_keyboard_confirmed: bool,
    /// The inline-unlock password, mlock'd; never leaves this thread.
    pub password_buffer: SecureVec,
}

impl Runtime {
    /// Feed `event` to the controller and execute the commands it returns.
    ///
    /// # Errors
    ///
    /// The [`execute`](Self::execute) errors.
    pub async fn handle(&mut self, event: Event) -> anyhow::Result<()> {
        let commands = {
            let windows = self.windows.lock().await;
            self.controller.handle(event, &windows, &self.wm_config)
        };
        self.execute(commands).await
    }

    /// Send `cmd` to the overlay thread; a thread that has exited is
    /// logged (the main loop respawns it when its event channel closes).
    pub fn overlay(&self, cmd: OverlayCmd) {
        if self.overlay_cmd_tx.send(cmd).is_err() {
            tracing::error!("overlay thread has exited unexpectedly");
        }
    }

    /// Ask daemon-input to forward keyboard events to this daemon.
    ///
    /// # Errors
    ///
    /// The bus outbound channel is closed.
    pub async fn request_grab(&self) -> anyhow::Result<()> {
        self.client
            .publish(
                EventKind::InputGrabRequest {
                    requester: self.client.daemon_id(),
                },
                SecurityLevel::Internal,
            )
            .await
            .context("InputGrabRequest publish failed")
    }

    /// Ask daemon-input to stop forwarding keyboard events.
    ///
    /// # Errors
    ///
    /// The bus outbound channel is closed: the keyboard stays grabbed, so
    /// the caller exits for a systemd restart.
    pub async fn release_grab(&self) -> anyhow::Result<()> {
        self.client
            .publish(
                EventKind::InputGrabRelease {
                    requester: self.client.daemon_id(),
                },
                SecurityLevel::Internal,
            )
            .await
            .context("InputGrabRelease publish failed: keyboard grab not released")
    }

    /// Focus `window` through the compositor and record it as most recently
    /// used. Returns whether the compositor accepted the activation; without
    /// a compositor backend no window can be activated.
    ///
    /// The activation request blocks on Wayland round-trips, so it runs on
    /// the blocking pool, not the event loop's thread.
    pub async fn activate_window(&self, window: &Window) -> bool {
        #[cfg(target_os = "linux")]
        let Some(backend) = &self.backend else {
            tracing::warn!(target = %window.id, "no compositor backend: window not activated");
            return false;
        };
        #[cfg(target_os = "linux")]
        {
            let backend = Arc::clone(backend);
            let id = window.id;
            let result = tokio::task::spawn_blocking(move || backend.activate_window(&id))
                .await
                .unwrap_or_else(|e| {
                    Err(core_types::Error::Platform(format!(
                        "activation task failed: {e}"
                    )))
                });
            if let Err(e) = result {
                tracing::warn!(error = %e, target = %window.id, "compositor activate_window failed");
                return false;
            }
        }
        self.mru.save(&window.id.to_string());
        tracing::info!(target = %window.id, app_id = %window.app_id, "window activated");
        true
    }

    /// The profile name the unlock overlay shows.
    fn unlock_label(&self) -> String {
        self.controller
            .current_unlock_profile()
            .map_or_else(|| "vault".into(), ToString::to_string)
    }

    /// Show the password prompt with the current buffer length.
    fn show_password_prompt(&self, error: Option<String>) {
        self.overlay(OverlayCmd::ShowUnlockPrompt {
            profile: self.unlock_label(),
            password_len: self.password_buffer.char_count(),
            error,
        });
    }

    /// Execute controller commands in order.
    ///
    /// # Errors
    ///
    /// A control message (keyboard grab request or release, controller
    /// event) that cannot be published: the bus outbound channel is closed,
    /// and a dropped grab release would leave the keyboard grabbed. The
    /// caller exits for a systemd restart, as on bus disconnect.
    pub async fn execute(&mut self, commands: Vec<Command>) -> anyhow::Result<()> {
        for cmd in commands {
            self.run(cmd).await?;
        }
        Ok(())
    }

    /// Execute one controller command.
    async fn run(&mut self, cmd: Command) -> anyhow::Result<()> {
        match cmd {
            Command::ShowBorder {
                zero_window_launcher,
            } => self.show_border(zero_window_launcher).await?,
            Command::ShowPicker { windows, hints } => {
                self.overlay(OverlayCmd::ShowFull { windows, hints });
            }
            Command::UpdatePicker { input, selection } => {
                self.overlay(OverlayCmd::UpdateInput { input, selection });
            }
            Command::HideAndSync => self.hide_and_sync().await?,
            Command::Hide => {
                self.release_grab().await?;
                self.overlay(OverlayCmd::Hide);
            }
            Command::ActivateWindow { window } => {
                self.activate_window(&window).await;
            }
            Command::LaunchApp(request) => self.launch_app(request).await?,
            Command::ShowLaunchStaged { command } => {
                self.overlay(OverlayCmd::ShowLaunchStaged { command });
            }
            Command::ResetGrace => self.overlay(OverlayCmd::ResetGrace),
            Command::ShowLaunching => self.overlay(OverlayCmd::ShowLaunching),
            Command::ShowLaunchError { message } => {
                self.overlay(OverlayCmd::ShowLaunchError { message });
            }
            Command::Publish(event, level) => {
                self.client
                    .publish(event, level)
                    .await
                    .context("controller event publish failed")?;
            }
            Command::ResolveUnlock { profile } => self.resolve_unlock(profile).await?,
            Command::ShowPasswordPrompt { profile } => {
                self.show_new_password_prompt(&profile).await?;
            }
            Command::PasswordChar(ch) => {
                self.password_buffer.push_char(ch);
                self.show_password_prompt(None);
            }
            Command::PasswordBackspace => {
                self.password_buffer.pop_char();
                self.show_password_prompt(None);
            }
            Command::SubmitPasswordUnlock { profile } => {
                self.submit_password_unlock(profile).await?;
            }
            Command::ClearPasswordBuffer => {
                self.password_buffer.clear();
                tracing::info!(
                    audit = "unlock-flow",
                    event_type = "password-buffer-cleared",
                    "password buffer cleared and zeroized"
                );
            }
            Command::ActivateProfiles { profiles } => self.activate_profiles(&profiles).await,
            Command::ShowUnlockError { message } => {
                tracing::warn!(audit = "unlock-flow", event_type = "unlock-error", %message, "unlock error displayed to user");
                self.show_password_prompt(Some(message));
            }
        }
        Ok(())
    }

    /// Show the armed overlay and take the keyboard from daemon-input. A
    /// launcher with no windows confirms IPC keyboard input at once: the
    /// compositor grants no focus without a toplevel.
    async fn show_border(&mut self, zero_window_launcher: bool) -> anyhow::Result<()> {
        self.ipc_keyboard_confirmed = zero_window_launcher;
        self.overlay(OverlayCmd::ShowBorder);
        if zero_window_launcher {
            self.overlay(OverlayCmd::ConfirmKeyboardInput);
        }
        self.request_grab().await
    }

    /// Release the keyboard, then hide the overlay and wait (bounded by
    /// [`UNMAP_TIMEOUT`]) until its surface is unmapped, so the window
    /// activated next receives focus from an overlay already gone.
    async fn hide_and_sync(&mut self) -> anyhow::Result<()> {
        // Release the grab BEFORE hiding: daemon-input stops forwarding.
        self.release_grab().await?;
        if self.overlay_cmd_tx.send(OverlayCmd::HideAndSync).is_err() {
            tracing::error!("overlay thread has exited unexpectedly");
            return Ok(());
        }
        // A dead overlay thread closes the channel, ending the wait.
        let unmapped = tokio::time::timeout(UNMAP_TIMEOUT, async {
            while let Some(event) = self.overlay_event_rx.recv().await {
                if matches!(event, OverlayEvent::SurfaceUnmapped) {
                    return;
                }
            }
        });
        if unmapped.await.is_err() {
            tracing::error!("timed out waiting for SurfaceUnmapped from overlay thread");
            // Queued for when a stuck overlay thread resumes.
            self.overlay(OverlayCmd::Hide);
        }
        Ok(())
    }

    /// Launch `request` and feed its outcome to the controller. Key
    /// forwarding stops first; the "Launching…" toast stays visible during
    /// the request.
    async fn launch_app(&mut self, request: LaunchRequest) -> anyhow::Result<()> {
        tracing::info!(command = %request.command, tags = ?request.tags, launch_args = ?request.launch_args, "launch-or-focus: launching app");
        self.release_grab().await?;
        let outcome = self.launch(&request).await;
        Box::pin(self.handle(Event::LaunchResult { request, outcome })).await
    }

    /// Show an empty password prompt for `profile`, taking the keyboard
    /// back (the launch released it).
    async fn show_new_password_prompt(
        &mut self,
        profile: &core_types::TrustProfileName,
    ) -> anyhow::Result<()> {
        tracing::info!(audit = "unlock-flow", event_type = "password-prompt-shown", %profile, "showing password prompt for vault unlock");
        self.ipc_keyboard_confirmed = false;
        self.request_grab().await?;
        self.overlay(OverlayCmd::ShowUnlockPrompt {
            profile: profile.to_string(),
            password_len: 0,
            error: None,
        });
        Ok(())
    }

    /// Show unlock progress `message` (it names the profile).
    pub(crate) fn show_unlock_progress(&self, message: String) {
        self.overlay(OverlayCmd::ShowUnlockProgress { message });
    }

    /// Ask daemon-launcher to launch `request` under the configured default
    /// profile. A request daemon-launcher does not answer is `Failed`.
    async fn launch(&self, request: &LaunchRequest) -> LaunchOutcome {
        let profile = match self.config_state.read() {
            Ok(config) => config.global.default_profile.clone(),
            Err(e) => {
                return LaunchOutcome::Failed {
                    reason: format!("configuration state unavailable: {e}"),
                };
            }
        };
        let reply = self
            .client
            .request(
                EventKind::LaunchExecute {
                    entry_id: request.command.clone(),
                    profile: Some(profile),
                    tags: request.tags.clone(),
                    launch_args: request.launch_args.clone(),
                },
                SecurityLevel::Internal,
                LAUNCH_TIMEOUT,
            )
            .await;
        match reply {
            Ok(msg) => match msg.payload {
                EventKind::LaunchExecuteResponse { outcome } => outcome,
                other => LaunchOutcome::Failed {
                    reason: format!("unexpected response from daemon-launcher: {other:?}"),
                },
            },
            Err(e) => LaunchOutcome::Failed {
                reason: format!("launch request failed: {e}"),
            },
        }
    }
}
