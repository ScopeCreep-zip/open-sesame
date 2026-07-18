//! OverlayCmd processing — maps commands to state mutations.

use smithay_client_toolkit::shell::wlr_layer::KeyboardInteractivity;
use wayland_client::QueueHandle;

use super::app::OverlayApp;
use super::{OverlayCmd, OverlayEvent, OverlayPhase};

impl OverlayApp {
    pub fn process_command(&mut self, cmd: OverlayCmd, qh: &QueueHandle<Self>) {
        match cmd {
            OverlayCmd::ShowBorder => {
                self.phase = OverlayPhase::BorderOnly;
                self.input_buffer.clear();
                self.selection = 0;
                self.activated_at = Some(std::time::Instant::now());
                self.received_key_event = false;
                self.ipc_keyboard_active = false;
                self.last_real_input_at = None;
                self.staged_launch = None;
                self.modifier_released_sent = false;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowFull { windows, hints } => {
                self.phase = OverlayPhase::Full;
                self.windows = windows;
                self.hints = hints;
                if self.activated_at.is_none() {
                    self.activated_at = Some(std::time::Instant::now());
                    self.received_key_event = false;
                    self.ipc_keyboard_active = false;
                    self.last_real_input_at = None;
                }
                self.modifier_released_sent = false;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::UpdateInput { input, selection } => {
                self.input_buffer = input;
                self.staged_launch = None;
                self.selection = selection;
                self.last_real_input_at = Some(std::time::Instant::now());
                self.needs_redraw = true;
            }
            OverlayCmd::Hide => {
                self.hide_common();
                self.render_frame(qh);
            }
            OverlayCmd::HideAndSync => {
                self.hide_common();
                self.render_frame(qh);
                self.pending_sync = true;
                self.send_event(OverlayEvent::SurfaceUnmapped);
                self.pending_sync = false;
            }
            OverlayCmd::ShowLaunchStaged { command } => {
                self.staged_launch = Some(command);
                self.last_real_input_at = Some(std::time::Instant::now());
                self.needs_redraw = true;
            }
            OverlayCmd::ShowLaunching => {
                self.phase = OverlayPhase::Launching;
                self.error_message.clear();
                self.last_real_input_at = Some(std::time::Instant::now());
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowLaunchError { message } => {
                self.phase = OverlayPhase::LaunchError;
                self.error_message = message;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowUnlockPrompt {
                profile,
                password_len,
                error,
            } => {
                self.phase = OverlayPhase::UnlockPrompt;
                self.unlock_profile = profile;
                self.unlock_password_len = password_len;
                if let Some(err) = error {
                    self.error_message = err;
                } else {
                    self.error_message.clear();
                }
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowUnlockProgress { profile, message } => {
                self.phase = OverlayPhase::UnlockProgress;
                self.unlock_profile = profile;
                self.unlock_message = message;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ResetGrace => {
                self.activated_at = Some(std::time::Instant::now());
                self.received_key_event = false;
                self.ipc_keyboard_active = false;
                self.last_real_input_at = None;
                self.modifier_released_sent = false;
            }
            OverlayCmd::ConfirmKeyboardInput => {
                self.received_key_event = true;
                self.ipc_keyboard_active = true;
            }
            OverlayCmd::UpdateTheme(theme) => {
                self.theme = *theme;
                self.needs_redraw = true;
            }
            OverlayCmd::Quit => {
                self.running = false;
            }
        }
    }
}
