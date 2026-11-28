//! `OverlayCmd` processing: each command's view and activation change.

use smithay_client_toolkit::shell::wlr_layer::KeyboardInteractivity;

use super::app::{OverlayApp, View};
use super::poll::Activation;
use super::{OverlayCmd, OverlayEvent};

impl OverlayApp {
    pub fn process_command(&mut self, cmd: OverlayCmd) {
        match cmd {
            OverlayCmd::ShowBorder => {
                self.activation = Activation::now();
                self.view = View::Border;
                self.needs_redraw = true;
                self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
            }
            OverlayCmd::ShowFull { windows, hints } => {
                // Shown straight from Hidden (launcher mode), the picker
                // starts its own activation.
                if !self.activation.started() {
                    self.activation = Activation::now();
                }
                self.activation.rearm();
                self.show(View::Picker {
                    windows,
                    hints,
                    input: String::new(),
                    selection: 0,
                    staged_launch: None,
                });
            }
            OverlayCmd::UpdateInput { input, selection } => {
                self.activation.input();
                if let View::Picker {
                    input: shown,
                    selection: selected,
                    staged_launch,
                    ..
                } = &mut self.view
                {
                    *shown = input;
                    *selected = selection;
                    *staged_launch = None;
                    self.needs_redraw = true;
                }
            }
            OverlayCmd::ShowLaunchStaged { command } => {
                self.activation.input();
                if let View::Picker { staged_launch, .. } = &mut self.view {
                    *staged_launch = Some(command);
                    self.needs_redraw = true;
                }
            }
            OverlayCmd::Hide => {
                self.hide();
                self.render_frame();
            }
            OverlayCmd::HideAndSync => {
                self.hide();
                self.render_frame();
                self.send_event(OverlayEvent::SurfaceUnmapped);
            }
            OverlayCmd::ShowLaunching => {
                self.activation.input();
                self.show(View::Launching);
            }
            OverlayCmd::ShowLaunchError { message } => self.show(View::LaunchError(message)),
            OverlayCmd::ShowUnlockPrompt {
                profile,
                password_len,
                error,
            } => self.show(View::UnlockPrompt {
                profile,
                password_len,
                error,
            }),
            OverlayCmd::ShowUnlockProgress { message } => self.show(View::UnlockProgress(message)),
            OverlayCmd::ResetGrace => self.activation = Activation::now(),
            OverlayCmd::ConfirmKeyboardInput => self.activation.confirm_ipc(),
            OverlayCmd::Reconfigure {
                theme,
                columns,
                reply,
            } => {
                self.theme = *theme;
                self.columns = columns;
                self.needs_redraw = true;
                // The renderer now holds both settings. A closed receiver
                // means the daemon abandoned the attempt and restarts.
                if let Some(reply) = reply {
                    let _ = reply.send(Ok(()));
                }
            }
            OverlayCmd::Quit => self.running = false,
        }
    }
}
