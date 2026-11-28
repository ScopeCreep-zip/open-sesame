//! The daemon's events and how the runtime answers them: bus requests,
//! overlay key events, controller deadlines, configuration reloads, and
//! overlay thread respawns.

use crate::commands::Runtime;
use crate::controller::Event;
use crate::ipc_keys::{KeyDeduplicator, map_ipc_key_to_event};
use crate::mru;
use crate::render::OverlayTheme;
use crate::surface::wayland::{self, OverlayCmd, OverlayEvent};
use crate::winlist::Refresh;
use anyhow::Context;
use core_config::{Config, WmConfig};
use core_ipc::Message;
use core_types::{EventKind, keysym};
use std::time::{Duration, Instant};

/// Most overlay thread respawns within [`RESPAWN_WINDOW`] before the
/// daemon stops for a systemd restart.
const MAX_RESPAWNS: usize = 5;
/// The window over which overlay respawns are counted.
const RESPAWN_WINDOW: Duration = Duration::from_mins(2);
/// The delay before a dead overlay thread is respawned.
const RESPAWN_DELAY: Duration = Duration::from_secs(2);
/// Longest wait for a fresh window list when the overlay activates.
const FRESH_WINDOWS_WAIT: Duration = Duration::from_millis(200);

/// The window-manager settings of the configured default profile; its
/// compiled defaults when the configuration has no table for it.
#[must_use]
pub fn wm_config_of(config: &Config) -> WmConfig {
    config
        .default_profile_config()
        .map(|profile| profile.wm.clone())
        .unwrap_or_default()
}

/// What the daemon's own sources produced.
#[derive(Debug)]
pub enum Local {
    /// The overlay thread sent an event; `None` when it has died.
    Overlay(Option<OverlayEvent>),
    /// The controller's dwell or activation deadline passed.
    Deadline,
    /// A dead overlay thread is due to be respawned.
    Respawn,
    /// The compositor connection is dead.
    CompositorLost,
}

/// Overlay thread respawn accounting: recent respawns and the one pending.
#[derive(Debug, Default)]
pub struct Respawns {
    recent: Vec<Instant>,
    due: Option<tokio::time::Instant>,
}

impl Respawns {
    /// Whether resource recovery must finish before configuration application.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.due.is_some()
    }

    /// Schedule a respawn of the overlay thread that just died.
    ///
    /// # Errors
    ///
    /// When `MAX_RESPAWNS` respawns already happened within
    /// `RESPAWN_WINDOW`: the overlay keeps dying, and the daemon stops
    /// for a systemd restart.
    pub fn schedule(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        self.recent
            .retain(|at| now.duration_since(*at) < RESPAWN_WINDOW);
        anyhow::ensure!(
            self.recent.len() < MAX_RESPAWNS,
            "overlay thread died {} times within {RESPAWN_WINDOW:?}",
            self.recent.len()
        );
        self.recent.push(now);
        self.due = Some(tokio::time::Instant::now() + RESPAWN_DELAY);
        Ok(())
    }

    /// The respawn is happening: no longer pending.
    fn done(&mut self) {
        self.due = None;
    }

    /// The daemon's next own wake-up: a lost compositor connection first;
    /// then the pending respawn while the overlay thread is dead, otherwise
    /// its next event; then the controller `deadline`.
    pub async fn next(
        &self,
        overlay: &mut tokio::sync::mpsc::Receiver<OverlayEvent>,
        deadline: Option<Instant>,
        refresh: Option<&mut Refresh>,
    ) -> Local {
        let deadline = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        let lost = async {
            match refresh {
                Some(refresh) => refresh.lost().await,
                None => std::future::pending().await,
            }
        };
        if let Some(due) = self.due {
            tokio::select! {
                biased;
                () = lost => Local::CompositorLost,
                () = tokio::time::sleep_until(due) => Local::Respawn,
                () = deadline => Local::Deadline,
            }
        } else {
            tokio::select! {
                biased;
                () = lost => Local::CompositorLost,
                event = overlay.recv() => Local::Overlay(event),
                () = deadline => Local::Deadline,
            }
        }
    }
}

/// The controller event and log label (the request's id) for an overlay
/// activation request.
fn overlay_activation(payload: &EventKind) -> Option<(Event, &'static str)> {
    let request = core_types::OverlayRequest::from_event(payload)?;
    let event = match request {
        core_types::OverlayRequest::Forward => Event::Activate,
        core_types::OverlayRequest::Backward => Event::ActivateBackward,
        core_types::OverlayRequest::Launcher => Event::ActivateLauncher,
        core_types::OverlayRequest::LauncherBackward => Event::ActivateLauncherBackward,
    };
    Some((event, request.id()))
}

/// The controller event for an overlay keyboard event, or `None` when the
/// overlay event carries none or `dedup` has already seen the key from IPC.
fn overlay_key_event(event: &OverlayEvent, dedup: &mut KeyDeduplicator) -> Option<Event> {
    let (keyval, pressed, event) = match *event {
        OverlayEvent::KeyChar(ch) => (u32::from(ch), true, Event::Char(ch)),
        OverlayEvent::Backspace => (keysym::BACKSPACE, true, Event::Backspace),
        OverlayEvent::SelectionDown => (keysym::DOWN, true, Event::SelectionDown),
        OverlayEvent::SelectionUp => (keysym::UP, true, Event::SelectionUp),
        OverlayEvent::Confirm => (keysym::RETURN, true, Event::Confirm),
        OverlayEvent::Escape => (keysym::ESCAPE, true, Event::Escape),
        OverlayEvent::ModifierReleased => (keysym::ALT_L, false, Event::ModifierReleased),
        OverlayEvent::Dismiss => return Some(Event::Dismiss),
        OverlayEvent::SurfaceUnmapped => return None,
    };
    dedup.accept(keyval, pressed).then_some(event)
}

/// The controller event of an IPC key event, when it is one the overlay
/// handles and `dedup` has not already seen from the overlay. Of releases,
/// only Alt/Meta (the end of a cycle) count.
fn ipc_key_event(
    dedup: &mut KeyDeduplicator,
    keyval: u32,
    pressed: bool,
    unicode: Option<char>,
) -> Option<Event> {
    if pressed {
        dedup
            .accept(keyval, true)
            .then(|| map_ipc_key_to_event(keyval, unicode))
            .flatten()
    } else {
        (keysym::is_alt_or_meta(keyval) && dedup.accept(keyval, false))
            .then_some(Event::ModifierReleased)
    }
}

impl Runtime {
    /// Handle an event of the overlay thread.
    ///
    /// # Errors
    ///
    /// The [`Runtime::handle`] errors.
    pub async fn overlay_event(&mut self, event: OverlayEvent) -> anyhow::Result<()> {
        // Trace level: the event may carry a keystroke.
        tracing::trace!(?event, "overlay event received");
        match overlay_key_event(&event, &mut self.dedup) {
            Some(event) => self.handle(event).await,
            None => Ok(()),
        }
    }

    /// The overlay thread died: discard the activation and its sensitive
    /// state, release the keyboard, and schedule a respawn.
    ///
    /// # Errors
    ///
    /// The [`Respawns::schedule`] error, and a keyboard grab that cannot be
    /// released.
    pub async fn overlay_died(&mut self, respawns: &mut Respawns) -> anyhow::Result<()> {
        tracing::error!("overlay thread has died (event channel closed), scheduling respawn");
        self.config_state
            .resource_lost("overlay thread exited".into());
        respawns.schedule()?;
        self.controller.force_idle();
        self.password_buffer.clear();
        self.ipc_keyboard_confirmed = false;
        self.dedup = KeyDeduplicator::new();
        self.release_grab().await
    }

    /// Start a new overlay thread in place of the dead one.
    ///
    /// # Errors
    ///
    /// When the thread cannot be spawned.
    pub fn respawn_overlay(&mut self, respawns: &mut Respawns) -> anyhow::Result<()> {
        respawns.done();
        let (cmd_tx, event_rx) = wayland::spawn_overlay(&self.wm_config)
            .context("failed to respawn the overlay thread")?;
        self.overlay_cmd_tx = cmd_tx;
        self.overlay_event_rx = event_rx;
        tracing::info!(respawns = respawns.recent.len(), "overlay thread respawned");
        Ok(())
    }

    /// The overlay command installing `config`'s renderer settings, the
    /// acknowledgement sent on `reply` when there is one.
    fn reconfiguration(
        config: &WmConfig,
        reply: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    ) -> OverlayCmd {
        OverlayCmd::Reconfigure {
            theme: Box::new(OverlayTheme::from_config(config)),
            columns: crate::render::Columns::of(config),
            reply,
        }
    }

    /// Apply a reloaded configuration's window-manager settings: the
    /// controller adopts them once the overlay acknowledges its renderer
    /// settings, and only then is the reload acknowledged applied.
    ///
    /// # Errors
    ///
    /// When the overlay is gone or does not acknowledge in time: the
    /// controller and renderer may disagree, so the daemon stops for a
    /// restart.
    pub async fn reconfigure(&mut self, reload: core_daemon::Reload) -> anyhow::Result<()> {
        let candidate = wm_config_of(&reload.snapshot.config);
        let (reply, acknowledged) = tokio::sync::oneshot::channel();
        if self
            .overlay_cmd_tx
            .send(Self::reconfiguration(&candidate, Some(reply)))
            .is_err()
        {
            reload.reject("overlay command channel closed".into());
            anyhow::bail!("overlay unavailable during configuration application");
        }
        let result = tokio::time::timeout(Duration::from_secs(5), acknowledged).await;
        match result {
            Ok(Ok(Ok(()))) => {
                self.wm_config = candidate;
                reload.applied(&self.client).await;
                Ok(())
            }
            Ok(Ok(Err(reason))) => {
                reload.reject(reason);
                Ok(())
            }
            other => {
                let reason = format!("overlay configuration acknowledgement failed: {other:?}");
                reload.reject(reason.clone());
                // An unconfirmed renderer may still apply the queued command;
                // restarting prevents serving a mixed controller/renderer state.
                anyhow::bail!(reason)
            }
        }
    }

    /// Send the overlay the renderer settings of the applied configuration
    /// and the desktop theme as it is now.
    fn refresh_theme(&self) {
        self.overlay(Self::reconfiguration(&self.wm_config, None));
    }

    /// Handle a bus message from another daemon: overlay activations, key
    /// events forwarded by daemon-input, and the window requests, which are
    /// answered.
    ///
    /// # Errors
    ///
    /// The [`Runtime::handle`] errors.
    pub async fn message(&mut self, msg: &Message<EventKind>) -> anyhow::Result<()> {
        if let Some((event, label)) = overlay_activation(&msg.payload) {
            tracing::info!("{label} requested via IPC");
            return self.activate(event).await;
        }
        let response = match &msg.payload {
            EventKind::WmListWindows => {
                let mut windows = self.windows.lock().await.clone();
                mru::reorder(&mut windows, |w| w.id.to_string(), &self.mru.load());
                Some(EventKind::WmListWindowsResponse { windows })
            }
            EventKind::WmActivateWindow { window_id } => {
                Some(EventKind::WmActivateWindowResponse {
                    success: self.activate_by_id(window_id).await,
                })
            }
            EventKind::InputKeyEvent {
                keyval,
                pressed,
                unicode,
                ..
            } => {
                self.ipc_key(*keyval, *pressed, *unicode).await?;
                None
            }
            _ => None,
        };
        if let Some(response) = response {
            core_daemon::reply(&self.client, msg, response).await;
        }
        Ok(())
    }

    /// Activate the overlay with `event`. A fresh activation (from idle)
    /// re-reads the theme, so dark/light, accent, and frosted-glass changes
    /// apply without a restart, and waits briefly for a fresh window list,
    /// so windows closed since the last poll are not offered.
    async fn activate(&mut self, event: Event) -> anyhow::Result<()> {
        if self.controller.is_idle() {
            self.refresh_theme();
        }
        if let Some(refresh) = &self.refresh {
            refresh.fresh(FRESH_WINDOWS_WAIT).await;
        }
        self.handle(event).await
    }

    /// Focus the window `window_id` names (its id or app id): whether the
    /// compositor accepted it.
    async fn activate_by_id(&self, window_id: &str) -> bool {
        let found = self
            .windows
            .lock()
            .await
            .iter()
            .find(|w| w.id.to_string() == window_id || w.app_id.as_str() == window_id)
            .cloned();
        let Some(window) = found else {
            tracing::warn!(window_id, "window not found for activation");
            return false;
        };
        self.activate_window(&window).await
    }

    /// Handle a key event daemon-input forwarded while the overlay is
    /// active. The first one in an activation tells the overlay thread
    /// that keyboard input works over IPC, ending its stale-activation
    /// timeout and Exclusive-mode requests.
    async fn ipc_key(
        &mut self,
        keyval: u32,
        pressed: bool,
        unicode: Option<char>,
    ) -> anyhow::Result<()> {
        if self.controller.is_idle() {
            return Ok(());
        }
        if !self.ipc_keyboard_confirmed {
            self.ipc_keyboard_confirmed = true;
            self.overlay(OverlayCmd::ConfirmKeyboardInput);
        }
        match ipc_key_event(&mut self.dedup, keyval, pressed, unicode) {
            Some(event) => self.handle(event).await,
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wm_config_comes_from_the_default_profile() {
        let config: Config = toml::from_str(
            "[global]\ndefault_profile = \"work\"\n\
             [profiles.alpha.wm]\nhint_keys = \"zx\"\n\
             [profiles.work.wm]\nhint_keys = \"qw\"\n",
        )
        .unwrap();
        assert_eq!(wm_config_of(&config).hint_keys, "qw");
        let without: Config = toml::from_str("[profiles.alpha.wm]\nhint_keys = \"zx\"\n").unwrap();
        assert_eq!(
            wm_config_of(&without).hint_keys,
            WmConfig::default().hint_keys
        );
    }

    #[test]
    fn overlay_and_ipc_copies_of_a_key_count_once() {
        let mut dedup = KeyDeduplicator::new();
        assert!(matches!(
            overlay_key_event(&OverlayEvent::Confirm, &mut dedup),
            Some(Event::Confirm)
        ));
        assert!(ipc_key_event(&mut dedup, keysym::RETURN, true, None).is_none());
        assert!(matches!(
            ipc_key_event(&mut dedup, keysym::ALT_R, false, None),
            Some(Event::ModifierReleased)
        ));
        assert!(overlay_key_event(&OverlayEvent::SurfaceUnmapped, &mut dedup).is_none());
        assert!(
            ipc_key_event(&mut dedup, 0x61, false, Some('a')).is_none(),
            "only Alt/Meta releases"
        );
    }

    #[test]
    fn activations_map_to_their_controller_events() {
        assert!(matches!(
            overlay_activation(&EventKind::WmActivateOverlayLauncherBackward),
            Some((Event::ActivateLauncherBackward, _))
        ));
        assert!(overlay_activation(&EventKind::WmListWindows).is_none());
    }

    #[tokio::test]
    async fn respawns_are_limited_within_the_window() {
        let mut respawns = Respawns::default();
        for _ in 0..MAX_RESPAWNS {
            respawns.schedule().unwrap();
        }
        assert!(respawns.schedule().is_err());
    }

    #[tokio::test]
    async fn a_pending_respawn_ignores_the_dead_channel_and_the_deadline_still_fires() {
        let mut respawns = Respawns::default();
        respawns.schedule().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        drop(tx);
        // The closed channel would answer at once; while a respawn is
        // pending, the deadline (already past) answers instead.
        let past = Instant::now();
        assert!(matches!(
            respawns.next(&mut rx, Some(past), None).await,
            Local::Deadline
        ));
        respawns.done();
        assert!(matches!(
            respawns.next(&mut rx, None, None).await,
            Local::Overlay(None)
        ));
    }

    #[tokio::test]
    async fn a_lost_compositor_wakes_the_daemon_first() {
        let windows = crate::winlist::Windows::default();
        let mut refresh = crate::winlist::poll_compositor(
            || Err(core_types::Error::Platform("compositor gone".into())),
            &windows,
        )
        .unwrap();
        let (_tx, mut rx) = tokio::sync::mpsc::channel(1);
        let woke = tokio::time::timeout(
            Duration::from_mins(1),
            Respawns::default().next(&mut rx, None, Some(&mut refresh)),
        )
        .await
        .expect("the daemon wakes");
        assert!(matches!(woke, Local::CompositorLost));
    }
}
