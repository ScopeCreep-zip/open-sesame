//! Overlay lifecycle controller.
//!
//! Single owner of all overlay state, timing, and decisions. The main loop
//! feeds events in, executes the returned commands, and does nothing else.
//!
//! States:
//! - `Idle`: nothing happening.
//! - `Armed`: border visible, keyboard exclusive, picker NOT visible.
//!   Waiting for modifier release (quick-switch) or dwell timeout (show picker).
//! - `Picking`: picker visible, user browsing/typing.
//!
//! All window data (MRU order, hints, overlay info) is pre-computed eagerly
//! at activation time and carried through phase transitions. No recomputation
//! occurs after user keyboard actions — only index updates and command emission.
//!
//! Origin handling: after `mru::reorder`, the currently focused window (origin)
//! sits at the last index — lowest priority in cycling order. The user can
//! still reach it by cycling all the way around or by typing its hint key.
//! Origin is never the *default* target for quick-switch or initial selection.

use crate::hints::{self, MatchResult};
use crate::mru;
use crate::overlay::WindowInfo;
use core_config::WmConfig;
use core_types::{EventKind, LaunchDenial, SecurityLevel, TrustProfileName, Window};
use std::collections::BTreeMap;
use std::time::Instant;

/// Maximum input buffer length.
const MAX_INPUT_LENGTH: usize = 64;

// ---------------------------------------------------------------------------
// Commands — concrete orders the main loop executes without interpretation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Command {
    /// Send OverlayCmd::ShowBorder to overlay (acquires KeyboardInteractivity::Exclusive).
    /// When `zero_window_launcher` is true, immediately confirm IPC keyboard input
    /// to prevent the stale activation timeout (the Wayland compositor will not
    /// grant keyboard focus when zero toplevel windows exist).
    ShowBorder { zero_window_launcher: bool },
    /// Send OverlayCmd::ShowFull with the given data.
    ShowPicker {
        windows: Vec<WindowInfo>,
        hints: Vec<String>,
    },
    /// Send OverlayCmd::UpdateInput.
    UpdatePicker { input: String, selection: usize },
    /// Send OverlayCmd::HideAndSync, wait for SurfaceUnmapped ack.
    HideAndSync,
    /// Send OverlayCmd::Hide (no sync needed).
    Hide,
    /// Activate a window via compositor backend + save MRU state.
    ActivateWindow { window: Window },
    /// Launch an application via IPC (request-response, not fire-and-forget).
    LaunchApp {
        command: String,
        tags: Vec<String>,
        launch_args: Vec<String>,
    },
    /// Show a launch error toast in the overlay.
    ShowLaunchError {
        message: String,
        denial: Option<LaunchDenial>,
    },
    /// Show "Launching..." spinner/status in the overlay (launch in progress).
    ShowLaunching,
    /// Show staged launch intent in the overlay (waiting for Alt release).
    ShowLaunchStaged { command: String },
    /// Reset the overlay's modifier-poll grace timer. Sent on IPC
    /// re-activation to prove Alt is still held and prevent premature commit.
    ResetGrace,
    /// Publish an IPC event.
    Publish(EventKind, SecurityLevel),
    /// Attempt auto-unlock via `AuthDispatcher`.
    AttemptAutoUnlock { profile: TrustProfileName },
    /// Show password entry prompt.
    ShowPasswordPrompt { profile: TrustProfileName },
    /// Show "Touch your security key..." prompt.
    ShowTouchPrompt { profile: TrustProfileName },
    /// Show "Authenticating..." progress.
    ShowAutoUnlockProgress { profile: TrustProfileName },
    /// Show "Verifying..." while password IPC round-trip is in progress.
    ShowVerifying,
    /// A password character was typed. Main loop appends to `SecureVec`.
    PasswordChar(char),
    /// Backspace in password mode. Main loop truncates `SecureVec`.
    PasswordBackspace,
    /// Submit password buffer to daemon-secrets via `UnlockRequest`.
    SubmitPasswordUnlock { profile: TrustProfileName },
    /// Zeroize and reset the password buffer.
    ClearPasswordBuffer,
    /// Show error message in unlock overlay.
    ShowUnlockError { message: String },
    /// Activate profiles via IPC before retrying a launch.
    ActivateProfiles { profiles: Vec<TrustProfileName> },
}

// ---------------------------------------------------------------------------
// Events — everything the controller can receive
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Event {
    /// Alt+Tab / activation requested.
    Activate,
    /// Alt+Shift+Tab / backward activation.
    ActivateBackward,
    /// Alt+Space / launcher mode (brief Armed dwell for keyboard focus, then Picking).
    ActivateLauncher,
    /// Alt+Shift+Space / launcher mode with backward initial selection.
    ActivateLauncherBackward,
    /// Modifier (Alt) released.
    ModifierReleased,
    /// Character typed.
    Char(char),
    /// Backspace.
    Backspace,
    /// Tab / Down arrow.
    SelectionDown,
    /// Shift+Tab / Up arrow.
    SelectionUp,
    /// Enter.
    Confirm,
    /// Escape.
    Escape,
    /// Stale activation timeout — overlay was visible too long with no
    /// keyboard interaction. Dismiss without activating any window.
    Dismiss,
    /// The dwell timer expired (main loop polls `next_deadline()`).
    DwellTimeout,
    /// Launch request completed (success or failure). Fed back from main loop.
    LaunchResult {
        success: bool,
        error: Option<String>,
        denial: Option<LaunchDenial>,
        original_command: Option<String>,
        original_tags: Option<Vec<String>>,
        original_launch_args: Option<Vec<String>>,
    },
    /// Auto-unlock backend completed. Fed back from main loop.
    AutoUnlockResult {
        success: bool,
        profile: TrustProfileName,
        needs_touch: bool,
    },
    /// Touch-based unlock completed. Fed back from main loop.
    TouchResult {
        success: bool,
        profile: TrustProfileName,
    },
    /// Password unlock IPC response received. Fed back from main loop.
    UnlockResult {
        success: bool,
        profile: TrustProfileName,
    },
}

// ---------------------------------------------------------------------------
// Pre-computed activation snapshot — built once, carried through phases
// ---------------------------------------------------------------------------

/// All data needed for the overlay lifecycle, computed eagerly at activation.
///
/// After `mru::reorder`, the window list is ordered:
/// `[MRU previous, ..., origin]`
///
/// Index 0 = most recent non-origin window (forward quick-switch target).
/// Last index = origin (currently focused, lowest switch priority).
///
/// The origin is always present for display and reachable by full-circle
/// cycling or explicit hint selection. It is never the default target for
/// quick-switch or initial selection.
#[derive(Debug, Clone)]
struct Snapshot {
    /// MRU-reordered, truncated window list.
    windows: Vec<Window>,
    /// Assigned hint strings (parallel to windows).
    hints: Vec<String>,
    /// Overlay-ready window info (parallel to windows).
    overlay_windows: Vec<WindowInfo>,
    /// Index of the origin window in `windows`, if present.
    /// Used to prevent auto-selection of origin on quick-switch.
    origin_index: Option<usize>,
    /// Key bindings snapshot for launch-or-focus.
    key_bindings: BTreeMap<String, core_config::WmKeyBinding>,
}

impl Snapshot {
    fn build(windows: &[Window], config: &WmConfig) -> Self {
        let mru_state = mru::load();
        let mut win_list = windows.to_vec();
        mru::reorder(&mut win_list, |w| w.id.to_string(), &mru_state);
        win_list.truncate(config.max_visible_windows as usize);

        // Rotate origin (MRU current, typically index 0) to the end of the
        // list. This gives the picker a natural display order:
        //   top    = MRU previous (switch target)
        //   ...    = remaining windows in MRU order
        //   bottom = origin (currently focused, lowest priority)
        let origin_index = if let Some(current_id) = mru_state.current() {
            if let Some(pos) = win_list.iter().position(|w| w.id.to_string() == current_id) {
                let origin = win_list.remove(pos);
                win_list.push(origin);
                Some(win_list.len() - 1)
            } else {
                None
            }
        } else {
            None
        };

        let app_ids: Vec<&str> = win_list.iter().map(|w| w.app_id.as_str()).collect();
        let app_hints = hints::assign_app_hints(&app_ids, &config.key_bindings);
        let hint_strings: Vec<String> = app_hints.iter().map(|(h, _)| h.clone()).collect();

        let overlay_windows: Vec<WindowInfo> = win_list
            .iter()
            .map(|w| WindowInfo {
                app_id: w.app_id.to_string(),
                title: w.title.clone(),
            })
            .collect();

        tracing::info!(
            window_count = win_list.len(),
            ?origin_index,
            hints = ?hint_strings,
            apps = ?app_ids,
            mru_origin = mru_state.current().unwrap_or("<none>"),
            quick_target = win_list.first().map(|w| w.id.to_string()).as_deref().unwrap_or("<none>"),
            "snapshot: pre-computed overlay data"
        );

        Self {
            windows: win_list,
            hints: hint_strings,
            overlay_windows,
            origin_index,
            key_bindings: config.key_bindings.clone(),
        }
    }

    /// First valid forward selection (index 0 unless that's origin).
    fn initial_forward(&self) -> usize {
        if self.origin_index == Some(0) && self.windows.len() > 1 {
            1
        } else {
            0
        }
    }

    /// First valid backward selection (last index unless that's origin).
    fn initial_backward(&self) -> usize {
        let last = self.windows.len().saturating_sub(1);
        if self.origin_index == Some(last) && last > 0 {
            last - 1
        } else {
            last
        }
    }

    /// Whether there are any windows to activate. A single window is a valid
    /// target — the user may be on a different workspace and Alt+Tab should
    /// bring it to them.
    fn has_targets(&self) -> bool {
        !self.windows.is_empty()
    }

    /// Test-only constructor with explicit origin_index.
    #[cfg(test)]
    fn with_origin(windows: &[Window], config: &WmConfig, origin_index: Option<usize>) -> Self {
        let app_ids: Vec<&str> = windows.iter().map(|w| w.app_id.as_str()).collect();
        let app_hints = hints::assign_app_hints(&app_ids, &config.key_bindings);
        let hint_strings: Vec<String> = app_hints.iter().map(|(h, _)| h.clone()).collect();
        let overlay_windows: Vec<WindowInfo> = windows
            .iter()
            .map(|w| WindowInfo {
                app_id: w.app_id.to_string(),
                title: w.title.clone(),
            })
            .collect();
        Self {
            windows: windows.to_vec(),
            hints: hint_strings,
            overlay_windows,
            origin_index,
            key_bindings: config.key_bindings.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

/// Staged launch — user typed a launch key but hasn't released Alt yet.
/// Stored in Armed/Picking so `on_modifier_released` can execute it.
#[derive(Debug, Clone)]
struct PendingLaunch {
    command: String,
    tags: Vec<String>,
    launch_args: Vec<String>,
}

/// Sub-mode within the vault unlock flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMode {
    /// core-auth attempting non-interactive unlock. Overlay shows "Authenticating...".
    AutoAttempt,
    /// Waiting for hardware token touch. Overlay shows "Touch your security key...".
    WaitingForTouch,
    /// Password entry mode. Overlay shows dot-masked field.
    Password,
    /// Unlock request in-flight. Overlay shows "Verifying...".
    Verifying,
}

#[derive(Debug)]
enum Phase {
    Idle,
    Armed {
        entered_at: Instant,
        snap: Snapshot,
        selection: usize,
        input: String,
        dwell_ms: u32,
        pending_launch: Option<PendingLaunch>,
    },
    Picking {
        snap: Snapshot,
        selection: usize,
        input: String,
        pending_launch: Option<PendingLaunch>,
    },
    /// Waiting for LaunchExecuteResponse from daemon-launcher.
    Launching,
    /// Launch failed — showing error toast. Any key dismisses.
    /// Error details are already forwarded to the overlay via ShowLaunchError.
    LaunchError,
    /// Vault unlock in progress — waiting for auth or password input.
    Unlocking {
        /// All profiles that need unlocking.
        profiles_to_unlock: Vec<TrustProfileName>,
        /// Index into `profiles_to_unlock` for the current profile.
        current_index: usize,
        /// Number of characters in the password buffer (for dot rendering).
        password_len: usize,
        /// Current unlock sub-mode.
        unlock_mode: UnlockMode,
        /// Original launch command for auto-retry.
        retry_command: String,
        /// Original launch tags.
        retry_tags: Vec<String>,
        /// Original launch args.
        retry_launch_args: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy)]
enum ActivationMode {
    /// Alt+Tab: Armed, selection at MRU previous, quick-switch eligible.
    Forward,
    /// Alt+Shift+Tab: Armed, selection at least-recently-used non-origin.
    Backward,
    /// Alt+Space: brief Armed dwell for keyboard focus, then Picking.
    Launcher,
    /// Alt+Shift+Space: launcher mode with backward initial selection.
    LauncherBackward,
}

/// Window within which a SelectionDown/SelectionUp event is suppressed
/// after an IPC re-activation already advanced the selection. Prevents
/// the same physical keystroke from advancing twice (once via IPC
/// WmActivateOverlay and once via the SCTK/IPC keyboard event).
const REACTIVATION_DEDUP_MS: u128 = 100;

#[derive(Debug)]
pub struct OverlayController {
    phase: Phase,
    /// Timestamp of the last IPC re-activation that advanced selection.
    /// Used to suppress duplicate SelectionDown/SelectionUp events from
    /// the SCTK keyboard handler or IPC InputKeyEvent that correspond to
    /// the same physical keystroke that triggered the re-activation.
    last_ipc_advance: Option<Instant>,
}

impl OverlayController {
    pub fn new() -> Self {
        Self {
            phase: Phase::Idle,
            last_ipc_advance: None,
        }
    }

    /// Returns the next deadline the main loop should wake for, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        match &self.phase {
            Phase::Armed {
                entered_at,
                dwell_ms,
                ..
            } => Some(*entered_at + std::time::Duration::from_millis(*dwell_ms as u64)),
            _ => None,
        }
    }

    /// Is the controller idle?
    pub fn is_idle(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }

    /// Force the controller back to Idle, discarding all in-flight state.
    /// Used when the overlay thread dies and must be respawned.
    pub fn force_idle(&mut self) {
        self.phase = Phase::Idle;
        self.last_ipc_advance = None;
    }

    /// Return the profile currently being unlocked, if in the unlocking phase.
    pub fn current_unlock_profile(&self) -> Option<&TrustProfileName> {
        if let Phase::Unlocking {
            profiles_to_unlock,
            current_index,
            ..
        } = &self.phase
        {
            profiles_to_unlock.get(*current_index)
        } else {
            None
        }
    }

    /// Test-only: enter Armed phase with a pre-built snapshot.
    #[cfg(test)]
    fn arm_with_snapshot(&mut self, snap: Snapshot, dwell_ms: u32) {
        let selection = snap.initial_forward();
        self.phase = Phase::Armed {
            entered_at: Instant::now(),
            snap,
            selection,
            input: String::new(),
            dwell_ms,
            pending_launch: None,
        };
    }

    /// Test-only: enter Picking phase with a pre-built snapshot.
    #[cfg(test)]
    fn pick_with_snapshot(&mut self, snap: Snapshot) {
        let selection = snap.initial_forward();
        self.phase = Phase::Picking {
            snap,
            selection,
            input: String::new(),
            pending_launch: None,
        };
    }

    /// Handle an event, returning commands to execute.
    pub fn handle(&mut self, event: Event, windows: &[Window], config: &WmConfig) -> Vec<Command> {
        match event {
            Event::Activate => self.on_activate(windows, config, ActivationMode::Forward),
            Event::ActivateBackward => self.on_activate(windows, config, ActivationMode::Backward),
            Event::ActivateLauncher => self.on_activate(windows, config, ActivationMode::Launcher),
            Event::ActivateLauncherBackward => {
                self.on_activate(windows, config, ActivationMode::LauncherBackward)
            }
            Event::ModifierReleased => self.on_modifier_released(),
            Event::Char(ch) => self.on_char(ch),
            Event::Backspace => self.on_backspace(),
            Event::SelectionDown => self.on_selection_down(),
            Event::SelectionUp => self.on_selection_up(),
            Event::Confirm => self.on_confirm(),
            Event::Escape | Event::Dismiss => self.on_escape(),
            Event::DwellTimeout => self.on_dwell_timeout(),
            Event::LaunchResult {
                success,
                error,
                denial,
                original_command,
                original_tags,
                original_launch_args,
            } => self.on_launch_result(
                success,
                error,
                denial,
                original_command,
                original_tags,
                original_launch_args,
            ),
            Event::AutoUnlockResult {
                success,
                profile,
                needs_touch,
            } => self.on_auto_unlock_result(success, profile, needs_touch),
            Event::TouchResult { success, profile } => self.on_touch_result(success, profile),
            Event::UnlockResult { success, profile } => self.on_unlock_result(success, profile),
        }
    }

    // -----------------------------------------------------------------------
    // Activation
    // -----------------------------------------------------------------------

    fn on_activate(
        &mut self,
        windows: &[Window],
        config: &WmConfig,
        mode: ActivationMode,
    ) -> Vec<Command> {
        // Take ownership of the current phase. For Idle this is a no-op
        // (replaced with Idle). For Armed/Picking we need ownership to
        // cycle selection and transition without borrow conflicts.
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => {
                let snap = Snapshot::build(windows, config);

                // Launcher mode always activates — it's a launcher, not just
                // a switcher. Zero windows is a valid state for launching apps.
                // Forward/Backward require at least one switchable target.
                if !matches!(
                    mode,
                    ActivationMode::Launcher | ActivationMode::LauncherBackward
                ) && !snap.has_targets()
                {
                    return Vec::new();
                }

                match mode {
                    ActivationMode::Forward => {
                        let selection = snap.initial_forward();
                        self.phase = Phase::Armed {
                            entered_at: Instant::now(),
                            snap,
                            selection,
                            input: String::new(),
                            dwell_ms: config.quick_switch_threshold_ms,
                            pending_launch: None,
                        };
                        vec![
                            Command::ShowBorder {
                                zero_window_launcher: false,
                            },
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ]
                    }
                    ActivationMode::Backward => {
                        let selection = snap.initial_backward();
                        self.phase = Phase::Armed {
                            entered_at: Instant::now(),
                            snap,
                            selection,
                            input: String::new(),
                            dwell_ms: config.quick_switch_threshold_ms,
                            pending_launch: None,
                        };
                        vec![
                            Command::ShowBorder {
                                zero_window_launcher: false,
                            },
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ]
                    }
                    ActivationMode::Launcher | ActivationMode::LauncherBackward => {
                        // Enter Armed with a short dwell to let the compositor
                        // grant keyboard exclusivity before the user's first
                        // keypress. on_char works in Armed, so fast typists
                        // are handled. DwellTimeout then transitions to Picking.
                        let zero_window_launcher = !snap.has_targets();
                        let selection = if matches!(mode, ActivationMode::LauncherBackward) {
                            snap.initial_backward()
                        } else {
                            snap.initial_forward()
                        };
                        self.phase = Phase::Armed {
                            entered_at: Instant::now(),
                            snap,
                            selection,
                            input: String::new(),
                            dwell_ms: config.overlay_delay_ms.min(100),
                            pending_launch: None,
                        };
                        vec![
                            Command::ShowBorder {
                                zero_window_launcher,
                            },
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ]
                    }
                }
            }
            Phase::Armed {
                snap,
                mut selection,
                input,
                pending_launch,
                ..
            } => {
                // Re-activation via IPC (e.g. repeated Alt+Tab intercepted
                // by compositor). Cycle selection, show the picker so the user
                // sees feedback, and reset the modifier-poll grace timer to
                // prevent premature commit.
                if !snap.windows.is_empty() {
                    let len = snap.windows.len();
                    selection = match mode {
                        ActivationMode::Backward | ActivationMode::LauncherBackward => {
                            (selection + len - 1) % len
                        }
                        _ => (selection + 1) % len,
                    };
                    // Record that we advanced via IPC so we can suppress the
                    // duplicate SelectionDown/Up from the keyboard handler.
                    self.last_ipc_advance = Some(Instant::now());
                }
                let cmds = vec![
                    Command::ShowPicker {
                        windows: snap.overlay_windows.clone(),
                        hints: snap.hints.clone(),
                    },
                    Command::UpdatePicker {
                        input: input.clone(),
                        selection,
                    },
                    Command::ResetGrace,
                ];
                self.phase = Phase::Picking {
                    snap,
                    selection,
                    input,
                    pending_launch,
                };
                cmds
            }
            Phase::Picking {
                snap,
                mut selection,
                input,
                pending_launch,
            } => {
                // Re-activation while picker is visible. Cycle and reset grace.
                if !snap.windows.is_empty() {
                    let len = snap.windows.len();
                    selection = match mode {
                        ActivationMode::Backward | ActivationMode::LauncherBackward => {
                            (selection + len - 1) % len
                        }
                        _ => (selection + 1) % len,
                    };
                    self.last_ipc_advance = Some(Instant::now());
                }
                let cmds = vec![
                    Command::UpdatePicker {
                        input: input.clone(),
                        selection,
                    },
                    Command::ResetGrace,
                ];
                self.phase = Phase::Picking {
                    snap,
                    selection,
                    input,
                    pending_launch,
                };
                cmds
            }
            other @ (Phase::Launching | Phase::LaunchError | Phase::Unlocking { .. }) => {
                self.phase = other;
                Vec::new()
            }
        }
    }

    // -----------------------------------------------------------------------
    // Modifier released
    // -----------------------------------------------------------------------

    fn on_modifier_released(&mut self) -> Vec<Command> {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Armed {
                entered_at,
                dwell_ms,
                selection,
                input,
                snap,
                pending_launch,
            } => {
                // Pending launch takes priority over window activation.
                if let Some(launch) = pending_launch {
                    self.phase = Phase::Launching;
                    return vec![
                        Command::ShowLaunching,
                        Command::LaunchApp {
                            command: launch.command,
                            tags: launch.tags,
                            launch_args: launch.launch_args,
                        },
                    ];
                }

                if snap.windows.is_empty() {
                    let cmds = vec![Command::ShowPicker {
                        windows: snap.overlay_windows.clone(),
                        hints: snap.hints.clone(),
                    }];
                    self.phase = Phase::Picking {
                        snap,
                        selection,
                        input,
                        pending_launch: None,
                    };
                    return cmds;
                }

                let elapsed = entered_at.elapsed().as_millis() as u32;

                if elapsed < dwell_ms && selection == snap.initial_forward() && input.is_empty() {
                    // Quick-switch: fast release, no interaction → MRU previous.
                    self.activate_index(snap.initial_forward(), &snap)
                } else {
                    // Slow release or user interacted: activate current selection.
                    self.activate_index(selection, &snap)
                }
            }
            Phase::Picking {
                selection,
                snap,
                pending_launch,
                input,
            } => {
                // Pending launch takes priority over window activation.
                if let Some(launch) = pending_launch {
                    self.phase = Phase::Launching;
                    return vec![
                        Command::ShowLaunching,
                        Command::LaunchApp {
                            command: launch.command,
                            tags: launch.tags,
                            launch_args: launch.launch_args,
                        },
                    ];
                }

                if snap.windows.is_empty() {
                    self.phase = Phase::Picking {
                        snap,
                        selection,
                        input,
                        pending_launch: None,
                    };
                    return Vec::new();
                }

                self.activate_index(selection, &snap)
            }
            other @ (Phase::Idle
            | Phase::Launching
            | Phase::LaunchError
            | Phase::Unlocking { .. }) => {
                self.phase = other;
                Vec::new()
            }
        }
    }

    /// Activate window at `index`. Honors any selection including origin.
    fn activate_index(&mut self, index: usize, snap: &Snapshot) -> Vec<Command> {
        self.phase = Phase::Idle;
        self.last_ipc_advance = None;

        if let Some(w) = snap.windows.get(index) {
            tracing::info!(
                index,
                target = %w.id,
                app_id = %w.app_id,
                "activating window"
            );
            vec![
                Command::HideAndSync,
                Command::ActivateWindow { window: w.clone() },
                Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
            ]
        } else {
            vec![
                Command::Hide,
                Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
            ]
        }
    }

    // -----------------------------------------------------------------------
    // Dwell timeout — transition Armed → Picking
    // -----------------------------------------------------------------------

    fn on_dwell_timeout(&mut self) -> Vec<Command> {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Armed {
                snap,
                selection,
                input,
                pending_launch,
                ..
            } => {
                let cmds = vec![Command::ShowPicker {
                    windows: snap.overlay_windows.clone(),
                    hints: snap.hints.clone(),
                }];
                self.phase = Phase::Picking {
                    snap,
                    selection,
                    input,
                    pending_launch,
                };
                cmds
            }
            other => {
                self.phase = other;
                Vec::new()
            }
        }
    }

    // -----------------------------------------------------------------------
    // Character input
    // -----------------------------------------------------------------------

    fn on_char(&mut self, ch: char) -> Vec<Command> {
        match &mut self.phase {
            Phase::Armed { input, .. } | Phase::Picking { input, .. } => {
                // Centralised character filter: only alphanumeric chars are valid
                // for launcher search input. All printable chars pass through the
                // overlay/IPC layers; filtering happens here so every input path
                // shares the same policy.
                if !ch.is_alphanumeric() {
                    return Vec::new();
                }
                if input.len() >= MAX_INPUT_LENGTH {
                    return Vec::new();
                }
                input.push(ch);
                self.check_hint_or_launch()
            }
            Phase::Unlocking {
                unlock_mode: UnlockMode::Password,
                password_len,
                ..
            } => {
                *password_len += 1;
                vec![Command::PasswordChar(ch)]
            }
            Phase::Unlocking { .. } => Vec::new(),
            Phase::LaunchError => {
                self.phase = Phase::Idle;
                vec![
                    Command::Hide,
                    Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
                ]
            }
            _ => Vec::new(),
        }
    }

    fn check_hint_or_launch(&mut self) -> Vec<Command> {
        let (input, hints, key_bindings, is_armed) = match &self.phase {
            Phase::Armed { input, snap, .. } => {
                (input.clone(), &snap.hints, &snap.key_bindings, true)
            }
            Phase::Picking { input, snap, .. } => {
                (input.clone(), &snap.hints, &snap.key_bindings, false)
            }
            _ => return Vec::new(),
        };

        let match_result = hints::match_input(&input, hints);
        tracing::debug!(
            input = %input,
            ?match_result,
            ?hints,
            key_binding_keys = ?key_bindings.keys().collect::<Vec<_>>(),
            is_armed,
            "check_hint_or_launch"
        );

        match match_result {
            MatchResult::Exact(idx) => {
                // Exact hint match — SELECT the window, do NOT commit.
                // Commitment only happens on Alt release (on_modifier_released)
                // or explicit Enter (on_confirm). This gives the user time to
                // see the selection, press Backspace to correct, or Escape.
                self.update_selection(idx);
                // Clear any pending launch — user switched to window selection.
                self.clear_pending_launch();
                if is_armed {
                    self.transition_armed_to_picking()
                } else {
                    vec![Command::UpdatePicker {
                        input,
                        selection: idx,
                    }]
                }
            }
            MatchResult::NoMatch => {
                if input.len() == 1 {
                    let key = input.chars().next().unwrap();
                    if let Some(cmd) = hints::launch_for_key(key, key_bindings) {
                        // Stage the launch — do NOT execute yet.
                        // Commitment happens on Alt release or Enter.
                        // User can Backspace to cancel or Escape to dismiss.
                        let command = cmd.to_string();
                        let tags = hints::tags_for_key(key, key_bindings);
                        let launch_args = hints::launch_args_for_key(key, key_bindings);
                        self.set_pending_launch(PendingLaunch {
                            command: command.clone(),
                            tags,
                            launch_args,
                        });
                        let mut cmds = if is_armed {
                            self.transition_armed_to_picking()
                        } else {
                            vec![Command::UpdatePicker {
                                input,
                                selection: self.current_selection(),
                            }]
                        };
                        cmds.push(Command::ShowLaunchStaged { command });
                        return cmds;
                    }
                }
                // Clear any pending launch — input no longer matches.
                self.clear_pending_launch();
                if is_armed {
                    self.transition_armed_to_picking()
                } else {
                    vec![Command::UpdatePicker {
                        input,
                        selection: self.current_selection(),
                    }]
                }
            }
            MatchResult::Partial(_) => {
                // Clear any pending launch — still typing.
                self.clear_pending_launch();
                if is_armed {
                    self.transition_armed_to_picking()
                } else {
                    vec![Command::UpdatePicker {
                        input,
                        selection: self.current_selection(),
                    }]
                }
            }
        }
    }

    fn transition_armed_to_picking(&mut self) -> Vec<Command> {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Armed {
                snap,
                selection,
                input,
                pending_launch,
                ..
            } => {
                let cmds = vec![
                    Command::ShowPicker {
                        windows: snap.overlay_windows.clone(),
                        hints: snap.hints.clone(),
                    },
                    Command::UpdatePicker {
                        input: input.clone(),
                        selection,
                    },
                ];
                self.phase = Phase::Picking {
                    snap,
                    selection,
                    input,
                    pending_launch,
                };
                cmds
            }
            other => {
                self.phase = other;
                Vec::new()
            }
        }
    }

    // -----------------------------------------------------------------------
    // Navigation — full-circle cycling, origin is just last in MRU order
    // -----------------------------------------------------------------------

    /// Check if a recent IPC re-activation already advanced the selection,
    /// making this keyboard-driven SelectionDown/Up redundant.
    fn is_reactivation_duplicate(&mut self) -> bool {
        if let Some(ts) = self.last_ipc_advance {
            if ts.elapsed().as_millis() < REACTIVATION_DEDUP_MS {
                // Consume the timestamp so only one keyboard event is suppressed
                // per re-activation. This allows subsequent Tab presses (without
                // a matching IPC re-activation) to work normally.
                self.last_ipc_advance = None;
                return true;
            }
            self.last_ipc_advance = None;
        }
        false
    }

    fn on_selection_down(&mut self) -> Vec<Command> {
        if self.is_reactivation_duplicate() {
            return Vec::new();
        }
        match &mut self.phase {
            Phase::Armed {
                selection, snap, ..
            } => {
                if !snap.windows.is_empty() {
                    *selection = (*selection + 1) % snap.windows.len();
                }
                self.transition_armed_to_picking()
            }
            Phase::Picking {
                selection,
                snap,
                input,
                ..
            } => {
                if !snap.windows.is_empty() {
                    *selection = (*selection + 1) % snap.windows.len();
                }
                vec![Command::UpdatePicker {
                    input: input.clone(),
                    selection: *selection,
                }]
            }
            _ => Vec::new(),
        }
    }

    fn on_selection_up(&mut self) -> Vec<Command> {
        if self.is_reactivation_duplicate() {
            return Vec::new();
        }
        match &mut self.phase {
            Phase::Armed {
                selection, snap, ..
            } => {
                if !snap.windows.is_empty() {
                    *selection = if *selection == 0 {
                        snap.windows.len() - 1
                    } else {
                        *selection - 1
                    };
                }
                self.transition_armed_to_picking()
            }
            Phase::Picking {
                selection,
                snap,
                input,
                ..
            } => {
                if !snap.windows.is_empty() {
                    *selection = if *selection == 0 {
                        snap.windows.len() - 1
                    } else {
                        *selection - 1
                    };
                }
                vec![Command::UpdatePicker {
                    input: input.clone(),
                    selection: *selection,
                }]
            }
            _ => Vec::new(),
        }
    }

    fn on_backspace(&mut self) -> Vec<Command> {
        match &mut self.phase {
            Phase::Unlocking {
                unlock_mode: UnlockMode::Password,
                password_len,
                ..
            } => {
                if *password_len > 0 {
                    *password_len -= 1;
                    vec![Command::PasswordBackspace]
                } else {
                    Vec::new()
                }
            }
            Phase::Armed {
                input,
                pending_launch,
                ..
            } => {
                input.pop();
                // Clear pending launch if input is emptied (user cancelled).
                if input.is_empty() {
                    *pending_launch = None;
                }
                Vec::new()
            }
            Phase::Picking {
                input,
                selection,
                pending_launch,
                ..
            } => {
                input.pop();
                if input.is_empty() {
                    *pending_launch = None;
                }
                vec![Command::UpdatePicker {
                    input: input.clone(),
                    selection: *selection,
                }]
            }
            _ => Vec::new(),
        }
    }

    fn on_confirm(&mut self) -> Vec<Command> {
        // Handle Unlocking/Password first via mutable borrow.
        if let Phase::Unlocking {
            unlock_mode,
            profiles_to_unlock,
            current_index,
            ..
        } = &mut self.phase
            && *unlock_mode == UnlockMode::Password
        {
            let profile = profiles_to_unlock[*current_index].clone();
            *unlock_mode = UnlockMode::Verifying;
            // ShowVerifying is handled inside the SubmitPasswordUnlock executor
            // BEFORE the IPC round-trip, not as a separate command after it.
            // Emitting it here would cause it to execute AFTER the unlock IPC
            // completes and its result commands are recursively processed,
            // overwriting whatever the unlock result displayed.
            return vec![Command::SubmitPasswordUnlock { profile }];
        }

        match std::mem::replace(&mut self.phase, Phase::Idle) {
            unlocking @ Phase::Unlocking { .. } => {
                // Confirm during non-Password unlock modes is a no-op.
                self.phase = unlocking;
                Vec::new()
            }
            Phase::Armed {
                selection, snap, ..
            }
            | Phase::Picking {
                selection, snap, ..
            } => self.activate_index(selection, &snap),
            Phase::LaunchError => vec![
                Command::Hide,
                Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
            ],
            Phase::Idle | Phase::Launching => Vec::new(),
        }
    }

    fn on_escape(&mut self) -> Vec<Command> {
        self.last_ipc_advance = None;
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => Vec::new(),
            Phase::Unlocking { .. } => {
                vec![
                    Command::ClearPasswordBuffer,
                    Command::Hide,
                    Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
                ]
            }
            _ => vec![
                Command::Hide,
                Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
            ],
        }
    }

    // -----------------------------------------------------------------------
    // Launch result
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn on_launch_result(
        &mut self,
        success: bool,
        error: Option<String>,
        denial: Option<LaunchDenial>,
        original_command: Option<String>,
        original_tags: Option<Vec<String>>,
        original_launch_args: Option<Vec<String>>,
    ) -> Vec<Command> {
        if !matches!(self.phase, Phase::Launching) {
            return Vec::new();
        }

        if success {
            self.phase = Phase::Idle;
            return vec![
                Command::Hide,
                Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
            ];
        }

        // Check for VaultsLocked denial — transition to inline unlock.
        if let Some(LaunchDenial::VaultsLocked { locked_profiles }) = denial
            && let (Some(cmd), Some(tags), Some(args)) =
                (original_command, original_tags, original_launch_args)
            && let Some(first_profile) = locked_profiles.first()
        {
            let profile = first_profile.clone();
            self.phase = Phase::Unlocking {
                profiles_to_unlock: locked_profiles,
                current_index: 0,
                password_len: 0,
                unlock_mode: UnlockMode::AutoAttempt,
                retry_command: cmd,
                retry_tags: tags,
                retry_launch_args: args,
            };
            return vec![Command::AttemptAutoUnlock { profile }];
        }

        let message = error.unwrap_or_else(|| "launch failed".into());
        self.phase = Phase::LaunchError;
        vec![Command::ShowLaunchError {
            message,
            denial: None,
        }]
    }

    // -----------------------------------------------------------------------
    // Unlock result handlers
    // -----------------------------------------------------------------------

    fn on_auto_unlock_result(
        &mut self,
        success: bool,
        profile: TrustProfileName,
        needs_touch: bool,
    ) -> Vec<Command> {
        if !matches!(self.phase, Phase::Unlocking { .. }) {
            return Vec::new();
        }
        if success {
            return self.advance_to_next_profile_or_retry();
        }
        if needs_touch {
            if let Phase::Unlocking { unlock_mode, .. } = &mut self.phase {
                *unlock_mode = UnlockMode::WaitingForTouch;
            }
            return vec![Command::ShowTouchPrompt { profile }];
        }
        // Fall back to password.
        if let Phase::Unlocking { unlock_mode, .. } = &mut self.phase {
            *unlock_mode = UnlockMode::Password;
        }
        vec![Command::ShowPasswordPrompt { profile }]
    }

    fn on_touch_result(&mut self, success: bool, profile: TrustProfileName) -> Vec<Command> {
        if !matches!(self.phase, Phase::Unlocking { .. }) {
            return Vec::new();
        }
        if success {
            return self.advance_to_next_profile_or_retry();
        }
        // Fall back to password on touch failure.
        if let Phase::Unlocking { unlock_mode, .. } = &mut self.phase {
            *unlock_mode = UnlockMode::Password;
        }
        vec![
            Command::ShowPasswordPrompt { profile },
            Command::ShowUnlockError {
                message: "Touch verification failed".into(),
            },
        ]
    }

    fn on_unlock_result(&mut self, success: bool, profile: TrustProfileName) -> Vec<Command> {
        if !matches!(self.phase, Phase::Unlocking { .. }) {
            return Vec::new();
        }
        if success {
            return self.advance_to_next_profile_or_retry();
        }
        // Wrong password — reset for retry.
        if let Phase::Unlocking {
            password_len,
            unlock_mode,
            ..
        } = &mut self.phase
        {
            *password_len = 0;
            *unlock_mode = UnlockMode::Password;
        }
        vec![
            Command::ClearPasswordBuffer,
            Command::ShowPasswordPrompt { profile },
            Command::ShowUnlockError {
                message: "Wrong password".into(),
            },
        ]
    }

    /// Advance to the next locked profile, or retry the original launch.
    fn advance_to_next_profile_or_retry(&mut self) -> Vec<Command> {
        let mut cmds = vec![Command::ClearPasswordBuffer];

        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Unlocking {
                profiles_to_unlock,
                current_index,
                retry_command,
                retry_tags,
                retry_launch_args,
                ..
            } => {
                let next_index = current_index + 1;
                if next_index < profiles_to_unlock.len() {
                    // More profiles to unlock.
                    let profile = profiles_to_unlock[next_index].clone();
                    self.phase = Phase::Unlocking {
                        profiles_to_unlock,
                        current_index: next_index,
                        password_len: 0,
                        unlock_mode: UnlockMode::AutoAttempt,
                        retry_command,
                        retry_tags,
                        retry_launch_args,
                    };
                    cmds.push(Command::AttemptAutoUnlock { profile });
                } else {
                    // All profiles unlocked — activate them, then retry the launch.
                    self.phase = Phase::Launching;
                    cmds.push(Command::ShowLaunching);
                    cmds.push(Command::ActivateProfiles {
                        profiles: profiles_to_unlock,
                    });
                    cmds.push(Command::LaunchApp {
                        command: retry_command,
                        tags: retry_tags,
                        launch_args: retry_launch_args,
                    });
                }
            }
            other => {
                self.phase = other;
            }
        }

        cmds
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn current_selection(&self) -> usize {
        match &self.phase {
            Phase::Armed { selection, .. } | Phase::Picking { selection, .. } => *selection,
            _ => 0,
        }
    }

    fn update_selection(&mut self, idx: usize) {
        match &mut self.phase {
            Phase::Armed { selection, .. } | Phase::Picking { selection, .. } => {
                *selection = idx;
            }
            _ => {}
        }
    }

    fn set_pending_launch(&mut self, launch: PendingLaunch) {
        match &mut self.phase {
            Phase::Armed { pending_launch, .. } | Phase::Picking { pending_launch, .. } => {
                *pending_launch = Some(launch);
            }
            _ => {}
        }
    }

    fn clear_pending_launch(&mut self) {
        match &mut self.phase {
            Phase::Armed { pending_launch, .. } | Phase::Picking { pending_launch, .. } => {
                *pending_launch = None;
            }
            _ => {}
        }
    }
}

impl Default for OverlayController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::WmKeyBinding;

    fn test_config() -> WmConfig {
        WmConfig {
            quick_switch_threshold_ms: 250,
            activation_delay_ms: 200,
            max_visible_windows: 20,
            hint_keys: "asdfghjkl".into(),
            key_bindings: [
                ("g", vec!["com.mitchellh.ghostty"], Some("ghostty")),
                ("f", vec!["firefox"], Some("firefox")),
                ("e", vec!["microsoft-edge"], Some("microsoft-edge")),
            ]
            .into_iter()
            .map(|(k, apps, launch)| {
                (
                    k.to_string(),
                    WmKeyBinding {
                        apps: apps.into_iter().map(String::from).collect(),
                        launch: launch.map(String::from),
                        tags: Vec::new(),
                        launch_args: Vec::new(),
                    },
                )
            })
            .collect(),
            ..Default::default()
        }
    }

    fn test_windows() -> Vec<Window> {
        vec![
            Window {
                id: core_types::WindowId::new(),
                app_id: core_types::AppId::new("com.mitchellh.ghostty"),
                title: "Terminal".into(),
                workspace_id: core_types::CompositorWorkspaceId::new(),
                monitor_id: core_types::MonitorId::new(),
                geometry: core_types::Geometry {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                },
                is_focused: true,
                is_minimized: false,
                is_fullscreen: false,
                profile_id: core_types::ProfileId::new(),
            },
            Window {
                id: core_types::WindowId::new(),
                app_id: core_types::AppId::new("firefox"),
                title: "Firefox".into(),
                workspace_id: core_types::CompositorWorkspaceId::new(),
                monitor_id: core_types::MonitorId::new(),
                geometry: core_types::Geometry {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                },
                is_focused: false,
                is_minimized: false,
                is_fullscreen: false,
                profile_id: core_types::ProfileId::new(),
            },
            Window {
                id: core_types::WindowId::new(),
                app_id: core_types::AppId::new("microsoft-edge"),
                title: "Edge".into(),
                workspace_id: core_types::CompositorWorkspaceId::new(),
                monitor_id: core_types::MonitorId::new(),
                geometry: core_types::Geometry {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                },
                is_focused: false,
                is_minimized: false,
                is_fullscreen: false,
                profile_id: core_types::ProfileId::new(),
            },
        ]
    }

    // === Forward activation ===

    #[test]
    fn activate_emits_show_border() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::Activate, &test_windows(), &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowBorder { .. })));
        assert!(!ctrl.is_idle());
    }

    #[test]
    fn activate_sets_dwell_deadline() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::Activate, &test_windows(), &test_config());
        assert!(ctrl.next_deadline().is_some());
    }

    #[test]
    fn forward_initial_selection_is_not_origin() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::Activate, &test_windows(), &test_config());
        if let Phase::Armed {
            selection, snap, ..
        } = &ctrl.phase
        {
            assert_ne!(
                Some(*selection),
                snap.origin_index,
                "forward should not default-select origin"
            );
        }
    }

    // === Backward activation ===

    #[test]
    fn backward_initial_selection_is_not_origin() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateBackward, &test_windows(), &test_config());
        if let Phase::Armed {
            selection, snap, ..
        } = &ctrl.phase
        {
            assert_ne!(
                Some(*selection),
                snap.origin_index,
                "backward should not default-select origin"
            );
        }
    }

    // === Launcher activation ===

    #[test]
    fn launcher_enters_armed_with_short_dwell() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::ActivateLauncher, &test_windows(), &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowBorder { .. })));
        assert!(matches!(ctrl.phase, Phase::Armed { .. }));
        // Short dwell means a deadline is set.
        assert!(ctrl.next_deadline().is_some());
    }

    #[test]
    fn launcher_dwell_transitions_to_picking() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        let cmds = ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
        assert!(matches!(ctrl.phase, Phase::Picking { .. }));
    }

    #[test]
    fn launcher_initial_selection_is_not_origin() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateLauncher, &test_windows(), &test_config());
        if let Phase::Armed {
            selection, snap, ..
        } = &ctrl.phase
        {
            assert_ne!(Some(*selection), snap.origin_index);
        }
    }

    // === Quick-switch ===

    #[test]
    fn fast_release_quick_switches_to_non_origin() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::HideAndSync)));
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    #[test]
    fn no_targets_is_noop_for_switcher() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::Activate, &[], &test_config());
        assert!(cmds.is_empty());
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_activates_with_zero_windows() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::ShowBorder { .. })),
            "launcher must activate even with zero windows"
        );
        assert!(!ctrl.is_idle());
    }

    #[test]
    fn launcher_zero_windows_can_stage_launch() {
        let mut ctrl = OverlayController::new();
        let config = test_config();
        ctrl.handle(Event::ActivateLauncher, &[], &config);
        // Type 'g' — no ghostty window, but launch binding exists.
        let cmds = ctrl.handle(Event::Char('g'), &[], &config);
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowLaunchStaged { .. })),
            "must stage ghostty launch with zero windows, got: {cmds:?}"
        );
        // Alt release executes.
        let cmds = ctrl.handle(Event::ModifierReleased, &[], &config);
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "ghostty"))
        );
    }

    // === Full-circle cycling reaches origin ===

    #[test]
    fn full_circle_cycling_visits_all_indices() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());

        let snap_len = if let Phase::Picking { snap, .. } = &ctrl.phase {
            snap.windows.len()
        } else {
            panic!("expected Picking");
        };

        // Collect every selection index visited over a full cycle.
        let mut visited = std::collections::HashSet::new();
        for _ in 0..snap_len {
            if let Phase::Picking { selection, .. } = &ctrl.phase {
                visited.insert(*selection);
            }
            ctrl.handle(Event::SelectionDown, &windows, &test_config());
        }
        // After full cycle we're back at start — check that too.
        if let Phase::Picking { selection, .. } = &ctrl.phase {
            visited.insert(*selection);
        }

        // Every index must be reachable (including origin when it exists).
        assert_eq!(
            visited.len(),
            snap_len,
            "full-circle cycling must visit all {snap_len} indices, visited {visited:?}"
        );
    }

    // === Hint match selects, does NOT commit (commit on Alt release) ===

    #[test]
    fn hint_match_selects_origin_without_commit() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        // 'g' is the hint for ghostty (the origin/focused window).
        // Typing it SELECTS ghostty but does NOT commit.
        let cmds = ctrl.handle(Event::Char('g'), &windows, &test_config());
        assert!(
            !cmds
                .iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. })),
            "hint match must NOT activate on keypress"
        );
        assert!(!ctrl.is_idle(), "must stay in Picking, not Idle");
        // Alt release commits the selection.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. })),
            "Alt release must commit the hint selection"
        );
        assert!(ctrl.is_idle());
    }

    // === Dwell timeout ===

    #[test]
    fn dwell_timeout_shows_picker() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
        assert!(matches!(ctrl.phase, Phase::Picking { .. }));
    }

    // === Char input — stage launch or select, never commit on keypress ===

    #[test]
    fn char_stages_launch_when_no_window() {
        let mut ctrl = OverlayController::new();
        let windows = vec![test_windows()[0].clone()]; // only ghostty
        ctrl.handle(Event::Activate, &windows, &test_config());
        // 'e' has no window → stages launch, does NOT execute.
        let cmds = ctrl.handle(Event::Char('e'), &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowLaunchStaged { .. })),
            "must show staged launch, got: {cmds:?}"
        );
        assert!(
            !cmds.iter().any(|c| matches!(c, Command::LaunchApp { .. })),
            "must NOT execute launch on keypress"
        );
        assert!(matches!(ctrl.phase, Phase::Picking { .. }));
        // Alt release executes the staged launch.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter().any(
                |c| matches!(c, Command::LaunchApp { command, .. } if command == "microsoft-edge")
            ),
            "Alt release must execute staged launch"
        );
    }

    #[test]
    fn char_selects_hint_without_commit() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        // 'e' matches edge window hint → selects, does NOT commit.
        let cmds = ctrl.handle(Event::Char('e'), &windows, &test_config());
        assert!(
            !cmds
                .iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. })),
            "hint match must NOT activate on keypress"
        );
        assert!(!ctrl.is_idle());
        // Alt release commits.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_char_f_stages_launch_when_not_running() {
        let mut ctrl = OverlayController::new();
        // Only ghostty and edge — no firefox window.
        let windows = vec![test_windows()[0].clone(), test_windows()[2].clone()];
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        assert!(matches!(ctrl.phase, Phase::Armed { .. }));
        // 'f' has no window → stages launch, does NOT execute.
        let cmds = ctrl.handle(Event::Char('f'), &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowLaunchStaged { .. })),
            "expected ShowLaunchStaged for firefox, got: {cmds:?}"
        );
        assert!(matches!(ctrl.phase, Phase::Picking { .. }));
        // Alt release executes.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "firefox"))
        );
    }

    #[test]
    fn launcher_char_f_selects_firefox_when_running() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows(); // includes firefox
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        // 'f' matches firefox hint → selects, does NOT commit.
        let cmds = ctrl.handle(Event::Char('f'), &windows, &test_config());
        assert!(
            !cmds
                .iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. })),
            "hint match must NOT activate on keypress, got: {cmds:?}"
        );
        assert!(!ctrl.is_idle());
        // Alt release commits.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    #[test]
    fn backspace_cancels_staged_launch() {
        let mut ctrl = OverlayController::new();
        let windows = vec![test_windows()[0].clone()]; // only ghostty
        ctrl.handle(Event::Activate, &windows, &test_config());
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        // Stage a launch.
        ctrl.handle(Event::Char('e'), &windows, &test_config());
        assert!(matches!(
            ctrl.phase,
            Phase::Picking {
                pending_launch: Some(_),
                ..
            }
        ));
        // Backspace clears input and pending launch.
        ctrl.handle(Event::Backspace, &windows, &test_config());
        assert!(matches!(
            ctrl.phase,
            Phase::Picking {
                pending_launch: None,
                ..
            }
        ));
        // Alt release now activates a window, not a launch.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            !cmds.iter().any(|c| matches!(c, Command::LaunchApp { .. })),
            "backspace must cancel staged launch"
        );
    }

    // === Navigation shows picker ===

    #[test]
    fn tab_in_armed_shows_picker() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::SelectionDown, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
        assert!(matches!(ctrl.phase, Phase::Picking { .. }));
    }

    // === Escape ===

    #[test]
    fn escape_from_armed_dismisses() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::Activate, &test_windows(), &test_config());
        let cmds = ctrl.handle(Event::Escape, &test_windows(), &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::Hide)));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn escape_from_idle_is_noop() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::Escape, &[], &test_config());
        assert!(cmds.is_empty());
    }

    // === Confirm ===

    #[test]
    fn confirm_in_picking_activates() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        let cmds = ctrl.handle(Event::Confirm, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    // === Re-activation cycles all windows ===

    #[test]
    fn reactivate_transitions_armed_to_picking() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::Activate, &windows, &test_config());
        // Re-activation in Armed transitions to Picking with picker visible.
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
        assert!(cmds.iter().any(|c| matches!(c, Command::ResetGrace)));
        if let Phase::Picking {
            selection, snap, ..
        } = &ctrl.phase
        {
            assert!(*selection < snap.windows.len());
        } else {
            panic!("expected Picking after re-activation");
        }
    }

    // === Re-activation grace reset (prevents modifier poll premature commit) ===

    #[test]
    fn reactivate_armed_emits_reset_grace() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::Activate, &windows, &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::ResetGrace)),
            "re-activation in Armed must emit ResetGrace to prevent modifier poll commit"
        );
    }

    #[test]
    fn reactivate_picking_emits_reset_grace() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        assert!(matches!(ctrl.phase, Phase::Picking { .. }));
        let cmds = ctrl.handle(Event::Activate, &windows, &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::ResetGrace)),
            "re-activation in Picking must emit ResetGrace to prevent modifier poll commit"
        );
    }

    #[test]
    fn reactivate_launcher_emits_reset_grace() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        let cmds = ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::ResetGrace)),
            "launcher re-activation must emit ResetGrace"
        );
    }

    #[test]
    fn reactivate_backward_emits_reset_grace() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::ResetGrace)),
            "backward re-activation must emit ResetGrace"
        );
    }

    // === Rapid re-activation cycling (Alt+Space+Space+Space...) ===

    #[test]
    fn rapid_reactivation_cycles_all_windows() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());

        let snap_len = match &ctrl.phase {
            Phase::Armed { snap, .. } => snap.windows.len(),
            _ => panic!("expected Armed"),
        };

        // Simulate Alt+Space repeated — each re-activation should cycle
        // forward through all windows without committing.
        let mut visited = std::collections::HashSet::new();
        for _ in 0..snap_len {
            let cmds = ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
            // Must never commit (no ActivateWindow or HideAndSync).
            assert!(
                !cmds
                    .iter()
                    .any(|c| matches!(c, Command::ActivateWindow { .. } | Command::HideAndSync)),
                "re-activation must not commit"
            );
            if let Phase::Picking { selection, .. } = &ctrl.phase {
                visited.insert(*selection);
            }
        }

        assert_eq!(
            visited.len(),
            snap_len,
            "rapid re-activation must visit all {snap_len} windows, visited {visited:?}"
        );
    }

    #[test]
    fn rapid_reactivation_no_commit_until_modifier_released() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());

        // 20 rapid re-activations — none should commit.
        for i in 0..20 {
            let cmds = ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
            assert!(
                !cmds
                    .iter()
                    .any(|c| matches!(c, Command::ActivateWindow { .. })),
                "re-activation #{i} must not activate a window"
            );
            assert!(!ctrl.is_idle(), "must not return to Idle during cycling");
        }

        // Only ModifierReleased commits.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    #[test]
    fn rapid_reactivation_forward_then_backward() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());

        // Forward 3 times.
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        let sel_after_forward = match &ctrl.phase {
            Phase::Picking { selection, .. } => *selection,
            _ => panic!("expected Picking"),
        };

        // Backward 2 times (simulates adding Shift mid-cycle).
        ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        let sel_after_backward = match &ctrl.phase {
            Phase::Picking { selection, .. } => *selection,
            _ => panic!("expected Picking"),
        };

        // Net movement: 3 forward - 2 backward = 1 forward from initial.
        // Initial Armed selection is initial_forward(), first re-activation
        // cycles +1, so after 3 forward we're at initial+3, minus 2 backward = initial+1.
        assert_ne!(
            sel_after_forward, sel_after_backward,
            "backward must change selection from forward position"
        );
    }

    // === Release after interaction ===

    #[test]
    fn release_after_tab_activates_selection() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
    }

    #[test]
    fn launcher_modifier_release_commits() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        // Releasing Alt commits the selection, same as Alt+Tab mode.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_confirm_activates_selection() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        let cmds = ctrl.handle(Event::Confirm, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    // === Confirm on origin is valid (user navigated there) ===

    #[test]
    fn confirm_on_origin_is_valid() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        // DwellTimeout transitions Armed → Picking.
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());

        // Navigate to origin by cycling all the way around.
        let snap_len = if let Phase::Picking { snap, .. } = &ctrl.phase {
            snap.windows.len()
        } else {
            panic!("expected Picking")
        };

        for _ in 0..snap_len {
            ctrl.handle(Event::SelectionDown, &windows, &test_config());
        }
        // After full circle we're back at the initial (non-origin) position.
        // Navigate one more step back to reach origin (which is last).
        ctrl.handle(Event::SelectionUp, &windows, &test_config());

        // Confirm — should activate whatever is selected, even if origin.
        let cmds = ctrl.handle(Event::Confirm, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. }))
        );
        assert!(ctrl.is_idle());
    }

    // ===================================================================
    // Snapshot unit tests — origin_index explicitly set
    // ===================================================================

    #[test]
    fn snapshot_initial_forward_skips_origin_at_0() {
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(0));
        assert_eq!(snap.initial_forward(), 1);
    }

    #[test]
    fn snapshot_initial_forward_returns_0_when_origin_elsewhere() {
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        assert_eq!(snap.initial_forward(), 0);
    }

    #[test]
    fn snapshot_initial_forward_returns_0_when_no_origin() {
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), None);
        assert_eq!(snap.initial_forward(), 0);
    }

    #[test]
    fn snapshot_initial_backward_skips_origin_at_last() {
        let windows = test_windows(); // 3 windows, last = index 2
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        assert_eq!(snap.initial_backward(), 1);
    }

    #[test]
    fn snapshot_initial_backward_returns_last_when_origin_elsewhere() {
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(0));
        assert_eq!(snap.initial_backward(), 2);
    }

    #[test]
    fn snapshot_initial_backward_returns_last_when_no_origin() {
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), None);
        assert_eq!(snap.initial_backward(), 2);
    }

    #[test]
    fn snapshot_has_targets_single_window_with_origin() {
        let single = vec![test_windows()[0].clone()];
        let snap = Snapshot::with_origin(&single, &test_config(), Some(0));
        assert!(
            snap.has_targets(),
            "single window is a valid target (user may be on a different workspace)"
        );
    }

    #[test]
    fn snapshot_has_targets_with_origin_and_others() {
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        assert!(snap.has_targets());
    }

    #[test]
    fn snapshot_has_targets_no_origin() {
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), None);
        assert!(snap.has_targets());
    }

    #[test]
    fn snapshot_has_targets_empty() {
        let empty: Vec<Window> = vec![];
        let snap = Snapshot::with_origin(&empty, &test_config(), None);
        assert!(!snap.has_targets());
    }

    // ===================================================================
    // Controller with injected origin — exercises origin-skipping paths
    // ===================================================================

    #[test]
    fn armed_with_origin_at_last_skips_origin_on_quick_switch() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        // Origin at index 2 (last) — typical after mru::reorder.
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        ctrl.arm_with_snapshot(snap, 250);

        // Fast release → quick-switch to index 0 (not origin at 2).
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        let activated = cmds.iter().find_map(|c| match c {
            Command::ActivateWindow { window, .. } => Some(window.clone()),
            _ => None,
        });
        assert!(activated.is_some(), "should activate a window");
        assert_eq!(
            activated.unwrap().id,
            windows[0].id,
            "should activate index 0, not origin"
        );
        assert!(ctrl.is_idle());
    }

    #[test]
    fn armed_with_origin_at_0_skips_origin_on_quick_switch() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        // Edge case: origin at index 0 — forward should skip to 1.
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(0));
        ctrl.arm_with_snapshot(snap, 250);

        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        let activated = cmds.iter().find_map(|c| match c {
            Command::ActivateWindow { window, .. } => Some(window.clone()),
            _ => None,
        });
        assert!(activated.is_some());
        assert_eq!(
            activated.unwrap().id,
            windows[1].id,
            "should activate index 1, skipping origin at 0"
        );
    }

    #[test]
    fn picking_with_origin_starts_at_non_origin() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        ctrl.pick_with_snapshot(snap);

        if let Phase::Picking {
            selection, snap, ..
        } = &ctrl.phase
        {
            assert_ne!(*selection, 2, "should not start at origin");
            assert_ne!(Some(*selection), snap.origin_index);
            assert_eq!(*selection, 0);
        } else {
            panic!("expected Picking");
        }
    }

    #[test]
    fn single_window_is_origin_still_activatable() {
        let single = vec![test_windows()[0].clone()];
        let snap = Snapshot::with_origin(&single, &test_config(), Some(0));
        assert!(snap.has_targets());
    }

    #[test]
    fn cycling_with_origin_visits_origin_too() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        ctrl.pick_with_snapshot(snap);

        let mut visited = std::collections::HashSet::new();
        for _ in 0..windows.len() {
            if let Phase::Picking { selection, .. } = &ctrl.phase {
                visited.insert(*selection);
            }
            ctrl.handle(Event::SelectionDown, &windows, &test_config());
        }
        if let Phase::Picking { selection, .. } = &ctrl.phase {
            visited.insert(*selection);
        }

        assert!(visited.contains(&2), "cycling must visit origin at index 2");
        assert_eq!(visited.len(), windows.len(), "must visit all indices");
    }

    // === Origin rotation in Snapshot::build layout ===

    #[test]
    fn origin_at_last_display_order() {
        // Simulates what build() does: origin rotated to end.
        // Given 3 windows [A=origin, B, C] after MRU reorder,
        // rotation produces [B, C, A] with origin_index = 2.
        let windows = test_windows(); // ghostty, vivaldi, edge
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        // Origin is at the end.
        assert_eq!(snap.origin_index, Some(2));
        // Forward selection starts at 0 (top of picker, not origin).
        assert_eq!(snap.initial_forward(), 0);
        // Backward selection starts at 1 (last non-origin).
        assert_eq!(snap.initial_backward(), 1);
    }

    #[test]
    fn origin_rotation_preserves_mru_order() {
        // After rotation: [MRU previous, ..., origin]
        // The non-origin windows maintain their relative MRU order.
        let windows = test_windows(); // ghostty(0), firefox(1), edge(2)
        // If ghostty is origin (index 0 pre-rotation), rotation produces:
        // [firefox, edge, ghostty] with origin_index = 2
        let mut rotated = windows.clone();
        let origin = rotated.remove(0);
        rotated.push(origin);
        let snap = Snapshot::with_origin(&rotated, &test_config(), Some(2));

        assert_eq!(snap.windows[0].app_id.as_str(), "firefox");
        assert_eq!(snap.windows[1].app_id.as_str(), "microsoft-edge");
        assert_eq!(snap.windows[2].app_id.as_str(), "com.mitchellh.ghostty");
        assert_eq!(snap.origin_index, Some(2));
    }

    #[test]
    fn origin_at_last_picker_top_is_switch_target() {
        // The top of the picker (index 0) should be the quick-switch
        // target, not the origin.
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        let mut ctrl = OverlayController::new();
        ctrl.arm_with_snapshot(snap, 5000);

        // Quick-switch (fast release) should activate index 0.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        let activated = cmds.iter().find_map(|c| match c {
            Command::ActivateWindow { window, .. } => Some(window),
            _ => None,
        });
        assert!(activated.is_some());
        assert_eq!(
            activated.unwrap().id,
            windows[0].id,
            "quick-switch should activate top of picker (index 0), not origin"
        );
    }

    // === In-flight direction change (Alt+Tab then Alt+Shift+Tab) ===

    #[test]
    fn armed_forward_then_backward_reverses() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows(); // 3 windows, origin at 2
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        ctrl.arm_with_snapshot(snap, 5000);

        // Initial forward selection is 0.
        if let Phase::Armed { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 0);
        }

        // Forward re-activation: selection moves to 1.
        ctrl.handle(Event::Activate, &windows, &test_config());
        if let Phase::Armed { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 1);
        }

        // Backward re-activation: selection moves back to 0.
        ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        if let Phase::Armed { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 0);
        }
    }

    #[test]
    fn picking_forward_then_backward_reverses() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        ctrl.pick_with_snapshot(snap);

        // Initial forward selection is 0.
        if let Phase::Picking { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 0);
        }

        // Forward re-activation: 0 → 1.
        ctrl.handle(Event::Activate, &windows, &test_config());
        if let Phase::Picking { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 1);
        }

        // Backward re-activation: 1 → 0.
        ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        if let Phase::Picking { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 0);
        }

        // Backward again: 0 → 2 (wraps).
        ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        if let Phase::Picking { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 2);
        }
    }

    // ===================================================================
    // Vault unlock flow tests
    // ===================================================================

    /// Helper: drive the controller to Phase::Launching with a staged ghostty launch.
    /// Uses an empty window list so 'g' hits the launch binding (not a hint match).
    fn drive_to_launching(ctrl: &mut OverlayController, _windows: &[Window], config: &WmConfig) {
        let no_windows: Vec<Window> = vec![];
        ctrl.handle(Event::ActivateLauncher, &no_windows, config);
        ctrl.handle(Event::Char('g'), &no_windows, config);
        let cmds = ctrl.handle(Event::ModifierReleased, &no_windows, config);
        assert!(
            matches!(ctrl.phase, Phase::Launching),
            "expected Phase::Launching after modifier release with staged launch, \
             phase={:?}, cmds={cmds:?}",
            ctrl.phase
        );
    }

    /// Helper: construct a VaultsLocked LaunchResult event.
    fn vaults_locked_event(profiles: &[&str]) -> Event {
        Event::LaunchResult {
            success: false,
            error: Some("VaultsLocked".into()),
            denial: Some(LaunchDenial::VaultsLocked {
                locked_profiles: profiles
                    .iter()
                    .map(|p| TrustProfileName::try_from(*p).unwrap())
                    .collect(),
            }),
            original_command: Some("ghostty".into()),
            original_tags: Some(vec!["dev".into()]),
            original_launch_args: Some(vec![]),
        }
    }

    /// Helper: drive to Phase::Unlocking (Password mode) for a single profile.
    fn drive_to_password_prompt(
        ctrl: &mut OverlayController,
        windows: &[Window],
        config: &WmConfig,
        profile: &str,
    ) {
        drive_to_launching(ctrl, windows, config);
        ctrl.handle(vaults_locked_event(&[profile]), windows, config);
        ctrl.handle(
            Event::AutoUnlockResult {
                success: false,
                profile: TrustProfileName::try_from(profile).unwrap(),
                needs_touch: false,
            },
            windows,
            config,
        );
        assert!(
            matches!(
                ctrl.phase,
                Phase::Unlocking {
                    unlock_mode: UnlockMode::Password,
                    ..
                }
            ),
            "expected Phase::Unlocking(Password) after auto-unlock failure"
        );
    }

    #[test]
    fn vaults_locked_transitions_to_unlocking() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_launching(&mut ctrl, &windows, &config);

        let cmds = ctrl.handle(vaults_locked_event(&["default", "work"]), &windows, &config);

        assert!(
            matches!(ctrl.phase, Phase::Unlocking { .. }),
            "VaultsLocked must transition to Phase::Unlocking"
        );
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::AttemptAutoUnlock { .. })),
            "VaultsLocked must emit AttemptAutoUnlock, got: {cmds:?}"
        );
    }

    #[test]
    fn auto_unlock_failure_falls_back_to_password() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_launching(&mut ctrl, &windows, &config);
        ctrl.handle(vaults_locked_event(&["default"]), &windows, &config);

        let cmds = ctrl.handle(
            Event::AutoUnlockResult {
                success: false,
                profile: TrustProfileName::try_from("default").unwrap(),
                needs_touch: false,
            },
            &windows,
            &config,
        );

        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowPasswordPrompt { .. })),
            "auto-unlock failure must fall back to password prompt, got: {cmds:?}"
        );
        if let Phase::Unlocking { unlock_mode, .. } = &ctrl.phase {
            assert_eq!(*unlock_mode, UnlockMode::Password);
        } else {
            panic!("expected Phase::Unlocking");
        }
    }

    #[test]
    fn password_chars_tracked_in_unlock_phase() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_password_prompt(&mut ctrl, &windows, &config, "default");

        let cmds = ctrl.handle(Event::Char('p'), &windows, &config);
        assert!(cmds.iter().any(|c| matches!(c, Command::PasswordChar('p'))));

        let cmds = ctrl.handle(Event::Char('a'), &windows, &config);
        assert!(cmds.iter().any(|c| matches!(c, Command::PasswordChar('a'))));

        if let Phase::Unlocking { password_len, .. } = &ctrl.phase {
            assert_eq!(*password_len, 2);
        } else {
            panic!("expected Phase::Unlocking");
        }
    }

    #[test]
    fn confirm_during_password_emits_submit() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_password_prompt(&mut ctrl, &windows, &config, "default");
        ctrl.handle(Event::Char('p'), &windows, &config);

        let cmds = ctrl.handle(Event::Confirm, &windows, &config);
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::SubmitPasswordUnlock { .. })),
            "Confirm during password must emit SubmitPasswordUnlock, got: {cmds:?}"
        );
        // ShowVerifying is now emitted by the main.rs handler before IPC,
        // not by the controller, so we only check SubmitPasswordUnlock here.
    }

    #[test]
    fn successful_unlock_retries_launch() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_password_prompt(&mut ctrl, &windows, &config, "default");

        let cmds = ctrl.handle(
            Event::UnlockResult {
                success: true,
                profile: TrustProfileName::try_from("default").unwrap(),
            },
            &windows,
            &config,
        );

        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateProfiles { .. })),
            "successful unlock must activate profiles before retry, got: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "ghostty")),
            "successful unlock must retry original launch, got: {cmds:?}"
        );
        assert!(matches!(ctrl.phase, Phase::Launching));
    }

    #[test]
    fn multi_profile_sequential_unlock() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_launching(&mut ctrl, &windows, &config);
        ctrl.handle(vaults_locked_event(&["default", "work"]), &windows, &config);

        // First profile: auto-unlock fails, password succeeds.
        ctrl.handle(
            Event::AutoUnlockResult {
                success: false,
                profile: TrustProfileName::try_from("default").unwrap(),
                needs_touch: false,
            },
            &windows,
            &config,
        );
        let cmds = ctrl.handle(
            Event::UnlockResult {
                success: true,
                profile: TrustProfileName::try_from("default").unwrap(),
            },
            &windows,
            &config,
        );

        // Must advance to second profile, NOT retry launch yet.
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::AttemptAutoUnlock { profile }
            if profile.as_ref() == "work")),
            "must advance to next locked profile, got: {cmds:?}"
        );
        if let Phase::Unlocking { current_index, .. } = &ctrl.phase {
            assert_eq!(*current_index, 1);
        } else {
            panic!("expected Phase::Unlocking at index 1");
        }

        // Second profile: auto-unlock fails, password succeeds.
        ctrl.handle(
            Event::AutoUnlockResult {
                success: false,
                profile: TrustProfileName::try_from("work").unwrap(),
                needs_touch: false,
            },
            &windows,
            &config,
        );
        let cmds = ctrl.handle(
            Event::UnlockResult {
                success: true,
                profile: TrustProfileName::try_from("work").unwrap(),
            },
            &windows,
            &config,
        );

        // NOW activate profiles and retry the launch.
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateProfiles { .. })),
            "all profiles unlocked must activate profiles before retry, got: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "ghostty")),
            "all profiles unlocked must retry launch, got: {cmds:?}"
        );
        assert!(matches!(ctrl.phase, Phase::Launching));
    }

    #[test]
    fn wrong_password_resets_for_retry() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_password_prompt(&mut ctrl, &windows, &config, "default");
        ctrl.handle(Event::Char('x'), &windows, &config);

        let cmds = ctrl.handle(
            Event::UnlockResult {
                success: false,
                profile: TrustProfileName::try_from("default").unwrap(),
            },
            &windows,
            &config,
        );

        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ClearPasswordBuffer))
        );
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowPasswordPrompt { .. }))
        );
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowUnlockError { .. }))
        );

        if let Phase::Unlocking {
            password_len,
            unlock_mode,
            ..
        } = &ctrl.phase
        {
            assert_eq!(*password_len, 0);
            assert_eq!(*unlock_mode, UnlockMode::Password);
        } else {
            panic!("expected Phase::Unlocking after wrong password");
        }
    }

    #[test]
    fn escape_during_unlock_dismisses_and_clears() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_launching(&mut ctrl, &windows, &config);
        ctrl.handle(vaults_locked_event(&["default"]), &windows, &config);

        let cmds = ctrl.handle(Event::Escape, &windows, &config);

        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ClearPasswordBuffer)),
            "escape during unlock must clear password buffer"
        );
        assert!(cmds.iter().any(|c| matches!(c, Command::Hide)));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn vaults_locked_without_original_command_shows_error() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_launching(&mut ctrl, &windows, &config);

        // VaultsLocked but missing original_command — can't retry.
        let cmds = ctrl.handle(
            Event::LaunchResult {
                success: false,
                error: Some("VaultsLocked".into()),
                denial: Some(LaunchDenial::VaultsLocked {
                    locked_profiles: vec![TrustProfileName::try_from("default").unwrap()],
                }),
                original_command: None,
                original_tags: None,
                original_launch_args: None,
            },
            &windows,
            &config,
        );

        // Must fall through to error display, not unlock flow.
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowLaunchError { .. })),
            "VaultsLocked without retry context must show error, got: {cmds:?}"
        );
    }

    #[test]
    fn launch_result_in_wrong_phase_is_noop() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        // Controller is Idle — LaunchResult should be ignored.
        let cmds = ctrl.handle(
            Event::LaunchResult {
                success: false,
                error: None,
                denial: Some(LaunchDenial::VaultsLocked {
                    locked_profiles: vec![TrustProfileName::try_from("default").unwrap()],
                }),
                original_command: Some("ghostty".into()),
                original_tags: Some(vec![]),
                original_launch_args: Some(vec![]),
            },
            &windows,
            &config,
        );

        assert!(cmds.is_empty());
        assert!(ctrl.is_idle());
    }

    #[test]
    fn profiles_activated_before_retry_launch_after_unlock() {
        // Regression: after unlocking all vaults, the retry launch would fail
        // with "denied-profile-not-active" because profiles were never activated.
        // The controller must emit ActivateProfiles BEFORE LaunchApp.
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let config = test_config();

        drive_to_launching(&mut ctrl, &windows, &config);
        ctrl.handle(vaults_locked_event(&["alpha", "beta"]), &windows, &config);

        // Unlock both profiles.
        ctrl.handle(
            Event::AutoUnlockResult {
                success: false,
                profile: TrustProfileName::try_from("alpha").unwrap(),
                needs_touch: false,
            },
            &windows,
            &config,
        );
        ctrl.handle(
            Event::UnlockResult {
                success: true,
                profile: TrustProfileName::try_from("alpha").unwrap(),
            },
            &windows,
            &config,
        );
        ctrl.handle(
            Event::AutoUnlockResult {
                success: false,
                profile: TrustProfileName::try_from("beta").unwrap(),
                needs_touch: false,
            },
            &windows,
            &config,
        );
        let cmds = ctrl.handle(
            Event::UnlockResult {
                success: true,
                profile: TrustProfileName::try_from("beta").unwrap(),
            },
            &windows,
            &config,
        );

        // Find positions to verify ordering.
        let activate_pos = cmds
            .iter()
            .position(|c| matches!(c, Command::ActivateProfiles { .. }));
        let launch_pos = cmds
            .iter()
            .position(|c| matches!(c, Command::LaunchApp { .. }));

        assert!(
            activate_pos.is_some(),
            "ActivateProfiles must be emitted before launch retry, got: {cmds:?}"
        );
        assert!(
            launch_pos.is_some(),
            "LaunchApp must be emitted for retry, got: {cmds:?}"
        );
        assert!(
            activate_pos.unwrap() < launch_pos.unwrap(),
            "ActivateProfiles must come before LaunchApp, got: {cmds:?}"
        );

        // Verify the profiles list contains both unlocked profiles.
        if let Some(Command::ActivateProfiles { profiles }) = cmds
            .iter()
            .find(|c| matches!(c, Command::ActivateProfiles { .. }))
        {
            assert_eq!(profiles.len(), 2);
            assert!(profiles.iter().any(|p| p.as_ref() == "alpha"));
            assert!(profiles.iter().any(|p| p.as_ref() == "beta"));
        }
    }

    // === Zero-window launcher mode ===

    #[test]
    fn launcher_zero_windows_emits_show_border_with_flag() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        assert!(
            cmds.iter().any(|c| matches!(
                c,
                Command::ShowBorder {
                    zero_window_launcher: true
                }
            )),
            "launcher with zero windows must set zero_window_launcher flag, got: {cmds:?}"
        );
        assert!(!ctrl.is_idle());
    }

    #[test]
    fn launcher_zero_windows_dwell_shows_picker() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        let cmds = ctrl.handle(Event::DwellTimeout, &[], &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
    }

    #[test]
    fn launcher_zero_windows_alt_release_is_noop_in_picking() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        ctrl.handle(Event::DwellTimeout, &[], &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &[], &test_config());
        assert!(
            !cmds.iter().any(|c| matches!(
                c,
                Command::Hide | Command::HideAndSync | Command::ActivateWindow { .. }
            )),
            "Alt release in zero-window launcher should be no-op, got: {cmds:?}"
        );
        assert!(!ctrl.is_idle());
    }

    #[test]
    fn launcher_zero_windows_alt_release_in_armed_transitions_to_picking() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &[], &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })),
            "Alt release from Armed with zero windows should show picker, got: {cmds:?}"
        );
        assert!(!ctrl.is_idle());
    }

    #[test]
    fn launcher_zero_windows_escape_dismisses() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        ctrl.handle(Event::DwellTimeout, &[], &test_config());
        let cmds = ctrl.handle(Event::Escape, &[], &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::Hide)));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_zero_windows_char_stages_launch() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        ctrl.handle(Event::DwellTimeout, &[], &test_config());
        let cmds = ctrl.handle(Event::Char('g'), &[], &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ShowLaunchStaged { .. })),
            "typing configured key in zero-window launcher should stage launch, got: {cmds:?}"
        );
    }

    #[test]
    fn launcher_zero_windows_alt_release_executes_staged_launch() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateLauncher, &[], &test_config());
        ctrl.handle(Event::DwellTimeout, &[], &test_config());
        ctrl.handle(Event::Char('g'), &[], &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &[], &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "ghostty")),
            "Alt release with staged launch should execute it, got: {cmds:?}"
        );
    }

    #[test]
    fn switcher_zero_windows_still_noop() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::Activate, &[], &test_config());
        assert!(cmds.is_empty(), "Alt+Tab with zero windows must be no-op");
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_with_windows_flag_is_false() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::ActivateLauncher, &test_windows(), &test_config());
        assert!(
            cmds.iter().any(|c| matches!(
                c,
                Command::ShowBorder {
                    zero_window_launcher: false
                }
            )),
            "launcher with windows should NOT set zero_window_launcher, got: {cmds:?}"
        );
    }

    #[test]
    fn launcher_with_windows_alt_release_activates() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::ActivateWindow { .. })),
            "Alt release with windows should activate, got: {cmds:?}"
        );
        assert!(ctrl.is_idle());
    }
}
