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
use core_types::{EventKind, SecurityLevel, Window};
use std::collections::BTreeMap;
use std::time::Instant;

/// Maximum input buffer length.
const MAX_INPUT_LENGTH: usize = 64;

// ---------------------------------------------------------------------------
// Commands — concrete orders the main loop executes without interpretation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Command {
    /// Send OverlayCmd::ShowBorder to GTK (acquires KeyboardMode::Exclusive).
    ShowBorder,
    /// Send OverlayCmd::ShowFull with the given data.
    ShowPicker {
        windows: Vec<WindowInfo>,
        hints: Vec<String>,
    },
    /// Send OverlayCmd::UpdateInput.
    UpdatePicker {
        input: String,
        selection: usize,
    },
    /// Send OverlayCmd::HideAndSync, wait for SurfaceUnmapped ack.
    HideAndSync,
    /// Send OverlayCmd::Hide (no sync needed).
    Hide,
    /// Activate a window via compositor backend + save MRU state.
    ActivateWindow {
        window: Window,
        origin: Option<String>,
    },
    /// Launch an application via IPC.
    LaunchApp {
        command: String,
        tags: Vec<String>,
    },
    /// Publish an IPC event.
    Publish(EventKind, SecurityLevel),
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
    /// The dwell timer expired (main loop polls `next_deadline()`).
    DwellTimeout,
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
    /// MRU origin window ID (focused window before switch).
    mru_origin: Option<String>,
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
        mru::reorder(&mut win_list, |w| w.id.to_string());
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
        let app_hints = hints::assign_app_hints(&app_ids, &config.hint_keys, &config.key_bindings);
        let hint_strings: Vec<String> = app_hints.iter().map(|(h, _)| h.clone()).collect();

        let overlay_windows: Vec<WindowInfo> = win_list.iter().map(|w| WindowInfo {
            app_id: w.app_id.to_string(),
            title: w.title.clone(),
        }).collect();

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
            mru_origin: mru_state.current().map(|s| s.to_string()),
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

    /// Whether there's at least one non-origin window to switch to.
    fn has_targets(&self) -> bool {
        match self.origin_index {
            Some(_) => self.windows.len() > 1,
            None => !self.windows.is_empty(),
        }
    }

    /// Test-only constructor with explicit origin_index.
    #[cfg(test)]
    fn with_origin(windows: &[Window], config: &WmConfig, origin_index: Option<usize>) -> Self {
        let app_ids: Vec<&str> = windows.iter().map(|w| w.app_id.as_str()).collect();
        let app_hints = hints::assign_app_hints(&app_ids, &config.hint_keys, &config.key_bindings);
        let hint_strings: Vec<String> = app_hints.iter().map(|(h, _)| h.clone()).collect();
        let overlay_windows: Vec<WindowInfo> = windows.iter().map(|w| WindowInfo {
            app_id: w.app_id.to_string(),
            title: w.title.clone(),
        }).collect();
        let mru_origin = origin_index.map(|i| windows[i].id.to_string());

        Self {
            windows: windows.to_vec(),
            hints: hint_strings,
            overlay_windows,
            mru_origin,
            origin_index,
            key_bindings: config.key_bindings.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Phase {
    Idle,
    Armed {
        entered_at: Instant,
        snap: Snapshot,
        selection: usize,
        input: String,
        dwell_ms: u32,
    },
    Picking {
        snap: Snapshot,
        selection: usize,
        input: String,
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
}

#[derive(Debug)]
pub struct OverlayController {
    phase: Phase,
}

impl OverlayController {
    pub fn new() -> Self {
        Self { phase: Phase::Idle }
    }

    /// Returns the next deadline the main loop should wake for, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        match &self.phase {
            Phase::Armed { entered_at, dwell_ms, .. } => {
                Some(*entered_at + std::time::Duration::from_millis(*dwell_ms as u64))
            }
            _ => None,
        }
    }

    /// Is the controller idle?
    pub fn is_idle(&self) -> bool {
        matches!(self.phase, Phase::Idle)
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
        };
    }

    /// Handle an event, returning commands to execute.
    pub fn handle(
        &mut self,
        event: Event,
        windows: &[Window],
        config: &WmConfig,
    ) -> Vec<Command> {
        match event {
            Event::Activate => self.on_activate(windows, config, ActivationMode::Forward),
            Event::ActivateBackward => self.on_activate(windows, config, ActivationMode::Backward),
            Event::ActivateLauncher => self.on_activate(windows, config, ActivationMode::Launcher),
            Event::ModifierReleased => self.on_modifier_released(),
            Event::Char(ch) => self.on_char(ch),
            Event::Backspace => self.on_backspace(),
            Event::SelectionDown => self.on_selection_down(),
            Event::SelectionUp => self.on_selection_up(),
            Event::Confirm => self.on_confirm(),
            Event::Escape => self.on_escape(),
            Event::DwellTimeout => self.on_dwell_timeout(),
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
        match &mut self.phase {
            Phase::Idle => {
                let snap = Snapshot::build(windows, config);

                if !snap.has_targets() {
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
                        };
                        vec![
                            Command::ShowBorder,
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
                        };
                        vec![
                            Command::ShowBorder,
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ]
                    }
                    ActivationMode::Launcher => {
                        // Enter Armed with a short dwell to let the compositor
                        // grant keyboard exclusivity before the user's first
                        // keypress. on_char works in Armed, so fast typists
                        // are handled. DwellTimeout then transitions to Picking.
                        let selection = snap.initial_forward();
                        self.phase = Phase::Armed {
                            entered_at: Instant::now(),
                            snap,
                            selection,
                            input: String::new(),
                            dwell_ms: config.overlay_delay_ms.min(100),
                        };
                        vec![
                            Command::ShowBorder,
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ]
                    }
                }
            }
            Phase::Armed { selection, snap, .. } => {
                // Re-activation cycles in the requested direction.
                if !snap.windows.is_empty() {
                    let len = snap.windows.len();
                    match mode {
                        ActivationMode::Backward => {
                            *selection = (*selection + len - 1) % len;
                        }
                        _ => {
                            *selection = (*selection + 1) % len;
                        }
                    }
                }
                Vec::new()
            }
            Phase::Picking { selection, snap, input, .. } => {
                if !snap.windows.is_empty() {
                    let len = snap.windows.len();
                    match mode {
                        ActivationMode::Backward => {
                            *selection = (*selection + len - 1) % len;
                        }
                        _ => {
                            *selection = (*selection + 1) % len;
                        }
                    }
                }
                vec![Command::UpdatePicker {
                    input: input.clone(),
                    selection: *selection,
                }]
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
            } => {
                let elapsed = entered_at.elapsed().as_millis() as u32;

                if elapsed < dwell_ms && selection == snap.initial_forward() && input.is_empty() {
                    // Quick-switch: fast release, no interaction → MRU previous.
                    self.activate_index(snap.initial_forward(), &snap)
                } else {
                    // Slow release or user interacted: activate current selection.
                    self.activate_index(selection, &snap)
                }
            }
            Phase::Picking { selection, snap, .. } => {
                self.activate_index(selection, &snap)
            }
            Phase::Idle => Vec::new(),
        }
    }

    /// Activate window at `index`. Honors any selection including origin.
    fn activate_index(&mut self, index: usize, snap: &Snapshot) -> Vec<Command> {
        self.phase = Phase::Idle;

        if let Some(w) = snap.windows.get(index) {
            tracing::info!(
                index,
                target = %w.id,
                app_id = %w.app_id,
                "activating window"
            );
            vec![
                Command::HideAndSync,
                Command::ActivateWindow {
                    window: w.clone(),
                    origin: snap.mru_origin.clone(),
                },
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
            Phase::Armed { snap, selection, input, .. } => {
                let cmds = vec![Command::ShowPicker {
                    windows: snap.overlay_windows.clone(),
                    hints: snap.hints.clone(),
                }];
                self.phase = Phase::Picking { snap, selection, input };
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
                if input.len() >= MAX_INPUT_LENGTH {
                    return Vec::new();
                }
                input.push(ch);
                self.check_hint_or_launch()
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
                // Exact hint match — activate that window. Origin included:
                // the user explicitly typed a hint, honor the intent.
                let snap = match std::mem::replace(&mut self.phase, Phase::Idle) {
                    Phase::Armed { snap, .. } | Phase::Picking { snap, .. } => snap,
                    _ => unreachable!(),
                };
                self.activate_index(idx, &snap)
            }
            MatchResult::NoMatch => {
                if input.len() == 1 {
                    let key = input.chars().next().unwrap();
                    if let Some(cmd) = hints::launch_for_key(key, key_bindings) {
                        let command = cmd.to_string();
                        let tags = hints::tags_for_key(key, key_bindings);
                        self.phase = Phase::Idle;
                        return vec![
                            Command::Hide,
                            Command::LaunchApp { command, tags },
                            Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
                        ];
                    }
                }
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
            Phase::Armed { snap, selection, input, .. } => {
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
                self.phase = Phase::Picking { snap, selection, input };
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

    fn on_selection_down(&mut self) -> Vec<Command> {
        match &mut self.phase {
            Phase::Armed { selection, snap, .. } => {
                if !snap.windows.is_empty() {
                    *selection = (*selection + 1) % snap.windows.len();
                }
                self.transition_armed_to_picking()
            }
            Phase::Picking { selection, snap, input, .. } => {
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
        match &mut self.phase {
            Phase::Armed { selection, snap, .. } => {
                if !snap.windows.is_empty() {
                    *selection = if *selection == 0 { snap.windows.len() - 1 } else { *selection - 1 };
                }
                self.transition_armed_to_picking()
            }
            Phase::Picking { selection, snap, input, .. } => {
                if !snap.windows.is_empty() {
                    *selection = if *selection == 0 { snap.windows.len() - 1 } else { *selection - 1 };
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
            Phase::Armed { input, .. } => {
                input.pop();
                Vec::new()
            }
            Phase::Picking { input, selection, .. } => {
                input.pop();
                vec![Command::UpdatePicker {
                    input: input.clone(),
                    selection: *selection,
                }]
            }
            _ => Vec::new(),
        }
    }

    fn on_confirm(&mut self) -> Vec<Command> {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Armed { selection, snap, .. } |
            Phase::Picking { selection, snap, .. } => {
                self.activate_index(selection, &snap)
            }
            Phase::Idle => Vec::new(),
        }
    }

    fn on_escape(&mut self) -> Vec<Command> {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => Vec::new(),
            _ => vec![
                Command::Hide,
                Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
            ],
        }
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
                workspace_id: core_types::WorkspaceId::new(),
                monitor_id: core_types::MonitorId::new(),
                geometry: core_types::Geometry { x: 0, y: 0, width: 800, height: 600 },
                is_focused: true,
                is_minimized: false,
                is_fullscreen: false,
                profile_id: core_types::ProfileId::new(),
            },
            Window {
                id: core_types::WindowId::new(),
                app_id: core_types::AppId::new("firefox"),
                title: "Firefox".into(),
                workspace_id: core_types::WorkspaceId::new(),
                monitor_id: core_types::MonitorId::new(),
                geometry: core_types::Geometry { x: 0, y: 0, width: 800, height: 600 },
                is_focused: false,
                is_minimized: false,
                is_fullscreen: false,
                profile_id: core_types::ProfileId::new(),
            },
            Window {
                id: core_types::WindowId::new(),
                app_id: core_types::AppId::new("microsoft-edge"),
                title: "Edge".into(),
                workspace_id: core_types::WorkspaceId::new(),
                monitor_id: core_types::MonitorId::new(),
                geometry: core_types::Geometry { x: 0, y: 0, width: 800, height: 600 },
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
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowBorder)));
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
        if let Phase::Armed { selection, snap, .. } = &ctrl.phase {
            assert_ne!(Some(*selection), snap.origin_index,
                "forward should not default-select origin");
        }
    }

    // === Backward activation ===

    #[test]
    fn backward_initial_selection_is_not_origin() {
        let mut ctrl = OverlayController::new();
        ctrl.handle(Event::ActivateBackward, &test_windows(), &test_config());
        if let Phase::Armed { selection, snap, .. } = &ctrl.phase {
            assert_ne!(Some(*selection), snap.origin_index,
                "backward should not default-select origin");
        }
    }

    // === Launcher activation ===

    #[test]
    fn launcher_enters_armed_with_short_dwell() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::ActivateLauncher, &test_windows(), &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowBorder)));
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
        if let Phase::Armed { selection, snap, .. } = &ctrl.phase {
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
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn no_targets_is_noop() {
        let mut ctrl = OverlayController::new();
        let cmds = ctrl.handle(Event::Activate, &[], &test_config());
        assert!(cmds.is_empty());
        assert!(ctrl.is_idle());
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
        assert_eq!(visited.len(), snap_len,
            "full-circle cycling must visit all {snap_len} indices, visited {visited:?}");
    }

    // === Hint match activates origin when user explicitly types it ===

    #[test]
    fn hint_match_honors_origin() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        // 'g' is the hint for ghostty (the origin/focused window).
        // User explicitly typed it — must be honored.
        let cmds = ctrl.handle(Event::Char('g'), &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
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

    // === Char input — launch-or-focus ===

    #[test]
    fn char_launches_app_when_no_window() {
        let mut ctrl = OverlayController::new();
        let windows = vec![test_windows()[0].clone()]; // only ghostty
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::Char('e'), &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "microsoft-edge")));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn char_matches_hint_activates() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::Char('e'), &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_char_f_launches_firefox_when_not_running() {
        let mut ctrl = OverlayController::new();
        // Only ghostty and edge — no firefox window.
        let windows = vec![test_windows()[0].clone(), test_windows()[2].clone()];
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        assert!(matches!(ctrl.phase, Phase::Armed { .. }));
        // Char input works in Armed phase (the fix: keyboard focus acquired).
        let cmds = ctrl.handle(Event::Char('f'), &windows, &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "firefox")),
            "expected LaunchApp for firefox, got: {cmds:?}"
        );
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_char_f_focuses_firefox_when_running() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows(); // includes firefox
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        // Char input in Armed phase — keyboard focus already acquired.
        let cmds = ctrl.handle(Event::Char('f'), &windows, &test_config());
        assert!(
            cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })),
            "expected ActivateWindow for firefox, got: {cmds:?}"
        );
        assert!(ctrl.is_idle());
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
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
        assert!(ctrl.is_idle());
    }

    // === Re-activation cycles all windows ===

    #[test]
    fn reactivate_cycles_in_armed() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        ctrl.handle(Event::Activate, &windows, &test_config());
        if let Phase::Armed { selection, snap, .. } = &ctrl.phase {
            assert!(*selection < snap.windows.len());
        } else {
            panic!("expected Armed");
        }
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
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
    }

    #[test]
    fn launcher_modifier_release_commits() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        // Releasing Alt commits the selection, same as Alt+Tab mode.
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn launcher_confirm_activates_selection() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        let cmds = ctrl.handle(Event::Confirm, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
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
        } else { panic!("expected Picking") };

        for _ in 0..snap_len {
            ctrl.handle(Event::SelectionDown, &windows, &test_config());
        }
        // After full circle we're back at the initial (non-origin) position.
        // Navigate one more step back to reach origin (which is last).
        ctrl.handle(Event::SelectionUp, &windows, &test_config());

        // Confirm — should activate whatever is selected, even if origin.
        let cmds = ctrl.handle(Event::Confirm, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
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
    fn snapshot_has_targets_with_origin_needs_more_than_one() {
        let single = vec![test_windows()[0].clone()];
        let snap = Snapshot::with_origin(&single, &test_config(), Some(0));
        assert!(!snap.has_targets(), "single window that is origin = no targets");
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
        assert_eq!(activated.unwrap().id, windows[0].id, "should activate index 0, not origin");
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
        assert_eq!(activated.unwrap().id, windows[1].id, "should activate index 1, skipping origin at 0");
    }

    #[test]
    fn picking_with_origin_starts_at_non_origin() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let snap = Snapshot::with_origin(&windows, &test_config(), Some(2));
        ctrl.pick_with_snapshot(snap);

        if let Phase::Picking { selection, snap, .. } = &ctrl.phase {
            assert_ne!(*selection, 2, "should not start at origin");
            assert_ne!(Some(*selection), snap.origin_index);
            assert_eq!(*selection, 0);
        } else {
            panic!("expected Picking");
        }
    }

    #[test]
    fn single_window_is_origin_no_activation() {
        let single = vec![test_windows()[0].clone()];
        let snap = Snapshot::with_origin(&single, &test_config(), Some(0));
        assert!(!snap.has_targets());
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
        assert_eq!(activated.unwrap().id, windows[0].id,
            "quick-switch should activate top of picker (index 0), not origin");
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
}
