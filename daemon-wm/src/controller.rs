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
    /// Alt+Shift+Tab / backward activation (selection starts at end).
    ActivateBackward,
    /// Alt+Space / launcher mode (skip Armed, go straight to Picking).
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
#[derive(Debug, Clone)]
struct Snapshot {
    /// MRU-reordered, truncated window list.
    windows: Vec<Window>,
    /// Assigned hint strings (parallel to windows).
    hints: Vec<String>,
    /// Overlay-ready window info (parallel to windows).
    overlay_windows: Vec<WindowInfo>,
    /// MRU origin (focused window before switch).
    mru_origin: Option<String>,
    /// Key bindings snapshot for launch-or-focus.
    key_bindings: BTreeMap<String, core_config::WmKeyBinding>,
}

impl Snapshot {
    fn build(windows: &[Window], config: &WmConfig) -> Self {
        let mru_state = mru::load();
        let mut win_list = windows.to_vec();
        mru::reorder(&mut win_list, |w| w.id.to_string());
        win_list.truncate(config.max_visible_windows as usize);

        let app_ids: Vec<&str> = win_list.iter().map(|w| w.app_id.as_str()).collect();
        let app_hints = hints::assign_app_hints(&app_ids, &config.hint_keys, &config.key_bindings);
        let hint_strings: Vec<String> = app_hints.iter().map(|(h, _)| h.clone()).collect();

        let overlay_windows: Vec<WindowInfo> = win_list.iter().map(|w| WindowInfo {
            app_id: w.app_id.to_string(),
            title: w.title.clone(),
        }).collect();

        tracing::info!(
            window_count = win_list.len(),
            hints = ?hint_strings,
            apps = ?app_ids,
            mru_origin = mru_state.current.as_deref().unwrap_or("<none>"),
            quick_target = win_list.first().map(|w| w.id.to_string()).as_deref().unwrap_or("<none>"),
            "snapshot: pre-computed overlay data"
        );

        Self {
            windows: win_list,
            hints: hint_strings,
            overlay_windows,
            mru_origin: mru_state.current,
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
        /// When activation started (for quick-switch threshold).
        entered_at: Instant,
        /// Pre-computed snapshot.
        snap: Snapshot,
        /// Current selection index.
        selection: usize,
        /// User input buffer.
        input: String,
        /// Dwell threshold snapshot.
        dwell_ms: u32,
    },
    Picking {
        /// Pre-computed snapshot.
        snap: Snapshot,
        /// Selection index.
        selection: usize,
        /// Input buffer.
        input: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum ActivationMode {
    /// Alt+Tab: Armed phase, selection=0, quick-switch eligible.
    Forward,
    /// Alt+Shift+Tab: Armed phase, selection starts at last window.
    Backward,
    /// Alt+Space: Skip Armed, go directly to Picking (no quick-switch).
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
    /// The main loop should call `handle(Event::DwellTimeout)` when this fires.
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

                match mode {
                    ActivationMode::Forward => {
                        let cmds = vec![
                            Command::ShowBorder,
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ];
                        self.phase = Phase::Armed {
                            entered_at: Instant::now(),
                            snap,
                            selection: 0,
                            input: String::new(),
                            dwell_ms: config.quick_switch_threshold_ms,
                        };
                        cmds
                    }
                    ActivationMode::Backward => {
                        let selection = snap.windows.len().saturating_sub(1);
                        let cmds = vec![
                            Command::ShowBorder,
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ];
                        self.phase = Phase::Armed {
                            entered_at: Instant::now(),
                            snap,
                            selection,
                            input: String::new(),
                            dwell_ms: config.quick_switch_threshold_ms,
                        };
                        cmds
                    }
                    ActivationMode::Launcher => {
                        let cmds = vec![
                            Command::ShowPicker {
                                windows: snap.overlay_windows.clone(),
                                hints: snap.hints.clone(),
                            },
                            Command::Publish(EventKind::WmOverlayShown, SecurityLevel::Internal),
                        ];
                        self.phase = Phase::Picking {
                            snap,
                            selection: 0,
                            input: String::new(),
                        };
                        cmds
                    }
                }
            }
            Phase::Armed { selection, snap, .. } => {
                if !snap.windows.is_empty() {
                    *selection = (*selection + 1) % snap.windows.len();
                }
                Vec::new()
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

                if elapsed < dwell_ms && selection == 0 && input.is_empty() {
                    // Quick-switch: fast release, no interaction.
                    self.activate_index(0, &snap)
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

    /// Activate window at `index` (or first window, or dismiss if empty).
    fn activate_index(&mut self, index: usize, snap: &Snapshot) -> Vec<Command> {
        self.phase = Phase::Idle;

        let target = snap.windows.get(index).or_else(|| snap.windows.first());

        if let Some(w) = target {
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

        match hints::match_input(&input, hints) {
            MatchResult::Exact(idx) => {
                // Exact hint match — activate that window immediately.
                let snap = match std::mem::replace(&mut self.phase, Phase::Idle) {
                    Phase::Armed { snap, .. } | Phase::Picking { snap, .. } => snap,
                    _ => unreachable!(),
                };
                self.activate_index(idx, &snap)
            }
            MatchResult::NoMatch => {
                // No hint matches. Check launch-or-focus.
                if input.len() == 1 {
                    let key = input.chars().next().unwrap();
                    if let Some(cmd) = hints::launch_for_key(key, key_bindings) {
                        let command = cmd.to_string();
                        self.phase = Phase::Idle;
                        return vec![
                            Command::Hide,
                            Command::LaunchApp { command },
                            Command::Publish(EventKind::WmOverlayDismissed, SecurityLevel::Internal),
                        ];
                    }
                }
                // No launch either — if armed, transition to picking to show input.
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
                // Partial match — if armed, show picker to display narrowed results.
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
    // Navigation
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
                    *selection = selection.checked_sub(1).unwrap_or(snap.windows.len() - 1);
                }
                self.transition_armed_to_picking()
            }
            Phase::Picking { selection, snap, input, .. } => {
                if !snap.windows.is_empty() {
                    *selection = selection.checked_sub(1).unwrap_or(snap.windows.len() - 1);
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
            Phase::Armed { selection, snap, .. } => {
                self.activate_index(selection, &snap)
            }
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
    fn activate_from_idle_emits_show_border() {
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

    // === Backward activation ===

    #[test]
    fn backward_starts_at_last_window() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        if let Phase::Armed { selection, snap, .. } = &ctrl.phase {
            assert_eq!(*selection, snap.windows.len() - 1);
        } else {
            panic!("expected Armed");
        }
    }

    // === Launcher activation ===

    #[test]
    fn launcher_skips_armed_goes_to_picking() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        let cmds = ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
        assert!(matches!(ctrl.phase, Phase::Picking { .. }));
        // No dwell deadline — already in Picking.
        assert!(ctrl.next_deadline().is_none());
    }

    // === Quick-switch ===

    #[test]
    fn fast_release_quick_switches() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::HideAndSync)));
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn fast_release_no_windows_dismisses() {
        let mut ctrl = OverlayController::new();
        let empty: Vec<Window> = vec![];
        ctrl.handle(Event::Activate, &empty, &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &empty, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::Hide)));
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
        assert!(cmds.iter().any(|c| matches!(c, Command::LaunchApp { command } if command == "microsoft-edge")));
        assert!(ctrl.is_idle());
    }

    #[test]
    fn char_matches_hint_when_window_exists() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::Char('e'), &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
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
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        let cmds = ctrl.handle(Event::Escape, &windows, &test_config());
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

    // === Selection cycling ===

    #[test]
    fn selection_cycles_in_picking() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        ctrl.handle(Event::DwellTimeout, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        if let Phase::Picking { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 1);
        } else {
            panic!("expected Picking");
        }
    }

    // === Re-activation cycles selection ===

    #[test]
    fn reactivate_cycles_selection_in_armed() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::Activate, &windows, &test_config());
        ctrl.handle(Event::Activate, &windows, &test_config());
        if let Phase::Armed { selection, .. } = &ctrl.phase {
            assert_eq!(*selection, 1);
        } else {
            panic!("expected Armed");
        }
    }

    // === Modifier release after interaction activates selection ===

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

    // === Launcher-mode modifier release activates selection ===

    #[test]
    fn launcher_release_activates_selection() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
        ctrl.handle(Event::SelectionDown, &windows, &test_config());
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
        assert!(ctrl.is_idle());
    }

    // === Backward activation quick-switch activates last ===

    #[test]
    fn backward_fast_release_activates_last() {
        let mut ctrl = OverlayController::new();
        let windows = test_windows();
        ctrl.handle(Event::ActivateBackward, &windows, &test_config());
        // selection != 0, so even fast release activates current selection (last window).
        let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
        assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
        assert!(ctrl.is_idle());
    }
}
