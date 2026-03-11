//! Integration tests for daemon-wm modules.
//!
//! Tests hint assignment, hint matching, MRU state parsing, controller
//! lifecycle, and config validation. These tests do NOT require a running
//! daemon or Wayland compositor.

use core_config::WmKeyBinding;
use daemon_wm::controller::{Command, Event, OverlayController};
use daemon_wm::hints::{assign_hints, assign_app_hints, match_input, MatchResult, auto_key_for_app, key_for_app};
use std::collections::BTreeMap;

fn make_bindings(entries: &[(&str, &[&str])]) -> BTreeMap<String, WmKeyBinding> {
    entries.iter().map(|(k, apps)| {
        (k.to_string(), WmKeyBinding {
            apps: apps.iter().map(|s| s.to_string()).collect(),
            launch: None,
            tags: Vec::new(),
        })
    }).collect()
}

fn test_config() -> core_config::WmConfig {
    core_config::WmConfig {
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

fn test_windows() -> Vec<core_types::Window> {
    vec![
        core_types::Window {
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
        core_types::Window {
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
        core_types::Window {
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

// ============================================================================
// Hint Assignment
// ============================================================================

#[test]
fn assign_hints_single_key_set() {
    let hints = assign_hints(3, "a");
    assert_eq!(hints, vec!["a", "aa", "aaa"]);
}

#[test]
fn assign_hints_multi_key_set() {
    let hints = assign_hints(7, "asd");
    assert_eq!(hints, vec!["a", "s", "d", "aa", "ss", "dd", "aaa"]);
}

#[test]
fn assign_hints_exact_key_count() {
    let hints = assign_hints(3, "abc");
    assert_eq!(hints, vec!["a", "b", "c"]);
}

#[test]
fn assign_hints_empty_inputs() {
    assert!(assign_hints(0, "abc").is_empty());
    assert!(assign_hints(5, "").is_empty());
}

// ============================================================================
// Hint Matching
// ============================================================================

#[test]
fn match_exact_unique() {
    let hints: Vec<String> = vec!["a".into(), "s".into(), "d".into()];
    assert_eq!(match_input("s", &hints), MatchResult::Exact(1));
}

#[test]
fn match_no_match() {
    let hints: Vec<String> = vec!["a".into(), "s".into()];
    assert_eq!(match_input("z", &hints), MatchResult::NoMatch);
}

#[test]
fn match_empty_input() {
    let hints: Vec<String> = vec!["a".into()];
    assert_eq!(match_input("", &hints), MatchResult::NoMatch);
}

#[test]
fn match_partial_prefix() {
    let hints: Vec<String> = vec!["a".into(), "aa".into(), "aaa".into()];
    match match_input("a", &hints) {
        MatchResult::Partial(indices) => {
            assert_eq!(indices.len(), 3);
        }
        other => panic!("expected Partial, got {other:?}"),
    }
}

#[test]
fn match_numeric_shorthand() {
    let hints: Vec<String> = vec!["a".into(), "aa".into(), "aaa".into()];
    assert_eq!(match_input("a3", &hints), MatchResult::Exact(2));
}

#[test]
fn match_case_insensitive() {
    let hints: Vec<String> = vec!["a".into(), "s".into()];
    assert_eq!(match_input("A", &hints), MatchResult::Exact(0));
    assert_eq!(match_input("S", &hints), MatchResult::Exact(1));
}

// ============================================================================
// Auto Key
// ============================================================================

#[test]
fn auto_key_from_reverse_dns() {
    assert_eq!(auto_key_for_app("com.mitchellh.ghostty"), Some('g'));
    assert_eq!(auto_key_for_app("org.mozilla.firefox"), Some('f'));
}

#[test]
fn auto_key_from_simple_name() {
    assert_eq!(auto_key_for_app("firefox"), Some('f'));
    assert_eq!(auto_key_for_app("ghostty"), Some('g'));
}

// ============================================================================
// App-Grouped Hints
// ============================================================================

#[test]
fn app_hints_groups_by_app() {
    let apps = vec!["firefox", "firefox", "ghostty", "code"];
    let empty: BTreeMap<String, WmKeyBinding> = BTreeMap::new();
    let result = assign_app_hints(&apps, "fgcasdjkl", &empty);
    assert_eq!(result.len(), 4);

    let ff_hints: Vec<&str> = result.iter()
        .filter(|(_, idx)| apps[*idx] == "firefox")
        .map(|(h, _)| h.as_str())
        .collect();
    assert!(ff_hints.contains(&"f"));
    assert!(ff_hints.contains(&"ff"));

    let g_hints: Vec<&str> = result.iter()
        .filter(|(_, idx)| apps[*idx] == "ghostty")
        .map(|(h, _)| h.as_str())
        .collect();
    assert!(g_hints.contains(&"g"));
}

// ============================================================================
// MRU State Parsing and File I/O
// ============================================================================

#[test]
fn mru_file_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mru");

    std::fs::write(&path, "prev-window\ncurr-window").unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines[0], "prev-window");
    assert_eq!(lines[1], "curr-window");
}

// ============================================================================
// Controller: Forward Activation
// ============================================================================

#[test]
fn controller_activate_emits_show_border() {
    let mut ctrl = OverlayController::new();
    let cmds = ctrl.handle(Event::Activate, &test_windows(), &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ShowBorder)));
    assert!(!ctrl.is_idle());
    assert!(ctrl.next_deadline().is_some());
}

#[test]
fn controller_fast_release_quick_switches() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::Activate, &windows, &test_config());
    let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::HideAndSync)));
    assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
    assert!(ctrl.is_idle());
}

#[test]
fn controller_activate_no_windows_is_noop() {
    let mut ctrl = OverlayController::new();
    let cmds = ctrl.handle(Event::Activate, &[], &test_config());
    assert!(cmds.is_empty(), "no targets = no activation");
    assert!(ctrl.is_idle());
}

// ============================================================================
// Controller: Backward Activation
// ============================================================================

#[test]
fn controller_backward_emits_show_border() {
    let mut ctrl = OverlayController::new();
    let cmds = ctrl.handle(Event::ActivateBackward, &test_windows(), &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ShowBorder)));
    assert!(!ctrl.is_idle());
}

#[test]
fn controller_backward_fast_release_activates() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::ActivateBackward, &windows, &test_config());
    // Selection != 0, so release always activates (no quick-switch).
    let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
    assert!(ctrl.is_idle());
}

// ============================================================================
// Controller: Launcher Activation
// ============================================================================

#[test]
fn controller_launcher_skips_armed() {
    let mut ctrl = OverlayController::new();
    let cmds = ctrl.handle(Event::ActivateLauncher, &test_windows(), &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
    // No dwell deadline — already in Picking.
    assert!(ctrl.next_deadline().is_none());
}

#[test]
fn controller_launcher_modifier_release_commits() {
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
fn controller_launcher_confirm_activates() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
    ctrl.handle(Event::SelectionDown, &windows, &test_config());
    let cmds = ctrl.handle(Event::Confirm, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
    assert!(ctrl.is_idle());
}

// ============================================================================
// Controller: Dwell Timeout
// ============================================================================

#[test]
fn controller_dwell_timeout_shows_picker() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::Activate, &windows, &test_config());
    let cmds = ctrl.handle(Event::DwellTimeout, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
    assert!(!ctrl.is_idle());
}

// ============================================================================
// Controller: Char Input
// ============================================================================

#[test]
fn controller_char_launches_app_when_no_window() {
    let mut ctrl = OverlayController::new();
    let windows = vec![test_windows()[0].clone()]; // only ghostty
    ctrl.handle(Event::Activate, &windows, &test_config());
    let cmds = ctrl.handle(Event::Char('e'), &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::LaunchApp { command, .. } if command == "microsoft-edge")));
    assert!(ctrl.is_idle());
}

#[test]
fn controller_char_activates_on_exact_hint() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::Activate, &windows, &test_config());
    let cmds = ctrl.handle(Event::Char('e'), &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
    assert!(ctrl.is_idle());
}

// ============================================================================
// Controller: Navigation
// ============================================================================

#[test]
fn controller_tab_in_armed_shows_picker() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::Activate, &windows, &test_config());
    let cmds = ctrl.handle(Event::SelectionDown, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ShowPicker { .. })));
}

#[test]
fn controller_selection_cycles_in_picking() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::Activate, &windows, &test_config());
    ctrl.handle(Event::DwellTimeout, &windows, &test_config());
    let cmds = ctrl.handle(Event::SelectionDown, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::UpdatePicker { selection: 1, .. })));
}

// ============================================================================
// Controller: Escape
// ============================================================================

#[test]
fn controller_escape_from_armed_dismisses() {
    let mut ctrl = OverlayController::new();
    ctrl.handle(Event::Activate, &test_windows(), &test_config());
    let cmds = ctrl.handle(Event::Escape, &test_windows(), &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::Hide)));
    assert!(ctrl.is_idle());
}

#[test]
fn controller_escape_from_idle_is_noop() {
    let mut ctrl = OverlayController::new();
    let cmds = ctrl.handle(Event::Escape, &[], &test_config());
    assert!(cmds.is_empty());
}

// ============================================================================
// Controller: Confirm
// ============================================================================

#[test]
fn controller_confirm_in_picking_activates() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::Activate, &windows, &test_config());
    ctrl.handle(Event::DwellTimeout, &windows, &test_config());
    let cmds = ctrl.handle(Event::Confirm, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
    assert!(ctrl.is_idle());
}

// ============================================================================
// Controller: Re-activation cycles
// ============================================================================

#[test]
fn controller_reactivate_in_picking_cycles_and_updates() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::ActivateLauncher, &windows, &test_config());
    let cmds = ctrl.handle(Event::Activate, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::UpdatePicker { selection: 1, .. })));
}

// ============================================================================
// Controller: Release after interaction
// ============================================================================

#[test]
fn controller_release_after_tab_activates_selection() {
    let mut ctrl = OverlayController::new();
    let windows = test_windows();
    ctrl.handle(Event::Activate, &windows, &test_config());
    ctrl.handle(Event::DwellTimeout, &windows, &test_config());
    ctrl.handle(Event::SelectionDown, &windows, &test_config());
    ctrl.handle(Event::SelectionDown, &windows, &test_config());
    let cmds = ctrl.handle(Event::ModifierReleased, &windows, &test_config());
    assert!(cmds.iter().any(|c| matches!(c, Command::ActivateWindow { .. })));
}

// ============================================================================
// Config-driven key_for_app
// ============================================================================

#[test]
fn key_for_app_with_bindings() {
    let bindings = make_bindings(&[("f", &["firefox", "org.mozilla.firefox"])]);
    assert_eq!(key_for_app("firefox", &bindings), Some('f'));
    assert_eq!(key_for_app("org.mozilla.firefox", &bindings), Some('f'));
}

#[test]
fn key_for_app_falls_back_to_auto() {
    let bindings: BTreeMap<String, WmKeyBinding> = BTreeMap::new();
    assert_eq!(key_for_app("firefox", &bindings), Some('f'));
    assert_eq!(key_for_app("unknown-app", &bindings), Some('u'));
}

#[test]
fn key_for_app_case_insensitive() {
    let bindings = make_bindings(&[("g", &["Ghostty"])]);
    assert_eq!(key_for_app("ghostty", &bindings), Some('g'));
}

#[test]
fn key_for_app_last_segment_match() {
    let bindings = make_bindings(&[("g", &["ghostty"])]);
    assert_eq!(key_for_app("com.mitchellh.ghostty", &bindings), Some('g'));
}

#[test]
fn assign_app_hints_with_config_overrides() {
    let bindings = make_bindings(&[("x", &["firefox"])]);
    let apps = vec!["firefox", "ghostty"];
    let result = assign_app_hints(&apps, "xgasdjkl", &bindings);
    let hint_strs: Vec<&str> = result.iter().map(|(h, _)| h.as_str()).collect();
    assert!(hint_strs.contains(&"x"));
    assert!(hint_strs.contains(&"g"));
}

// ============================================================================
// Launch-or-focus hints
// ============================================================================

#[test]
fn launch_for_key_returns_command() {
    use daemon_wm::hints::launch_for_key;
    let mut bindings = BTreeMap::new();
    bindings.insert("g".to_string(), WmKeyBinding {
        apps: vec!["ghostty".to_string()],
        launch: Some("ghostty".to_string()),
        tags: Vec::new(),
    });
    assert_eq!(launch_for_key('g', &bindings), Some("ghostty"));
    assert_eq!(launch_for_key('z', &bindings), None);
}

#[test]
fn launch_for_key_none_when_no_launch() {
    use daemon_wm::hints::launch_for_key;
    let bindings = make_bindings(&[("c", &["chromium"])]);
    assert_eq!(launch_for_key('c', &bindings), None);
}

// ============================================================================
// WM Config Validation
// ============================================================================

#[test]
fn wm_config_defaults_are_valid() {
    let config = core_config::Config::default();
    let diagnostics = core_config::validate(&config);
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.severity == core_config::DiagnosticSeverity::Error)
        .collect();
    assert!(errors.is_empty(), "default config should have no errors: {errors:?}");
}

#[test]
fn wm_config_rejects_empty_hint_keys() {
    let mut config = core_config::Config::default();
    let mut profile = core_config::ProfileConfig::default();
    profile.wm.hint_keys = String::new();
    config.profiles.insert("test".into(), profile);

    let diagnostics = core_config::validate(&config);
    assert!(
        diagnostics.iter().any(|d| {
            d.severity == core_config::DiagnosticSeverity::Error
                && d.message.contains("hint_keys")
        }),
        "expected error for empty hint_keys: {diagnostics:?}"
    );
}

#[test]
fn wm_config_rejects_duplicate_hint_keys() {
    let mut config = core_config::Config::default();
    let mut profile = core_config::ProfileConfig::default();
    profile.wm.hint_keys = "aasdf".into();
    config.profiles.insert("test".into(), profile);

    let diagnostics = core_config::validate(&config);
    assert!(
        diagnostics.iter().any(|d| {
            d.severity == core_config::DiagnosticSeverity::Error
                && d.message.contains("duplicate")
        }),
        "expected error for duplicate hint_keys: {diagnostics:?}"
    );
}

#[test]
fn wm_config_warns_on_extreme_delay() {
    let mut config = core_config::Config::default();
    let mut profile = core_config::ProfileConfig::default();
    profile.wm.overlay_delay_ms = 5000;
    config.profiles.insert("test".into(), profile);

    let diagnostics = core_config::validate(&config);
    assert!(
        diagnostics.iter().any(|d| {
            d.severity == core_config::DiagnosticSeverity::Warning
                && d.message.contains("overlay_delay_ms")
        }),
        "expected warning for extreme delay: {diagnostics:?}"
    );
}
