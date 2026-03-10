//! Integration tests for daemon-wm modules.
//!
//! Tests hint assignment, hint matching, MRU state parsing, and state machine
//! transitions. These tests do NOT require a running daemon or Wayland compositor.

use core_config::WmKeyBinding;
use daemon_wm::hints::{assign_hints, assign_app_hints, match_input, MatchResult, auto_key_for_app, key_for_app};
use daemon_wm::state::{WmState, Action};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn make_bindings(entries: &[(&str, &[&str])]) -> BTreeMap<String, WmKeyBinding> {
    entries.iter().map(|(k, apps)| {
        (k.to_string(), WmKeyBinding {
            apps: apps.iter().map(|s| s.to_string()).collect(),
            launch: None,
        })
    }).collect()
}

/// Helper to construct a FullOverlay with entered_at = now.
fn full_overlay(input: &str, selection: usize, window_count: usize) -> WmState {
    WmState::FullOverlay {
        input_buffer: input.into(),
        selection,
        window_count,
        entered_at: Instant::now(),
    }
}

/// Helper to construct a FullOverlay with a past entered_at.
fn full_overlay_aged(input: &str, selection: usize, window_count: usize, age: Duration) -> WmState {
    WmState::FullOverlay {
        input_buffer: input.into(),
        selection,
        window_count,
        entered_at: Instant::now() - age,
    }
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
// State Machine
// ============================================================================

#[test]
fn state_idle_to_full_overlay() {
    let mut state = WmState::new();
    assert!(state.is_idle());
    let action = state.on_activate();
    assert_eq!(action, Action::ShowOverlay);
    assert!(state.is_overlay_visible());
    assert!(matches!(state, WmState::FullOverlay { selection: 0, .. }));
}

#[test]
fn state_border_to_overlay_requires_frames_and_delay() {
    let mut state = WmState::BorderOnly {
        entered_at: Instant::now(),
        frame_count: 0,
    };
    let action = state.on_frame(0);
    assert_eq!(action, Action::None);
    let action = state.on_frame(0);
    assert_eq!(action, Action::ShowOverlay);
}

#[test]
fn state_fast_release_quick_switches() {
    let mut state = WmState::new();
    state.on_activate();
    state.set_window_count(3);
    // Fast release with no interaction → QuickSwitch.
    let action = state.on_modifier_release(250, 500);
    assert_eq!(action, Action::QuickSwitch);
    assert!(state.is_idle());
}

#[test]
fn state_slow_release_activates() {
    let mut state = full_overlay_aged("", 0, 3, Duration::from_millis(300));
    let action = state.on_modifier_release(250, 500);
    assert_eq!(action, Action::ActivateWindow(0));
    assert!(state.is_idle());
}

#[test]
fn state_slow_release_from_border_forces_overlay() {
    let mut state = WmState::BorderOnly {
        entered_at: Instant::now() - Duration::from_millis(200),
        frame_count: 0,
    };
    let action = state.on_modifier_release(100, 150);
    assert_eq!(action, Action::ShowOverlay);
}

#[test]
fn state_escape_returns_to_idle() {
    let mut state = full_overlay("", 0, 5);
    assert_eq!(state.on_escape(), Action::Dismiss);
    assert!(state.is_idle());
}

#[test]
fn state_selection_wraps_down() {
    let mut state = full_overlay("", 4, 5);
    state.on_selection_down();
    assert_eq!(state.selection(), Some(0));
}

#[test]
fn state_selection_wraps_up() {
    let mut state = full_overlay("", 0, 5);
    state.on_selection_up();
    assert_eq!(state.selection(), Some(4));
}

#[test]
fn state_confirm_on_empty_is_noop() {
    let mut state = full_overlay("", 0, 0);
    assert_eq!(state.on_confirm(), Action::None);
}

#[test]
fn state_confirm_activates_selection() {
    let mut state = full_overlay("", 2, 5);
    let action = state.on_confirm();
    assert_eq!(action, Action::ActivateWindow(2));
}

#[test]
fn state_hint_match_transitions() {
    let mut state = full_overlay("", 0, 5);
    let action = state.on_hint_match(3);
    assert_eq!(action, Action::ActivateWindow(3));
    assert!(matches!(state, WmState::PendingActivation { target: 3, .. }));
}

#[test]
fn state_backspace_from_pending_returns_to_overlay() {
    let mut state = WmState::PendingActivation {
        target: 0,
        pending_key: None,
        entered_at: Instant::now(),
        input_buffer: String::new(),
    };
    let action = state.on_backspace();
    assert_eq!(action, Action::ShowOverlay);
    assert!(matches!(state, WmState::FullOverlay { .. }));
}

#[test]
fn state_char_input_appends_to_buffer() {
    let mut state = full_overlay("", 0, 3);
    state.on_char('a');
    state.on_char('b');
    assert_eq!(state.input_buffer(), Some("ab"));
    state.on_backspace();
    assert_eq!(state.input_buffer(), Some("a"));
}

#[test]
fn state_activation_timeout() {
    let mut state = WmState::PendingActivation {
        target: 2,
        pending_key: None,
        entered_at: Instant::now() - Duration::from_millis(300),
        input_buffer: String::new(),
    };
    let action = state.check_activation_timeout(200);
    assert_eq!(action, Action::ActivateWindow(2));
    assert!(state.is_idle());
}

#[test]
fn state_activation_not_yet_timed_out() {
    let mut state = WmState::PendingActivation {
        target: 2,
        pending_key: None,
        entered_at: Instant::now(),
        input_buffer: String::new(),
    };
    let action = state.check_activation_timeout(5000);
    assert_eq!(action, Action::None);
}

// ============================================================================
// Alt release in FullOverlay / PendingActivation
// ============================================================================

#[test]
fn state_alt_release_full_overlay_activates() {
    let mut state = full_overlay_aged("", 2, 5, Duration::from_millis(500));
    let action = state.on_modifier_release(250, 500);
    assert_eq!(action, Action::ActivateWindow(2));
    assert!(state.is_idle());
}

#[test]
fn state_alt_release_pending_activates() {
    let mut state = WmState::PendingActivation {
        target: 1,
        pending_key: None,
        entered_at: Instant::now(),
        input_buffer: String::new(),
    };
    let action = state.on_modifier_release(250, 500);
    assert_eq!(action, Action::ActivateWindow(1));
    assert!(state.is_idle());
}

// ============================================================================
// Char in BorderOnly
// ============================================================================

#[test]
fn state_char_in_border_transitions_to_overlay() {
    let mut state = WmState::BorderOnly {
        entered_at: Instant::now(),
        frame_count: 0,
    };
    let action = state.on_char('g');
    assert_eq!(action, Action::ShowOverlay);
    assert_eq!(state.input_buffer(), Some("g"));
}

// ============================================================================
// Tab in BorderOnly
// ============================================================================

#[test]
fn state_tab_in_border_transitions_to_overlay() {
    let mut state = WmState::BorderOnly {
        entered_at: Instant::now(),
        frame_count: 0,
    };
    let action = state.on_selection_down();
    assert_eq!(action, Action::ShowOverlay);
    assert_eq!(state.selection(), Some(1));
}

#[test]
fn state_shift_tab_in_border_transitions() {
    let mut state = WmState::BorderOnly {
        entered_at: Instant::now(),
        frame_count: 0,
    };
    let action = state.on_selection_up();
    assert_eq!(action, Action::ShowOverlay);
    state.set_window_count(5);
    assert_eq!(state.selection(), Some(4));
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
// Launcher mode activation
// ============================================================================

#[test]
fn state_launcher_mode_activates() {
    let mut state = WmState::new();
    let action = state.on_activate_launcher();
    assert_eq!(action, Action::ShowOverlay);
    assert!(matches!(state, WmState::FullOverlay { .. }));
}

#[test]
fn state_launcher_mode_from_non_idle_cycles_selection() {
    let mut state = full_overlay("", 0, 5);
    assert_eq!(state.on_activate_launcher(), Action::Redraw);
    assert_eq!(state.selection(), Some(1));
}

// ============================================================================
// Backspace from PendingActivation preserves input
// ============================================================================

#[test]
fn backspace_from_pending_preserves_input_minus_last() {
    let mut state = full_overlay("", 0, 5);
    state.on_char('g');
    state.on_char('g');
    assert_eq!(state.input_buffer(), Some("gg"));
    let action = state.on_hint_match(2);
    assert_eq!(action, Action::ActivateWindow(2));
    assert!(matches!(state, WmState::PendingActivation { .. }));
    let action = state.on_backspace();
    assert_eq!(action, Action::ShowOverlay);
    assert_eq!(state.input_buffer(), Some("g"));
}

// ============================================================================
// Escape from PendingActivation
// ============================================================================

#[test]
fn escape_from_pending_activation_dismisses() {
    let mut state = WmState::PendingActivation {
        target: 2,
        pending_key: None,
        entered_at: Instant::now(),
        input_buffer: String::new(),
    };
    assert_eq!(state.on_escape(), Action::Dismiss);
    assert!(state.is_idle());
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

// ============================================================================
// Keyboard navigation failure mode scenarios
// ============================================================================

/// Alt+Space repeated should cycle through windows.
#[test]
fn scenario_alt_space_repeat_cycles() {
    let mut state = WmState::new();
    let action = state.on_activate_launcher();
    assert_eq!(action, Action::ShowOverlay);
    state.set_window_count(4);
    assert_eq!(state.selection(), Some(0));

    let action = state.on_activate_launcher();
    assert_eq!(action, Action::Redraw);
    assert_eq!(state.selection(), Some(1));

    let action = state.on_activate_launcher();
    assert_eq!(action, Action::Redraw);
    assert_eq!(state.selection(), Some(2));

    state.on_activate_launcher();
    state.on_activate_launcher();
    assert_eq!(state.selection(), Some(0));
}

/// Alt+Tab repeated should cycle selection.
#[test]
fn scenario_alt_tab_repeat_cycles() {
    let mut state = WmState::new();
    assert_eq!(state.on_activate(), Action::ShowOverlay);
    state.set_window_count(3);

    let action = state.on_activate();
    assert_eq!(action, Action::Redraw);
    assert_eq!(state.selection(), Some(1));

    let action = state.on_activate();
    assert_eq!(action, Action::Redraw);
    assert_eq!(state.selection(), Some(2));

    let action = state.on_activate();
    assert_eq!(action, Action::Redraw);
    assert_eq!(state.selection(), Some(0));
}

/// Quick alt+tab → QuickSwitch (no GUI).
#[test]
fn scenario_quick_alt_tab_quick_switches() {
    let mut state = WmState::new();
    state.on_activate();
    state.set_window_count(3);
    let action = state.on_modifier_release(250, 500);
    assert_eq!(action, Action::QuickSwitch);
    assert!(state.is_idle());
}

/// Tab key repeats in FullOverlay should wrap correctly.
#[test]
fn scenario_tab_repeat_wraps() {
    let mut state = full_overlay("", 0, 3);
    state.on_selection_down(); // 1
    state.on_selection_down(); // 2
    state.on_selection_down(); // 0 (wrapped)
    assert_eq!(state.selection(), Some(0));
    state.on_selection_down(); // 1
    assert_eq!(state.selection(), Some(1));
}

/// Alt release in PendingActivation should still activate target.
#[test]
fn scenario_alt_release_during_pending() {
    let mut state = WmState::new();
    state.on_activate_launcher();
    state.set_window_count(3);
    state.on_char('g');
    let action = state.on_hint_match(1);
    assert_eq!(action, Action::ActivateWindow(1));
    assert!(matches!(state, WmState::PendingActivation { target: 1, .. }));
    let action = state.on_modifier_release(250, 500);
    assert_eq!(action, Action::ActivateWindow(1));
    assert!(state.is_idle());
}
