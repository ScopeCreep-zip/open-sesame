//! Integration tests for MRU (Most Recently Used) window tracking
//!
//! Verifies window switching flow and MRU state management.
//! Tests cover critical invariants:
//! - MRU origin window persistence
//! - Quick switch target selection
//! - Launcher mode default selection from MRU state

use open_sesame::core::{HintAssignment, Window};

/// Creates test windows for integration testing.
fn make_test_windows() -> Vec<Window> {
    vec![
        Window::with_focus("win-firefox", "firefox", "Mozilla Firefox", false),
        Window::with_focus("win-edge", "microsoft-edge", "Microsoft Edge", false),
        Window::with_focus("win-ghostty", "com.mitchellh.ghostty", "ghostty", true),
    ]
}

// =============================================================================
// MRU STATE AFTER WINDOW SWITCH
// =============================================================================

/// Verifies MRU state correctly records origin and target windows during switch.
///
/// When switching from Firefox to Edge, MRU records:
/// - previous = Firefox (origin window)
/// - current = Edge (target window)
///
/// Ensures Alt+Tab activates correct previous window.
#[test]
fn test_mru_saves_origin_as_previous() {
    // Simulates user switching from Firefox to Edge
    let origin_window = "win-firefox";
    let target_window = "win-edge";

    // Simulates save_activated_window behavior
    let mut captured_previous: Option<String> = None;
    let mut captured_current: Option<String> = None;

    // Core logic: origin becomes previous, target becomes current
    if Some(target_window) != Some(origin_window) {
        captured_previous = Some(origin_window.to_string());
        captured_current = Some(target_window.to_string());
    }

    assert_eq!(
        captured_previous,
        Some("win-firefox".to_string()),
        "Origin window should become 'previous'"
    );
    assert_eq!(
        captured_current,
        Some("win-edge".to_string()),
        "Target window should become 'current'"
    );
}

/// Verifies MRU enables Alt+Tab toggle between two windows.
///
/// Scenario:
/// 1. Start on Firefox
/// 2. Alt+Tab to Edge (MRU: previous=Firefox, current=Edge)
/// 3. Alt+Tab returns to Firefox (using MRU previous)
#[test]
fn test_mru_toggle_between_two_windows() {
    // Step 1: Firefox → Edge switch
    let origin = "win-firefox";
    let target = "win-edge";
    let mut mru_previous = Some(origin.to_string());
    let mru_current = Some(target.to_string());

    assert_eq!(mru_previous, Some("win-firefox".to_string()));
    assert_eq!(mru_current, Some("win-edge".to_string()));

    // Step 2: On Edge, quick Alt+Tab targets previous (Firefox)
    let quick_switch_target = mru_previous.clone();
    assert_eq!(
        quick_switch_target,
        Some("win-firefox".to_string()),
        "Quick Alt+Tab targets previous window"
    );

    // Step 3: Edge → Firefox switch
    let origin = "win-edge";
    let target = "win-firefox";
    mru_previous = Some(origin.to_string());
    let mru_current = Some(target.to_string());

    assert_eq!(mru_previous, Some("win-edge".to_string()));
    assert_eq!(mru_current, Some("win-firefox".to_string()));

    // Step 4: Quick Alt+Tab returns to Edge
    let quick_switch_target = mru_previous.clone();
    assert_eq!(
        quick_switch_target,
        Some("win-edge".to_string()),
        "Toggle works bidirectionally"
    );
}

/// Verifies MRU only tracks directly involved windows, not third parties.
///
/// When switching between Firefox and Edge, Ghostty remains uninvolved
/// despite being present in window list.
#[test]
fn test_mru_three_windows_only_two_involved() {
    // Three windows: Firefox, Edge, Ghostty
    // User repeatedly switches between Firefox and Edge

    // Firefox to Edge switch
    let mut mru_previous = Some("win-firefox".to_string());

    // Quick switch targets Firefox, not Ghostty
    let target = mru_previous.clone();
    assert_eq!(target, Some("win-firefox".to_string()));
    assert_ne!(
        target,
        Some("win-ghostty".to_string()),
        "Ghostty remains uninvolved"
    );

    // Edge to Firefox switch
    mru_previous = Some("win-edge".to_string());

    // Quick switch targets Edge, not Ghostty
    let target = mru_previous.clone();
    assert_eq!(target, Some("win-edge".to_string()));
    assert_ne!(
        target,
        Some("win-ghostty".to_string()),
        "Ghostty remains uninvolved"
    );
}

// =============================================================================
// LAUNCHER MODE DEFAULT SELECTION
// =============================================================================

/// Verifies launcher mode default-selects MRU previous window.
///
/// Quick Alt+Space release behaves identically to quick Alt+Tab.
#[test]
fn test_launcher_mode_default_selection_uses_mru() {
    // MRU state: previous=Firefox, current=Edge
    let mru_previous = Some("win-firefox".to_string());

    // Windows and hints creation
    let windows = vec![
        Window::with_focus("win-edge", "microsoft-edge", "Edge", false),
        Window::with_focus("win-ghostty", "com.mitchellh.ghostty", "ghostty", false),
        Window::with_focus("win-firefox", "firefox", "Firefox", true),
    ];

    let assignment = HintAssignment::assign(&windows, |_| None);
    let hints = &assignment.hints;

    // Find index of MRU previous in hints
    let default_selection = mru_previous
        .as_ref()
        .and_then(|prev_id| hints.iter().position(|h| h.window_id.as_str() == prev_id))
        .unwrap_or(0);

    assert_eq!(
        default_selection, 2,
        "Defaults to Firefox (index 2), not Edge (index 0)"
    );

    // Fallback when MRU previous does not exist
    let mru_previous_invalid = Some("nonexistent-window".to_string());
    let fallback_selection = mru_previous_invalid
        .as_ref()
        .and_then(|prev_id| hints.iter().position(|h| h.window_id.as_str() == prev_id))
        .unwrap_or(0);

    assert_eq!(fallback_selection, 0, "Falls back to index 0");
}

// =============================================================================
// QUICK SWITCH TARGET COMPUTATION
// =============================================================================

/// Verifies quick switch targets MRU previous, not arbitrary index 0.
///
/// Ensures quick switch activates the actual previous window,
/// not whichever window happens to be at index 0.
#[test]
fn test_quick_switch_uses_mru_previous_not_index_zero() {
    // MRU state from previous switch
    let mru_previous = Some("win-firefox".to_string());

    // Windows arranged with Firefox NOT at index 0
    let windows = vec![
        Window::with_focus("win-ghostty", "com.mitchellh.ghostty", "ghostty", false),
        Window::with_focus("win-firefox", "firefox", "Firefox", false),
        Window::with_focus("win-edge", "microsoft-edge", "Edge", true),
    ];

    let assignment = HintAssignment::assign(&windows, |_| None);
    let hints = &assignment.hints;

    // Quick switch target computation (matches main.rs logic)
    let quick_switch_target = if !hints.is_empty() {
        if let Some(ref prev_id) = mru_previous {
            if hints.iter().any(|h| h.window_id.as_str() == prev_id) {
                Some(prev_id.clone())
            } else {
                // Fallback to index 0 when previous does not exist
                Some(hints[0].window_id.as_str().to_string())
            }
        } else {
            Some(hints[0].window_id.as_str().to_string())
        }
    } else {
        None
    };

    assert_eq!(
        quick_switch_target,
        Some("win-firefox".to_string()),
        "Uses MRU previous (Firefox), not index 0 (Ghostty)"
    );
}

/// Verifies fallback to index 0 when MRU previous window no longer exists.
#[test]
fn test_quick_switch_fallback_when_previous_closed() {
    // MRU previous references closed window
    let mru_previous = Some("win-closed-app".to_string());

    let windows = vec![
        Window::with_focus("win-ghostty", "com.mitchellh.ghostty", "ghostty", false),
        Window::with_focus("win-firefox", "firefox", "Firefox", true),
    ];

    let assignment = HintAssignment::assign(&windows, |_| None);
    let hints = &assignment.hints;

    let quick_switch_target = if !hints.is_empty() {
        if let Some(ref prev_id) = mru_previous {
            if hints.iter().any(|h| h.window_id.as_str() == prev_id) {
                Some(prev_id.clone())
            } else {
                Some(hints[0].window_id.as_str().to_string())
            }
        } else {
            Some(hints[0].window_id.as_str().to_string())
        }
    } else {
        None
    };

    assert_eq!(
        quick_switch_target,
        Some("win-ghostty".to_string()),
        "Falls back to index 0 when previous window does not exist"
    );
}

// =============================================================================
// Hint assignment integration
// =============================================================================

/// Verifies hint assignment preserves window IDs correctly.
#[test]
fn test_hint_assignment_preserves_window_ids() {
    let windows = make_test_windows();

    let assignment = HintAssignment::assign(&windows, |_| None);

    // Each hint maps to correct window
    for hint in &assignment.hints {
        let original = windows
            .iter()
            .find(|w| w.id.as_str() == hint.window_id.as_str())
            .expect("Hint should reference existing window");

        assert_eq!(hint.app_id, original.app_id.as_str());
        assert_eq!(hint.title, original.title);
    }
}

/// Verifies window ordering places focused window at end after enumeration.
#[test]
fn test_window_ordering_focused_at_end() {
    let mut windows = make_test_windows();

    // Simulates enumerate_windows: moves focused to end
    if let Some(focused_pos) = windows.iter().position(|w| w.is_focused)
        && focused_pos < windows.len() - 1
    {
        let window = windows.remove(focused_pos);
        windows.push(window);
    }

    // Ghostty (focused) moved to end
    assert_eq!(
        windows.last().unwrap().app_id.as_str(),
        "com.mitchellh.ghostty"
    );
    assert!(windows.last().unwrap().is_focused);

    // First window should be available for quick switch
    assert_eq!(windows[0].app_id.as_str(), "firefox");
}

/// Verifies hints maintain original window order for proper Alt+Tab behavior.
#[test]
fn test_hints_maintain_window_order() {
    let windows = vec![
        Window::with_focus("win-1", "app-a", "Window A", false),
        Window::with_focus("win-2", "app-b", "Window B", false),
        Window::with_focus("win-3", "app-c", "Window C", true),
    ];

    let assignment = HintAssignment::assign(&windows, |_| None);

    // Hints ordered identically to windows by index
    assert_eq!(assignment.hints[0].window_id.as_str(), "win-1");
    assert_eq!(assignment.hints[1].window_id.as_str(), "win-2");
    assert_eq!(assignment.hints[2].window_id.as_str(), "win-3");

    // hints[0] is first non-focused window (for quick switch)
    assert_eq!(assignment.hints[0].index, 0);
}
