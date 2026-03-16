//! Letter-hint assignment and prefix matching.
//!
//! Assigns repeated-letter hints to windows based on a configurable key set.
//! Supports numeric shorthand: "a2" matches "aa", "a3" matches "aaa".

use core_config::WmKeyBinding;
use std::collections::{BTreeMap, HashMap};

/// Assigns unique repeated-letter hints from a key set to N items.
///
/// For keys "asdf" and 6 items: a, s, d, f, aa, as.
/// Each key is used once before any key repeats.
#[must_use]
pub fn assign_hints(count: usize, hint_keys: &str) -> Vec<String> {
    if count == 0 || hint_keys.is_empty() {
        return Vec::new();
    }

    let keys: Vec<char> = hint_keys.chars().collect();
    let key_count = keys.len();
    let mut hints = Vec::with_capacity(count);

    for i in 0..count {
        let base_idx = i % key_count;
        let repeat = (i / key_count) + 1;
        let hint: String = std::iter::repeat_n(keys[base_idx], repeat).collect();
        hints.push(hint);
    }

    hints
}

/// Result of matching user input against assigned hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    /// No hints match the input.
    NoMatch,
    /// Multiple hints share this prefix; indices into the hint list.
    Partial(Vec<usize>),
    /// Exactly one hint matches; index into the hint list.
    Exact(usize),
}

/// Match user input against a set of assigned hints.
///
/// Normalizes numeric shorthand before matching: "a2" -> "aa".
/// Case-insensitive.
#[must_use]
pub fn match_input(input: &str, hints: &[String]) -> MatchResult {
    let normalized = normalize_input(input);
    if normalized.is_empty() {
        return MatchResult::NoMatch;
    }

    let mut exact: Option<usize> = None;
    let mut partial: Vec<usize> = Vec::new();

    for (i, hint) in hints.iter().enumerate() {
        if hint == &normalized {
            exact = Some(i);
            partial.push(i);
        } else if hint.starts_with(&normalized) {
            partial.push(i);
        }
    }

    if partial.is_empty() {
        MatchResult::NoMatch
    } else if let Some(idx) = exact
        && partial.len() == 1
    {
        MatchResult::Exact(idx)
    } else if let Some(idx) = exact
        && partial.len() > 1
    {
        // Exact match exists but other hints share the prefix.
        // Still report partial so the UI can narrow display.
        // The caller can decide to activate on timeout or wait.
        let _ = idx;
        MatchResult::Partial(partial)
    } else {
        MatchResult::Partial(partial)
    }
}

/// Normalize input: lowercase, expand numeric shorthand (a2 -> aa).
fn normalize_input(input: &str) -> String {
    let input = input.to_lowercase();

    if input.len() >= 2 {
        let chars: Vec<char> = input.chars().collect();

        // Find where numeric suffix starts.
        let mut letter_end = chars.len();
        while letter_end > 0 && chars[letter_end - 1].is_ascii_digit() {
            letter_end -= 1;
        }

        if letter_end > 0 && letter_end < chars.len() {
            let letters: String = chars[..letter_end].iter().collect();
            let num_str: String = chars[letter_end..].iter().collect();

            if let Ok(num) = num_str.parse::<usize>()
                && num > 0
                && num <= 26
                && letters
                    .chars()
                    .all(|c| c == letters.chars().next().unwrap_or(' '))
            {
                let base = letters.chars().next().unwrap();
                return std::iter::repeat_n(base, num).collect();
            }
        }
    }

    input
}

/// Auto-generate a hint key from an app ID by extracting its first alphabetic character.
#[must_use]
pub fn auto_key_for_app(app_id: &str) -> Option<char> {
    let segment = app_id.rsplit('.').next().unwrap_or(app_id);
    segment
        .chars()
        .find(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
}

/// Look up the configured hint key for an app_id, falling back to auto-detection.
#[must_use]
pub fn key_for_app(app_id: &str, key_bindings: &BTreeMap<String, WmKeyBinding>) -> Option<char> {
    let app_lower = app_id.to_lowercase();
    let last_segment = app_id.rsplit('.').next().map(|s| s.to_lowercase());

    for (key, binding) in key_bindings {
        for pattern in &binding.apps {
            if pattern == app_id
                || pattern.to_lowercase() == app_lower
                || last_segment.as_deref() == Some(&pattern.to_lowercase())
            {
                return key.chars().next();
            }
        }
    }
    auto_key_for_app(app_id)
}

/// Look up the launch command for a key character.
#[must_use]
pub fn launch_for_key(key: char, key_bindings: &BTreeMap<String, WmKeyBinding>) -> Option<&str> {
    let key_str = key.to_lowercase().to_string();
    key_bindings.get(&key_str).and_then(|b| b.launch.as_deref())
}

/// Look up the launch profile tags for a key character.
#[must_use]
pub fn tags_for_key(key: char, key_bindings: &BTreeMap<String, WmKeyBinding>) -> Vec<String> {
    let key_str = key.to_lowercase().to_string();
    key_bindings
        .get(&key_str)
        .map(|b| b.tags.clone())
        .unwrap_or_default()
}

/// Look up the launch args for a key character.
#[must_use]
pub fn launch_args_for_key(
    key: char,
    key_bindings: &BTreeMap<String, WmKeyBinding>,
) -> Vec<String> {
    let key_str = key.to_lowercase().to_string();
    key_bindings
        .get(&key_str)
        .map(|b| b.launch_args.clone())
        .unwrap_or_default()
}

/// Assign hints to windows grouped by app, using configured key mappings.
///
/// Hint key priority:
/// 1. Explicit config (`key_bindings` maps app to a specific key)
/// 2. First letter of the app name (reverse-DNS last segment)
///
/// Windows sharing the same key get consecutive repetitions: v, vv, vvv
/// (with numeric shorthand v1, v2, v3).
/// Returns `(hint_string, original_index)` pairs in original window order.
#[must_use]
pub fn assign_app_hints(
    app_ids: &[&str],
    _hint_keys: &str,
    key_bindings: &BTreeMap<String, WmKeyBinding>,
) -> Vec<(String, usize)> {
    if app_ids.is_empty() {
        return Vec::new();
    }

    // Group indices by app base key.
    let mut by_key: HashMap<char, Vec<usize>> = HashMap::new();

    for (i, app_id) in app_ids.iter().enumerate() {
        let key = key_for_app(app_id, key_bindings).unwrap_or('a');
        by_key.entry(key).or_default().push(i);
    }

    let mut result: Vec<(String, usize)> = Vec::with_capacity(app_ids.len());

    for (base, indices) in &by_key {
        for (count, &idx) in indices.iter().enumerate() {
            let hint: String = std::iter::repeat_n(*base, count + 1).collect();
            result.push((hint, idx));
        }
    }

    // Sort by original index to maintain window order.
    result.sort_by_key(|&(_, idx)| idx);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_hints_basic() {
        let hints = assign_hints(5, "asd");
        assert_eq!(hints, vec!["a", "s", "d", "aa", "ss"]);
    }

    #[test]
    fn assign_hints_empty() {
        assert!(assign_hints(0, "abc").is_empty());
        assert!(assign_hints(5, "").is_empty());
    }

    #[test]
    fn match_exact() {
        let hints = vec!["a".into(), "s".into(), "d".into(), "aa".into()];
        assert_eq!(match_input("d", &hints), MatchResult::Exact(2));
    }

    #[test]
    fn match_partial() {
        let hints = vec!["a".into(), "aa".into(), "aaa".into()];
        // "a" matches all three as prefix, exact on index 0 but partial because others share prefix.
        if let MatchResult::Partial(indices) = match_input("a", &hints) {
            assert_eq!(indices.len(), 3);
        } else {
            panic!("expected Partial");
        }
    }

    #[test]
    fn match_no_match() {
        let hints = vec!["a".into(), "s".into()];
        assert_eq!(match_input("z", &hints), MatchResult::NoMatch);
    }

    #[test]
    fn match_numeric_shorthand() {
        let hints = vec!["a".into(), "aa".into(), "aaa".into()];
        // "a3" normalizes to "aaa" -> exact match on index 2.
        assert_eq!(match_input("a3", &hints), MatchResult::Exact(2));
    }

    #[test]
    fn match_case_insensitive() {
        let hints = vec!["a".into(), "s".into()];
        assert_eq!(match_input("S", &hints), MatchResult::Exact(1));
    }

    #[test]
    fn auto_key_reverse_dns() {
        assert_eq!(auto_key_for_app("com.mitchellh.ghostty"), Some('g'));
    }

    #[test]
    fn auto_key_simple() {
        assert_eq!(auto_key_for_app("firefox"), Some('f'));
    }

    fn empty_bindings() -> BTreeMap<String, WmKeyBinding> {
        BTreeMap::new()
    }

    #[test]
    fn assign_app_hints_groups() {
        let apps = vec!["firefox", "firefox", "ghostty"];
        let result = assign_app_hints(&apps, "", &empty_bindings());
        // Two firefox windows: "f", "ff"; one ghostty: "g"
        let hint_strs: Vec<&str> = result.iter().map(|(h, _)| h.as_str()).collect();
        assert!(hint_strs.contains(&"f"));
        assert!(hint_strs.contains(&"ff"));
        assert!(hint_strs.contains(&"g"));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn launch_for_key_case_insensitive() {
        let mut bindings = BTreeMap::new();
        bindings.insert(
            "f".to_string(),
            WmKeyBinding {
                apps: vec!["app-f".into()],
                launch: Some("app-f".into()),
                tags: Vec::new(),
                launch_args: Vec::new(),
            },
        );
        assert_eq!(launch_for_key('f', &bindings), Some("app-f"));
        assert_eq!(launch_for_key('F', &bindings), Some("app-f"));
        assert_eq!(launch_for_key('z', &bindings), None);
    }

    #[test]
    fn assign_app_hints_uses_first_letter() {
        let apps = vec!["vivaldi", "com.mitchellh.ghostty", "microsoft-edge"];
        let result = assign_app_hints(&apps, "", &empty_bindings());
        let hint_strs: Vec<&str> = result.iter().map(|(h, _)| h.as_str()).collect();
        assert!(hint_strs.contains(&"v"), "vivaldi should get 'v'");
        assert!(hint_strs.contains(&"g"), "ghostty should get 'g'");
        assert!(hint_strs.contains(&"m"), "microsoft-edge should get 'm'");
    }

    #[test]
    fn tags_for_key_found() {
        let mut bindings = BTreeMap::new();
        bindings.insert(
            "g".to_string(),
            WmKeyBinding {
                apps: vec!["ghostty".into()],
                launch: Some("ghostty".into()),
                tags: vec!["dev-rust".into(), "ai-tools".into()],
                launch_args: Vec::new(),
            },
        );
        let tags = tags_for_key('g', &bindings);
        assert_eq!(tags, vec!["dev-rust", "ai-tools"]);
    }

    #[test]
    fn tags_for_key_not_found() {
        let bindings = BTreeMap::new();
        let tags = tags_for_key('z', &bindings);
        assert!(tags.is_empty());
    }

    #[test]
    fn tags_for_key_no_tags_on_binding() {
        let mut bindings = BTreeMap::new();
        bindings.insert(
            "f".to_string(),
            WmKeyBinding {
                apps: vec!["firefox".into()],
                launch: Some("firefox".into()),
                tags: Vec::new(),
                launch_args: Vec::new(),
            },
        );
        let tags = tags_for_key('f', &bindings);
        assert!(tags.is_empty());
    }
}
