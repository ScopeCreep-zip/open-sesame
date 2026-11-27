//! Mnemonic hint assignment and prefix matching.
//!
//! Each window's hint repeats its app's key: the key bound to the app in
//! `key_bindings`, else the first letter of its name, else a key from the
//! configured `hint_keys` pool. Windows of one app take consecutive
//! repetitions (`f`, `ff`, `fff`), which numeric shorthand abbreviates
//! (`f2`, `f3`). The same key launches the app when no window of it is
//! open (launch-or-focus).

use core_config::WmKeyBinding;
use std::collections::BTreeMap;

/// Result of matching user input against assigned hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    /// No hints match the input.
    NoMatch,
    /// Several hints start with the input (one may equal it); indices into
    /// the hint list.
    Partial(Vec<usize>),
    /// Exactly one hint starts with the input, and equals it.
    Exact(usize),
}

/// Match user input against a set of assigned hints, after normalizing it
/// (lowercase, numeric shorthand expanded: `a2` → `aa`).
///
/// An input equal to one hint but also a prefix of others (`a` among `a`,
/// `aa`) is [`MatchResult::Partial`]: the display narrows, and the user
/// commits with Enter or the modifier release.
#[must_use]
pub fn match_input(input: &str, hints: &[String]) -> MatchResult {
    let normalized = normalize_input(input);
    if normalized.is_empty() {
        return MatchResult::NoMatch;
    }
    let matching: Vec<usize> = hints
        .iter()
        .enumerate()
        .filter(|(_, hint)| hint.starts_with(&normalized))
        .map(|(i, _)| i)
        .collect();
    match matching.as_slice() {
        [] => MatchResult::NoMatch,
        [only] if hints[*only] == normalized => MatchResult::Exact(*only),
        _ => MatchResult::Partial(matching),
    }
}

/// Largest repetition count numeric shorthand expands.
const MAX_SHORTHAND: usize = 26;

/// Normalize input: lowercase, and expand numeric shorthand — one repeated
/// letter followed by a count from 1 to [`MAX_SHORTHAND`] (`a2`, `aa3`) —
/// into that many repetitions.
fn normalize_input(input: &str) -> String {
    let input = input.to_lowercase();
    let letters = input.trim_end_matches(|c: char| c.is_ascii_digit());
    let Some(base) = letters.chars().next() else {
        return input;
    };
    let count = input[letters.len()..]
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=MAX_SHORTHAND).contains(n));
    match count {
        Some(count) if letters.chars().all(|c| c == base) => {
            std::iter::repeat_n(base, count).collect()
        }
        _ => input,
    }
}

/// The last reverse-DNS segment of `app_id` (`com.mitchellh.ghostty` →
/// `ghostty`).
fn app_name(app_id: &str) -> &str {
    app_id.rsplit('.').next().unwrap_or(app_id)
}

/// The mnemonic key of an app id: the first letter of its name, lowercased.
#[must_use]
pub fn auto_key_for_app(app_id: &str) -> Option<char> {
    app_name(app_id)
        .chars()
        .find(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_lowercase())
}

/// The key bound to `app_id` in `key_bindings` — a pattern equal to the app
/// id or its name, ignoring case — else its mnemonic key.
#[must_use]
pub fn key_for_app(app_id: &str, key_bindings: &BTreeMap<String, WmKeyBinding>) -> Option<char> {
    let name = app_name(app_id);
    key_bindings
        .iter()
        .find(|(_, binding)| {
            binding.apps.iter().any(|pattern| {
                pattern.to_lowercase() == app_id.to_lowercase()
                    || pattern.to_lowercase() == name.to_lowercase()
            })
        })
        .and_then(|(key, _)| key.chars().next())
        .or_else(|| auto_key_for_app(app_id))
}

/// The binding of hint key `key` (case-insensitive): what typing it
/// launches when no window matches.
#[must_use]
pub fn binding_for_key(
    key: char,
    key_bindings: &BTreeMap<String, WmKeyBinding>,
) -> Option<&WmKeyBinding> {
    key_bindings.get(&key.to_lowercase().to_string())
}

/// Hints for windows of `app_ids`, in window order: each app's key (see
/// [`key_for_app`]), repeated once per earlier window of the same key.
/// Apps without a key take the first `hint_keys` key no other app on
/// screen uses (the first pool key when every one is taken).
#[must_use]
pub fn assign_app_hints(
    app_ids: &[&str],
    key_bindings: &BTreeMap<String, WmKeyBinding>,
    hint_keys: &str,
) -> Vec<String> {
    let keys: Vec<Option<char>> = app_ids
        .iter()
        .map(|app_id| key_for_app(app_id, key_bindings))
        .collect();
    let fallback = hint_keys
        .chars()
        .find(|c| !keys.contains(&Some(*c)))
        .or_else(|| hint_keys.chars().next());
    let mut repeats: BTreeMap<char, usize> = BTreeMap::new();
    keys.into_iter()
        .filter_map(|key| key.or(fallback))
        .map(|key| {
            let count = repeats.entry(key).or_default();
            *count += 1;
            std::iter::repeat_n(key, *count).collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hints(values: &[&str]) -> Vec<String> {
        values.iter().map(|&v| v.to_owned()).collect()
    }

    fn binding(apps: &[&str], launch: Option<&str>) -> WmKeyBinding {
        WmKeyBinding {
            apps: apps.iter().map(|&a| a.to_owned()).collect(),
            launch: launch.map(str::to_owned),
            tags: vec!["dev".into()],
            launch_args: Vec::new(),
        }
    }

    #[test]
    fn a_unique_hint_matches_exactly() {
        assert_eq!(
            match_input("d", &hints(&["a", "s", "d", "aa"])),
            MatchResult::Exact(2)
        );
        assert_eq!(match_input("S", &hints(&["a", "s"])), MatchResult::Exact(1));
    }

    #[test]
    fn a_shared_prefix_is_partial_even_with_an_equal_hint() {
        assert_eq!(
            match_input("a", &hints(&["a", "aa", "aaa"])),
            MatchResult::Partial(vec![0, 1, 2])
        );
    }

    #[test]
    fn unmatched_and_empty_input_match_nothing() {
        assert_eq!(match_input("z", &hints(&["a", "s"])), MatchResult::NoMatch);
        assert_eq!(match_input("", &hints(&["a"])), MatchResult::NoMatch);
    }

    #[test]
    fn numeric_shorthand_expands_one_repeated_letter() {
        assert_eq!(normalize_input("a3"), "aaa");
        assert_eq!(normalize_input("AA2"), "aa");
        assert_eq!(normalize_input("ab2"), "ab2", "mixed letters do not expand");
        assert_eq!(normalize_input("a27"), "a27", "beyond the limit");
        assert_eq!(normalize_input("a0"), "a0");
        assert_eq!(normalize_input("42"), "42", "no letter");
        assert_eq!(
            match_input("a3", &hints(&["a", "aa", "aaa"])),
            MatchResult::Exact(2)
        );
    }

    #[test]
    fn mnemonic_keys_are_the_first_letter_of_the_app_name() {
        assert_eq!(auto_key_for_app("com.mitchellh.ghostty"), Some('g'));
        assert_eq!(auto_key_for_app("Firefox"), Some('f'));
        assert_eq!(auto_key_for_app("org.x.123"), None);
    }

    #[test]
    fn bindings_win_over_mnemonics_and_match_ids_or_names() {
        let bindings = BTreeMap::from([("x".to_owned(), binding(&["Firefox"], None))]);
        assert_eq!(key_for_app("org.mozilla.firefox", &bindings), Some('x'));
        assert_eq!(key_for_app("firefox", &bindings), Some('x'));
        assert_eq!(key_for_app("ghostty", &bindings), Some('g'));
    }

    #[test]
    fn windows_of_one_app_repeat_its_key_in_window_order() {
        let assigned =
            assign_app_hints(&["firefox", "ghostty", "firefox"], &BTreeMap::new(), "asd");
        assert_eq!(assigned, ["f", "g", "ff"]);
    }

    #[test]
    fn apps_without_a_letter_take_a_free_pool_key() {
        // 'a' belongs to alacritty, so the letterless app takes 's'.
        let assigned = assign_app_hints(
            &["alacritty", "org.x.123", "org.y.456"],
            &BTreeMap::new(),
            "asd",
        );
        assert_eq!(assigned, ["a", "s", "ss"]);
        // With every pool key taken, the first is shared by repetition.
        let assigned = assign_app_hints(&["alacritty", "org.x.123"], &BTreeMap::new(), "a");
        assert_eq!(assigned, ["a", "aa"]);
    }

    #[test]
    fn bindings_are_found_by_key_ignoring_case() {
        let bindings = BTreeMap::from([("g".to_owned(), binding(&["ghostty"], Some("ghostty")))]);
        assert_eq!(
            binding_for_key('G', &bindings).and_then(|b| b.launch.as_deref()),
            Some("ghostty")
        );
        assert!(binding_for_key('z', &bindings).is_none());
    }
}
