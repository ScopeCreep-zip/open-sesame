//! XDG desktop entry discovery.
//!
//! Scans `$XDG_DATA_DIRS/applications/` for `.desktop` files and converts them
//! to `MatchItem` for injection into the fuzzy matcher. Filters out entries
//! with `NoDisplay=true`, `Hidden=true`, or missing `Exec=` fields (ADR-LNC-003).
//!
//! The `scan()` function is synchronous (freedesktop-desktop-entry is sync)
//! and must be called via `tokio::task::spawn_blocking`.

use core_fuzzy::MatchItem;
use std::collections::HashSet;

/// A cached desktop entry with the Exec line preserved for post-sandbox launching.
#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub id: String,
    pub exec: String,
}

/// Scan all XDG desktop entry paths and return launchable items.
///
/// Filters:
/// - `NoDisplay=true` → skipped (non-launchable, e.g. D-Bus activatable only)
/// - `Hidden=true` → skipped (explicitly hidden by packager)
/// - No `Exec=` field → skipped (not a launchable application)
/// - Duplicate IDs → only the first occurrence is kept
///
/// This function is blocking. Call via `tokio::task::spawn_blocking`.
pub fn scan() -> Vec<MatchItem> {
    let locales = freedesktop_desktop_entry::get_languages_from_env();
    let entries = freedesktop_desktop_entry::desktop_entries(&locales);

    let mut seen = HashSet::new();
    entries
        .into_iter()
        .filter(|e| !e.no_display())
        .filter(|e| !e.hidden())
        .filter(|e| e.exec().is_some())
        .filter(|e| seen.insert(e.id().to_owned()))
        .map(|e| {
            let id = e.id().to_owned();
            let name = e
                .name(&locales)
                .map(|c| c.into_owned())
                .unwrap_or_else(|| id.clone());

            let mut extra_parts: Vec<String> = Vec::new();

            if let Some(keywords) = e.keywords(&locales) {
                for kw in keywords {
                    let s = kw.into_owned();
                    if !s.is_empty() {
                        extra_parts.push(s);
                    }
                }
            }

            if let Some(categories) = e.categories() {
                for cat in categories {
                    if !cat.is_empty() {
                        extra_parts.push(cat.to_owned());
                    }
                }
            }

            MatchItem {
                id,
                name,
                extra: extra_parts.join(" "),
            }
        })
        .collect()
}

/// Scan desktop entries and cache their Exec lines for post-sandbox launching.
///
/// Same filtering as `scan()`, but also captures the raw Exec field so that
/// `launch_entry()` does not need filesystem access after sandbox is applied.
///
/// This function is blocking. Call via `tokio::task::spawn_blocking`.
pub fn scan_cached() -> Vec<CachedEntry> {
    let locales = freedesktop_desktop_entry::get_languages_from_env();
    let entries = freedesktop_desktop_entry::desktop_entries(&locales);

    let mut seen = HashSet::new();
    entries
        .into_iter()
        .filter(|e| !e.no_display())
        .filter(|e| !e.hidden())
        .filter(|e| e.exec().is_some())
        .filter(|e| seen.insert(e.id().to_owned()))
        .map(|e| {
            let id = e.id().to_owned();
            let exec = e.exec().unwrap().to_owned();
            CachedEntry { id, exec }
        })
        .collect()
}

/// Strip freedesktop `%`-prefixed field codes from an Exec line (ADR-LNC-005).
///
/// Field codes: `%f`, `%F`, `%u`, `%U`, `%d`, `%D`, `%n`, `%N`,
/// `%i`, `%c`, `%k`, `%v`, `%m`, `%%`.
pub fn strip_field_codes(exec: &str) -> String {
    let mut result = String::with_capacity(exec.len());
    let mut chars = exec.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next) = chars.peek() {
                match next {
                    'f' | 'F' | 'u' | 'U' | 'd' | 'D' | 'n' | 'N' | 'i' | 'c' | 'k' | 'v'
                    | 'm' => {
                        chars.next(); // consume the field code letter
                    }
                    '%' => {
                        chars.next();
                        result.push('%'); // literal percent
                    }
                    _ => {
                        result.push(ch);
                    }
                }
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }

    // Collapse multiple spaces from removed codes.
    let collapsed: String = result.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
}

/// Tokenize an Exec value per freedesktop Desktop Entry Specification.
///
/// Handles double-quote escaping (the spec only defines `\"`, `\``, `\\`,
/// `\$` as escape sequences inside double quotes). Does NOT invoke a shell.
/// Field codes should be stripped via `strip_field_codes()` before calling.
pub fn tokenize_exec(exec: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = exec.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => {
                if let Some(&next) = chars.peek() {
                    match next {
                        '"' | '\\' | '$' | '`' => {
                            current.push(chars.next().unwrap());
                        }
                        _ => {
                            current.push('\\');
                        }
                    }
                }
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_simple_codes() {
        assert_eq!(strip_field_codes("firefox %u"), "firefox");
        assert_eq!(strip_field_codes("code %F"), "code");
        assert_eq!(strip_field_codes("xdg-open %U"), "xdg-open");
    }

    #[test]
    fn strip_multiple_codes() {
        assert_eq!(
            strip_field_codes("app --flag %f %u --verbose"),
            "app --flag --verbose"
        );
    }

    #[test]
    fn strip_preserves_literal_percent() {
        assert_eq!(strip_field_codes("echo 100%%"), "echo 100%");
    }

    #[test]
    fn strip_no_codes() {
        assert_eq!(strip_field_codes("firefox --new-window"), "firefox --new-window");
    }

    #[test]
    fn strip_unknown_percent_code_preserved() {
        assert_eq!(strip_field_codes("app %z"), "app %z");
    }

    #[test]
    fn tokenize_simple() {
        assert_eq!(tokenize_exec("/usr/bin/simple"), vec!["/usr/bin/simple"]);
    }

    #[test]
    fn tokenize_multiple_args() {
        assert_eq!(
            tokenize_exec("/usr/bin/app --flag value"),
            vec!["/usr/bin/app", "--flag", "value"]
        );
    }

    #[test]
    fn tokenize_quoted_path_with_spaces() {
        assert_eq!(
            tokenize_exec(r#"/usr/bin/app --config "path with spaces""#),
            vec!["/usr/bin/app", "--config", "path with spaces"]
        );
    }

    #[test]
    fn tokenize_escaped_quote_inside_quotes() {
        assert_eq!(
            tokenize_exec(r#"/usr/bin/app "arg with \"quotes\"""#),
            vec!["/usr/bin/app", r#"arg with "quotes""#]
        );
    }

    #[test]
    fn tokenize_escaped_backslash_inside_quotes() {
        assert_eq!(
            tokenize_exec(r#"/usr/bin/app "path\\dir""#),
            vec!["/usr/bin/app", r"path\dir"]
        );
    }

    #[test]
    fn tokenize_multiple_whitespace_collapsed() {
        assert_eq!(
            tokenize_exec("/usr/bin/app   --flag   value"),
            vec!["/usr/bin/app", "--flag", "value"]
        );
    }

    #[test]
    fn tokenize_empty_string() {
        let result: Vec<String> = tokenize_exec("");
        assert!(result.is_empty());
    }
}
