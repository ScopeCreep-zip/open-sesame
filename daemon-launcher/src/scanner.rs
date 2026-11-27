//! XDG desktop entry discovery.
//!
//! Scans `$XDG_DATA_DIRS/applications/` for `.desktop` files and converts them
//! to `MatchItem` for injection into the fuzzy matcher. Filters out entries
//! with `NoDisplay=true`, `Hidden=true`, or missing `Exec=` fields (ADR-LNC-003).
//!
//! [`scan_all`] is synchronous (freedesktop-desktop-entry is sync) and
//! must be called via `tokio::task::spawn_blocking`.

use core_fuzzy::MatchItem;
use std::borrow::Cow;
use std::collections::HashSet;

/// A cached desktop entry: its Exec line, preserved for launching after
/// the scan.
#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub id: String,
    pub exec: String,
}

/// Scan all XDG desktop entry paths in a single pass, returning both fuzzy
/// matcher items and cached Exec lines for post-sandbox launching.
///
/// Filters:
/// - `NoDisplay=true` → skipped (non-launchable, e.g. D-Bus activatable only)
/// - `Hidden=true` → skipped (explicitly hidden by packager)
/// - No `Exec=` field → skipped (not a launchable application)
/// - Duplicate IDs → only the first occurrence is kept
///
/// This function is blocking. Call via `tokio::task::spawn_blocking`.
pub fn scan_all() -> (Vec<MatchItem>, Vec<CachedEntry>) {
    let locales = freedesktop_desktop_entry::get_languages_from_env();
    let entries = freedesktop_desktop_entry::desktop_entries(&locales);

    let mut seen = HashSet::new();
    let mut items = Vec::new();
    let mut cached = Vec::new();

    for e in entries {
        let Some(exec) = e.exec() else {
            continue;
        };
        if e.no_display() || e.hidden() {
            continue;
        }
        let id = e.id().to_owned();
        if !seen.insert(id.clone()) {
            continue;
        }

        cached.push(CachedEntry {
            id: id.clone(),
            exec: exec.to_owned(),
        });

        let name = e.name(&locales).map_or_else(|| id.clone(), Cow::into_owned);
        let keywords = e.keywords(&locales).unwrap_or_default();
        let categories = e.categories().unwrap_or_default();
        let extra: Vec<&str> = keywords
            .iter()
            .map(AsRef::as_ref)
            .chain(categories)
            .filter(|part| !part.is_empty())
            .collect();

        items.push(MatchItem {
            id,
            name,
            extra: extra.join(" "),
            icon: e.icon().map(str::to_owned),
        });
    }

    (items, cached)
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
                    'f' | 'F' | 'u' | 'U' | 'd' | 'D' | 'n' | 'N' | 'i' | 'c' | 'k' | 'v' | 'm' => {
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
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Tokenize an Exec value per freedesktop Desktop Entry Specification.
///
/// Handles double-quote escaping (the spec only defines `\"`, `` \` ``,
/// `\\`, `\$` as escape sequences inside double quotes); any other
/// backslash is literal. Does NOT invoke a shell. Field codes should be
/// stripped via [`strip_field_codes`] before calling.
pub fn tokenize_exec(exec: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = exec.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => match chars.peek() {
                Some(&next @ ('"' | '\\' | '$' | '`')) => {
                    chars.next();
                    current.push(next);
                }
                _ => current.push('\\'),
            },
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
        assert_eq!(
            strip_field_codes("firefox --new-window"),
            "firefox --new-window"
        );
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
    fn unspecified_and_trailing_backslashes_are_literal() {
        assert_eq!(
            tokenize_exec(r#"/usr/bin/app "a\nb" "tail\"#),
            vec!["/usr/bin/app", r"a\nb", r"tail\"]
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
