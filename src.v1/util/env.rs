//! Environment file parsing utilities
//!
//! Supports direnv-style .env files with layered loading.

use crate::util::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Expand ~ to home directory in path
pub fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

/// Parse a .env file (direnv style) and return key-value pairs
///
/// Supports:
/// - KEY=value
/// - KEY="value with spaces"
/// - KEY='value with spaces'
/// - export KEY=value
/// - # comments
/// - Empty lines
pub fn parse_env_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;

    let mut env = HashMap::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Empty lines and comments skipped
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Optional 'export ' prefix stripped
        let line = line.strip_prefix("export ").unwrap_or(line);

        // Find the = separator
        let Some(eq_pos) = line.find('=') else {
            tracing::warn!(
                "{}:{}: Invalid line (no '='): {}",
                path.display(),
                line_num + 1,
                line
            );
            continue;
        };

        let key = line[..eq_pos].trim().to_string();
        let value_raw = line[eq_pos + 1..].trim();

        // Parse the value (handle quotes)
        let value = parse_env_value(value_raw);

        if !key.is_empty() {
            env.insert(key, value);
        }
    }

    Ok(env)
}

/// Returns whether value contains potentially dangerous shell metacharacters.
fn contains_shell_metacharacters(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c, '$' | '`' | '|' | ';' | '&' | '<' | '>' | '\n' | '\r'))
}

/// Parses environment variable value, handling single/double quotes.
fn parse_env_value(raw: &str) -> String {
    let raw = raw.trim();

    // Double-quoted value processing
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        let value = raw[1..raw.len() - 1]
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");

        if contains_shell_metacharacters(&value) {
            tracing::warn!("Environment value contains shell metacharacters: {}", raw);
        }

        return value;
    }

    // Single-quoted value (no escape processing applied)
    if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
        let value = raw[1..raw.len() - 1].to_string();

        if contains_shell_metacharacters(&value) {
            tracing::warn!("Environment value contains shell metacharacters: {}", raw);
        }

        return value;
    }

    // Unquoted value with inline comments stripped
    let value = if let Some(comment_pos) = raw.find(" #") {
        raw[..comment_pos].trim().to_string()
    } else {
        raw.to_string()
    };

    if contains_shell_metacharacters(&value) {
        tracing::warn!("Environment value contains shell metacharacters: {}", raw);
    }

    value
}

/// Loads environment variables from list of env files.
///
/// Later files override earlier ones.
pub fn load_env_files(paths: &[String]) -> HashMap<String, String> {
    let mut env = HashMap::new();

    for path_str in paths {
        let path = expand_path(path_str);
        if !path.exists() {
            tracing::debug!("Env file not found (skipping): {:?}", path);
            continue;
        }

        match parse_env_file(&path) {
            Ok(file_env) => {
                tracing::debug!("Loaded {} vars from {:?}", file_env.len(), path);
                env.extend(file_env);
            }
            Err(e) => {
                tracing::warn!("Failed to parse env file {:?}: {}", path, e);
            }
        }
    }

    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_value_unquoted() {
        assert_eq!(parse_env_value("hello"), "hello");
        assert_eq!(parse_env_value("  hello  "), "hello");
    }

    #[test]
    fn test_parse_env_value_double_quoted() {
        assert_eq!(parse_env_value(r#""hello world""#), "hello world");
        assert_eq!(parse_env_value(r#""line1\nline2""#), "line1\nline2");
        assert_eq!(parse_env_value(r#""tab\there""#), "tab\there");
        assert_eq!(parse_env_value(r#""escaped\"quote""#), "escaped\"quote");
    }

    #[test]
    fn test_parse_env_value_single_quoted() {
        assert_eq!(parse_env_value("'hello world'"), "hello world");
        assert_eq!(parse_env_value(r"'no\nescapes'"), r"no\nescapes");
    }

    #[test]
    fn test_parse_env_value_inline_comment() {
        assert_eq!(parse_env_value("value # comment"), "value");
    }

    #[test]
    fn test_expand_path() {
        // Non-tilde paths remain unchanged
        assert_eq!(expand_path("/usr/bin"), PathBuf::from("/usr/bin"));
        assert_eq!(expand_path("relative/path"), PathBuf::from("relative/path"));

        // Tilde expansion when home dir exists
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_path("~/test"), home.join("test"));
            assert_eq!(expand_path("~/.config/app"), home.join(".config/app"));
        }
    }
}
