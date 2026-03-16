//! COSMIC keybinding integration
//!
//! Manages keybindings in COSMIC desktop's shortcut configuration.

use crate::util::paths;
use crate::util::{Error, Result};
use std::fs;
use std::path::PathBuf;

/// Path to COSMIC custom shortcuts config
///
/// Uses the centralized paths module which properly handles missing HOME.
fn cosmic_shortcuts_path() -> Result<PathBuf> {
    paths::cosmic_shortcuts_path()
}

/// Parse a key combo string like "super+space" or "alt+tab" into COSMIC Ron format
fn parse_key_combo(combo: &str) -> Result<(Vec<String>, String)> {
    let parts: Vec<&str> = combo.split('+').map(|s| s.trim()).collect();

    if parts.is_empty() {
        return Err(Error::Other("Empty key combo".to_string()));
    }

    let key = parts.last().unwrap().to_string();
    let modifiers: Vec<String> = parts[..parts.len() - 1]
        .iter()
        .map(|m| match m.to_lowercase().as_str() {
            "super" | "mod" | "logo" | "win" => "Super".to_string(),
            "shift" => "Shift".to_string(),
            "ctrl" | "control" => "Ctrl".to_string(),
            "alt" => "Alt".to_string(),
            other => other.to_string(),
        })
        .collect();

    Ok((modifiers, key))
}

/// Escape a string for RON format (handles quotes and backslashes)
///
/// RON uses the same escaping rules as Rust strings:
/// - `\` becomes `\\`
/// - `"` becomes `\"`
fn escape_ron_string(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Format a keybinding entry in COSMIC Ron format
///
/// All string values are properly escaped to prevent RON injection.
fn format_keybinding(modifiers: &[String], key: &str, command: &str) -> String {
    let mods = if modifiers.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", modifiers.join(", "))
    };
    // Escape key and command to prevent RON injection
    let escaped_key = escape_ron_string(key);
    let escaped_command = escape_ron_string(command);
    format!(
        "    (modifiers: {}, key: \"{}\"): Spawn(\"{}\"),",
        mods, escaped_key, escaped_command
    )
}

/// Read the current custom shortcuts file
fn read_shortcuts() -> Result<String> {
    let path = cosmic_shortcuts_path()?;
    if path.exists() {
        fs::read_to_string(&path)
            .map_err(|e| Error::Other(format!("Failed to read {}: {}", path.display(), e)))
    } else {
        Ok("{\n}".to_string())
    }
}

/// Write the custom shortcuts file with backup
fn write_shortcuts(content: &str) -> Result<()> {
    let path = cosmic_shortcuts_path()?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::Other(format!("Failed to create {}: {}", parent.display(), e)))?;
    }

    // Create backup of existing file
    if path.exists() {
        let backup_path = path.with_extension("bak");
        if let Err(e) = fs::copy(&path, &backup_path) {
            tracing::warn!(
                "Failed to create backup at {}: {}. Proceeding without backup.",
                backup_path.display(),
                e
            );
        } else {
            tracing::info!("Created backup at {}", backup_path.display());
        }
    }

    // Basic validation: check if content looks like valid RON
    let trimmed = content.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        tracing::warn!(
            "Shortcuts content does not look like valid RON (should start with '{{' and end with '}}'). Writing anyway but format may be incorrect."
        );
    }

    fs::write(&path, content)
        .map_err(|e| Error::Other(format!("Failed to write {}: {}", path.display(), e)))
}

/// Check if sesame keybinding already exists
fn has_sesame_binding(content: &str) -> bool {
    content.contains("sesame")
}

/// Remove existing sesame bindings from content
fn remove_sesame_bindings(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let filtered: Vec<&str> = lines
        .into_iter()
        .filter(|line| !line.contains("sesame"))
        .collect();
    filtered.join("\n")
}

/// Add a keybinding entry to the shortcuts content
fn add_binding(content: &str, binding: &str) -> String {
    let trimmed = content.trim();

    // Handle empty or minimal content
    if trimmed.is_empty() || trimmed == "{}" || trimmed == "{\n}" {
        return format!("{{\n{}\n}}", binding);
    }

    // Insert before the closing brace
    if let Some(close_pos) = trimmed.rfind('}') {
        let before = &trimmed[..close_pos].trim_end();
        // Determine if comma separator is needed
        let needs_comma = !before.ends_with('{') && !before.ends_with(',');
        let comma = if needs_comma { "," } else { "" };
        format!("{}{}\n{}\n}}", before, comma, binding)
    } else {
        format!("{{\n{}\n}}", binding)
    }
}

/// Setup all sesame keybindings in COSMIC
/// Configures:
/// - Alt+Tab: Window switcher (quick cycling)
/// - Alt+Shift+Tab: Window switcher backward
/// - Alt+Space (or custom): Launcher mode with hints
pub fn setup_keybinding(launcher_key_combo: &str) -> Result<()> {
    let (launcher_mods, launcher_key) = parse_key_combo(launcher_key_combo)?;

    // Launcher binding (Alt+Space by default) - shows full overlay with hints
    let launcher_binding = format_keybinding(&launcher_mods, &launcher_key, "sesame --launcher");

    // Switcher bindings (always Alt+Tab/Alt+Shift+Tab for standard window switching)
    let switcher_forward = format_keybinding(&["Alt".to_string()], "tab", "sesame");
    let switcher_backward = format_keybinding(
        &["Alt".to_string(), "Shift".to_string()],
        "tab",
        "sesame --backward",
    );

    let mut content = read_shortcuts()?;

    // Remove existing sesame bindings if present
    if has_sesame_binding(&content) {
        tracing::info!("Removing existing sesame keybindings");
        content = remove_sesame_bindings(&content);
    }

    // Insert configured bindings
    let content = add_binding(&content, &switcher_forward);
    let content = add_binding(&content, &switcher_backward);
    let new_content = add_binding(&content, &launcher_binding);
    write_shortcuts(&new_content)?;

    tracing::info!(
        "Configured COSMIC keybindings: alt+tab (switcher), alt+shift+tab (backward), {} (launcher)",
        launcher_key_combo
    );
    println!("✓ Keybindings configured:");
    println!("    alt+tab       -> sesame (window switcher)");
    println!("    alt+shift+tab -> sesame --backward");
    println!(
        "    {}     -> sesame --launcher (hint-based)",
        launcher_key_combo
    );
    println!("  Config: {}", cosmic_shortcuts_path()?.display());
    println!("  Note: You may need to log out and back in for changes to take effect.");

    Ok(())
}

/// Remove the sesame keybinding from COSMIC
pub fn remove_keybinding() -> Result<()> {
    let content = read_shortcuts()?;

    if !has_sesame_binding(&content) {
        println!("No sesame keybinding found");
        return Ok(());
    }

    let new_content = remove_sesame_bindings(&content);
    write_shortcuts(&new_content)?;

    println!("✓ Removed sesame keybinding");
    println!("  Note: You may need to log out and back in for changes to take effect.");

    Ok(())
}

/// Check current keybinding status
pub fn keybinding_status() -> Result<()> {
    let path = cosmic_shortcuts_path()?;

    if !path.exists() {
        println!("COSMIC shortcuts file not found: {}", path.display());
        println!("Run 'sesame --setup-keybinding' to configure.");
        return Ok(());
    }

    let content = read_shortcuts()?;

    if has_sesame_binding(&content) {
        // Find and display the binding
        for line in content.lines() {
            if line.contains("sesame") {
                println!("✓ Keybinding active: {}", line.trim());
            }
        }
    } else {
        println!("✗ No sesame keybinding configured");
        println!("  Run 'sesame --setup-keybinding' to configure.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_combo() {
        let (mods, key) = parse_key_combo("super+space").unwrap();
        assert_eq!(mods, vec!["Super"]);
        assert_eq!(key, "space");

        let (mods, key) = parse_key_combo("alt+tab").unwrap();
        assert_eq!(mods, vec!["Alt"]);
        assert_eq!(key, "tab");

        let (mods, key) = parse_key_combo("ctrl+shift+a").unwrap();
        assert_eq!(mods, vec!["Ctrl", "Shift"]);
        assert_eq!(key, "a");

        let (mods, key) = parse_key_combo("super+shift+g").unwrap();
        assert_eq!(mods, vec!["Super", "Shift"]);
        assert_eq!(key, "g");
    }

    #[test]
    fn test_format_keybinding() {
        let result = format_keybinding(&["Super".to_string()], "space", "sesame");
        assert!(result.contains("modifiers: [Super]"));
        assert!(result.contains("key: \"space\""));
        assert!(result.contains("Spawn(\"sesame\")"));
    }

    #[test]
    fn test_add_binding() {
        let content = "{\n}";
        let binding = "    (modifiers: [Super], key: \"space\"): Spawn(\"test\"),";
        let result = add_binding(content, binding);
        assert!(result.contains(binding));
        assert!(result.starts_with('{'));
        assert!(result.ends_with('}'));
    }

    #[test]
    fn test_remove_bindings() {
        let content = r#"{
    (modifiers: [Super], key: "space"): Spawn("sesame"),
    (modifiers: [Alt], key: "tab"): Spawn("other-app"),
}"#;
        let result = remove_sesame_bindings(content);
        assert!(!result.contains("sesame"));
        assert!(result.contains("other-app"));
    }

    #[test]
    fn test_escape_ron_string() {
        // Normal strings pass through unchanged
        assert_eq!(escape_ron_string("sesame"), "sesame");
        assert_eq!(escape_ron_string("simple"), "simple");

        // Quotes are escaped
        assert_eq!(escape_ron_string(r#"test"quote"#), r#"test\"quote"#);

        // Backslashes are escaped
        assert_eq!(escape_ron_string(r"path\to\file"), r"path\\to\\file");

        // Combined
        assert_eq!(escape_ron_string(r#"a\"b"#), r#"a\\\"b"#);
    }

    #[test]
    fn test_format_keybinding_escapes_injection() {
        // Attempt to inject RON - should be safely escaped
        let result = format_keybinding(
            &["Super".to_string()],
            "space",
            r#"malicious"), Other("injected"#,
        );
        // The result should contain escaped quotes within the Spawn string
        // Input: malicious"), Other("injected
        // Escaped: malicious\"), Other(\"injected
        // Full output: Spawn("malicious\"), Other(\"injected")
        assert!(
            result.contains(r#"Spawn("malicious\"), Other(\"injected")"#),
            "Result was: {}",
            result
        );
        // Should still have proper RON structure
        assert!(result.contains("modifiers: [Super]"));
        assert!(result.ends_with(","));
    }
}
