//! COSMIC keybinding integration.
//!
//! Manages keybindings in COSMIC desktop's shortcut configuration file
//! (`~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom`).
//!
//! The compositor watches this file via `cosmic_config::calloop::ConfigWatchSource`
//! and live-reloads keybindings on change — no logout required.

use std::fs;
use std::path::PathBuf;

/// Path to COSMIC custom shortcuts config.
///
/// COSMIC reads custom keybindings from:
///   `~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom`
///
/// The compositor watches this file and live-reloads on change (no logout needed).
fn cosmic_shortcuts_path() -> core_types::Result<PathBuf> {
    let base = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .ok_or_else(|| {
            core_types::Error::Platform(
                "cannot determine config directory: HOME not set".into(),
            )
        })?;
    Ok(base.join("cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom"))
}

/// Parse a key combo string like "super+space" into (modifiers, key).
fn parse_key_combo(combo: &str) -> core_types::Result<(Vec<String>, String)> {
    let parts: Vec<&str> = combo.split('+').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return Err(core_types::Error::Platform("empty key combo".into()));
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

/// Escape a string for RON format (prevents injection).
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

/// Format a keybinding entry in COSMIC RON format.
fn format_keybinding(modifiers: &[String], key: &str, command: &str) -> String {
    let mods = if modifiers.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", modifiers.join(", "))
    };
    let escaped_key = escape_ron_string(key);
    let escaped_command = escape_ron_string(command);
    format!(
        "    (modifiers: {}, key: \"{}\"): Spawn(\"{}\"),",
        mods, escaped_key, escaped_command
    )
}

/// Read the current custom shortcuts file.
fn read_shortcuts() -> core_types::Result<String> {
    let path = cosmic_shortcuts_path()?;
    if path.exists() {
        fs::read_to_string(&path).map_err(|e| {
            core_types::Error::Platform(format!("failed to read {}: {e}", path.display()))
        })
    } else {
        Ok("{\n}".to_string())
    }
}

/// Write the custom shortcuts file with backup.
fn write_shortcuts(content: &str) -> core_types::Result<()> {
    let path = cosmic_shortcuts_path()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            core_types::Error::Platform(format!("failed to create {}: {e}", parent.display()))
        })?;
    }

    if path.exists() {
        let backup = path.with_extension("bak");
        if let Err(e) = fs::copy(&path, &backup) {
            tracing::warn!("failed to create backup at {}: {e}", backup.display());
        } else {
            tracing::info!("created backup at {}", backup.display());
        }
    }

    fs::write(&path, content).map_err(|e| {
        core_types::Error::Platform(format!("failed to write {}: {e}", path.display()))
    })
}

/// Remove existing sesame bindings from content.
fn remove_sesame_bindings(content: &str) -> String {
    content
        .lines()
        .filter(|line| !line.contains("sesame"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Add a keybinding entry before the closing brace.
fn add_binding(content: &str, binding: &str) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed == "{}" || trimmed == "{\n}" {
        return format!("{{\n{binding}\n}}");
    }

    if let Some(close_pos) = trimmed.rfind('}') {
        let before = trimmed[..close_pos].trim_end();
        let needs_comma = !before.ends_with('{') && !before.ends_with(',');
        let comma = if needs_comma { "," } else { "" };
        format!("{before}{comma}\n{binding}\n}}")
    } else {
        format!("{{\n{binding}\n}}")
    }
}

/// Setup all sesame keybindings in COSMIC.
///
/// Configures:
/// - Alt+Tab: window switcher (quick cycling)
/// - Alt+Shift+Tab: window switcher backward
/// - Launcher key (configurable, default alt+space): full overlay with hints
pub fn setup_keybinding(launcher_key_combo: &str) -> core_types::Result<()> {
    let (launcher_mods, launcher_key) = parse_key_combo(launcher_key_combo)?;

    let launcher_binding = format_keybinding(&launcher_mods, &launcher_key, "sesame wm overlay --launcher");
    let switcher_forward = format_keybinding(&["Alt".to_string()], "tab", "sesame wm overlay");
    let switcher_backward = format_keybinding(
        &["Alt".to_string(), "Shift".to_string()],
        "tab",
        "sesame wm overlay --backward",
    );

    let mut content = read_shortcuts()?;

    if content.contains("sesame") {
        tracing::info!("removing existing sesame keybindings");
        content = remove_sesame_bindings(&content);
    }

    let content = add_binding(&content, &switcher_forward);
    let content = add_binding(&content, &switcher_backward);
    let new_content = add_binding(&content, &launcher_binding);
    write_shortcuts(&new_content)?;

    tracing::info!(
        "configured COSMIC keybindings: alt+tab, alt+shift+tab, {launcher_key_combo}"
    );
    println!("Keybindings configured:");
    println!("    alt+tab       -> sesame wm overlay");
    println!("    alt+shift+tab -> sesame wm overlay --backward");
    println!("    {launcher_key_combo:<14}-> sesame wm overlay --launcher");
    println!("  Config: {}", cosmic_shortcuts_path()?.display());

    Ok(())
}

/// Remove sesame keybindings from COSMIC.
pub fn remove_keybinding() -> core_types::Result<()> {
    let content = read_shortcuts()?;

    if !content.contains("sesame") {
        println!("No sesame keybinding found.");
        return Ok(());
    }

    let new_content = remove_sesame_bindings(&content);
    write_shortcuts(&new_content)?;
    println!("Removed sesame keybindings.");
    Ok(())
}

/// Show current keybinding status.
pub fn keybinding_status() -> core_types::Result<()> {
    let path = cosmic_shortcuts_path()?;

    if !path.exists() {
        println!("COSMIC shortcuts file not found: {}", path.display());
        println!("Run 'sesame setup-keybinding' to configure.");
        return Ok(());
    }

    let content = read_shortcuts()?;
    if content.contains("sesame") {
        for line in content.lines() {
            if line.contains("sesame") {
                println!("  Active: {}", line.trim());
            }
        }
    } else {
        println!("No sesame keybinding configured.");
        println!("  Run 'sesame setup-keybinding' to configure.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_combo_super_space() {
        let (mods, key) = parse_key_combo("super+space").unwrap();
        assert_eq!(mods, vec!["Super"]);
        assert_eq!(key, "space");
    }

    #[test]
    fn parse_key_combo_alt_tab() {
        let (mods, key) = parse_key_combo("alt+tab").unwrap();
        assert_eq!(mods, vec!["Alt"]);
        assert_eq!(key, "tab");
    }

    #[test]
    fn parse_key_combo_triple() {
        let (mods, key) = parse_key_combo("ctrl+shift+a").unwrap();
        assert_eq!(mods, vec!["Ctrl", "Shift"]);
        assert_eq!(key, "a");
    }

    #[test]
    fn format_keybinding_basic() {
        let result = format_keybinding(&["Super".to_string()], "space", "sesame");
        assert!(result.contains("modifiers: [Super]"));
        assert!(result.contains("key: \"space\""));
        assert!(result.contains("Spawn(\"sesame\")"));
    }

    #[test]
    fn add_binding_to_empty() {
        let result = add_binding("{}", "    test,");
        assert!(result.starts_with('{'));
        assert!(result.ends_with('}'));
        assert!(result.contains("test,"));
    }

    #[test]
    fn remove_bindings_selective() {
        let content = r#"{
    (modifiers: [Super], key: "space"): Spawn("sesame"),
    (modifiers: [Alt], key: "tab"): Spawn("other-app"),
}"#;
        let result = remove_sesame_bindings(content);
        assert!(!result.contains("sesame"));
        assert!(result.contains("other-app"));
    }

    #[test]
    fn escape_ron_string_injection() {
        assert_eq!(escape_ron_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_ron_string(r"a\b"), r"a\\b");
    }
}
