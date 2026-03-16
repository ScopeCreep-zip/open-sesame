//! COSMIC keybinding integration.
//!
//! Manages keybindings in COSMIC desktop's shortcut configuration files:
//! - `~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom` (custom shortcuts)
//! - `~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/system_actions` (system action commands)
//!
//! Strategy for Alt+Tab: COSMIC's default keybindings map Alt+Tab to
//! `System(WindowSwitcher)`. Rather than adding a competing `Spawn(...)` binding
//! (which would race with the default and leak the Alt modifier to apps), we
//! override the `system_actions` config to point `WindowSwitcher` and
//! `WindowSwitcherPrevious` at sesame commands. This way the compositor's own
//! built-in Alt+Tab binding fires sesame, and the key event is consumed at
//! compositor level before any app sees the Alt keypress.
//!
//! The compositor watches these files via `cosmic_config::calloop::ConfigWatchSource`
//! and live-reloads on change — no logout required.

use std::fs;
use std::path::PathBuf;

/// Base path for COSMIC shortcuts config directory.
fn cosmic_shortcuts_dir() -> core_types::Result<PathBuf> {
    let base = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .ok_or_else(|| {
            core_types::Error::Platform("cannot determine config directory: HOME not set".into())
        })?;
    Ok(base.join("cosmic/com.system76.CosmicSettings.Shortcuts/v1"))
}

/// Path to COSMIC custom shortcuts config.
///
/// COSMIC reads custom keybindings from:
///   `~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom`
///
/// The compositor watches this file and live-reloads on change (no logout needed).
fn cosmic_shortcuts_path() -> core_types::Result<PathBuf> {
    Ok(cosmic_shortcuts_dir()?.join("custom"))
}

/// Path to COSMIC system_actions config.
///
/// Maps `System(...)` action enum variants to command strings.
/// E.g., `WindowSwitcher` -> "sesame wm overlay".
fn cosmic_system_actions_path() -> core_types::Result<PathBuf> {
    Ok(cosmic_shortcuts_dir()?.join("system_actions"))
}

/// Capitalize a key name to match COSMIC's expected format.
///
/// COSMIC uses X11-style key names with initial caps: "Tab", "Space", "Escape",
/// "Return", etc. Single-character keys (a-z) stay lowercase per XKB convention.
fn capitalize_key(key: &str) -> String {
    if key.len() <= 1 {
        return key.to_string();
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap().to_uppercase().to_string();
    format!("{first}{}", chars.as_str().to_lowercase())
}

/// Parse a key combo string like "super+space" into (modifiers, key).
fn parse_key_combo(combo: &str) -> core_types::Result<(Vec<String>, String)> {
    let parts: Vec<&str> = combo.split('+').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return Err(core_types::Error::Platform("empty key combo".into()));
    }

    // COSMIC key names are capitalized (e.g. "Tab", "Space", "Escape").
    // Normalize the key so user input like "tab" becomes "Tab".
    let raw_key = parts.last().unwrap();
    let key = capitalize_key(raw_key);
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

/// Read the current system_actions file.
fn read_system_actions() -> core_types::Result<String> {
    let path = cosmic_system_actions_path()?;
    if path.exists() {
        fs::read_to_string(&path).map_err(|e| {
            core_types::Error::Platform(format!("failed to read {}: {e}", path.display()))
        })
    } else {
        Ok("{\n}".to_string())
    }
}

/// Write the system_actions file with backup.
fn write_system_actions(content: &str) -> core_types::Result<()> {
    let path = cosmic_system_actions_path()?;

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

/// Update system_actions to point WindowSwitcher/WindowSwitcherPrevious at sesame.
///
/// This overrides the commands that COSMIC's built-in `System(WindowSwitcher)`
/// and `System(WindowSwitcherPrevious)` actions execute. The keybindings
/// themselves (Alt+Tab, Super+Tab, etc.) remain unchanged — we only change
/// what program they launch.
fn setup_system_actions() -> core_types::Result<()> {
    let mut content = read_system_actions()?;

    // Remove any existing WindowSwitcher entries.
    content = content
        .lines()
        .filter(|line| !line.contains("WindowSwitcher"))
        .collect::<Vec<_>>()
        .join("\n");

    // Add sesame entries.
    let switcher_entry = "    WindowSwitcher: \"sesame wm overlay\",";
    let switcher_prev_entry = "    WindowSwitcherPrevious: \"sesame wm overlay --backward\",";

    let content = add_binding(&content, switcher_entry);
    let content = add_binding(&content, switcher_prev_entry);

    write_system_actions(&content)?;
    Ok(())
}

/// Remove sesame entries from system_actions, restoring COSMIC defaults.
fn remove_system_actions() -> core_types::Result<()> {
    let path = cosmic_system_actions_path()?;
    if !path.exists() {
        return Ok(());
    }

    let content = read_system_actions()?;

    // Remove WindowSwitcher entries that point to sesame.
    let new_content: String = content
        .lines()
        .filter(|line| !(line.contains("WindowSwitcher") && line.contains("sesame")))
        .collect::<Vec<_>>()
        .join("\n");

    // If file is now effectively empty, remove it so COSMIC falls back to
    // system defaults (installed at /usr/share/cosmic/...).
    let trimmed = new_content.trim();
    if trimmed.is_empty() || trimmed == "{}" || trimmed == "{\n}" {
        let _ = fs::remove_file(&path);
        tracing::info!("removed empty system_actions override (COSMIC will use system defaults)");
    } else {
        write_system_actions(&new_content)?;
    }
    Ok(())
}

/// Setup all sesame keybindings in COSMIC.
///
/// Configures:
/// - Alt+Tab / Super+Tab: overrides COSMIC's built-in WindowSwitcher command
///   via `system_actions` so the compositor's own binding runs sesame. This
///   ensures the Alt modifier is consumed at compositor level (no leak to apps).
/// - Launcher key (configurable, default alt+space): custom `Spawn(...)` binding
///   for full overlay with hints.
pub fn setup_keybinding(launcher_key_combo: &str) -> core_types::Result<()> {
    let (launcher_mods, launcher_key) = parse_key_combo(launcher_key_combo)?;

    // -- Step 1: Override system_actions so COSMIC's built-in Alt+Tab runs sesame --
    setup_system_actions()?;

    // -- Step 2: Add launcher key as a custom Spawn binding --
    // (Alt+Tab is handled by the system_actions override above, not a custom binding.)
    let launcher_binding = format_keybinding(
        &launcher_mods,
        &launcher_key,
        "sesame wm overlay --launcher",
    );

    let mut content = read_shortcuts()?;

    if content.contains("sesame") {
        tracing::info!("removing existing sesame keybindings");
        content = remove_sesame_bindings(&content);
    }

    let new_content = add_binding(&content, &launcher_binding);
    write_shortcuts(&new_content)?;

    tracing::info!("configured COSMIC keybindings: system_actions override + {launcher_key_combo}");
    println!("Keybindings configured:");
    println!("    alt+tab       -> sesame wm overlay (via system_actions override)");
    println!("    alt+shift+tab -> sesame wm overlay --backward (via system_actions override)");
    println!("    super+tab     -> sesame wm overlay (via system_actions override)");
    println!("    {launcher_key_combo:<14}-> sesame wm overlay --launcher");
    println!(
        "  System actions: {}",
        cosmic_system_actions_path()?.display()
    );
    println!("  Custom keys:    {}", cosmic_shortcuts_path()?.display());

    Ok(())
}

/// Remove sesame keybindings from COSMIC.
pub fn remove_keybinding() -> core_types::Result<()> {
    let mut found = false;

    // Remove system_actions override.
    let sa_path = cosmic_system_actions_path()?;
    if sa_path.exists() {
        let sa_content = read_system_actions()?;
        if sa_content.contains("sesame") {
            remove_system_actions()?;
            println!("Removed sesame system_actions override.");
            found = true;
        }
    }

    // Remove custom shortcuts.
    let content = read_shortcuts()?;
    if content.contains("sesame") {
        let new_content = remove_sesame_bindings(&content);
        write_shortcuts(&new_content)?;
        println!("Removed sesame custom keybindings.");
        found = true;
    }

    if !found {
        println!("No sesame keybinding found.");
    }
    Ok(())
}

/// Show current keybinding status.
pub fn keybinding_status() -> core_types::Result<()> {
    let mut found = false;

    // Check system_actions override.
    let sa_path = cosmic_system_actions_path()?;
    if sa_path.exists() {
        let sa_content = read_system_actions()?;
        if sa_content.contains("sesame") {
            println!("  System actions override ({}):", sa_path.display());
            for line in sa_content.lines() {
                if line.contains("sesame") {
                    println!("    {}", line.trim());
                }
            }
            found = true;
        }
    }

    // Check custom shortcuts.
    let path = cosmic_shortcuts_path()?;
    if path.exists() {
        let content = read_shortcuts()?;
        if content.contains("sesame") {
            println!("  Custom shortcuts ({}):", path.display());
            for line in content.lines() {
                if line.contains("sesame") {
                    println!("    {}", line.trim());
                }
            }
            found = true;
        }
    }

    if !found {
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
        assert_eq!(key, "Space");
    }

    #[test]
    fn parse_key_combo_alt_tab() {
        let (mods, key) = parse_key_combo("alt+tab").unwrap();
        assert_eq!(mods, vec!["Alt"]);
        assert_eq!(key, "Tab");
    }

    #[test]
    fn parse_key_combo_triple() {
        let (mods, key) = parse_key_combo("ctrl+shift+a").unwrap();
        assert_eq!(mods, vec!["Ctrl", "Shift"]);
        assert_eq!(key, "a");
    }

    #[test]
    fn format_keybinding_basic() {
        let result = format_keybinding(&["Super".to_string()], "Space", "sesame");
        assert!(result.contains("modifiers: [Super]"));
        assert!(result.contains("key: \"Space\""));
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

    #[test]
    fn system_actions_format() {
        let content = "{\n}";
        let entry = "    WindowSwitcher: \"sesame wm overlay\",";
        let result = add_binding(content, entry);
        assert!(result.contains("WindowSwitcher: \"sesame wm overlay\""));
        assert!(result.starts_with('{'));
        assert!(result.ends_with('}'));
    }
}
