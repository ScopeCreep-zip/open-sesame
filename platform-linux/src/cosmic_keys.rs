//! COSMIC keybinding integration.
//!
//! Manages keybindings in COSMIC desktop's shortcut configuration files,
//! under `Layout::cosmic_config_dir`:
//! - `com.system76.CosmicSettings.Shortcuts/v1/custom` (custom shortcuts)
//! - `com.system76.CosmicSettings.Shortcuts/v1/system_actions` (system action commands)
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

use core_layout::Layout;
use core_types::{KeyCombo, Modifier, OverlayRequest};
use std::fs;
use std::path::{Path, PathBuf};

/// COSMIC's shortcuts configuration schema directory.
fn cosmic_shortcuts_dir(layout: &Layout) -> core_types::Result<PathBuf> {
    Ok(layout
        .cosmic_config_dir()?
        .join("com.system76.CosmicSettings.Shortcuts")
        .join("v1"))
}

/// COSMIC custom shortcuts config. The compositor watches this file and
/// live-reloads on change.
fn cosmic_shortcuts_path(layout: &Layout) -> core_types::Result<PathBuf> {
    Ok(cosmic_shortcuts_dir(layout)?.join("custom"))
}

/// COSMIC `system_actions` config: maps `System(...)` action enum variants
/// to command strings (e.g. `WindowSwitcher` -> "sesame wm overlay").
fn cosmic_system_actions_path(layout: &Layout) -> core_types::Result<PathBuf> {
    Ok(cosmic_shortcuts_dir(layout)?.join("system_actions"))
}

/// Whether COSMIC reads shortcuts on this system: its default shortcut
/// configuration is installed under a system data directory
/// (`Layout::cosmic_shortcut_defaults`). A property of the system, not of
/// the calling shell's environment.
#[must_use]
pub fn shortcuts_supported(layout: &Layout) -> bool {
    layout
        .cosmic_shortcut_defaults()
        .iter()
        .any(|dir| dir.is_dir())
}

/// Whether `path` exists; a failure to determine it is an error.
fn exists(path: &Path) -> core_types::Result<bool> {
    path.try_exists().map_err(|e| {
        core_types::Error::Platform(format!("failed to check {}: {e}", path.display()))
    })
}

/// COSMIC's name for `modifier` in a shortcut's `modifiers` list.
const fn cosmic_modifier(modifier: Modifier) -> &'static str {
    match modifier {
        Modifier::Super => "Super",
        Modifier::Ctrl => "Ctrl",
        Modifier::Alt => "Alt",
        Modifier::Shift => "Shift",
    }
}

/// The command a COSMIC binding runs for `request`: `sesame` and the
/// request's arguments.
fn command(request: OverlayRequest) -> String {
    std::iter::once("sesame")
        .chain(request.command_args().iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
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

/// The COSMIC RON entry binding `combo` to `request`. COSMIC matches keys
/// against lowercase XKB keysym names (`space`, `tab`): a capitalized
/// name draws cosmic-comp's "only matched case insensitive" warning and
/// may not dispatch, so the key is lowercased.
fn format_keybinding(combo: &KeyCombo, request: OverlayRequest) -> String {
    let mods: Vec<&str> = combo
        .modifiers()
        .iter()
        .map(|m| cosmic_modifier(*m))
        .collect();
    let escaped_key = escape_ron_string(&combo.key().to_lowercase());
    let escaped_command = escape_ron_string(&command(request));
    format!(
        "    (modifiers: [{}], key: \"{escaped_key}\"): Spawn(\"{escaped_command}\"),",
        mods.join(", ")
    )
}

/// Read a COSMIC RON config file; an absent file is an empty map.
fn read_config(path: &Path) -> core_types::Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("{\n}".to_string()),
        Err(e) => Err(core_types::Error::Platform(format!(
            "failed to read {}: {e}",
            path.display()
        ))),
    }
}

/// Write a COSMIC RON config file, first copying an existing file to
/// `<path>.bak`. A failed backup aborts the write: the user's
/// configuration is never overwritten without one.
fn write_config(path: &Path, content: &str) -> core_types::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            core_types::Error::Platform(format!("failed to create {}: {e}", parent.display()))
        })?;
    }

    let backup = path.with_extension("bak");
    match fs::copy(path, &backup) {
        Ok(_) => tracing::info!("created backup at {}", backup.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(core_types::Error::Platform(format!(
                "failed to back up {} to {}: {e}; not modified",
                path.display(),
                backup.display()
            )));
        }
    }

    fs::write(path, content).map_err(|e| {
        core_types::Error::Platform(format!("failed to write {}: {e}", path.display()))
    })
}

/// Read the current custom shortcuts file.
fn read_shortcuts(layout: &Layout) -> core_types::Result<String> {
    read_config(&cosmic_shortcuts_path(layout)?)
}

/// Write the custom shortcuts file with backup.
fn write_shortcuts(layout: &Layout, content: &str) -> core_types::Result<()> {
    write_config(&cosmic_shortcuts_path(layout)?, content)
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

/// Read the current `system_actions` file.
fn read_system_actions(layout: &Layout) -> core_types::Result<String> {
    read_config(&cosmic_system_actions_path(layout)?)
}

/// Write the `system_actions` file with backup.
fn write_system_actions(layout: &Layout, content: &str) -> core_types::Result<()> {
    write_config(&cosmic_system_actions_path(layout)?, content)
}

/// Update `system_actions` to point `WindowSwitcher`/`WindowSwitcherPrevious` at sesame.
///
/// This overrides the commands that COSMIC's built-in `System(WindowSwitcher)`
/// and `System(WindowSwitcherPrevious)` actions execute. The keybindings
/// themselves (Alt+Tab, Super+Tab, etc.) remain unchanged — we only change
/// what program they launch.
fn setup_system_actions(layout: &Layout) -> core_types::Result<()> {
    let mut content = read_system_actions(layout)?;

    // Remove any existing WindowSwitcher entries.
    content = content
        .lines()
        .filter(|line| !line.contains("WindowSwitcher"))
        .collect::<Vec<_>>()
        .join("\n");

    // Add sesame entries.
    let entry = |action: &str, request: OverlayRequest| {
        format!(
            "    {action}: \"{}\",",
            escape_ron_string(&command(request))
        )
    };
    let content = add_binding(&content, &entry("WindowSwitcher", OverlayRequest::Forward));
    let content = add_binding(
        &content,
        &entry("WindowSwitcherPrevious", OverlayRequest::Backward),
    );

    write_system_actions(layout, &content)?;
    Ok(())
}

/// Remove sesame entries from `system_actions`, restoring COSMIC defaults.
fn remove_system_actions(layout: &Layout) -> core_types::Result<()> {
    let path = cosmic_system_actions_path(layout)?;
    if !exists(&path)? {
        return Ok(());
    }

    let content = read_system_actions(layout)?;

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
        fs::remove_file(&path).map_err(|e| {
            core_types::Error::Platform(format!("failed to remove {}: {e}", path.display()))
        })?;
        tracing::info!("removed empty system_actions override (COSMIC will use system defaults)");
    } else {
        write_system_actions(layout, &new_content)?;
    }
    Ok(())
}

/// Setup all sesame keybindings in COSMIC.
///
/// Configures:
/// - Alt+Tab / Super+Tab: overrides COSMIC's built-in `WindowSwitcher` command
///   via `system_actions` so the compositor's own binding runs sesame. This
///   ensures the Alt modifier is consumed at compositor level (no leak to apps).
/// - Launcher key (configurable, default alt+space): custom `Spawn(...)` binding
///   for full overlay with hints.
///
/// # Errors
///
/// A COSMIC config file that cannot be read, backed up, or written.
pub fn setup_keybinding(layout: &Layout, launcher: &KeyCombo) -> core_types::Result<()> {
    // -- Step 1: Override system_actions so COSMIC's built-in Alt+Tab runs sesame --
    setup_system_actions(layout)?;

    // -- Step 2: the launcher requests as custom Spawn bindings (the
    // window switcher is the system_actions override above).
    let launcher_binding = format_keybinding(
        &OverlayRequest::Launcher.trigger(launcher),
        OverlayRequest::Launcher,
    );
    let launcher_backward_binding = format_keybinding(
        &OverlayRequest::LauncherBackward.trigger(launcher),
        OverlayRequest::LauncherBackward,
    );

    let mut content = read_shortcuts(layout)?;

    if content.contains("sesame") {
        tracing::info!("removing existing sesame keybindings");
        content = remove_sesame_bindings(&content);
    }

    let content = add_binding(&content, &launcher_binding);
    let new_content = add_binding(&content, &launcher_backward_binding);
    write_shortcuts(layout, &new_content)?;

    tracing::info!(%launcher, "configured COSMIC keybindings: system_actions override and the launcher key");
    println!("Keybindings configured (COSMIC):");
    for request in OverlayRequest::ALL {
        let via = match request {
            OverlayRequest::Forward => " (COSMIC's WindowSwitcher)",
            OverlayRequest::Backward => " (COSMIC's WindowSwitcherPrevious)",
            OverlayRequest::Launcher | OverlayRequest::LauncherBackward => "",
        };
        println!(
            "    {:<18}-> {}{via}",
            request.trigger(launcher).to_string(),
            command(request)
        );
    }
    println!(
        "  System actions: {}",
        cosmic_system_actions_path(layout)?.display()
    );
    println!(
        "  Custom keys:    {}",
        cosmic_shortcuts_path(layout)?.display()
    );

    Ok(())
}

/// Remove sesame keybindings from COSMIC.
///
/// # Errors
///
/// A COSMIC config file that cannot be read, backed up, written, or removed.
pub fn remove_keybinding(layout: &Layout) -> core_types::Result<()> {
    let mut found = false;

    // Remove system_actions override.
    let sa_path = cosmic_system_actions_path(layout)?;
    if exists(&sa_path)? {
        let sa_content = read_system_actions(layout)?;
        if sa_content.contains("sesame") {
            remove_system_actions(layout)?;
            println!("Removed sesame system_actions override.");
            found = true;
        }
    }

    // Remove custom shortcuts.
    let content = read_shortcuts(layout)?;
    if content.contains("sesame") {
        let new_content = remove_sesame_bindings(&content);
        write_shortcuts(layout, &new_content)?;
        println!("Removed sesame custom keybindings.");
        found = true;
    }

    if !found {
        println!("No sesame keybinding found.");
    }
    Ok(())
}

/// Show current keybinding status.
///
/// # Errors
///
/// A COSMIC config file whose presence or contents cannot be read.
pub fn keybinding_status(layout: &Layout) -> core_types::Result<()> {
    let mut found = false;

    // Check system_actions override.
    let sa_path = cosmic_system_actions_path(layout)?;
    if exists(&sa_path)? {
        let sa_content = read_system_actions(layout)?;
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
    let path = cosmic_shortcuts_path(layout)?;
    if exists(&path)? {
        let content = read_shortcuts(layout)?;
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

    fn combo(written: &str) -> KeyCombo {
        written.parse().unwrap()
    }

    #[test]
    fn bindings_render_cosmic_modifiers_lowercase_keys_and_the_request_command() {
        assert_eq!(
            format_keybinding(&combo("shift+ctrl+Tab"), OverlayRequest::LauncherBackward),
            "    (modifiers: [Ctrl, Shift], key: \"tab\"): Spawn(\"sesame wm overlay --launcher --backward\"),"
        );
        assert_eq!(
            format_keybinding(&combo("F12"), OverlayRequest::Launcher),
            "    (modifiers: [], key: \"f12\"): Spawn(\"sesame wm overlay --launcher\"),"
        );
    }

    #[test]
    fn commands_are_the_request_arguments() {
        for request in OverlayRequest::ALL {
            assert_eq!(
                command(request),
                format!("sesame {}", request.command_args().join(" "))
            );
        }
    }

    #[test]
    fn write_config_backs_up_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom");
        std::fs::write(&path, "old").unwrap();
        write_config(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(
            std::fs::read_to_string(path.with_extension("bak")).unwrap(),
            "old"
        );
    }

    #[test]
    fn write_config_refuses_to_overwrite_without_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom");
        std::fs::write(&path, "old").unwrap();
        // A directory at the backup path makes the copy fail.
        std::fs::create_dir(path.with_extension("bak")).unwrap();
        assert!(write_config(&path, "new").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
    }

    #[test]
    fn shortcut_files_live_under_the_cosmic_config_dir() {
        let layout = Layout::under(Path::new("/r"));
        let dir = layout
            .cosmic_config_dir()
            .unwrap()
            .join("com.system76.CosmicSettings.Shortcuts/v1");
        assert_eq!(cosmic_shortcuts_path(&layout).unwrap(), dir.join("custom"));
        assert_eq!(
            cosmic_system_actions_path(&layout).unwrap(),
            dir.join("system_actions")
        );
    }

    #[test]
    fn setup_then_remove_round_trips_under_a_layout() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        setup_keybinding(&layout, &combo("alt+space")).unwrap();
        let shortcuts = read_shortcuts(&layout).unwrap();
        assert!(shortcuts.contains(&format_keybinding(
            &combo("alt+space"),
            OverlayRequest::Launcher
        )));
        assert!(shortcuts.contains(&format_keybinding(
            &combo("alt+shift+space"),
            OverlayRequest::LauncherBackward
        )));
        let actions = read_system_actions(&layout).unwrap();
        assert!(actions.contains("WindowSwitcher: \"sesame wm overlay\""));
        assert!(actions.contains("WindowSwitcherPrevious: \"sesame wm overlay --backward\""));
        remove_keybinding(&layout).unwrap();
        assert!(!read_shortcuts(&layout).unwrap().contains("sesame"));
        assert!(!exists(&cosmic_system_actions_path(&layout).unwrap()).unwrap());
    }

    #[test]
    fn read_config_absent_is_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_config(&dir.path().join("absent")).unwrap(), "{\n}");
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
