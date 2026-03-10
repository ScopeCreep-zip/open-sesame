//! MRU (Most Recently Used) window tracking.
//!
//! Maintains a two-entry state file tracking the current and previous focused
//! window IDs. Used for Alt-Tab quick-switch behavior: releasing Alt during
//! border-only mode activates the previous window.
//!
//! File format: two lines — previous window ID, then current window ID.
//! Uses advisory file locking (flock) for atomic read-modify-write.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

/// MRU state: current and previous focused window IDs.
#[derive(Debug, Default, Clone)]
pub struct MruState {
    pub current: Option<String>,
    pub previous: Option<String>,
}

/// Resolve the MRU state file path.
///
/// `~/.cache/open-sesame/mru`, with directory created at 0o700 if missing.
fn mru_path() -> Option<PathBuf> {
    let cache = dirs::cache_dir()?.join("open-sesame");
    if !cache.exists() {
        #[cfg(unix)]
        {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;
            if DirBuilder::new().mode(0o700).recursive(true).create(&cache).is_err() {
                return None;
            }
        }
        #[cfg(not(unix))]
        {
            if std::fs::create_dir_all(&cache).is_err() {
                return None;
            }
        }
    }
    Some(cache.join("mru"))
}

/// Load MRU state from disk with shared lock.
#[must_use]
pub fn load() -> MruState {
    let Some(path) = mru_path() else {
        return MruState::default();
    };
    let Ok(mut file) = File::open(&path) else {
        return MruState::default();
    };

    if !lock_shared(&file) {
        return MruState::default();
    }

    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return MruState::default();
    }

    parse(&contents)
}

/// Save MRU state after activating a window.
///
/// `origin` is the window that was focused before the switch.
/// `target` is the window being activated.
/// No-op if origin == target.
pub fn save(origin: Option<&str>, target: &str) {
    if origin == Some(target) {
        return;
    }

    let Some(path) = mru_path() else {
        return;
    };

    let Ok(mut file) = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    else {
        return;
    };

    if !lock_exclusive(&file) {
        return;
    }

    let previous = origin.unwrap_or("");
    let contents = format!("{previous}\n{target}");

    let _ = file.seek(std::io::SeekFrom::Start(0));
    let _ = file.set_len(0);
    let _ = file.write_all(contents.as_bytes());
}

/// Get the previous window ID for quick-switch.
#[must_use]
pub fn previous_window() -> Option<String> {
    load().previous
}

/// Seed MRU state from a window list if the file is empty or missing.
///
/// Sets current = focused window, previous = first non-focused window.
/// No-op if MRU state already has valid entries.
pub fn seed_if_empty(windows: &[core_types::Window]) {
    let state = load();
    if state.current.is_some() || state.previous.is_some() {
        return;
    }

    let focused = windows.iter().find(|w| w.is_focused);
    let first_other = windows.iter().find(|w| !w.is_focused);

    match (focused, first_other) {
        (Some(cur), Some(prev)) => {
            save(Some(&prev.id.to_string()), &cur.id.to_string());
        }
        (Some(cur), None) => {
            // Only one window — set it as current with no previous.
            save(None, &cur.id.to_string());
        }
        (None, Some(first)) => {
            // No focused window detected — use first as current.
            save(None, &first.id.to_string());
        }
        (None, None) => {}
    }
}

/// Reorder a window list for MRU display: move current window to end.
///
/// The closure returns a `String` rather than `&str` because ID types
/// (e.g. `WindowId`) format via `Display` without storing a `String` field
/// that could be borrowed.
pub fn reorder<T, F>(windows: &mut Vec<T>, get_id: F)
where
    F: Fn(&T) -> String,
{
    let state = load();
    let Some(current_id) = &state.current else {
        return;
    };

    if let Some(pos) = windows.iter().position(|w| get_id(w) == *current_id)
        && pos < windows.len().saturating_sub(1)
    {
        let window = windows.remove(pos);
        windows.push(window);
    }
}

fn parse(contents: &str) -> MruState {
    let lines: Vec<&str> = contents.lines().collect();
    let previous = lines
        .first()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let current = lines
        .get(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    MruState { current, previous }
}

#[cfg(unix)]
fn lock_shared(file: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) == 0 }
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) == 0 }
}

#[cfg(not(unix))]
fn lock_shared(_file: &File) -> bool { true }

#[cfg(not(unix))]
fn lock_exclusive(_file: &File) -> bool { true }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        let state = parse("");
        assert!(state.previous.is_none());
        assert!(state.current.is_none());
    }

    #[test]
    fn parse_two_lines() {
        let state = parse("window-prev\nwindow-current");
        assert_eq!(state.previous.as_deref(), Some("window-prev"));
        assert_eq!(state.current.as_deref(), Some("window-current"));
    }

    #[test]
    fn parse_whitespace() {
        let state = parse("  prev  \n  curr  ");
        assert_eq!(state.previous.as_deref(), Some("prev"));
        assert_eq!(state.current.as_deref(), Some("curr"));
    }

    #[test]
    fn reorder_moves_current_to_end() {
        let mut items = vec!["a", "b", "c"];
        // Simulate reorder with current_id = "a"
        let current_id = "a";
        if let Some(pos) = items.iter().position(|w| *w == current_id)
            && pos < items.len() - 1
        {
            let item = items.remove(pos);
            items.push(item);
        }
        assert_eq!(items, vec!["b", "c", "a"]);
    }

    #[test]
    fn reorder_noop_when_already_last() {
        let mut items = vec!["a", "b", "c"];
        let current_id = "c";
        let original = items.clone();
        if let Some(pos) = items.iter().position(|w| *w == current_id)
            && pos < items.len() - 1
        {
            let item = items.remove(pos);
            items.push(item);
        }
        assert_eq!(items, original);
    }
}
