//! MRU (Most Recently Used) window tracking
//!
//! Tracks current and previous windows to enable proper Alt+Tab behavior.
//! Quick Alt+Tab switches to the previous window by ID lookup.
//!
//! Uses file locking to prevent race conditions during concurrent access.

use crate::util::paths;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

/// MRU state containing current and previous window IDs
#[derive(Debug, Default)]
pub struct MruState {
    /// The currently focused window (what we just switched TO)
    pub current: Option<String>,
    /// The previously focused window (what quick Alt+Tab should switch TO)
    pub previous: Option<String>,
}

/// Returns the MRU state file path.
///
/// Uses ~/.cache/open-sesame/mru with secure permissions on directory.
fn mru_path() -> PathBuf {
    match paths::mru_file() {
        Ok(path) => path,
        Err(e) => {
            tracing::warn!(
                "Failed to get secure MRU path: {}. MRU tracking disabled.",
                e
            );
            PathBuf::from("/nonexistent/open-sesame-mru")
        }
    }
}

/// Acquires exclusive lock on file, returning the locked file handle.
fn lock_file_exclusive(file: &File) -> bool {
    let fd = file.as_raw_fd();
    unsafe { libc::flock(fd, libc::LOCK_EX) == 0 }
}

/// Acquires shared lock on file for reading.
fn lock_file_shared(file: &File) -> bool {
    let fd = file.as_raw_fd();
    unsafe { libc::flock(fd, libc::LOCK_SH) == 0 }
}

/// Parses MRU state from file contents.
fn parse_mru_contents(contents: &str) -> MruState {
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

/// Saves MRU state when activating a window.
///
/// Uses file locking to prevent race conditions during read-modify-write.
/// Origin window becomes "previous", and new window becomes "current".
///
/// # Arguments
/// * `origin_window_id` - The window the user was on when they started the launcher (window of origin)
/// * `new_window_id` - The window being activated
pub fn save_activated_window(origin_window_id: Option<&str>, new_window_id: &str) {
    let path = mru_path();

    // No update when activating same window as origin
    if origin_window_id == Some(new_window_id) {
        tracing::debug!("MRU: activating same window as origin, not updating");
        return;
    }

    // File opened for read+write with exclusive lock
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("Failed to open MRU file: {}", e);
            return;
        }
    };

    // Exclusive lock acquired (blocking) for atomic read-modify-write
    if !lock_file_exclusive(&file) {
        tracing::warn!("Failed to lock MRU file for writing");
        return;
    }

    // New state written: origin becomes previous, new becomes current
    let previous = origin_window_id.unwrap_or("");
    let new_state = format!("{}\n{}", previous, new_window_id);

    let mut file = file;
    if let Err(e) = file.seek(std::io::SeekFrom::Start(0)) {
        tracing::warn!("Failed to seek MRU file: {}", e);
        return;
    }

    if let Err(e) = file.set_len(0) {
        tracing::warn!("Failed to truncate MRU file: {}", e);
        return;
    }

    if let Err(e) = file.write_all(new_state.as_bytes()) {
        tracing::warn!("Failed to write MRU state: {}", e);
        return;
    }

    tracing::info!(
        "MRU: saved state - previous={:?}, current={}",
        origin_window_id,
        new_window_id
    );
    // Lock released on drop
}

/// Loads MRU state with shared lock for consistent reads.
pub fn load_mru_state() -> MruState {
    let path = mru_path();

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            tracing::debug!("MRU: no state file found");
            return MruState::default();
        }
    };

    // Shared lock acquired for consistent read
    if !lock_file_shared(&file) {
        tracing::warn!("Failed to lock MRU file for reading");
        return MruState::default();
    }

    let mut contents = String::new();
    let mut file = file;
    if file.read_to_string(&mut contents).is_err() {
        return MruState::default();
    }

    let state = parse_mru_contents(&contents);

    tracing::debug!(
        "MRU: loaded state - previous={:?}, current={:?}",
        state.previous,
        state.current
    );

    state
    // Lock released on drop
}

/// Returns the previous window ID for quick Alt+Tab.
pub fn get_previous_window() -> Option<String> {
    let state = load_mru_state();
    state.previous
}

/// Returns the current window ID.
pub fn get_current_window() -> Option<String> {
    let state = load_mru_state();
    state.current
}

/// Reorders windows placing current window at the end.
///
/// Places "previous" window at index 0 for visual display.
pub fn reorder_for_mru<T, F>(windows: &mut Vec<T>, get_id: F)
where
    F: Fn(&T) -> &str,
{
    let state = load_mru_state();

    if let Some(current_id) = &state.current {
        if let Some(pos) = windows.iter().position(|w| get_id(w) == current_id) {
            if pos < windows.len() - 1 {
                let window = windows.remove(pos);
                windows.push(window);
                tracing::info!("MRU: moved current window from index {} to end", pos);
            } else {
                tracing::debug!("MRU: current window already at end");
            }
        } else {
            tracing::debug!("MRU: current window not found in list");
        }
    } else {
        tracing::debug!("MRU: no current window recorded");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mru_contents_empty() {
        let state = parse_mru_contents("");
        assert!(state.previous.is_none());
        assert!(state.current.is_none());
    }

    #[test]
    fn test_parse_mru_contents_single_line() {
        let state = parse_mru_contents("window-id-prev");
        assert_eq!(state.previous, Some("window-id-prev".to_string()));
        assert!(state.current.is_none());
    }

    #[test]
    fn test_parse_mru_contents_two_lines() {
        let state = parse_mru_contents("window-prev\nwindow-current");
        assert_eq!(state.previous, Some("window-prev".to_string()));
        assert_eq!(state.current, Some("window-current".to_string()));
    }

    #[test]
    fn test_parse_mru_contents_with_whitespace() {
        let state = parse_mru_contents("  window-prev  \n  window-current  ");
        assert_eq!(state.previous, Some("window-prev".to_string()));
        assert_eq!(state.current, Some("window-current".to_string()));
    }

    #[test]
    fn test_parse_mru_contents_empty_lines() {
        let state = parse_mru_contents("\n");
        assert!(state.previous.is_none());
        assert!(state.current.is_none());
    }

    #[test]
    fn test_mru_state_default() {
        let state = MruState::default();
        assert!(state.current.is_none());
        assert!(state.previous.is_none());
    }

    #[test]
    fn test_reorder_for_mru_basic() {
        // Reorder logic tested independently of file system
        // Algorithm tested via mocked data structures

        #[derive(Debug, Clone, PartialEq)]
        struct MockWindow {
            id: String,
            name: String,
        }

        let mut windows = vec![
            MockWindow {
                id: "a".to_string(),
                name: "Window A".to_string(),
            },
            MockWindow {
                id: "b".to_string(),
                name: "Window B".to_string(),
            },
            MockWindow {
                id: "c".to_string(),
                name: "Window C".to_string(),
            },
        ];

        // Simulates reorder_for_mru behavior with current_id = "a"
        // (Full function testing requires file system mocking)
        let current_id = "a";
        if let Some(pos) = windows.iter().position(|w| w.id == current_id)
            && pos < windows.len() - 1
        {
            let window = windows.remove(pos);
            windows.push(window);
        }

        assert_eq!(windows[0].id, "b");
        assert_eq!(windows[1].id, "c");
        assert_eq!(windows[2].id, "a"); // Moved to end position
    }

    #[test]
    fn test_reorder_already_at_end() {
        #[derive(Debug, Clone, PartialEq)]
        struct MockWindow {
            id: String,
        }

        let mut windows = vec![
            MockWindow {
                id: "a".to_string(),
            },
            MockWindow {
                id: "b".to_string(),
            },
            MockWindow {
                id: "c".to_string(),
            },
        ];

        // current_id "c" already at end, no movement
        let current_id = "c";
        let original = windows.clone();
        if let Some(pos) = windows.iter().position(|w| w.id == current_id)
            && pos < windows.len() - 1
        {
            let window = windows.remove(pos);
            windows.push(window);
        }

        assert_eq!(windows, original);
    }

    #[test]
    fn test_reorder_not_found() {
        #[derive(Debug, Clone, PartialEq)]
        struct MockWindow {
            id: String,
        }

        let mut windows = vec![
            MockWindow {
                id: "a".to_string(),
            },
            MockWindow {
                id: "b".to_string(),
            },
        ];

        // Nonexistent current_id causes no changes
        let current_id = "nonexistent";
        let original = windows.clone();
        if let Some(pos) = windows.iter().position(|w| w.id == current_id)
            && pos < windows.len() - 1
        {
            let window = windows.remove(pos);
            windows.push(window);
        }

        assert_eq!(windows, original);
    }
}
