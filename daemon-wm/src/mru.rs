//! MRU (Most Recently Used) window stack.
//!
//! Maintains a fully ordered stack of window IDs on disk, most recently
//! focused first. Used to sort the Alt+Tab window list so that:
//!
//! - Index 0 = most recently used (after reorder: the quick-switch target)
//! - Last index = least recently used
//! - Origin (currently focused) is demoted to end by `reorder()`
//!
//! File format: one window ID per line, most recent first. Capped at 64
//! entries. Uses advisory file locking (flock) for atomic read-modify-write.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

/// Maximum entries in the MRU stack.
const MAX_ENTRIES: usize = 64;

/// MRU state: ordered stack of window IDs, most recent first.
#[derive(Debug, Default, Clone)]
pub struct MruState {
    /// Ordered window IDs. Index 0 = most recently focused (current).
    pub stack: Vec<String>,
}

impl MruState {
    /// The currently focused window (top of stack).
    pub fn current(&self) -> Option<&str> {
        self.stack.first().map(|s| s.as_str())
    }

    /// The previously focused window (second in stack).
    pub fn previous(&self) -> Option<&str> {
        self.stack.get(1).map(|s| s.as_str())
    }

    /// Position of a window ID in the MRU stack (0 = most recent).
    pub fn position(&self, id: &str) -> Option<usize> {
        self.stack.iter().position(|s| s == id)
    }
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
            if DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&cache)
                .is_err()
            {
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
        tracing::debug!("mru: no cache path available");
        return MruState::default();
    };
    let Ok(mut file) = File::open(&path) else {
        tracing::debug!("mru: file not found, returning empty state");
        return MruState::default();
    };

    if !lock_shared(&file) {
        tracing::warn!("mru: failed to acquire shared lock");
        return MruState::default();
    }

    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        tracing::warn!("mru: failed to read file");
        return MruState::default();
    }

    let state = parse(&contents);
    tracing::debug!(
        stack_len = state.stack.len(),
        current = state.current().unwrap_or("<none>"),
        previous = state.previous().unwrap_or("<none>"),
        "mru: loaded state"
    );
    state
}

/// Promote a window to the top of the MRU stack.
///
/// `target` moves to position 0. If it was already in the stack, it is
/// removed from its old position first. Stack is capped at MAX_ENTRIES.
/// No-op if target is already at position 0.
pub fn save(_origin: Option<&str>, target: &str) {
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

    // Read existing stack.
    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents);
    let mut state = parse(&contents);

    // Already at top — no-op.
    if state.current() == Some(target) {
        tracing::debug!(target, "mru: already at top, skipping");
        return;
    }

    tracing::info!(
        target,
        stack_len = state.stack.len(),
        "mru: promoting to top"
    );

    // Remove target from current position (if present) and insert at front.
    state.stack.retain(|s| s != target);
    state.stack.insert(0, target.to_string());
    state.stack.truncate(MAX_ENTRIES);

    // Write back.
    let serialized = state.stack.join("\n");
    let _ = file.seek(std::io::SeekFrom::Start(0));
    let _ = file.set_len(0);
    let _ = file.write_all(serialized.as_bytes());
}

/// Seed MRU stack from a window list if empty.
///
/// Sets focused window at top, all others in compositor order below.
/// No-op if MRU state already has entries.
pub fn seed_if_empty(windows: &[core_types::Window]) {
    let state = load();
    if !state.stack.is_empty() {
        tracing::debug!("mru: seed_if_empty skipped, state already populated");
        return;
    }

    if windows.is_empty() {
        tracing::warn!("mru: seed_if_empty called with empty window list");
        return;
    }

    // Focused window goes first, then the rest.
    let focused = windows.iter().find(|w| w.is_focused);
    if let Some(f) = focused {
        save(None, &f.id.to_string());
        tracing::info!(current = %f.app_id, "mru: seeded with focused window");
    } else {
        save(None, &windows[0].id.to_string());
        tracing::info!(current = %windows[0].app_id, "mru: seeded with first window (none focused)");
    }
}

/// Reorder a window list by MRU stack position.
///
/// Windows in the MRU stack are sorted by their stack position (most recent
/// first). Windows not in the stack are placed after all MRU-tracked windows,
/// preserving their relative compositor order.
///
/// After sorting, the origin (MRU position 0 / currently focused) is at
/// position 0 in the result. The caller (Snapshot::build) records
/// `origin_index` and the controller skips it for initial selection.
///
/// The closure returns a `String` rather than `&str` because ID types
/// (e.g. `WindowId`) format via `Display` without storing a `String` field
/// that could be borrowed.
pub fn reorder<T, F>(windows: &mut [T], get_id: F)
where
    F: Fn(&T) -> String,
{
    let state = load();
    if state.stack.is_empty() {
        return;
    }

    windows.sort_by(|a, b| {
        let pos_a = state.position(&get_id(a)).unwrap_or(usize::MAX);
        let pos_b = state.position(&get_id(b)).unwrap_or(usize::MAX);
        pos_a.cmp(&pos_b)
    });
}

fn parse(contents: &str) -> MruState {
    let stack: Vec<String> = contents
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    MruState { stack }
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
fn lock_shared(_file: &File) -> bool {
    true
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &File) -> bool {
    true
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn load_from(path: &std::path::Path) -> MruState {
    let Ok(mut file) = File::open(path) else {
        return MruState::default();
    };
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return MruState::default();
    }
    parse(&contents)
}

#[cfg(test)]
fn save_to(path: &std::path::Path, target: &str) {
    let Ok(mut file) = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
    else {
        return;
    };
    if !lock_exclusive(&file) {
        return;
    }

    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents);
    let mut state = parse(&contents);

    if state.current() == Some(target) {
        return;
    }

    state.stack.retain(|s| s != target);
    state.stack.insert(0, target.to_string());
    state.stack.truncate(MAX_ENTRIES);

    let serialized = state.stack.join("\n");
    let _ = file.seek(std::io::SeekFrom::Start(0));
    let _ = file.set_len(0);
    let _ = file.write_all(serialized.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        let state = parse("");
        assert!(state.stack.is_empty());
        assert!(state.current().is_none());
        assert!(state.previous().is_none());
    }

    #[test]
    fn parse_stack() {
        let state = parse("win-A\nwin-B\nwin-C");
        assert_eq!(state.stack, vec!["win-A", "win-B", "win-C"]);
        assert_eq!(state.current(), Some("win-A"));
        assert_eq!(state.previous(), Some("win-B"));
    }

    #[test]
    fn parse_whitespace() {
        let state = parse("  win-A  \n  win-B  ");
        assert_eq!(state.current(), Some("win-A"));
        assert_eq!(state.previous(), Some("win-B"));
    }

    #[test]
    fn position_lookup() {
        let state = parse("A\nB\nC\nD");
        assert_eq!(state.position("A"), Some(0));
        assert_eq!(state.position("C"), Some(2));
        assert_eq!(state.position("Z"), None);
    }

    #[test]
    fn promote_to_top() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        save_to(&path, "A");
        assert_eq!(load_from(&path).stack, vec!["A"]);

        save_to(&path, "B");
        assert_eq!(load_from(&path).stack, vec!["B", "A"]);

        save_to(&path, "C");
        assert_eq!(load_from(&path).stack, vec!["C", "B", "A"]);

        // Re-promote A: moves from position 2 to 0.
        save_to(&path, "A");
        assert_eq!(load_from(&path).stack, vec!["A", "C", "B"]);
    }

    #[test]
    fn promote_noop_when_already_top() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        save_to(&path, "A");
        save_to(&path, "B");
        save_to(&path, "B"); // already at top
        assert_eq!(load_from(&path).stack, vec!["B", "A"]);
    }

    #[test]
    fn alt_tab_ping_pong() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        // Start: A focused, B and C exist.
        save_to(&path, "C");
        save_to(&path, "B");
        save_to(&path, "A");
        assert_eq!(load_from(&path).stack, vec!["A", "B", "C"]);

        // Alt+Tab: switch to B (MRU previous).
        save_to(&path, "B");
        assert_eq!(load_from(&path).stack, vec!["B", "A", "C"]);

        // Alt+Tab again: switch back to A.
        save_to(&path, "A");
        assert_eq!(load_from(&path).stack, vec!["A", "B", "C"]);

        // 500 more times: still ping-ponging A↔B, C stays at position 2.
        for _ in 0..500 {
            save_to(&path, "B");
            assert_eq!(load_from(&path).current(), Some("B"));
            assert_eq!(load_from(&path).previous(), Some("A"));

            save_to(&path, "A");
            assert_eq!(load_from(&path).current(), Some("A"));
            assert_eq!(load_from(&path).previous(), Some("B"));
        }
        // C never moved.
        assert_eq!(load_from(&path).stack[2], "C");
    }

    #[test]
    fn reorder_sorts_by_mru() {
        // Simulate reorder logic directly (since reorder() calls load()
        // which reads from the real path, not testable here).
        let state = parse("B\nA\nC");

        let mut items = vec!["A", "C", "B"]; // arbitrary compositor order
        items.sort_by(|a, b| {
            let pa = state.position(a).unwrap_or(usize::MAX);
            let pb = state.position(b).unwrap_or(usize::MAX);
            pa.cmp(&pb)
        });
        assert_eq!(items, vec!["B", "A", "C"]); // MRU order
    }

    #[test]
    fn reorder_unknown_windows_go_last() {
        let state = parse("B\nA");

        let mut items = ["X", "A", "B", "Y"];
        items.sort_by(|a, b| {
            let pa = state.position(a).unwrap_or(usize::MAX);
            let pb = state.position(b).unwrap_or(usize::MAX);
            pa.cmp(&pb)
        });
        // B(0), A(1), then X and Y (both MAX, stable relative order).
        assert_eq!(items[0], "B");
        assert_eq!(items[1], "A");
        // X and Y are after, order between them is stable.
        assert!(items[2..].contains(&"X"));
        assert!(items[2..].contains(&"Y"));
    }

    #[test]
    fn stack_capped_at_max() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        for i in 0..100 {
            save_to(&path, &format!("win-{i}"));
        }
        let state = load_from(&path);
        assert_eq!(state.stack.len(), MAX_ENTRIES);
        assert_eq!(state.current(), Some("win-99"));
    }
}
