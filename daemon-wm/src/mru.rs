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
//!
//! The MRU stack orders the overlay; it is not authoritative state. The
//! [`MruStore`] methods log every I/O failure at `warn` and degrade to an
//! empty stack (load) or an unchanged file (save, prune). The path-based
//! functions they wrap return the error.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use core_layout::Layout;

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
    #[must_use]
    pub fn current(&self) -> Option<&str> {
        self.stack.first().map(String::as_str)
    }

    /// The previously focused window (second in stack).
    #[must_use]
    pub fn previous(&self) -> Option<&str> {
        self.stack.get(1).map(String::as_str)
    }

    /// Position of a window ID in the MRU stack (0 = most recent).
    #[must_use]
    pub fn position(&self, id: &str) -> Option<usize> {
        self.stack.iter().position(|s| s == id)
    }
}

/// The MRU stack file. Its directory is created by `Layout::bootstrap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MruStore {
    path: PathBuf,
}

impl MruStore {
    /// The store at `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The store at `Layout::mru_file`.
    ///
    /// # Errors
    ///
    /// The `Layout::mru_file` errors.
    pub fn from_layout(layout: &Layout) -> core_layout::Result<Self> {
        Ok(Self::new(layout.mru_file()?))
    }

    /// The stack, read under a shared lock.
    #[must_use]
    pub fn load(&self) -> MruState {
        match load_from(&self.path) {
            Ok(state) => {
                tracing::debug!(
                    stack_len = state.stack.len(),
                    current = state.current().unwrap_or("<none>"),
                    previous = state.previous().unwrap_or("<none>"),
                    "mru: loaded state"
                );
                state
            }
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e, "mru: load failed, using empty state");
                MruState::default()
            }
        }
    }

    /// Promote a window to the top of the MRU stack.
    ///
    /// `target` moves to position 0. If it was already in the stack, it is
    /// removed from its old position first. Stack is capped at
    /// `MAX_ENTRIES`. No-op if target is already at position 0.
    pub fn save(&self, target: &str) {
        if let Err(e) = save_to(&self.path, target) {
            tracing::warn!(target, path = %self.path.display(), error = %e, "mru: save failed");
        }
    }

    /// Remove MRU entries that no longer correspond to live windows.
    ///
    /// Called during overlay activation to keep the MRU file accurate.
    /// `live_ids` is the set of window ID strings currently reported by the
    /// compositor. Any MRU entry not in this set is removed.
    pub fn prune(&self, live_ids: &std::collections::HashSet<String>) {
        if let Err(e) = prune_from(&self.path, live_ids) {
            tracing::warn!(path = %self.path.display(), error = %e, "mru: prune failed");
        }
    }

    /// Seed the stack from a window list if it is empty: the focused
    /// window (or the first, when none is focused) goes on top. No-op when
    /// the stack already has entries or `windows` is empty.
    pub fn seed_if_empty(&self, windows: &[core_types::Window]) {
        if !self.load().stack.is_empty() {
            tracing::debug!("mru: seed_if_empty skipped, state already populated");
            return;
        }
        let Some(seed) = windows.iter().find(|w| w.is_focused).or(windows.first()) else {
            tracing::warn!("mru: seed_if_empty called with empty window list");
            return;
        };
        self.save(&seed.id.to_string());
        tracing::info!(current = %seed.app_id, focused = seed.is_focused, "mru: seeded");
    }
}

/// Read the stack at `path` under a shared lock. A missing file is an
/// empty stack.
fn load_from(path: &Path) -> std::io::Result<MruState> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(MruState::default()),
        Err(e) => return Err(e),
    };
    lock_shared(&file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(parse(&contents))
}

/// Promote `target` in the stack at `path` under an exclusive lock,
/// creating the file if absent.
fn save_to(path: &Path, target: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    lock_exclusive(&file)?;
    let mut state = read_locked(&mut file)?;

    if state.current() == Some(target) {
        tracing::debug!(target, "mru: already at top, skipping");
        return Ok(());
    }

    tracing::info!(
        target,
        stack_len = state.stack.len(),
        "mru: promoting to top"
    );
    state.stack.retain(|s| s != target);
    state.stack.insert(0, target.to_string());
    state.stack.truncate(MAX_ENTRIES);
    write_locked(&mut file, &state)
}

/// Drop entries absent from `live_ids` in the stack at `path` under an
/// exclusive lock. A missing file is left absent.
fn prune_from(path: &Path, live_ids: &std::collections::HashSet<String>) -> std::io::Result<()> {
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .truncate(false)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    lock_exclusive(&file)?;
    let mut state = read_locked(&mut file)?;

    let before = state.stack.len();
    state.stack.retain(|id| live_ids.contains(id));
    let removed = before - state.stack.len();
    if removed == 0 {
        return Ok(());
    }
    tracing::info!(
        removed,
        remaining = state.stack.len(),
        "mru: pruned dead entries"
    );
    write_locked(&mut file, &state)
}

fn read_locked(file: &mut File) -> std::io::Result<MruState> {
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(parse(&contents))
}

fn write_locked(file: &mut File, state: &MruState) -> std::io::Result<()> {
    file.seek(std::io::SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(state.stack.join("\n").as_bytes())
}

/// Reorder a window list by MRU stack position.
///
/// Windows in the MRU stack are sorted by their stack position (most recent
/// first). Windows not in the stack are placed after all MRU-tracked windows,
/// preserving their relative compositor order. The currently focused window
/// (stack position 0) sorts first; the overlay snapshot moves it last.
///
/// The closure returns a `String` rather than `&str` because ID types
/// (e.g. `WindowId`) format via `Display` without storing a `String` field
/// that could be borrowed. `state` is loaded once by the caller and shared
/// by every comparison.
pub fn reorder<T, F>(windows: &mut [T], get_id: F, state: &MruState)
where
    F: Fn(&T) -> String,
{
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

// Non-blocking (`flock` with `LOCK_NB` on Unix): the tokio thread never
// waits for another process; a held lock surfaces as `WouldBlock`.
fn lock_shared(file: &File) -> std::io::Result<()> {
    Ok(file.try_lock_shared()?)
}

fn lock_exclusive(file: &File) -> std::io::Result<()> {
    Ok(file.try_lock()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack(path: &Path) -> Vec<String> {
        load_from(path).unwrap().stack
    }

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

        save_to(&path, "A").unwrap();
        assert_eq!(stack(&path), vec!["A"]);

        save_to(&path, "B").unwrap();
        assert_eq!(stack(&path), vec!["B", "A"]);

        save_to(&path, "C").unwrap();
        assert_eq!(stack(&path), vec!["C", "B", "A"]);

        // Re-promote A: moves from position 2 to 0.
        save_to(&path, "A").unwrap();
        assert_eq!(stack(&path), vec!["A", "C", "B"]);
    }

    #[test]
    fn promote_noop_when_already_top() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        save_to(&path, "A").unwrap();
        save_to(&path, "B").unwrap();
        save_to(&path, "B").unwrap(); // already at top
        assert_eq!(stack(&path), vec!["B", "A"]);
    }

    #[test]
    fn alt_tab_ping_pong() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        // Start: A focused, B and C exist.
        save_to(&path, "C").unwrap();
        save_to(&path, "B").unwrap();
        save_to(&path, "A").unwrap();
        assert_eq!(stack(&path), vec!["A", "B", "C"]);

        // Alt+Tab: switch to B (MRU previous).
        save_to(&path, "B").unwrap();
        assert_eq!(stack(&path), vec!["B", "A", "C"]);

        // Alt+Tab again: switch back to A.
        save_to(&path, "A").unwrap();
        assert_eq!(stack(&path), vec!["A", "B", "C"]);

        // 500 more times: still ping-ponging A↔B, C stays at position 2.
        for _ in 0..500 {
            save_to(&path, "B").unwrap();
            let state = load_from(&path).unwrap();
            assert_eq!(state.current(), Some("B"));
            assert_eq!(state.previous(), Some("A"));

            save_to(&path, "A").unwrap();
            let state = load_from(&path).unwrap();
            assert_eq!(state.current(), Some("A"));
            assert_eq!(state.previous(), Some("B"));
        }
        // C never moved.
        assert_eq!(stack(&path)[2], "C");
    }

    #[test]
    fn reorder_sorts_by_mru() {
        let state = parse("B\nA\nC");
        let mut items = vec!["A", "C", "B"]; // arbitrary compositor order
        reorder(&mut items, |s| (*s).to_string(), &state);
        assert_eq!(items, vec!["B", "A", "C"]); // MRU order
    }

    #[test]
    fn reorder_unknown_windows_go_last() {
        let state = parse("B\nA");
        let mut items = ["X", "A", "B", "Y"];
        reorder(&mut items, |s| (*s).to_string(), &state);
        // B(0), A(1), then X and Y in stable compositor order.
        assert_eq!(items, ["B", "A", "X", "Y"]);
    }

    #[test]
    fn stack_capped_at_max() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        for i in 0..100 {
            save_to(&path, &format!("win-{i}")).unwrap();
        }
        let state = load_from(&path).unwrap();
        assert_eq!(state.stack.len(), MAX_ENTRIES);
        assert_eq!(state.current(), Some("win-99"));
    }

    #[test]
    fn prune_removes_dead_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        save_to(&path, "A").unwrap();
        save_to(&path, "B").unwrap();
        save_to(&path, "C").unwrap();
        assert_eq!(stack(&path), vec!["C", "B", "A"]);

        // B was closed — only A and C are live.
        let live: std::collections::HashSet<String> =
            ["A", "C"].iter().map(ToString::to_string).collect();
        prune_from(&path, &live).unwrap();
        assert_eq!(stack(&path), vec!["C", "A"]);
    }

    #[test]
    fn prune_preserves_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        save_to(&path, "A").unwrap();
        save_to(&path, "B").unwrap();
        save_to(&path, "C").unwrap();
        save_to(&path, "D").unwrap();
        // Stack: D, C, B, A. Remove C and A.
        let live: std::collections::HashSet<String> =
            ["D", "B"].iter().map(ToString::to_string).collect();
        prune_from(&path, &live).unwrap();
        assert_eq!(stack(&path), vec!["D", "B"]);
    }

    #[test]
    fn prune_all_dead_leaves_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        save_to(&path, "A").unwrap();
        save_to(&path, "B").unwrap();

        let live: std::collections::HashSet<String> = std::collections::HashSet::new();
        prune_from(&path, &live).unwrap();
        assert!(stack(&path).is_empty());
    }

    #[test]
    fn prune_all_live_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");

        save_to(&path, "A").unwrap();
        save_to(&path, "B").unwrap();
        save_to(&path, "C").unwrap();

        let live: std::collections::HashSet<String> =
            ["A", "B", "C"].iter().map(ToString::to_string).collect();
        prune_from(&path, &live).unwrap();
        assert_eq!(stack(&path), vec!["C", "B", "A"]);
    }

    #[test]
    fn prune_no_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");
        // File doesn't exist — prune must not fail or create it.
        let live: std::collections::HashSet<String> =
            ["A"].iter().map(ToString::to_string).collect();
        prune_from(&path, &live).unwrap();
        assert!(!path.exists());
        assert!(stack(&path).is_empty());
    }

    fn window(app: &str, focused: bool) -> core_types::Window {
        core_types::Window::new(
            core_types::WindowId::new(),
            core_types::AppId::new(app),
            app.into(),
            focused,
        )
    }

    #[test]
    fn seed_puts_the_focused_window_on_an_empty_stack() {
        let dir = tempfile::tempdir().unwrap();
        let store = MruStore::new(dir.path().join("mru"));
        let windows = [window("a", false), window("b", true)];
        store.seed_if_empty(&windows);
        assert_eq!(store.load().stack, [windows[1].id.to_string()]);
        // A populated stack is left as it is.
        store.seed_if_empty(&[window("c", true)]);
        assert_eq!(store.load().stack, [windows[1].id.to_string()]);
    }

    #[test]
    fn seed_without_focus_uses_the_first_window() {
        let dir = tempfile::tempdir().unwrap();
        let store = MruStore::new(dir.path().join("mru"));
        let windows = [window("a", false), window("b", false)];
        store.seed_if_empty(&windows);
        assert_eq!(store.load().stack, [windows[0].id.to_string()]);
    }

    #[test]
    fn load_reports_unreadable_path() {
        // A directory at the MRU path is an I/O error, not an empty stack.
        let dir = tempfile::tempdir().unwrap();
        assert!(load_from(dir.path()).is_err());
    }

    #[test]
    fn save_reports_held_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mru");
        save_to(&path, "A").unwrap();
        let holder = File::open(&path).unwrap();
        lock_exclusive(&holder).unwrap();
        let err = save_to(&path, "B").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        drop(holder);
        assert_eq!(stack(&path), vec!["A"]);
    }
}
