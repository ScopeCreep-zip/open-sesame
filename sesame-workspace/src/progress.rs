//! Stderr progress indicator for workspace inspection.
//!
//! Single updating line on stderr: completed/total, current repo, elapsed.
//! Suppressed when stderr is not a terminal (piped output).
//! Uses `\r` for in-place update, `\x1b[K` to clear line remainder.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Longest repository name shown, in characters.
const NAME_CHARS: usize = 40;

/// Thread-safe progress indicator that writes to stderr.
pub struct Progress {
    start: Instant,
    /// Whether progress is drawn: stderr is a terminal and no write to it
    /// has failed. Stderr is the reporting channel, so a failed write
    /// disables the indicator instead of being reported.
    enabled: AtomicBool,
    active: AtomicBool,
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

/// `name` cut to at most `NAME_CHARS` characters, never inside a code point.
fn display_name(name: &str) -> &str {
    match name.char_indices().nth(NAME_CHARS) {
        Some((end, _)) => &name[..end],
        None => name,
    }
}

impl Progress {
    /// Create a new progress indicator. Detects whether stderr is a terminal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            enabled: AtomicBool::new(std::io::IsTerminal::is_terminal(&std::io::stderr())),
            active: AtomicBool::new(false),
        }
    }

    /// Update the progress line. Safe to call from any thread.
    pub fn update(&self, completed: usize, total: usize, repo_name: &str, elapsed_ms: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        self.active.store(true, Ordering::Relaxed);
        let elapsed = self.start.elapsed().as_secs_f32();
        let name = display_name(repo_name);
        self.draw(format_args!(
            "\r\x1b[K  {completed}/{total} ({elapsed:.1}s) {name} [{elapsed_ms}ms]"
        ));
    }

    /// Clear the progress line and print a final summary.
    pub fn finish(&self, total: usize) {
        if !self.enabled.load(Ordering::Relaxed) || !self.active.load(Ordering::Relaxed) {
            return;
        }
        let elapsed = self.start.elapsed().as_secs_f32();
        self.draw(format_args!("\r\x1b[K  {total} repos in {elapsed:.1}s\n"));
    }

    fn draw(&self, line: std::fmt::Arguments<'_>) {
        let mut stderr = std::io::stderr().lock();
        if stderr
            .write_fmt(line)
            .and_then(|()| stderr.flush())
            .is_err()
        {
            self.enabled.store(false, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_are_unchanged() {
        assert_eq!(display_name("repo"), "repo");
        let exact = "a".repeat(NAME_CHARS);
        assert_eq!(display_name(&exact), exact);
    }

    #[test]
    fn long_names_are_cut_at_a_character_boundary() {
        // 'é' is 2 bytes: byte 40 falls inside the 21st character.
        let name = "é".repeat(50);
        let shown = display_name(&name);
        assert_eq!(shown.chars().count(), NAME_CHARS);
        assert_eq!(shown, "é".repeat(NAME_CHARS));
    }
}
