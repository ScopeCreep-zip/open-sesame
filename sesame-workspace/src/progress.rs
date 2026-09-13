//! Stderr progress indicator for workspace inspection.
//!
//! Single updating line on stderr: completed/total, current repo, elapsed.
//! Suppressed when stderr is not a terminal (piped output).
//! Uses `\r` for in-place update, `\x1b[K` to clear line remainder.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Thread-safe progress indicator that writes to stderr.
pub struct Progress {
    start: Instant,
    is_tty: bool,
    active: AtomicBool,
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

impl Progress {
    /// Create a new progress indicator. Detects whether stderr is a terminal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            is_tty: std::io::IsTerminal::is_terminal(&std::io::stderr()),
            active: AtomicBool::new(false),
        }
    }

    /// Update the progress line. Safe to call from any thread.
    pub fn update(&self, completed: usize, total: usize, repo_name: &str, elapsed_ms: u64) {
        if !self.is_tty {
            return;
        }
        self.active.store(true, Ordering::Relaxed);

        let elapsed = self.start.elapsed().as_secs_f32();
        let name = if repo_name.len() > 40 {
            &repo_name[..40]
        } else {
            repo_name
        };

        let _ = write!(
            std::io::stderr(),
            "\r\x1b[K  {completed}/{total} ({elapsed:.1}s) {name} [{elapsed_ms}ms]"
        );
        let _ = std::io::stderr().flush();
    }

    /// Clear the progress line and print a final summary.
    pub fn finish(&self, total: usize) {
        if !self.is_tty || !self.active.load(Ordering::Relaxed) {
            return;
        }
        let elapsed = self.start.elapsed().as_secs_f32();
        let _ = write!(
            std::io::stderr(),
            "\r\x1b[K  {total} repos in {elapsed:.1}s\n"
        );
        let _ = std::io::stderr().flush();
    }
}
