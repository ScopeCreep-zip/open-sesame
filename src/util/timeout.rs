//! Timeout tracking for activation delays
//!
//! Provides a clean abstraction over timeout logic instead of scattered `Option<Instant>`.

use std::time::{Duration, Instant};

/// Tracks timeout state for delayed actions
#[derive(Debug, Clone)]
pub struct TimeoutTracker {
    /// When the timeout started (None if not active)
    started_at: Option<Instant>,
    /// Duration to wait before triggering
    duration: Duration,
}

impl TimeoutTracker {
    /// Creates a new timeout tracker with specified duration in milliseconds.
    pub fn new(duration_ms: u64) -> Self {
        Self {
            started_at: None,
            duration: Duration::from_millis(duration_ms),
        }
    }

    /// Starts or restarts the timeout from current instant.
    pub fn start(&mut self) {
        self.started_at = Some(Instant::now());
    }

    /// Resets the timeout (equivalent to start).
    pub fn reset(&mut self) {
        self.start();
    }

    /// Cancels the timeout.
    pub fn cancel(&mut self) {
        self.started_at = None;
    }

    /// Returns whether timeout is active (started but not elapsed).
    pub fn is_active(&self) -> bool {
        self.started_at.is_some() && !self.has_elapsed()
    }

    /// Returns whether timeout has elapsed.
    pub fn has_elapsed(&self) -> bool {
        self.started_at
            .map(|start| start.elapsed() >= self.duration)
            .unwrap_or(false)
    }

    /// Returns remaining time until timeout (None when not active or already elapsed).
    pub fn remaining(&self) -> Option<Duration> {
        self.started_at.and_then(|start| {
            let elapsed = start.elapsed();
            if elapsed >= self.duration {
                None
            } else {
                Some(self.duration - elapsed)
            }
        })
    }

    /// Returns elapsed time since start (None when not active).
    pub fn elapsed(&self) -> Option<Duration> {
        self.started_at.map(|start| start.elapsed())
    }

    /// Returns the deadline instant when timeout triggers.
    pub fn deadline(&self) -> Option<Instant> {
        self.started_at.map(|start| start + self.duration)
    }

    /// Updates the duration without resetting the timer.
    pub fn set_duration(&mut self, duration_ms: u64) {
        self.duration = Duration::from_millis(duration_ms);
    }
}

impl Default for TimeoutTracker {
    fn default() -> Self {
        Self::new(200) // Default activation delay: 200ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_timeout_not_started() {
        let tracker = TimeoutTracker::new(100);
        assert!(!tracker.is_active());
        assert!(!tracker.has_elapsed());
        assert!(tracker.remaining().is_none());
    }

    #[test]
    fn test_timeout_started() {
        let mut tracker = TimeoutTracker::new(1000);
        tracker.start();
        assert!(tracker.is_active());
        assert!(!tracker.has_elapsed());
        assert!(tracker.remaining().is_some());
    }

    #[test]
    fn test_timeout_elapsed() {
        let mut tracker = TimeoutTracker::new(10);
        tracker.start();
        sleep(Duration::from_millis(20));
        assert!(tracker.has_elapsed());
        assert!(!tracker.is_active());
    }

    #[test]
    fn test_timeout_cancel() {
        let mut tracker = TimeoutTracker::new(1000);
        tracker.start();
        assert!(tracker.is_active());
        tracker.cancel();
        assert!(!tracker.is_active());
    }
}
