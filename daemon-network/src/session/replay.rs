//! Sliding-window replay detection for transport-phase sequence numbers.
//!
//! 64-entry bitmask window. Replay check happens BEFORE AEAD verification
//! to reject duplicates without wasting CPU on decryption.

/// Replay detection window tracking the last 64 sequence numbers.
#[derive(Debug)]
pub struct ReplayWindow {
    /// Highest accepted sequence number.
    top: u32,
    /// Bitmask: bit i is set if `top - i` has been seen.
    window: u64,
}

/// Result of a replay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// Sequence number is fresh — accept and process.
    Accept,
    /// Sequence number is a duplicate of a previously seen number.
    Duplicate,
    /// Sequence number is too far behind the window — likely old or replayed.
    TooOld,
}

impl ReplayWindow {
    /// Create a new replay window starting at sequence 0.
    #[must_use]
    pub fn new() -> Self {
        Self { top: 0, window: 0 }
    }

    /// Check a sequence number and update the window if accepted.
    ///
    /// Must be called BEFORE AEAD verification. If this returns `Accept`,
    /// proceed to AEAD. If AEAD fails, the window state is already updated —
    /// this is acceptable because the sequence number is consumed regardless.
    pub fn check_and_update(&mut self, seq: u32) -> ReplayCheck {
        if seq == 0 && self.top == 0 && self.window == 0 {
            // First packet ever — accept sequence 0.
            self.window = 1;
            return ReplayCheck::Accept;
        }

        if seq > self.top {
            let advance = seq - self.top;
            if advance >= 64 {
                self.window = 1;
            } else {
                self.window <<= advance;
                self.window |= 1;
            }
            self.top = seq;
            ReplayCheck::Accept
        } else {
            let offset = self.top - seq;
            if offset >= 64 {
                return ReplayCheck::TooOld;
            }
            let bit = 1u64 << offset;
            if self.window & bit != 0 {
                ReplayCheck::Duplicate
            } else {
                self.window |= bit;
                ReplayCheck::Accept
            }
        }
    }

    /// Current highest accepted sequence number.
    #[must_use]
    pub fn top(&self) -> u32 {
        self.top
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_accepted() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(0), ReplayCheck::Accept);
    }

    #[test]
    fn sequential_packets_accepted() {
        let mut w = ReplayWindow::new();
        for i in 0..100 {
            assert_eq!(w.check_and_update(i), ReplayCheck::Accept, "seq {i}");
        }
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(5), ReplayCheck::Accept);
        assert_eq!(w.check_and_update(5), ReplayCheck::Duplicate);
    }

    #[test]
    fn out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(0), ReplayCheck::Accept);
        assert_eq!(w.check_and_update(3), ReplayCheck::Accept);
        assert_eq!(w.check_and_update(1), ReplayCheck::Accept);
        assert_eq!(w.check_and_update(2), ReplayCheck::Accept);
        // All four accepted, duplicates rejected:
        assert_eq!(w.check_and_update(1), ReplayCheck::Duplicate);
        assert_eq!(w.check_and_update(3), ReplayCheck::Duplicate);
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(100), ReplayCheck::Accept);
        // Sequence 36 is 64 behind 100 — too old.
        assert_eq!(w.check_and_update(36), ReplayCheck::TooOld);
        // Sequence 37 is 63 behind — still in window.
        assert_eq!(w.check_and_update(37), ReplayCheck::Accept);
    }

    #[test]
    fn large_advance_resets_window() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(10), ReplayCheck::Accept);
        assert_eq!(w.check_and_update(200), ReplayCheck::Accept);
        // Everything before 200 - 63 = 137 is too old.
        assert_eq!(w.check_and_update(10), ReplayCheck::TooOld);
        assert_eq!(w.check_and_update(136), ReplayCheck::TooOld);
        assert_eq!(w.check_and_update(137), ReplayCheck::Accept);
    }

    #[test]
    fn window_boundary_exact() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(63), ReplayCheck::Accept);
        // Sequence 0 is exactly 63 behind — last position in window.
        assert_eq!(w.check_and_update(0), ReplayCheck::Accept);
        // Duplicate of 0.
        assert_eq!(w.check_and_update(0), ReplayCheck::Duplicate);
    }

    #[test]
    fn window_boundary_one_past() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(64), ReplayCheck::Accept);
        // Sequence 0 is exactly 64 behind — one past the window.
        assert_eq!(w.check_and_update(0), ReplayCheck::TooOld);
    }

    #[test]
    fn top_tracks_highest() {
        let mut w = ReplayWindow::new();
        w.check_and_update(5);
        assert_eq!(w.top(), 5);
        w.check_and_update(3);
        assert_eq!(w.top(), 5);
        w.check_and_update(100);
        assert_eq!(w.top(), 100);
    }

    #[test]
    fn stress_monotonic_sequence() {
        let mut w = ReplayWindow::new();
        for i in 0..10_000 {
            assert_eq!(w.check_and_update(i), ReplayCheck::Accept);
        }
        assert_eq!(w.top(), 9999);
    }

    #[test]
    fn stress_reverse_within_window() {
        let mut w = ReplayWindow::new();
        // Accept 63..0 in reverse.
        for i in (0..64).rev() {
            assert_eq!(w.check_and_update(i), ReplayCheck::Accept, "seq {i}");
        }
        // All 64 are now marked — duplicates rejected.
        for i in 0..64 {
            assert_eq!(w.check_and_update(i), ReplayCheck::Duplicate, "dup {i}");
        }
    }
}
