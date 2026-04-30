//! Token bucket rate limiter backed by governor.

use governor::{Quota, RateLimiter, clock::DefaultClock, state::InMemoryState, state::NotKeyed};
use std::num::NonZeroU32;

/// A single token bucket with configurable rate and burst.
pub struct TokenBucket {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// `rate_per_sec`: sustained tokens per second.
    /// `burst`: maximum tokens available at any instant.
    ///
    /// # Panics
    ///
    /// Panics if `rate_per_sec` or `burst` is zero.
    #[must_use]
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        let rate = NonZeroU32::new(rate_per_sec).expect("rate must be >0");
        let burst = NonZeroU32::new(burst).expect("burst must be >0");
        let quota = Quota::per_second(rate).allow_burst(burst);
        Self {
            limiter: RateLimiter::direct(quota),
        }
    }

    /// Check if a token is available. Returns `true` if allowed, `false` if rate-limited.
    pub fn check(&self) -> bool {
        self.limiter.check().is_ok()
    }
}

impl std::fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBucket").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_burst() {
        let bucket = TokenBucket::new(10, 20);
        // Should allow at least `burst` tokens immediately.
        for _ in 0..20 {
            assert!(bucket.check());
        }
    }

    #[test]
    fn rejects_after_burst_exhausted() {
        let bucket = TokenBucket::new(1, 1);
        assert!(bucket.check()); // First token.
        // Second should fail (1/sec rate, 1 burst, no time elapsed).
        assert!(!bucket.check());
    }
}
