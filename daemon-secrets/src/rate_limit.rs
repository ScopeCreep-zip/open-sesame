//! Per-requester rate limiting for secret operations.
//!
//! Token bucket: 10 requests/second, burst of 20.
//! Keyed on `verified_sender_name` (server-stamped from Noise IK registry),
//! NOT on `DaemonId` (client-generated UUID, trivially rotatable).

use std::collections::HashMap;
use std::num::NonZeroU32;

/// Sentinel key for unregistered clients (no `verified_sender_name`).
pub(crate) const ANONYMOUS_RATE_KEY: &str = "__anonymous__";

/// Per-requester rate limiter for secret operations.
///
/// Uses governor's in-memory GCRA algorithm.
/// Unregistered clients (CLI relay, `None` verified name) share a single
/// `__anonymous__` bucket to prevent bypass via new-connection-per-request.
pub(crate) struct SecretRateLimiter {
    limiters: HashMap<String, governor::DefaultDirectRateLimiter>,
    quota: governor::Quota,
}

impl SecretRateLimiter {
    pub(crate) fn new() -> Self {
        // 10 requests/sec with burst of 20.
        let quota = governor::Quota::per_second(NonZeroU32::new(10).expect("nonzero"))
            .allow_burst(NonZeroU32::new(20).expect("nonzero"));
        Self {
            limiters: HashMap::new(),
            quota,
        }
    }

    /// Check if the requester is within rate limits. Returns true if allowed.
    ///
    /// Uses `verified_sender_name` from the bus server's Noise IK registry
    /// lookup. Unregistered clients share a single anonymous bucket.
    pub(crate) fn check(&mut self, verified_sender_name: Option<&str>) -> bool {
        let key = verified_sender_name.unwrap_or(ANONYMOUS_RATE_KEY);
        let limiter = self
            .limiters
            .entry(key.to_owned())
            .or_insert_with(|| governor::RateLimiter::direct(self.quota));
        limiter.check().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SECURITY INVARIANT: The rate limiter must allow up to the burst capacity
    // (20 requests) before denying. This prevents legitimate burst traffic
    // from being incorrectly throttled.
    #[test]
    fn rate_001_burst_allowed() {
        let mut limiter = SecretRateLimiter::new();
        for i in 0..20 {
            assert!(
                limiter.check(Some("daemon-launcher")),
                "request {i} within burst should be allowed"
            );
        }
    }

    // SECURITY INVARIANT: The 21st request in a burst must be denied.
    // Rate limiting is the primary defense against secret enumeration
    // attacks.
    #[test]
    fn rate_002_burst_exhaustion_denies() {
        let mut limiter = SecretRateLimiter::new();
        for _ in 0..20 {
            limiter.check(Some("daemon-launcher"));
        }
        assert!(
            !limiter.check(Some("daemon-launcher")),
            "21st request must be denied after burst exhaustion"
        );
    }

    // SECURITY INVARIANT: Each daemon must have an independent rate limit
    // bucket. Exhausting one daemon's quota must not affect another daemon's
    // ability to access secrets.
    #[test]
    fn rate_003_cross_daemon_independence() {
        let mut limiter = SecretRateLimiter::new();
        // Exhaust daemon-launcher's bucket.
        for _ in 0..20 {
            limiter.check(Some("daemon-launcher"));
        }
        assert!(!limiter.check(Some("daemon-launcher")));
        // daemon-wm should still have quota.
        assert!(
            limiter.check(Some("daemon-wm")),
            "different daemon must have independent rate limit bucket"
        );
    }

    // SECURITY INVARIANT: Anonymous (unregistered) clients must have a bucket
    // independent from named daemons. Exhausting the anonymous bucket must not
    // affect registered daemons.
    #[test]
    fn rate_004_anonymous_bucket_isolation() {
        let mut limiter = SecretRateLimiter::new();
        // Exhaust anonymous bucket.
        for _ in 0..20 {
            limiter.check(None);
        }
        assert!(!limiter.check(None));
        // Named daemon must still have quota.
        assert!(
            limiter.check(Some("daemon-secrets")),
            "named daemon must be independent from anonymous bucket"
        );
    }

    // SECURITY INVARIANT: All anonymous (unregistered) clients must share a
    // single rate limit bucket keyed on "__anonymous__". This prevents bypass
    // via new-connection-per-request without verified identity.
    #[test]
    fn rate_005_anonymous_clients_share_bucket() {
        let mut limiter = SecretRateLimiter::new();
        for i in 0..20 {
            assert!(
                limiter.check(None),
                "anonymous request {i} within burst should be allowed"
            );
        }
        assert!(
            !limiter.check(None),
            "21st anonymous request must be denied (shared bucket)"
        );
    }
}
