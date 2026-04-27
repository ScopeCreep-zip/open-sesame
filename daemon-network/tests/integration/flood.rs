//! Integration test: rate limiter and cookie challenge activation under
//! sustained handshake load.

use daemon_network::ratelimit::bucket::TokenBucket;
use daemon_network::flood::cookie::CookieChallenger;
use std::net::SocketAddr;

#[test]
fn rate_limiter_rejects_excess() {
    // 2 per second, burst of 3.
    let limiter = TokenBucket::new(2, 3);

    // Burst: first 3 should pass.
    assert!(limiter.check(), "token 1");
    assert!(limiter.check(), "token 2");
    assert!(limiter.check(), "token 3");

    // 4th should fail (burst exhausted, no time for refill).
    assert!(!limiter.check(), "token 4 should be rejected");
}

#[test]
fn cookie_challenge_validates_correctly() {
    let cc = CookieChallenger::new(120);
    let addr: SocketAddr = "10.0.0.1:48627".parse().unwrap();
    let wrong_addr: SocketAddr = "10.0.0.2:48627".parse().unwrap();

    let cookie = cc.generate(&addr);

    // Valid cookie from correct address.
    assert!(cc.verify(&addr, &cookie), "valid cookie should verify");

    // Valid cookie from wrong address.
    assert!(!cc.verify(&wrong_addr, &cookie), "wrong address should fail");

    // Tampered cookie.
    let mut tampered = cookie;
    tampered[0] ^= 0xFF;
    assert!(!cc.verify(&addr, &tampered), "tampered cookie should fail");
}

#[test]
fn cookie_rotation_preserves_previous_epoch() {
    let mut cc = CookieChallenger::new(0); // 0-second epoch = rotates every call
    let addr: SocketAddr = "10.0.0.3:48627".parse().unwrap();

    let cookie_before = cc.generate(&addr);

    // Force rotation.
    std::thread::sleep(std::time::Duration::from_millis(10));
    cc.maybe_rotate();

    // Cookie from previous epoch should still verify (grace period).
    assert!(
        cc.verify(&addr, &cookie_before),
        "previous-epoch cookie should verify after rotation"
    );

    // New cookie should also verify.
    let cookie_after = cc.generate(&addr);
    assert!(cc.verify(&addr, &cookie_after), "new cookie should verify");
}

#[test]
fn sustained_handshake_load_exhausts_limiter() {
    // Simulate sustained load: 128 handshakes/sec burst of 256.
    let limiter = TokenBucket::new(128, 256);

    let mut accepted = 0u32;
    let mut rejected = 0u32;

    // Fire 1000 checks without any delay — should accept up to burst then reject.
    for _ in 0..1000 {
        if limiter.check() {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    // Should have accepted exactly the burst amount.
    assert_eq!(accepted, 256, "should accept exactly burst count");
    assert_eq!(rejected, 744, "remaining should be rejected");
}
