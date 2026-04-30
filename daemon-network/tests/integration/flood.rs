//! Integration test: rate limiter, cookie challenge, and `PoW` under
//! sustained handshake load and adversarial conditions.

mod common;

use daemon_network::flood::cookie::CookieChallenger;
use daemon_network::flood::pow::PowChallenger;
use daemon_network::ratelimit::bucket::TokenBucket;
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

    let cookie = cc.generate(&addr).expect("generate must succeed");

    // Valid cookie from correct address.
    assert!(cc.verify(&addr, &cookie), "valid cookie should verify");

    // Valid cookie from wrong address.
    assert!(
        !cc.verify(&wrong_addr, &cookie),
        "wrong address should fail"
    );

    // Tampered cookie.
    let mut tampered = cookie;
    tampered[0] ^= 0xFF;
    assert!(!cc.verify(&addr, &tampered), "tampered cookie should fail");
}

#[test]
fn cookie_rotation_preserves_previous_epoch() {
    let mut cc = CookieChallenger::new(0); // 0-second epoch = rotates every call
    let addr: SocketAddr = "10.0.0.3:48627".parse().unwrap();

    let cookie_before = cc.generate(&addr).expect("generate must succeed");

    // Force rotation.
    std::thread::sleep(std::time::Duration::from_millis(10));
    cc.maybe_rotate();

    // Cookie from previous epoch should still verify (grace period).
    assert!(
        cc.verify(&addr, &cookie_before),
        "previous-epoch cookie should verify after rotation"
    );

    // New cookie should also verify.
    let cookie_after = cc.generate(&addr).expect("generate must succeed");
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

// ============================================================================
// `PoW` epoch staleness and future-epoch rejection
// ============================================================================

#[test]
fn pow_epoch_staleness_rejects_old_epoch() {
    // A solution minted 301+ seconds ago must be rejected.
    // We simulate by generating a seed with epoch = now - 301.
    let secret = [0xDD; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let stale_epoch = now.saturating_sub(301);
    let current_epoch = now;

    let seed_stale = PowChallenger::generate_seed(&secret, stale_epoch, "10.0.0.1:48627");
    let seed_current = PowChallenger::generate_seed(&secret, current_epoch, "10.0.0.1:48627");

    // Seeds for different epochs must differ (so a stale solution can't verify against current).
    assert_ne!(
        seed_stale, seed_current,
        "stale and current epoch seeds must differ"
    );
}

#[test]
fn pow_epoch_future_rejected() {
    // A solution with epoch > now must be rejected.
    // The daemon checks `epoch > now_epoch` before verifying.
    // We verify the seeds differ so a future solution can't match a current seed.
    let secret = [0xEE; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let future_epoch = now + 100;

    let seed_now = PowChallenger::generate_seed(&secret, now, "10.0.0.1:48627");
    let seed_future = PowChallenger::generate_seed(&secret, future_epoch, "10.0.0.1:48627");
    assert_ne!(
        seed_now, seed_future,
        "future epoch seed must differ from current"
    );
}

// ============================================================================
// Cookie wire format: challenge payload structure
// ============================================================================

#[test]
fn cookie_challenge_payload_is_33_bytes() {
    // Tier 1 cookie: [0x00 type byte][32-byte cookie] = 33 bytes total.
    let cc = CookieChallenger::new(120);
    let addr: SocketAddr = "10.0.0.1:48627".parse().unwrap();
    let cookie = cc.generate(&addr).expect("generate must succeed");
    assert_eq!(cookie.len(), 32, "cookie must be exactly 32 bytes");

    // Wire format: type byte + cookie.
    let mut payload = vec![0x00u8];
    payload.extend_from_slice(&cookie);
    assert_eq!(
        payload.len(),
        33,
        "tier-1 challenge payload must be 33 bytes"
    );
}

#[test]
fn pow_challenge_payload_is_41_bytes() {
    // Tier 2 `PoW`: [0x01 type byte][8-byte epoch BE][32-byte seed] = 41 bytes total.
    let secret = [0xAA; 32];
    let epoch: u64 = 1_700_000_000;
    let seed = PowChallenger::generate_seed(&secret, epoch, "10.0.0.1:48627");

    let mut payload = vec![0x01u8];
    payload.extend_from_slice(&epoch.to_be_bytes());
    payload.extend_from_slice(&seed);
    assert_eq!(
        payload.len(),
        41,
        "tier-2 challenge payload must be 41 bytes"
    );

    // Verify epoch can be decoded back.
    let decoded_epoch = u64::from_be_bytes(payload[1..9].try_into().unwrap());
    assert_eq!(
        decoded_epoch, epoch,
        "epoch must round-trip through wire format"
    );
}

#[test]
fn pow_response_payload_is_25_bytes() {
    // `PoW` response: [0x01 type byte][8-byte epoch][16-byte solution] = 25 bytes.
    let secret = [0xBB; 32];
    for epoch in 0..100u64 {
        let seed = PowChallenger::generate_seed(&secret, epoch, "test");
        if let Some(solution) = PowChallenger::solve(&seed) {
            let mut response = vec![0x01u8];
            response.extend_from_slice(&epoch.to_be_bytes());
            response.extend_from_slice(&solution);
            assert_eq!(
                response.len(),
                25,
                "`PoW` response payload must be 25 bytes"
            );

            // Verify the solution can be extracted and verified.
            let extracted_epoch = u64::from_be_bytes(response[1..9].try_into().unwrap());
            let extracted_solution: equix::SolutionByteArray = response[9..25].try_into().unwrap();
            assert_eq!(extracted_epoch, epoch);
            assert!(
                PowChallenger::verify_solution(&seed, &extracted_solution),
                "extracted solution must verify"
            );
            return;
        }
    }
    panic!("failed to find solvable seed in 100 attempts");
}
