//! Stateless BLAKE3 cookie challenge for `DoS` resistance.
//!
//! When the global handshake rate exceeds the configured threshold,
//! `HandshakeInit` from unknown addresses is answered with a `CookieRequest`
//! instead of proceeding with the Noise handshake. The initiator must
//! echo the cookie in a `CookieResponse` before the responder allocates
//! any session state.
//!
//! `Cookie = BLAKE3(secret_key, source_addr_bytes || epoch_counter)`
//!
//! The secret key rotates every `epoch_secs` (default 120s). Cookies
//! from the current or previous epoch are accepted.

use core_crypto::SecureBytes;
use std::net::SocketAddr;
use std::time::Instant;

/// Cookie challenge state.
pub struct CookieChallenger {
    /// Current epoch secret (32 bytes, ProtectedAlloc-backed).
    current_secret: SecureBytes,
    /// Previous epoch secret (for grace period across rotation).
    previous_secret: SecureBytes,
    /// When the current epoch started.
    epoch_start: Instant,
    /// Epoch duration in seconds.
    epoch_secs: u64,
}

impl CookieChallenger {
    /// Create a new cookie challenger with random secrets.
    #[must_use]
    pub fn new(epoch_secs: u64) -> Self {
        Self {
            current_secret: SecureBytes::from_slice(&core_crypto::network::random_bytes::<32>()),
            previous_secret: SecureBytes::from_slice(&core_crypto::network::random_bytes::<32>()),
            epoch_start: Instant::now(),
            epoch_secs,
        }
    }

    /// Rotate secrets if the epoch has elapsed.
    pub fn maybe_rotate(&mut self) {
        if self.epoch_start.elapsed().as_secs() >= self.epoch_secs {
            // Previous secret = current secret (move, not copy).
            self.previous_secret = self.current_secret.clone();
            self.current_secret =
                SecureBytes::from_slice(&core_crypto::network::random_bytes::<32>());
            self.epoch_start = Instant::now();
        }
    }

    /// Generate a cookie for a source address.
    #[must_use]
    pub fn generate(&self, addr: &SocketAddr) -> [u8; 32] {
        compute_cookie(self.current_secret.as_bytes(), addr)
    }

    /// Verify a cookie from a source address (checks current and previous epoch).
    #[must_use]
    pub fn verify(&self, addr: &SocketAddr, cookie: &[u8; 32]) -> bool {
        let current = compute_cookie(self.current_secret.as_bytes(), addr);
        if constant_time_eq(&current, cookie) {
            return true;
        }
        let previous = compute_cookie(self.previous_secret.as_bytes(), addr);
        constant_time_eq(&previous, cookie)
    }
}

fn compute_cookie(secret: &[u8], addr: &SocketAddr) -> [u8; 32] {
    let key: &[u8; 32] = secret
        .try_into()
        .expect("cookie secret must be exactly 32 bytes");
    let addr_bytes = format!("{addr}");
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(addr_bytes.as_bytes());
    *hasher.finalize().as_bytes()
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl std::fmt::Debug for CookieChallenger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieChallenger")
            .field("epoch_secs", &self.epoch_secs)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_addr() -> SocketAddr {
        "127.0.0.1:48627".parse().unwrap()
    }

    #[test]
    fn generate_verify_round_trip() {
        let cc = CookieChallenger::new(120);
        let addr = test_addr();
        let cookie = cc.generate(&addr);
        assert!(cc.verify(&addr, &cookie));
    }

    #[test]
    fn wrong_address_fails() {
        let cc = CookieChallenger::new(120);
        let cookie = cc.generate(&test_addr());
        let wrong: SocketAddr = "192.168.1.1:48627".parse().unwrap();
        assert!(!cc.verify(&wrong, &cookie));
    }

    #[test]
    fn tampered_cookie_fails() {
        let cc = CookieChallenger::new(120);
        let mut cookie = cc.generate(&test_addr());
        cookie[0] ^= 0xFF;
        assert!(!cc.verify(&test_addr(), &cookie));
    }

    #[test]
    fn deterministic_for_same_epoch() {
        let cc = CookieChallenger::new(120);
        let addr = test_addr();
        let c1 = cc.generate(&addr);
        let c2 = cc.generate(&addr);
        assert_eq!(c1, c2);
    }
}
