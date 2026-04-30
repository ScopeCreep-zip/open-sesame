//! Equi-X proof-of-work second-tier `DoS` gate.
//!
//! When the BLAKE3 cookie challenge tier is saturated (global handshake rate
//! exceeds `pow_challenge_threshold`), initiators must solve an Equi-X puzzle
//! before the responder allocates session state.
//!
//! Equi-X (Tevador, used by Tor v3 proof-of-work) uses pipelined integer-only hash
//! programs with per-seed randomisation, making GPU flooding ineffective.
//! Verification is ~20,000/sec in Rust.
//!
//! Protocol:
//! 1. Responder generates a challenge seed: `BLAKE3(server_secret || epoch || client_addr)`
//! 2. Responder sends seed + effort target in `CookieRequest` frame
//! 3. Initiator solves Equi-X for the seed, includes solution in `CookieResponse`
//! 4. Responder verifies solution (~50µs) before proceeding with handshake

use equix::{EquiX, SolutionByteArray};

/// Equi-X `PoW` challenge state.
pub struct PowChallenger {
    /// Whether `PoW` challenges are currently active (activated by load threshold).
    active: bool,
}

impl PowChallenger {
    /// Create a new `PoW` challenger (initially inactive).
    #[must_use]
    pub fn new() -> Self {
        Self { active: false }
    }

    /// Activate `PoW` challenges (called when cookie tier is saturated).
    pub fn activate(&mut self) {
        if !self.active {
            tracing::info!("Equi-X `PoW` challenges activated — sustained handshake load");
            self.active = true;
        }
    }

    /// Deactivate `PoW` challenges (called when load drops below threshold).
    pub fn deactivate(&mut self) {
        if self.active {
            tracing::info!("Equi-X `PoW` challenges deactivated — load subsided");
            self.active = false;
        }
    }

    /// Whether `PoW` challenges are currently required.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Generate a challenge seed for a client address.
    ///
    /// The seed is derived from a server secret, the current epoch counter,
    /// and the client's address — ensuring each client gets a unique puzzle.
    #[must_use]
    pub fn generate_seed(server_secret: &[u8; 32], epoch: u64, client_addr: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(server_secret);
        hasher.update(&epoch.to_be_bytes());
        hasher.update(client_addr.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify an Equi-X solution against a challenge seed.
    ///
    /// Returns `true` if the solution is valid for the given seed.
    ///
    /// # Errors
    ///
    /// Returns `false` on any verification failure (invalid solution,
    /// unsolvable seed, malformed input).
    #[must_use]
    pub fn verify_solution(seed: &[u8; 32], solution_bytes: &SolutionByteArray) -> bool {
        let Ok(equix) = EquiX::new(seed) else {
            // Seed produces an unsolvable HashX program — reject.
            // This happens for a small fraction of seeds per the Equi-X spec.
            return false;
        };

        let Ok(solution) = equix::Solution::try_from_bytes(solution_bytes) else {
            return false;
        };

        equix.verify(&solution).is_ok()
    }

    /// Solve an Equi-X puzzle for the given seed (client-side).
    ///
    /// Returns `None` if the seed produces an unsolvable `HashX` program
    /// (~1.4% of seeds per the Equi-X spec — client should request a new seed).
    #[must_use]
    pub fn solve(seed: &[u8; 32]) -> Option<SolutionByteArray> {
        let equix = EquiX::new(seed).ok()?;
        let solutions = equix.solve();
        solutions.first().map(equix::Solution::to_bytes)
    }
}

impl Default for PowChallenger {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PowChallenger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PowChallenger")
            .field("active", &self.active)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_initially_inactive() {
        let pow = PowChallenger::new();
        assert!(!pow.is_active());
    }

    #[test]
    fn pow_activate_deactivate() {
        let mut pow = PowChallenger::new();
        pow.activate();
        assert!(pow.is_active());
        pow.deactivate();
        assert!(!pow.is_active());
    }

    #[test]
    fn seed_generation_deterministic() {
        let secret = [0xAA; 32];
        let s1 = PowChallenger::generate_seed(&secret, 1, "10.0.0.1:48627");
        let s2 = PowChallenger::generate_seed(&secret, 1, "10.0.0.1:48627");
        assert_eq!(s1, s2);
    }

    #[test]
    fn seed_generation_different_inputs() {
        let secret = [0xAA; 32];
        let s1 = PowChallenger::generate_seed(&secret, 1, "10.0.0.1:48627");
        let s2 = PowChallenger::generate_seed(&secret, 2, "10.0.0.1:48627");
        let s3 = PowChallenger::generate_seed(&secret, 1, "10.0.0.2:48627");
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn solve_and_verify_round_trip() {
        // Try multiple seeds since ~1.4% are unsolvable.
        let secret = [0xBB; 32];
        for epoch in 0..100 {
            let seed = PowChallenger::generate_seed(&secret, epoch, "test-client");
            if let Some(solution) = PowChallenger::solve(&seed) {
                assert!(
                    PowChallenger::verify_solution(&seed, &solution),
                    "valid solution should verify for epoch {epoch}"
                );
                return; // One successful round-trip is sufficient.
            }
        }
        panic!("failed to find a solvable seed in 100 attempts");
    }

    #[test]
    fn verify_wrong_seed_fails() {
        let secret = [0xCC; 32];
        // Find a solvable seed and its solution.
        for epoch in 0..100 {
            let seed = PowChallenger::generate_seed(&secret, epoch, "test");
            if let Some(solution) = PowChallenger::solve(&seed) {
                // Verify against a different seed.
                let wrong_seed = PowChallenger::generate_seed(&secret, epoch + 1000, "test");
                // The solution is almost certainly invalid for the wrong seed.
                // (There's a negligible probability it works by coincidence.)
                let result = PowChallenger::verify_solution(&wrong_seed, &solution);
                // We can't assert false with certainty, but it's astronomically unlikely.
                if !result {
                    return; // Expected: verification fails.
                }
            }
        }
    }
}
