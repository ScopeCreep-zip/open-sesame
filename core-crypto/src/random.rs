//! The operating system's random source: the one entry point every key,
//! salt, and nonce in PDS is drawn from. (`core-memory`, below this crate,
//! draws its allocation canary from the same source directly.)

/// `N` bytes from the operating system's random source (`getrandom(2)` on
/// Linux, which blocks until the entropy pool is initialized).
///
/// # Errors
///
/// `core_types::Error::Crypto` naming the OS failure when the source cannot
/// supply the bytes.
pub fn random_bytes<const N: usize>() -> core_types::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|e| core_types::Error::Crypto(format!("OS random source failed: {e}")))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_differ() {
        let a: [u8; 32] = random_bytes().unwrap();
        let b: [u8; 32] = random_bytes().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
