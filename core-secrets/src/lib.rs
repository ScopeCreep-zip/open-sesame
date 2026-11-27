//! Encrypted secret storage.
//!
//! Architecture (ADR-SEC-002):
//! - Individual secrets stored in an encrypted local store (`SQLCipher` via rusqlite)
//! - Cross-profile isolation is cryptographic: a different vault key per
//!   profile, not namespace-based
//!
//! Key hierarchy, every derivation under the vault's `hkdf`
//! (`core_crypto::derive_key`):
//!   master key (unwrapped by an enrolled factor) → per-profile vault key
//!   (`SQLCipher` page key) → per-entry AES-256-GCM key
//!
//! This crate contains NO platform-specific code.
#![forbid(unsafe_code)]

#[cfg(test)]
mod compliance;
mod jit;
mod sqlcipher;
mod store;

pub use jit::JitDelivery;
pub use sqlcipher::SqlCipherStore;
pub use store::SecretsStore;
