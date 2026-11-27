//! Cryptographic primitives for PDS.
//!
//! Provides AES-256-GCM encryption (with [`EncryptionKey::seal`], the one
//! random-nonce path), password-based key derivation
//! ([`derive_password_key`]), key derivation from key material
//! ([`derive_key`], [`derive_encryption_key`]), the OS random source
//! ([`random_bytes`]), `SecureBytes`
//! and `SecureVec` — all backed by page-aligned guard-page-protected memory
//! via `core_memory::ProtectedAlloc`.
//!
//! This crate contains no `unsafe` code. All memory protection (mmap, mlock,
//! mprotect, guard pages, canary, volatile zeroize) is delegated to `core-memory`.
#![forbid(unsafe_code)]

mod derive;
mod encryption;
mod kdf;
mod random;
mod secure_bytes;
mod secure_vec;

pub use derive::{KeyContext, derive_encryption_key, derive_key};
pub use encryption::{EncryptionKey, NONCE_LEN, TAG_LEN};
pub use kdf::derive_password_key;
pub use random::random_bytes;
pub use secure_bytes::SecureBytes;
pub use secure_vec::SecureVec;
