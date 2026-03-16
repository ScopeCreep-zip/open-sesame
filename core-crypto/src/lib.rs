//! Cryptographic primitives for PDS.
//!
//! Provides AES-256-GCM encryption, Argon2id key derivation, and SecureBytes
//! (mlock + zeroize + MADV_DONTDUMP).
//!
//! # Safety
//!
//! This crate uses `unsafe` for `mlock`/`munlock`/`madvise` syscalls on Unix
//! to prevent secret memory pages from being swapped to disk or included in
//! core dumps. All unsafe blocks are documented inline with justification.

mod encryption;
pub mod hkdf;
mod kdf;
mod secure_bytes;
mod secure_vec;

pub use encryption::EncryptionKey;
pub use hkdf::{
    derive_clipboard_key, derive_clipboard_key_with_algorithm, derive_ipc_auth_token,
    derive_ipc_auth_token_with_algorithm, derive_ipc_encryption_key,
    derive_ipc_encryption_key_with_algorithm, derive_kek, derive_key, derive_key_with_algorithm,
    derive_vault_key, derive_vault_key_with_algorithm,
};
pub use kdf::{derive_key_argon2, derive_key_kdf, derive_key_pbkdf2};
pub use secure_bytes::SecureBytes;
pub use secure_vec::SecureVec;
