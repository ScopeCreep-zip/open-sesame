//! Cryptographic primitives for PDS.
//!
//! Provides AES-256-GCM encryption, Argon2id key derivation, `SecureBytes`
//! and `SecureVec` — all backed by page-aligned guard-page-protected memory
//! via `core_memory::ProtectedAlloc`.
//!
//! This crate contains no `unsafe` code. All memory protection (mmap, mlock,
//! mprotect, guard pages, canary, volatile zeroize) is delegated to `core-memory`.

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

/// Initialize the secure memory subsystem. Must be called before seccomp
/// sandbox is applied. See [`core_memory::init`] for details.
pub fn init_secure_memory() {
    core_memory::init();
}
