//! Cryptographic primitives for PDS.
//!
//! Provides AES-256-GCM encryption, Argon2id key derivation, SecureBytes (mlock + zeroize),
//! and EncryptedStore (SQLCipher-backed encrypted journal).
//!
//! # Safety
//!
//! This crate uses `unsafe` for `mlock`/`madvise` syscalls on secret memory pages.
//! All unsafe is documented inline with justification.
