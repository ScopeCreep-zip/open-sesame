//! Secret storage abstraction over platform keystores and age-encrypted vaults.
//!
//! Provides a unified `SecretsStore` trait for secret CRUD across Linux
//! (Secret Service D-Bus), macOS (Keychain), Windows (Credential Manager),
//! 1Password CLI integration, and an age-encrypted fallback.
#![forbid(unsafe_code)]
