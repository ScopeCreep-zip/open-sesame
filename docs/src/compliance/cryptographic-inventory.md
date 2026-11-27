# Cryptographic Inventory

This page provides an exhaustive inventory of every cryptographic algorithm used in Open
Sesame, where it is used, the key sizes and parameters, and the relevant standards references.

## Algorithm Summary

| Algorithm | Purpose | Key Size | Standard | Crate |
| --- | --- | --- | --- | --- |
| Argon2id | Password -> password KEK | 32 bytes output | RFC 9106 | `core-crypto` (kdf.rs) |
| PBKDF2-SHA256 | Password -> password KEK (governance-compatible) | 32 bytes output | NIST SP 800-132, RFC 8018 | `core-crypto` (kdf.rs) |
| BLAKE3 derive_key | Key material -> per-purpose keys | 32 bytes output | BLAKE3 spec (domain-separated KDF mode) | `core-crypto` (derive.rs) |
| HKDF-SHA256 | Key material -> per-purpose keys (governance-compatible) | 32 bytes output | RFC 5869, NIST SP 800-56C | `core-crypto` (derive.rs) |
| AES-256-GCM | Key wrapping (WrappedKey, EnrollmentBlob), per-entry vault encryption | 256-bit key | NIST SP 800-38D, FIPS 197 | `core-crypto` (encryption.rs) |
| OS random source | Platform keyring KEK (256-bit), salts, nonces | 32 bytes (KEK) | `getrandom(2)` | `core-crypto` (random.rs) |
| AES-256-CBC + HMAC-SHA512 | SQLCipher page encryption | 256-bit key (encrypt) + 512-bit key (MAC) | FIPS 197, FIPS 198-1 | SQLCipher (via `rusqlite`) |
| X25519 | Noise IK key agreement | 256-bit (32 bytes) | RFC 7748 | `snow` (via `core-ipc`) |
| ChaChaPoly | Noise IK transport encryption (default) | 256-bit key | RFC 7539 | `snow` (via `core-ipc`) |
| BLAKE2s | Noise IK hashing (default) | 256-bit output | RFC 7693 | `snow` (via `core-ipc`) |
| AES-256-GCM (Noise) | Noise IK transport encryption (governance-compatible) | 256-bit key | NIST SP 800-38D | `snow` (via `core-ipc`) |
| SHA-256 (Noise) | Noise IK hashing (governance-compatible) | 256-bit output | FIPS 180-4 | `snow` (via `core-ipc`) |
| BLAKE3 | Audit log hash chain (default) | 256-bit output | BLAKE3 spec | `core-profile` |
| SHA-256 | Audit log hash chain (governance-compatible) | 256-bit output | FIPS 180-4 | `core-profile` |
| Ed25519 | Delegation grant signatures | 256-bit key (32 bytes) | RFC 8032 | `core-types` (security.rs) |

## Argon2id

**Standard:** RFC 9106

**Purpose:** Derives the password key-encrypting key (KEK), which wraps the vault's master
key, from a user-supplied password and the vault's salt. Used by the `Password`
authentication factor (`AuthFactorId::Password` in `core-types/src/auth.rs`).

**Parameters:**

| Parameter | Value | Rationale |
| --- | --- | --- |
| Memory | 19 MiB (19,456 KiB) | Memory-hard to resist GPU/ASIC attacks |
| Iterations | 2 | Balanced with memory cost for interactive use |
| Parallelism | 1 | Single-threaded derivation |
| Output | 32 bytes | 256-bit AES-256-GCM KEK |
| Salt | 16 bytes, per-profile, random | Unique per vault |

**Implementation:** `core-crypto/src/kdf.rs`, function `derive_password_key` with
`KdfAlgorithm::Argon2id`.

**Known residual:** The Argon2id working memory (19 MiB) resides on the unprotected heap
during derivation. This is an upstream limitation of the `argon2` crate. See GitHub
issue #14.

## BLAKE3 Key Derivation

**Standard:** BLAKE3 specification, KDF mode

**Purpose:** Derives per-purpose keys from key material (a master key, a vault key, a salt, a
signature, or factor pieces) using domain-separated context strings. Every context string is
declared once, as a `KeyContext` variant in `core-crypto/src/derive.rs`.

**Context strings used in the system:**

| Context String | Purpose | Derived From |
| --- | --- | --- |
| `"pds v2 vault-key {profile}"` | SQLCipher page key | Master key |
| `"pds v2 ipc-encryption-key {profile}"` | IPC field encryption key | Master key |
| `"pds v2 combined-master-key {profile}"` | Master key of an `All`-policy vault | Factor pieces |
| `"pds v2 ssh-challenge {profile}"` | Challenge the SSH agent signs | Vault salt |
| `"pds v2 ssh-vault-kek {profile}"` | KEK of the SSH enrollment | Challenge signature |
| `"pds v2 entry-encryption-key"` | Per-entry AES-256-GCM key | SQLCipher page key |

**Implementation:** `core-crypto/src/derive.rs`, functions `derive_key` and
`derive_encryption_key`, under the vault's `HkdfAlgorithm` (`blake3::derive_key` for BLAKE3).

BLAKE3's KDF mode internally derives a context key from the context string, then uses it as
keying material with extract-then-expand semantics equivalent to HKDF.

## HKDF-SHA256

**Standard:** RFC 5869, NIST SP 800-56C

**Purpose:** Governance-compatible alternative to BLAKE3 key derivation. Used when
`CryptoConfigToml.hkdf = "hkdf-sha256"` (`core-config/src/schema_crypto.rs`).

**Implementation:** `core-crypto/src/derive.rs`, the `HkdfAlgorithm::HkdfSha256` arm of the
derivation. Uses the `hkdf` crate with `sha2::Sha256`.

The same context strings listed above for BLAKE3 are used as the HKDF info parameter. No salt
is given (RFC 5869 then uses a zero-filled salt). Output is 32 bytes.

## AES-256-GCM (Key Wrapping)

**Standard:** NIST SP 800-38D, FIPS 197

**Purpose:** Wraps and unwraps the master key under a key-encryption key (KEK) derived from
an authentication factor.

**Used in:**

- `WrappedKey` (`core-auth/src/wrapped_key.rs`) -- the master key wrapped under a KEK, in
  two vault files:
  - `<profile>.password-wrap`: under the password KEK (the vault's password KDF, Argon2id or
    PBKDF2-SHA256);
  - `<profile>.keyring-enrollment`: under a random 256-bit KEK held in the platform
    credential store (the Secret Service on Linux).
- `EnrollmentBlob` (`<profile>.ssh-enrollment`) -- the master key wrapped under the KEK
  derived from the SSH agent's challenge signature.

**Parameters:**

| Parameter | Value |
| --- | --- |
| Key size | 256 bits (32 bytes) |
| Nonce | 96 bits (12 bytes), random per encryption (`EncryptionKey::seal`) |
| Tag | 128 bits (16 bytes) |

## AES-256-CBC + HMAC-SHA512 (SQLCipher)

**Standard:** FIPS 197 (AES), FIPS 198-1 (HMAC), FIPS 180-4 (SHA-512)

**Purpose:** SQLCipher page-level encryption for vault databases. Each page in the SQLite
database is independently encrypted and authenticated.

**Parameters:**

| Parameter | Value |
| --- | --- |
| Encryption | AES-256-CBC per page |
| Authentication | HMAC-SHA512 per page |
| Key derivation | Per-page key from vault key via SQLCipher's internal KDF |
| Page size | 4096 bytes (SQLCipher default) |
| KDF iterations | Controlled by SQLCipher; the vault key itself is pre-derived via Argon2id + BLAKE3 |

**Implementation:** SQLCipher via the `rusqlite` crate with the `bundled-sqlcipher` feature.

## Noise IK (IPC Transport)

**Standard:** Noise Protocol Framework (noiseprotocol.org), pattern IK

**Purpose:** All inter-daemon communication on the IPC bus. Provides mutual authentication,
encryption, and forward secrecy.

**Pattern:** IK (Initiator knows responder's static key)

**Default cipher suite:** `Noise_IK_25519_ChaChaPoly_BLAKE2s`

| Component | Default (LeadingEdge) | Governance-Compatible |
| --- | --- | --- |
| Key agreement | X25519 (RFC 7748) | X25519 (RFC 7748) |
| Cipher | ChaChaPoly (RFC 7539) | AES-256-GCM (NIST SP 800-38D) |
| Hash | BLAKE2s (RFC 7693) | SHA-256 (FIPS 180-4) |

**Additional binding:** The UCred (pid, uid, gid) of the connecting process is bound into
the Noise prologue, preventing a process from impersonating another process's Noise session.

**Implementation:** `core-ipc`, using the `snow` crate. Cipher suite selection is configured
via `CryptoConfigToml.noise_cipher` and `CryptoConfigToml.noise_hash` in
`core-config/src/schema_crypto.rs`.

## Ed25519 (Delegation Signatures)

**Standard:** RFC 8032

**Purpose:** Signs `DelegationGrant` structs to prevent tampering with capability
delegations. The 64-byte signature is stored in `DelegationGrant.signature`
(`core-types/src/security.rs`).

**Key size:** 256-bit private key, 256-bit public key.

## FIPS Path

The following table summarizes FIPS 140 validation status for each algorithm:

| Algorithm | FIPS-Validated Implementations Available | Open Sesame Profile |
| --- | --- | --- |
| Argon2id | No FIPS 140 validation exists | LeadingEdge only |
| PBKDF2-SHA256 | Yes (multiple vendors) | GovernanceCompatible |
| BLAKE3 | No FIPS 140 validation exists | LeadingEdge only |
| HKDF-SHA256 | Yes (via HMAC-SHA256) | GovernanceCompatible |
| AES-256-GCM | Yes (multiple vendors) | Both profiles |
| AES-256-CBC | Yes (multiple vendors) | Both profiles (SQLCipher) |
| HMAC-SHA512 | Yes (multiple vendors) | Both profiles (SQLCipher) |
| X25519 | Partial (some FIPS modules include it) | Both profiles |
| ChaChaPoly | No FIPS 140 validation exists | LeadingEdge only |
| AES-256-GCM (Noise) | Yes (multiple vendors) | GovernanceCompatible |
| BLAKE2s | No FIPS 140 validation exists | LeadingEdge only |
| SHA-256 | Yes (multiple vendors) | GovernanceCompatible |
| Ed25519 | Partial (some FIPS modules include it) | Both profiles |

For deployments requiring full FIPS 140 compliance, set the crypto profile to
`governance-compatible`:

```toml
[crypto]
kdf = "pbkdf2-sha256"
hkdf = "hkdf-sha256"
noise_cipher = "aes-gcm"
noise_hash = "sha256"
audit_hash = "sha256"
minimum_peer_profile = "governance-compatible"
```

This configuration uses only algorithms with widely available FIPS 140-validated
implementations. Open Sesame itself is not a FIPS-validated module; the FIPS boundary is
at the cryptographic library level.

## Crypto Agility

All cryptographic algorithm selections are config-driven via `CryptoConfigToml`
(`core-config/src/schema_crypto.rs`). The `to_typed()` method converts string-based
configuration into validated `CryptoConfig` enum variants.

Adding a new algorithm requires:

1. Adding a variant to the relevant enum in `core-types/src/crypto.rs`
   (e.g., `KdfAlgorithm::Scrypt`).
2. Adding the string mapping in `core-config/src/schema_crypto.rs`.
3. Implementing the algorithm in the corresponding `core-crypto` function.

The `minimum_peer_profile` field in `CryptoConfig` is the floor an installation is to
accept from federation peers. It is parsed and validated but read by nothing: federation is
not implemented, so it constrains no connection today.

## PBKDF2-SHA256

**Standard:** NIST SP 800-132, RFC 8018

**Purpose:** Governance-compatible alternative to Argon2id for password-based key derivation.
Used when `CryptoConfigToml.kdf = "pbkdf2-sha256"`.

**Parameters:**

| Parameter | Value |
| --- | --- |
| Hash | SHA-256 |
| Iterations | 600,000 |
| Output | 32 bytes |
| Salt | 16 bytes, per-profile, random |

**Implementation:** `core-crypto/src/kdf.rs`, function `derive_password_key` with
`KdfAlgorithm::Pbkdf2Sha256`.

PBKDF2-SHA256 provides FIPS 140 compliance for the KDF layer but is significantly less
resistant to GPU/ASIC attacks than Argon2id due to its lack of memory-hardness. It should
be selected only when FIPS compliance is a hard requirement.
