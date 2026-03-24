# Cryptographic Agility

Open Sesame implements config-driven cryptographic algorithm selection
across five independent axes: key derivation (KDF), hierarchical key
derivation (HKDF), Noise IPC transport cipher, Noise IPC transport hash,
and audit log chain hash. Algorithm choices are declared in the
`[crypto]` section of `config.toml` and dispatched at runtime through
typed enum matching. No algorithm is hardcoded at call sites.

## Configuration Schema

The `[crypto]` section of `config.toml` maps to `CryptoConfigToml`
(`core-config/src/schema_crypto.rs:14`), a string-based TOML
representation with six fields:

```toml
[crypto]
kdf = "argon2id"
hkdf = "blake3"
noise_cipher = "chacha-poly"
noise_hash = "blake2s"
audit_hash = "blake3"
minimum_peer_profile = "leading-edge"
```

These defaults are defined in the `Default` implementation
(`schema_crypto.rs:30-38`). At load time,
`CryptoConfigToml::to_typed()` (`schema_crypto.rs:48`) converts the
string values to validated enum variants in `core_types::CryptoConfig`
(`core-types/src/crypto.rs:82`). Unrecognized algorithm names produce a
`core_types::Error::Config` error, preventing the daemon from starting
with an invalid configuration.

## Algorithm Axes

### KDF: Password to Master Key

The KDF converts a user password and 16-byte salt into a 32-byte master
key. Two algorithms are available, selected by the `kdf` config field
and dispatched through `derive_key_kdf()`
(`core-crypto/src/kdf.rs:60-69`).

**argon2id** (default, `KdfAlgorithm::Argon2id`):

- Algorithm: Argon2id (hybrid mode, resists both side-channel and GPU
  attacks)
- Memory cost: 19,456 KiB (19 MiB) (`kdf.rs:28`)
- Time cost: 2 iterations (`kdf.rs:29`)
- Parallelism: 1 lane (`kdf.rs:30`)
- Output: 32 bytes (`kdf.rs:31`)
- Version: 0x13 (`kdf.rs:35`)
- Parameters follow OWASP minimum recommendations (`kdf.rs:14-17`)
- Implementation: `argon2` crate with
  `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)`
  (`kdf.rs:35`)

**pbkdf2-sha256** (`KdfAlgorithm::Pbkdf2Sha256`):

- Algorithm: PBKDF2-HMAC-SHA256
- Iterations: 600,000 (`kdf.rs:51`)
- Output: 32 bytes
- Parameters follow OWASP recommendations for PBKDF2-SHA256
  (`kdf.rs:47`)
- Implementation: `pbkdf2` crate with `Hmac<Sha256>` (`kdf.rs:51`)

Both functions return `SecureBytes` --- mlock'd, zeroize-on-drop memory
backed by `core_memory::ProtectedAlloc`. Intermediate stack arrays are
zeroized via `zeroize::Zeroizing` before the function returns
(`kdf.rs:37`, `kdf.rs:50`).

### HKDF: Master Key to Per-Purpose Keys

The HKDF layer derives per-profile, per-purpose 32-byte keys from the
master key. Two algorithms are available, dispatched through the
`*_with_algorithm()` family of functions in `core-crypto/src/hkdf.rs`.

**blake3** (default, `HkdfAlgorithm::Blake3`):

- Uses BLAKE3's built-in `derive_key` mode, which provides
  extract-then-expand semantics equivalent to HKDF (`hkdf.rs:1-5`)
- Context string format: `"pds v2 <purpose> <profile_id>"`
  (`hkdf.rs:39-41`)
- Domain separation is achieved via BLAKE3's context string parameter,
  which internally derives a context key from the string and uses it to
  key the hash of the input keying material (`hkdf.rs:27-33`)
- Implementation: `blake3::derive_key(context, ikm)` (`hkdf.rs:31`)
- Performance: 5-14x faster than SHA-256 with hardware acceleration via
  AVX2/AVX512/NEON (`hkdf.rs:5`)

**hkdf-sha256** (`HkdfAlgorithm::HkdfSha256`):

- Standard HKDF extract-then-expand per RFC 5869
- Salt: `None` (the IKM serves as both input keying material and
  implicit salt) (`hkdf.rs:121`)
- Info: the context string bytes, providing domain separation
  (`hkdf.rs:123`)
- Output: 32 bytes (`hkdf.rs:122`)
- Implementation: `Hkdf::<Sha256>::new(None, ikm)` followed by
  `hk.expand(context.as_bytes(), &mut key)` (`hkdf.rs:121-124`)
- Intermediate output array is zeroized before return (`hkdf.rs:126`)

The key hierarchy derived through HKDF (`hkdf.rs:7-14`):

```text
User password -> Argon2id -> Master Key (32 bytes)
  -> HKDF "vault-key"          -> per-profile vault key (encrypts SQLCipher DB)
  -> HKDF "clipboard-key"      -> per-profile clipboard key (zeroed on profile deactivation)
  -> HKDF "ipc-auth-token"     -> per-profile IPC authentication token
  -> HKDF "ipc-encryption-key" -> per-profile IPC field encryption key
```

Each purpose has a dedicated public function (`derive_vault_key`,
`derive_clipboard_key`, `derive_ipc_auth_token`,
`derive_ipc_encryption_key`) with a corresponding `*_with_algorithm()`
variant that accepts an `HkdfAlgorithm` parameter. The
algorithm-dispatching variants use a `match` statement to route to the
correct implementation (`hkdf.rs:137-141`).

A key-encrypting-key (KEK) for platform keyring storage is derived
separately via `derive_kek()` (`hkdf.rs:91-101`). The KEK uses the
hardcoded context string `"pds v2 key-encrypting-key"` and concatenates
password + salt as the IKM, ensuring cryptographic independence from the
Argon2id master key derivation path. The concatenated IKM is zeroized
after use (`hkdf.rs:99`).

An extensibility function `derive_key()` (`hkdf.rs:107-110`) accepts an
arbitrary purpose string, allowing new key purposes to be added without
modifying the module. Callers must ensure purpose strings are globally
unique.

### Noise Cipher: IPC Transport Encryption

The Noise IK protocol used for inter-daemon IPC communication supports
two cipher selections via the `noise_cipher` config field:

**chacha-poly** (default, `NoiseCipher::ChaChaPoly`):

- ChaCha20-Poly1305 authenticated encryption
- Constant-time on all architectures without hardware AES
- The leading-edge default for environments where AES-NI is not
  guaranteed

**aes-gcm** (`NoiseCipher::AesGcm`):

- AES-256-GCM authenticated encryption
- Optimal on processors with AES-NI hardware acceleration
- Required for NIST/FedRAMP compliance

The cipher selection is read from config and passed to the Noise
protocol builder at IPC bus initialization. The `NoiseCipher` enum is
defined in `core-types/src/crypto.rs:31-37`.

### Noise Hash: IPC Transport Hash

The Noise protocol hash function is selected via the `noise_hash`
config field:

**blake2s** (default, `NoiseHash::Blake2s`):

- BLAKE2s (256-bit output, optimized for 32-bit and 64-bit platforms)
- Faster than SHA-256 on platforms without SHA extensions
- The leading-edge default

**sha256** (`NoiseHash::Sha256`):

- SHA-256
- Required for NIST/FedRAMP compliance
- Optimal on processors with SHA-NI hardware extensions

The `NoiseHash` enum is defined in `core-types/src/crypto.rs:43-49`.

### Audit Hash: Audit Log Chain Integrity

The audit log uses a hash chain where each entry's hash covers the
previous entry's hash, providing tamper evidence. The hash function is
selected via the `audit_hash` config field:

**blake3** (default, `AuditHash::Blake3`):

- BLAKE3 (256-bit output)
- Hardware-accelerated via AVX2/AVX512/NEON where available
- The leading-edge default

**sha256** (`AuditHash::Sha256`):

- SHA-256
- Required for NIST/FedRAMP compliance

The `AuditHash` enum is defined in `core-types/src/crypto.rs:55-61`.

## At-Rest Encryption

Vault data at rest is encrypted with AES-256-GCM via the
`EncryptionKey` type (`core-crypto/src/encryption.rs:13`). This cipher
is not configurable --- it is always AES-256-GCM regardless of the
`[crypto]` config section. The implementation uses the RustCrypto
`aes-gcm` crate (`encryption.rs:5-6`).

- Key size: 32 bytes (AES-256) (`encryption.rs:24`)
- Nonce size: 12 bytes (`encryption.rs:42`)
- Output: ciphertext with appended 16-byte authentication tag
  (`encryption.rs:37`)
- Decrypted plaintext is returned as `SecureBytes` (mlock'd,
  zeroize-on-drop) (`encryption.rs:61`)
- The `Debug` implementation redacts key material, printing
  `"EncryptionKey([REDACTED])"` (`encryption.rs:66-68`)

Nonce reuse catastrophically breaks both confidentiality and
authenticity. Callers are responsible for ensuring nonce uniqueness per
encryption with the same key (`encryption.rs:36-37`).

## Pre-Defined Crypto Profiles

The `minimum_peer_profile` config field selects a pre-defined algorithm
profile via the `CryptoProfile` enum
(`core-types/src/crypto.rs:67-75`):

**leading-edge** (default, `CryptoProfile::LeadingEdge`):

| Axis | Algorithm |
|------|-----------|
| KDF | Argon2id (19 MiB, 2 iterations) |
| HKDF | BLAKE3 |
| Noise cipher | ChaCha20-Poly1305 |
| Noise hash | BLAKE2s |
| Audit hash | BLAKE3 |

This profile uses modern algorithms that prioritize security margin and
performance on commodity hardware without requiring specific hardware
acceleration.

**governance-compatible** (`CryptoProfile::GovernanceCompatible`):

| Axis | Algorithm |
|------|-----------|
| KDF | PBKDF2-SHA256 (600K iterations) |
| HKDF | HKDF-SHA256 |
| Noise cipher | AES-256-GCM |
| Noise hash | SHA-256 |
| Audit hash | SHA-256 |

This profile uses exclusively NIST-approved algorithms suitable for
environments subject to FedRAMP, FIPS 140-3, or equivalent governance
frameworks.

**custom** (`CryptoProfile::Custom`):

Individual algorithm selection via the per-axis config fields. Allows
mixing algorithms across profiles (e.g., Argon2id KDF with AES-GCM
Noise cipher).

The `minimum_peer_profile` field specifies the minimum cryptographic
profile that the local node will accept from federation peers. A node
configured with `"leading-edge"` will reject connections from peers
advertising a weaker profile. This field is defined in `CryptoConfig`
as `minimum_peer_profile: CryptoProfile`
(`core-types/src/crypto.rs:89`).

## Config-to-Runtime Dispatch

Algorithm selection flows from config to runtime through a three-stage
pipeline:

1. **TOML parsing**: The `[crypto]` section is deserialized into
   `CryptoConfigToml` (`core-config/src/schema_crypto.rs:14`), which
   stores all algorithm names as `String` values.

2. **Validation**: `CryptoConfigToml::to_typed()`
   (`schema_crypto.rs:48`) converts each string to a typed enum variant
   via `match` statements. Unrecognized strings produce an error. The
   result is a `core_types::CryptoConfig` struct with typed fields
   (`core-types/src/crypto.rs:82-90`).

3. **Dispatch**: Runtime code calls algorithm-dispatching functions that
   accept the typed enum and route to the correct implementation. For
   example, `derive_key_kdf()` (`core-crypto/src/kdf.rs:60-69`) matches
   on `KdfAlgorithm`:

    ```rust
    pub fn derive_key_kdf(
        algorithm: &KdfAlgorithm,
        password: &[u8],
        salt: &[u8; 16],
    ) -> core_types::Result<SecureBytes> {
        match algorithm {
            KdfAlgorithm::Argon2id => derive_key_argon2(password, salt),
            KdfAlgorithm::Pbkdf2Sha256 => derive_key_pbkdf2(password, salt),
        }
    }
    ```

    Similarly, `derive_vault_key_with_algorithm()`
    (`core-crypto/src/hkdf.rs:131-141`) matches on `HkdfAlgorithm`:

    ```rust
    pub fn derive_vault_key_with_algorithm(
        algorithm: &HkdfAlgorithm,
        master_key: &[u8],
        profile_id: &str,
    ) -> SecureBytes {
        let ctx = build_context("vault-key", profile_id);
        match algorithm {
            HkdfAlgorithm::Blake3 => derive_32(&ctx, master_key),
            HkdfAlgorithm::HkdfSha256 => derive_32_hkdf_sha256(&ctx, master_key),
        }
    }
    ```

This pattern ensures that adding a new algorithm requires three changes:
add a variant to the `core_types` enum, add a `match` arm in the TOML
validator, and add a `match` arm in the dispatch function. No call sites
need modification.

## FIPS Considerations

Open Sesame does not claim FIPS 140-3 validation. The cryptographic
implementations are provided by RustCrypto crates (`argon2`, `pbkdf2`,
`aes-gcm`, `blake3`, `hkdf`, `sha2`) which have not undergone CMVP
certification.

For deployments subject to FIPS requirements, the
`governance-compatible` profile restricts algorithm selection to
NIST-approved primitives (PBKDF2-SHA256, HKDF-SHA256, AES-256-GCM,
SHA-256). This satisfies the algorithm selection requirement but does
not address the validated module requirement. Organizations requiring a
FIPS-validated cryptographic module would need to replace the RustCrypto
backends with a certified implementation (e.g., AWS-LC, BoringCrypto)
and re-validate.

The `minimum_peer_profile` mechanism provides a policy enforcement
point: setting it to `"governance-compatible"` ensures that no peer in
a federated deployment can negotiate a session using non-NIST
algorithms, even if the local node supports them.

## Memory Protection

All key material derived through the KDF and HKDF paths is returned as
`SecureBytes` (`core-crypto/src/lib.rs:16`), which is backed by
`core_memory::ProtectedAlloc`. This provides:

- Page-aligned allocation with guard pages
- `mlock` to prevent swapping to disk
- Volatile zeroization on drop
- Canary bytes for buffer overflow detection

The `init_secure_memory()` function (`core-crypto/src/lib.rs:29-31`)
must be called before the seccomp sandbox is applied, because it probes
`memfd_secret` availability. After seccomp is active, `memfd_secret`
remains in the allowlist for all sandboxed daemons.
