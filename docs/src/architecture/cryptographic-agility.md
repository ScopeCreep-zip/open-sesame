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

### KDF: Password to Password KEK

The KDF converts a user password and the vault's 16-byte salt into the
vault's password key-encrypting key (KEK), the AES-256-GCM key that wraps
the vault's master key (`WrappedKey` in `.password-wrap`). Two algorithms are
available; `derive_password_key(algorithm, password, salt)`
(`core-crypto/src/kdf.rs`) dispatches on the vault's `KdfAlgorithm`.

**argon2id** (default, `KdfAlgorithm::Argon2id`):

- Algorithm: Argon2id v1.3 (hybrid mode, resists both side-channel and
  GPU attacks)
- Memory cost: 19,456 KiB (19 MiB)
- Time cost: 2 iterations
- Parallelism: 1 lane
- Output: 32 bytes
- Parameters follow the OWASP minimum recommendation
- Implementation: `argon2` crate,
  `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)` with
  `hash_password_into`

**pbkdf2-sha256** (`KdfAlgorithm::Pbkdf2Sha256`):

- Algorithm: PBKDF2-HMAC-SHA256 (RFC 8018)
- Iterations: 600,000 (OWASP recommendation)
- Output: 32 bytes
- Implementation: `pbkdf2::pbkdf2_hmac::<Sha256>`

The derived bytes are held in `zeroize::Zeroizing` and returned as an
`EncryptionKey`.

### HKDF: Key Material to Per-Purpose Keys

Every other 32-byte key is derived from key material (a master key, a
vault key, a salt, a signature, or factor pieces) by
`derive_key(algorithm, context, ikm)` or, for a key that only encrypts,
`derive_encryption_key` (`core-crypto/src/derive.rs`), under the vault's
`HkdfAlgorithm`.

**blake3** (default, `HkdfAlgorithm::Blake3`):

- BLAKE3's `derive_key` mode with the context string, which provides
  extract-then-expand semantics equivalent to HKDF
- Implementation: `blake3::derive_key(context, ikm)`

**hkdf-sha256** (`HkdfAlgorithm::HkdfSha256`):

- HKDF extract-then-expand per RFC 5869, no salt, the context string as
  `info`, 32 bytes of output
- Implementation: `Hkdf::<Sha256>::new(None, ikm)` and
  `expand(context.as_bytes(), &mut key)`

The context is a `KeyContext`, one variant per purpose; its string is
`"pds v2 <purpose>"`, followed by the profile for a per-profile purpose:

| `KeyContext` | Context string | Derived from | Key |
| --- | --- | --- | --- |
| `Vault(profile)` | `pds v2 vault-key <profile>` | Master key | `SQLCipher` page key |
| `IpcEncryption(profile)` | `pds v2 ipc-encryption-key <profile>` | Master key | Per-field IPC encryption key |
| `CombinedMasterKey(profile)` | `pds v2 combined-master-key <profile>` | Factor pieces | Master key of an `All`-policy vault |
| `SshChallenge(profile)` | `pds v2 ssh-challenge <profile>` | Vault salt | Challenge the SSH agent signs |
| `SshVaultKek(profile)` | `pds v2 ssh-vault-kek <profile>` | Challenge signature | KEK of the SSH enrollment |
| `SqlCipherEntry` | `pds v2 entry-encryption-key` | Page key | Per-entry AES-256-GCM key |

New purposes are new `KeyContext` variants, so every context string is
declared in one place and none can collide. Intermediate key bytes are
held in `zeroize::Zeroizing`; `derive_key` returns `SecureBytes`.

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

Key wrapping and per-entry vault encryption use AES-256-GCM via the
`EncryptionKey` type (`core-crypto/src/encryption.rs`). This cipher is
not configurable --- it is always AES-256-GCM regardless of the
`[crypto]` config section. The implementation uses the RustCrypto
`aes-gcm` crate.

- Key size: 32 bytes (AES-256)
- Nonce size: 12 bytes (`NONCE_LEN`)
- Output: ciphertext with appended 16-byte authentication tag
  (`TAG_LEN`)
- Decrypted plaintext is returned as `SecureBytes` (mlock'd,
  zeroize-on-drop)
- The `Debug` implementation redacts key material, printing
  `"EncryptionKey([REDACTED])"`

Nonce reuse catastrophically breaks both confidentiality and
authenticity. `EncryptionKey::seal` is the one random-nonce path: it
draws a fresh nonce from the OS random source (`random_bytes`) for every
encryption. `seal_wire` returns `nonce || ciphertext || tag` in one
buffer and `open_wire` decrypts it.

## Pre-Defined Crypto Profiles

The `minimum_peer_profile` config field selects a pre-defined algorithm
profile via the `CryptoProfile` enum
(`core-types/src/crypto.rs:67-75`):

**leading-edge** (default, `CryptoProfile::LeadingEdge`):

| Axis | Algorithm |
| --- | --- |
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
| --- | --- |
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

The `minimum_peer_profile` field names the minimum cryptographic
profile a node is to accept from federation peers. It is parsed and
validated into `CryptoConfig::minimum_peer_profile: CryptoProfile`
(`core-types/src/crypto.rs`), but nothing reads it yet: federation is
not implemented, so no peer connection is checked against it.

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

3. **Dispatch**: one function per axis takes the typed enum and matches
   on it. `derive_password_key(algorithm, password, salt)`
   (`core-crypto/src/kdf.rs`) matches on `KdfAlgorithm`, and every key
   derived from key material goes through the one `match` on
   `HkdfAlgorithm` in `core-crypto/src/derive.rs`:

    ```rust
    fn derive(algorithm: HkdfAlgorithm, context: &KeyContext<'_>, ikm: &[u8]) -> Zeroizing<[u8; 32]> {
        let context = context.string();
        match algorithm {
            HkdfAlgorithm::Blake3 => Zeroizing::new(blake3::derive_key(&context, ikm)),
            HkdfAlgorithm::HkdfSha256 => {
                let mut key = Zeroizing::new([0u8; 32]);
                hkdf::Hkdf::<sha2::Sha256>::new(None, ikm)
                    .expand(context.as_bytes(), &mut *key)
                    .expect("32 bytes is within the HKDF-SHA256 output limit of 8160");
                key
            }
        }
    }
    ```

Adding a new algorithm therefore requires three changes: a variant in the
`core_types` enum, a `match` arm in the TOML validator, and a `match`
arm in the dispatch function. No call sites need modification.

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

`minimum_peer_profile` is the intended enforcement point for peers:
set to `"governance-compatible"`, it is to refuse a federation session
using non-NIST algorithms. It enforces nothing until federation
exists; today the local `[crypto]` axes are the whole policy.

## Memory Protection

Key material derived through `derive_key` is returned as `SecureBytes`
(`core-crypto/src/secure_bytes.rs`), and decrypted plaintext likewise;
`SecureBytes` is backed by `core_memory::ProtectedAlloc`. This provides:

- Page-aligned allocation with guard pages
- `mlock` to prevent swapping to disk
- Volatile zeroization on drop
- Canary bytes for buffer overflow detection

The `core_types::init_secure_memory()` function (`core-types/src/lib.rs`) must be
called before the seccomp sandbox is applied, because it probes
`memfd_secret` availability. After seccomp is active, `memfd_secret`
remains in the allowlist for all sandboxed daemons.
