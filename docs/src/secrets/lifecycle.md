# Secret Lifecycle

This page describes how secrets move through the system: from storage in an encrypted vault,
through a JIT cache, across the IPC bus, and into a child process's environment. It also covers
key material lifecycle and the compliance testing framework.

## Secret Storage Operations

The `SecretsStore` trait (`core-secrets/src/store.rs`) defines four operations that every storage
backend must implement:

| Operation | Behavior |
|---|---|
| `get(key)` | Retrieve a secret by key. Returns an error if the key does not exist. |
| `set(key, value)` | Store a secret. Overwrites if the key already exists. Updates `updated_at`; sets `created_at` on first insert. |
| `delete(key)` | Delete a secret by key. Returns an error if the key does not exist. |
| `list_keys()` | List all key names in the store. Values are not returned (no bulk decryption). |

The `list_keys` method intentionally avoids returning values. Listing secrets does not trigger
bulk decryption of every entry, limiting the window during which plaintext exists in memory.

Two implementations exist:

- **`SqlCipherStore`** (`core-secrets/src/sqlcipher.rs`): Production backend. Each `set`
  encrypts the value with per-entry AES-256-GCM before writing to the database. Each `get`
  decrypts after reading. The `Mutex<Connection>` serializes all database access.
- **`InMemoryStore`** (`core-secrets/src/store.rs`): Testing backend. Holds secrets in a
  `HashMap<String, SecureBytes>` protected by a `tokio::sync::RwLock`. Values are stored as
  `SecureBytes` (mlock'd, zeroize-on-drop). Does not persist to disk.

## JIT Cache

The `JitDelivery<S>` wrapper (`core-secrets/src/jit.rs`) adds a time-limited in-memory cache in
front of any `SecretsStore` implementation. It exists to avoid repeated SQLCipher decryption for
frequently accessed secrets.

### Resolution

`JitDelivery::resolve(key)` checks the cache first. If a valid (non-expired) entry exists, the
cached `SecureBytes` clone is returned without touching the underlying store. If the entry is
missing or expired, the value is fetched from the store, cached, and returned.

Both the cache entry and the returned value are independent `SecureBytes` clones. Each
independently zeroizes on drop.

### TTL Expiry

Each cache entry records its `fetched_at` timestamp as a `std::time::Instant`. On the next
`resolve` call, if `fetched_at.elapsed() >= ttl`, the cached value is considered expired and a
fresh fetch occurs. The default TTL is 300 seconds, configurable via the daemon's `--ttl` flag
or `PDS_SECRET_TTL` environment variable.

The `ttl_expiry_refetches` test verifies that after TTL expiry, the underlying store is
re-queried and updated values are returned.

### Flush on Lock

`JitDelivery::flush()` clears the entire cache by calling `cache.clear()`. Because each value
in the cache is a `SecureBytes`, dropping the `HashMap` entries triggers zeroization of all
cached secret material. Flush is called during profile deactivation and locking, before the
vault is closed and key material is destroyed.

The `flush_clears_cache` test verifies that after a flush, the next `resolve` call fetches
fresh data from the underlying store.

### Store Bypass

`JitDelivery::store()` provides direct access to the underlying `SecretsStore`, bypassing the
cache. This is used for write operations (`set`, `delete`, `list_keys`) which should not
interact with the read cache. After a `set` or `delete`, the daemon calls
`vault.flush().await` to invalidate any stale cache entries.

## Key Material Lifecycle

All key material in the secrets subsystem is held in `SecureBytes` (`core-crypto`), which
provides:

- **mlock**: The backing memory is locked to prevent swapping to disk. On Linux, this uses
  `memfd_secret` with guard pages when available.
- **Zeroize on drop**: When a `SecureBytes` value is dropped, its backing memory is overwritten
  with zeros before deallocation. This is implemented via the `zeroize` crate's `Zeroize` trait.
- **Clone independence**: Cloning a `SecureBytes` value creates a new mlock'd allocation.
  Dropping the clone does not affect the original, and vice versa.

The lifecycle of key material through the system:

1. **Derivation**: The master key is derived via Argon2id from the user's password and a
   per-profile 16-byte salt (`derive_master_key()` in `daemon-secrets/src/unlock.rs`, which
   delegates to `core_crypto::derive_key_argon2()`). The result is a 32-byte `SecureBytes`
   value.
2. **Storage**: The master key is stored in `VaultState::master_keys`
   (`daemon-secrets/src/vault.rs`), a `HashMap<TrustProfileName, SecureBytes>`.
3. **Derivation (vault key)**: On first vault access, `core_crypto::derive_vault_key()` derives
   a 32-byte vault key from the master key via BLAKE3. The intermediate stack array is wrapped
   in `zeroize::Zeroizing` and zeroized on scope exit.
4. **Use**: The vault key is passed to `SqlCipherStore::open()`, which uses it for `PRAGMA key`
   and derives the entry key. The vault key is not retained by the store after open completes.
5. **Destruction**: On lock or deactivation, the JIT cache is flushed (zeroizing cached
   secrets), `pragma_rekey_clear()` scrubs the C-level key buffer, the `SqlCipherStore` is
   dropped (zeroizing the entry key), and the master key is removed from the map (zeroizing
   on drop).

## Field-Level IPC Encryption

When the `ipc-field-encryption` feature is enabled, secret values are encrypted with AES-256-GCM
before being placed on the IPC bus, providing a second encryption layer on top of the Noise IK
transport.

The per-profile IPC encryption key is derived via
`core_crypto::derive_ipc_encryption_key(master_key, profile_id)` using the context string
`"pds v2 ipc-encryption-key {profile_id}"`. The wire format is
`[12-byte random nonce][AES-256-GCM ciphertext + tag]`.

This feature is gated behind `ipc-field-encryption` and disabled by default for the following
reasons, documented in `daemon-secrets/src/vault.rs`:

- The Noise IK transport is already the security boundary, matching the precedent set by
  ssh-agent, 1Password, Vault, and gpg-agent.
- CLI clients lack the master key needed to decrypt per-field encrypted values.
- The per-field key derives from the same master key that transits inside the Noise channel,
  so it is not an independent trust root.

When enabled, the encryption path in `handle_secret_get` (`daemon-secrets/src/crud.rs`) encrypts
values before sending the `SecretGetResponse`, and the decryption path in `handle_secret_set`
decrypts incoming values before writing to the vault. The decrypted intermediate `Vec<u8>` is
explicitly zeroized after the store write completes.

## Compliance Testing

The `compliance_tests()` function (`core-secrets/src/compliance.rs`) defines a portable test
suite that every `SecretsStore` implementation must pass. The suite verifies:

| Test case | Assertion |
|---|---|
| Set and get | A stored value is retrievable with identical bytes. |
| Overwrite | Storing to an existing key replaces the value. |
| Get nonexistent | Retrieving a key that does not exist returns an error. |
| Delete | A deleted key is no longer retrievable. |
| Delete nonexistent | Deleting a key that does not exist returns an error. |
| List keys | All stored key names appear in the list. |
| Cleanup | After deleting all keys, the list is empty. |

The `in_memory_store_passes_compliance` test runs this suite against `InMemoryStore`. The
SQLCipher backend has its own compliance tests in `core-secrets/src/sqlcipher.rs` that
additionally verify encryption properties (no plaintext on disk, cross-profile isolation, nonce
uniqueness).

## Six-Gate Security Pipeline

Every secret CRUD operation passes through a six-gate security pipeline in
`daemon-secrets/src/crud.rs` before the vault is accessed. The gates execute in order from
cheapest to most expensive:

1. **Lock check**: Rejects the request if no profiles are unlocked (`master_keys` is empty).
2. **Active profile check**: Rejects if the requested profile is not in the `active_profiles`
   set.
3. **Identity check**: Logs the requester's `verified_sender_name` (stamped by the IPC bus
   server from the Noise IK registry). Expected requesters are `daemon-secrets`,
   `daemon-launcher`, or `None` (CLI relay).
4. **Rate limit check**: Applies per-requester token bucket rate limiting.
5. **ACL check**: Evaluates per-daemon per-key access control rules from config.
5.5. **Key validation**: Validates the secret key name via
   `core_types::validate_secret_key()`.
6. **Vault access**: Opens (or retrieves) the vault and performs the requested operation.

Each gate that denies a request emits both a structured `tracing` log entry and a
`SecretOperationAudit` IPC event (fire-and-forget to daemon-profile for persistent audit
logging). The denial response is sent immediately and processing stops.
