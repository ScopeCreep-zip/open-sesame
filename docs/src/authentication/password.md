# Password Backend

This page describes the password authentication backend implemented in
`core-auth/src/password.rs` and `core-auth/src/password_wrap.rs`. The backend uses Argon2id to
derive a key-encrypting key (KEK) from user-provided password bytes, then wraps or unwraps a
32-byte master key using AES-256-GCM.

## PasswordBackend

The `PasswordBackend` struct holds an optional `SecureVec` containing password bytes. Password
bytes must be injected via `with_password()` (builder pattern) or `set_password()` (mutation)
before calling `unlock()` or `enroll()`. The `SecureVec` type provides mlock'd memory and
zeroize-on-drop semantics.

### Trait Implementation

| Method | Behavior |
|--------|----------|
| `factor_id()` | Returns `AuthFactorId::Password` |
| `name()` | Returns `"Password"` |
| `backend_id()` | Returns `"password"` |
| `is_enrolled(profile, config_dir)` | Checks whether `{config_dir}/vaults/{profile}.password-wrap` exists |
| `can_unlock(profile, config_dir)` | Returns `true` only if enrolled AND password bytes have been set |
| `requires_interaction()` | Returns `AuthInteraction::PasswordEntry` |

### KEK Derivation

The `derive_kek()` method performs:

1. Validate salt is exactly 16 bytes.
2. Call `core_crypto::derive_key_argon2(password, salt)` -- Argon2id with project-wide
   parameters.
3. Copy the first 32 bytes of the Argon2id output into a `[u8; 32]` KEK array.

The Argon2id parameters are defined in `core-crypto` (not in `core-auth`).

### Unlock Flow

1. Read password bytes from the stored `SecureVec`. Fail with `BackendNotApplicable` if no
   password was set.
2. Load the `PasswordWrapBlob` from `{config_dir}/vaults/{profile}.password-wrap`.
3. Derive the KEK via `derive_kek(password, salt)`.
4. Call `blob.unwrap(&mut kek)` to decrypt the master key via AES-256-GCM. The KEK is
   zeroized after use.
5. Return an `UnlockOutcome` with `ipc_strategy: DirectMasterKey` and
   `factor_id: Password`.

### Enrollment Flow

1. Read password bytes from the stored `SecureVec`.
2. Derive the KEK via `derive_kek(password, salt)`.
3. Call `PasswordWrapBlob::wrap(master_key, &mut kek)` to encrypt the master key. The KEK is
   zeroized after use.
4. Write the blob to disk via `blob.save(config_dir, profile)`.

### Revocation

Revocation overwrites the wrap file with zeros before deletion to prevent casual recovery
from disk:

1. Read the file length.
2. Write a zero-filled buffer of the same length.
3. Delete the file via `std::fs::remove_file`.

## PasswordWrapBlob

Defined in `core-auth/src/password_wrap.rs`, the `PasswordWrapBlob` struct represents the
on-disk binary format for the AES-256-GCM wrapped master key.

### Binary Format

```text
Offset  Length  Field
0       1       Version byte (0x01)
1       12      Nonce (random, generated via getrandom)
13      48      Ciphertext (32-byte master key + 16-byte GCM tag)
```

Total size: 61 bytes.

The version constant `PASSWORD_WRAP_VERSION` is `0x01`.

### Wrapping (Encryption)

`PasswordWrapBlob::wrap(master_key, kek_bytes)`:

1. Construct an `EncryptionKey` from the 32-byte KEK.
2. Generate a 12-byte random nonce via `getrandom`.
3. Encrypt the master key with AES-256-GCM using the KEK and nonce.
4. Zeroize the KEK bytes.
5. Return the blob containing version, nonce, and ciphertext.

### Unwrapping (Decryption)

`PasswordWrapBlob::unwrap(kek_bytes)`:

1. Construct an `EncryptionKey` from the 32-byte KEK.
2. Zeroize the KEK bytes immediately after key construction.
3. Decrypt using AES-256-GCM with the stored nonce and ciphertext.
4. Return the plaintext as `SecureBytes` (mlock'd, zeroize-on-drop).
5. If GCM authentication fails (wrong password), return `AuthError::UnwrapFailed`.

### Deserialization

`PasswordWrapBlob::deserialize(data)` rejects:

- Data shorter than 61 bytes (`AuthError::InvalidBlob`).
- Version bytes other than `0x01` (`AuthError::InvalidBlob`).

### Persistence

**Path**: `{config_dir}/vaults/{profile}.password-wrap`

**Write**: `save()` uses atomic rename via a `.password-wrap.tmp` intermediate file. On Unix,
file permissions are set to `0o600` (owner read/write only) before the rename. The parent
`vaults/` directory is created if it does not exist.

**Read**: `load()` reads the file and calls `deserialize()`.

### Zeroization

The `PasswordWrapBlob` struct implements `Drop` to zeroize its `nonce` and `ciphertext`
fields. All KEK arrays are zeroized immediately after use in both `wrap()` and `unwrap()`.

## Salt

Each profile has an independent 16-byte salt stored at `{config_dir}/vaults/{profile}.salt`.
The salt is generated via `getrandom` during vault initialization
(`daemon-secrets/src/unlock.rs::generate_profile_salt`).

During `sesame init`, the salt file is written with:

- The `vaults/` directory created with permissions `0o700`.
- The salt file itself written via `core_config::atomic_write` and then set to
  permissions `0o600`.

The salt is used as input to both the Argon2id KDF (password backend) and the BLAKE3
challenge derivation (SSH agent backend). Using a per-profile salt ensures that the same
password produces different KEKs for different profiles.

## Key Material Handling

The password backend's key material lifecycle:

1. **Password bytes**: Stored in `SecureVec` (mlock'd, zeroize-on-drop). Acquired from the
   user via `dialoguer::Password` (terminal) or stdin (pipe). The `String` holding the raw
   password is zeroized immediately after copying into the `SecureVec`.

2. **KEK (Argon2id output)**: A `[u8; 32]` stack array. Zeroized by
   `PasswordWrapBlob::wrap()` and `PasswordWrapBlob::unwrap()` after use.

3. **Master key**: Returned as `SecureBytes` (backed by `ProtectedAlloc` -- mlock'd,
   mprotect'd, zeroize-on-drop). Transferred to daemon-secrets via `SensitiveBytes` IPC
   wrapper which also uses `ProtectedAlloc`.

At no point does the master key exist in an unprotected heap allocation. The KEK exists
briefly on the stack and is zeroized before the function returns.
