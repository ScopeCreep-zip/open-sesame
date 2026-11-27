# Password Backend

This page describes the password authentication backend, `PasswordBackend` in
`core-auth/src/password.rs`. It derives a key-encrypting key (KEK) from the vault password
under the vault's password KDF, and wraps or unwraps the vault's 32-byte master key with
AES-256-GCM in the vault's `.password-wrap` file.

## PasswordBackend

`PasswordBackend` holds an optional `SecureVec` with the password bytes (mlock'd,
zeroize-on-drop). The bytes are injected with `with_password()` before `unlock()` or
`enroll()`; without them both fail with `AuthError::BackendNotApplicable`.

### Trait Implementation

| Method | Behavior |
| --- | --- |
| `factor_id()` | `AuthFactorId::Password` |
| `name()` | `"Password"` |
| `backend_id()` | `"password"` |
| `is_enrolled(profile, layout)` | Whether `Layout::vault_file(profile, VaultFile::PasswordWrap)` exists |
| `can_unlock(profile, layout)` | Enrolled, and password bytes are set |
| `requires_interaction()` | `AuthInteraction::PasswordEntry` |

### KEK Derivation

The KEK is `core_crypto::derive_password_key(kdf, password, salt)`: the vault's password KDF
(`VaultKeying::algorithms.kdf`, fixed at vault creation by `[crypto] kdf`) over the password
and the vault's 16-byte salt, returned as an AES-256-GCM `EncryptionKey`.

- `KdfAlgorithm::Argon2id` (default): Argon2id with the parameters defined in `core-crypto`.
- `KdfAlgorithm::Pbkdf2Sha256`: PBKDF2-HMAC-SHA256, for deployments that require a
  NIST-approved KDF.

A vault's KDF cannot change after creation: an unlock under the other KDF derives a different
KEK and fails with `AuthError::UnwrapFailed`.

### Unlock

1. Derive the KEK from the injected password under the vault's keying
   (`VaultMetadata::load_keying`).
2. Load the wrapped master key from `.password-wrap` (`WrappedKey::load`); an absent file is
   `AuthError::NotEnrolled`.
3. Unwrap it; a wrong password fails GCM authentication and is `AuthError::UnwrapFailed`.
4. Return an `UnlockOutcome` with the master key, `factor_id: Password`, and audit metadata
   `{"backend": "password"}`. The caller submits it to daemon-secrets as one factor
   (`FactorSubmit`).

### Enrollment

1. Derive the KEK as above.
2. Wrap the master key under it with a fresh random nonce (`WrappedKey::wrap`).
3. Write the `.password-wrap` file (`WrappedKey::save`).

`sesame init` enrolls the password when it creates the vault. Other factors are enrolled from
the password: [Factor Architecture](./factor-architecture.md#enrollment-and-revocation)
describes the transaction.

### Revocation

`revoke()` destroys the `.password-wrap` file with `core_layout::file::destroy`: the file is
zero-filled in place, then removed. An absent file is not an error. A vault's last factor is
never revoked: the enrollment transaction refuses it.

## The Wrapped Master Key

`WrappedKey` (`core-auth/src/wrapped_key.rs`) is the on-disk format of a master key wrapped
under a factor's KEK. The password factor stores it in `.password-wrap`; the platform keyring
factor stores the same format in `.keyring-enrollment`.

### Binary Format

```text
Offset  Length  Field
0       1       Version byte (WRAPPED_KEY_VERSION = 0x01)
1       12      Nonce (random, from the OS random source)
13      48      Ciphertext (32-byte master key + 16-byte GCM tag)
```

Total size: 61 bytes.

### Errors

`WrappedKey::deserialize` rejects any length other than 61 bytes and any version other than
`0x01` with `AuthError::InvalidBlob`. `WrappedKey::load` names the file in the error, so a
damaged enrollment is reported by its path.

### Persistence

`WrappedKey::save` writes through `core_layout::file::write` with `Mode::OwnerOnly`: a
missing `vaults/` directory is created `0700`, and the file is written `0600` to
`<path>.tmp`, synced, and renamed into place, so a reader never sees a partial file.

## Salt

Each profile has an independent 16-byte salt at `<config dir>/vaults/<profile>.salt`
(`Layout::vault_file(profile, VaultFile::Salt)`). `core_auth::salt::create` draws it from the
OS random source when `sesame init` creates the vault and writes it owner-only like the
wrapped key. `salt::require` reads it; an absent salt is `AuthError::NotInitialized`, and a
salt of any other length is `AuthError::InvalidVaultFile` naming the file.

The salt is the KDF salt of the password factor and the input of the SSH agent factor's
challenge derivation (under the vault's `hkdf`). A per-profile salt makes the same password
derive different KEKs for different vaults.

## Key Material Handling

1. **Password bytes**: a `SecureVec` (mlock'd, zeroize-on-drop), filled by the CLI prompt or
   the overlay's password field, and moved into the backend.
2. **KEK**: an `EncryptionKey`; its AES key schedule is wiped on drop (`aes-gcm` with the
   `zeroize` feature).
3. **Master key**: `SecureBytes` backed by `ProtectedAlloc` (guard pages, mlock,
   zeroize-on-drop), moved into the `FactorSubmit` message's `SensitiveBytes` without a heap
   copy (`UnlockOutcome::into_factor_submit`).
