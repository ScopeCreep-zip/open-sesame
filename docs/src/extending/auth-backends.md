# Authentication Backends

The `core-auth` crate defines a pluggable authentication system for vault
unlock. Each authentication factor (password, SSH agent, hardware token)
is implemented as a struct that implements the `VaultAuthBackend` trait.
This page describes how to implement a new backend.

## The VaultAuthBackend Trait

The trait is defined in `core-auth/src/backend.rs`. A backend must implement
all of the following methods:

```rust
#[async_trait]
pub trait VaultAuthBackend: Send + Sync {
    fn factor_id(&self) -> AuthFactorId;
    fn name(&self) -> &str;
    fn backend_id(&self) -> &str;
    fn is_enrolled(&self, profile: &TrustProfileName, config_dir: &Path) -> bool;
    async fn can_unlock(&self, profile: &TrustProfileName, config_dir: &Path) -> bool;
    fn requires_interaction(&self) -> AuthInteraction;
    async fn unlock(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
        salt: &[u8],
    ) -> Result<UnlockOutcome, AuthError>;
    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        config_dir: &Path,
        salt: &[u8],
        selected_key_index: Option<usize>,
    ) -> Result<(), AuthError>;
    async fn revoke(
        &self, profile: &TrustProfileName, config_dir: &Path,
    ) -> Result<(), AuthError>;
}
```

### Method Descriptions

#### `factor_id()`

Returns the `AuthFactorId` enum variant that identifies this factor. Used in
policy evaluation and audit logging.

#### `name()`

Human-readable name for audit logs and overlay display (e.g., `"SSH Agent"`,
`"FIDO2 Token"`).

#### `backend_id()`

Short machine-readable identifier for IPC messages and configuration files
(e.g., `"ssh-agent"`, `"fido2"`).

#### `is_enrolled(profile, config_dir)`

Synchronous check for whether enrollment data exists for the given profile.
Reads from the filesystem under `config_dir`. Must not perform I/O that
could block.

#### `can_unlock(profile, config_dir)`

Asynchronous readiness check. Returns `true` if the backend can currently
perform an unlock. Must complete in under 100 ms. For example, an SSH agent
backend checks whether `SSH_AUTH_SOCK` is set and the agent is reachable; a
FIDO2 backend checks whether a token is plugged in.

#### `requires_interaction()`

Returns an `AuthInteraction` variant:

- `AuthInteraction::None` -- No user interaction needed (SSH software key,
  TPM, OS keyring).
- `AuthInteraction::PasswordEntry` -- Keyboard input required.
- `AuthInteraction::HardwareTouch` -- Physical touch on a hardware device.

#### `unlock(profile, config_dir, salt)`

The core unlock operation. Derives or unwraps the master key and returns an
`UnlockOutcome`.

#### `enroll(profile, master_key, config_dir, salt, selected_key_index)`

Enrolls this backend for a profile. Receives the master key so the backend
can wrap or encrypt it for later retrieval. `selected_key_index` optionally
specifies which eligible key to use (e.g., which SSH key from the agent).

#### `revoke(profile, config_dir)`

Removes enrollment data for this backend from the profile.

## UnlockOutcome

A successful `unlock()` call returns:

```rust
pub struct UnlockOutcome {
    pub master_key: SecureBytes,
    pub audit_metadata: BTreeMap<String, String>,
    pub ipc_strategy: IpcUnlockStrategy,
    pub factor_id: AuthFactorId,
}
```

- **`master_key`** -- The 32-byte master key (for `DirectMasterKey` strategy)
  or password bytes (for `PasswordUnlock` strategy). Held in `SecureBytes`,
  which is zeroized on drop.
- **`audit_metadata`** -- Key-value pairs for audit logging (e.g.,
  `"key_fingerprint" => "SHA256:..."`, `"key_comment" => "user@host"`).
- **`ipc_strategy`** -- Determines which IPC message type carries the key to
  daemon-secrets:
  - `IpcUnlockStrategy::PasswordUnlock` -- daemon-secrets performs the KDF.
  - `IpcUnlockStrategy::DirectMasterKey` -- The master key is pre-derived;
    daemon-secrets uses it directly.
- **`factor_id`** -- Echoes back the factor identifier for correlation.

## FactorContribution

The `FactorContribution` enum determines how a backend's output participates
in multi-factor composition:

- **`CompleteMasterKey`** -- This backend produces a complete, independently
  valid master key. Used in `Any` mode (any single factor suffices) and in
  `Policy` mode where individual factors can stand alone.
- **`FactorPiece`** -- This backend produces one piece of a combined key.
  Used in `All` mode, where the final master key is derived via HKDF from
  all factor pieces concatenated.

Backends that unwrap an encrypted copy of the master key (SSH agent, FIDO2
with hmac-secret) should use `CompleteMasterKey`. Backends that contribute
entropy toward a combined derivation (e.g., a partial PIN) should use
`FactorPiece`.

## Registration with AuthDispatcher

After implementing the trait, register the backend with the `AuthDispatcher`:

```rust
let fido2_backend = Fido2Backend::new(/* config */);
dispatcher.register(Box::new(fido2_backend));
```

The dispatcher iterates registered backends during unlock, filtering by
enrollment status and the active vault's auth policy.

## VaultMetadata Integration

Enrollment data is persisted alongside the vault's `VaultMetadata`. Each
backend is responsible for writing its own enrollment artifacts under
`config_dir/profiles/<profile>/auth/<backend_id>/`. The format is
backend-specific; common patterns include:

- A wrapped (encrypted) copy of the master key.
- A credential ID or public key for verification during unlock.
- Parameters for key derivation (iteration count, algorithm identifiers).

The `is_enrolled()` method checks for the existence and validity of these
artifacts.

## Example: Skeleton FIDO2 Backend

The following skeleton illustrates the structure of a hypothetical FIDO2
backend. It does not compile as-is; it shows the trait method signatures
and their responsibilities.

```rust
use core_auth::{
    AuthError, AuthInteraction, FactorContribution, IpcUnlockStrategy,
    UnlockOutcome, VaultAuthBackend,
};
use core_crypto::SecureBytes;
use core_types::{AuthFactorId, TrustProfileName};
use std::collections::BTreeMap;
use std::path::Path;

pub struct Fido2Backend {
    // Configuration: acceptable authenticator AAGUIDs, timeout, etc.
}

#[async_trait::async_trait]
impl VaultAuthBackend for Fido2Backend {
    fn factor_id(&self) -> AuthFactorId {
        AuthFactorId::Fido2
    }

    fn name(&self) -> &str {
        "FIDO2 Token"
    }

    fn backend_id(&self) -> &str {
        "fido2"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, config_dir: &Path) -> bool {
        let cred_path = config_dir
            .join("profiles")
            .join(profile.as_str())
            .join("auth/fido2/credential.json");
        cred_path.exists()
    }

    async fn can_unlock(&self, _profile: &TrustProfileName, _config_dir: &Path) -> bool {
        // Check if a FIDO2 authenticator is available via platform API.
        // Must return within 100 ms.
        check_authenticator_present().await
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::HardwareTouch
    }

    async fn unlock(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
        salt: &[u8],
    ) -> Result<UnlockOutcome, AuthError> {
        // 1. Load credential ID from enrollment data.
        let cred = load_credential(profile, config_dir)?;

        // 2. Perform FIDO2 assertion with hmac-secret extension.
        //    This requires user touch on the authenticator.
        let hmac_secret = perform_assertion(&cred, salt).await?;

        // 3. Use the hmac-secret output to unwrap the stored master key.
        let wrapped_key = load_wrapped_key(profile, config_dir)?;
        let master_key = unwrap_master_key(&wrapped_key, &hmac_secret)?;

        Ok(UnlockOutcome {
            master_key,
            audit_metadata: BTreeMap::from([
                ("credential_id".into(), hex::encode(&cred.id)),
                ("authenticator_aaguid".into(), cred.aaguid.to_string()),
            ]),
            ipc_strategy: IpcUnlockStrategy::DirectMasterKey,
            factor_id: AuthFactorId::Fido2,
        })
    }

    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        config_dir: &Path,
        salt: &[u8],
        _selected_key_index: Option<usize>,
    ) -> Result<(), AuthError> {
        // 1. Perform FIDO2 credential creation (MakeCredential).
        // 2. Use hmac-secret extension to derive a wrapping key.
        // 3. Wrap the master_key with the derived wrapping key.
        // 4. Persist credential ID + wrapped key under config_dir.
        Ok(())
    }

    async fn revoke(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
    ) -> Result<(), AuthError> {
        let auth_dir = config_dir
            .join("profiles")
            .join(profile.as_str())
            .join("auth/fido2");
        if auth_dir.exists() {
            std::fs::remove_dir_all(&auth_dir)
                .map_err(|e| AuthError::Io(e.to_string()))?;
        }
        Ok(())
    }
}
```

## Testing a New Backend

A backend implementation should verify the following:

1. **Enrollment round-trip** -- Enroll with a known master key, then confirm
   `is_enrolled()` returns `true` and the enrollment artifacts exist on disk.

2. **Unlock round-trip** -- After enrollment, call `unlock()` and verify the
   returned `master_key` matches the original.

3. **Wrong-key rejection** -- Tamper with enrollment data or use a different
   salt, and verify `unlock()` returns `AuthError`.

4. **Revocation** -- Call `revoke()`, confirm `is_enrolled()` returns `false`,
   and confirm the enrollment directory is removed.

5. **Readiness check** -- Verify `can_unlock()` returns `false` when the
   backing resource is unavailable (e.g., no SSH agent socket, no FIDO2
   token connected).

6. **Interaction declaration** -- Verify `requires_interaction()` returns the
   correct variant. The unlock UX uses this to decide whether to show a
   password prompt or a "touch your token" message.
