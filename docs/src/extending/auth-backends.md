# Authentication Backends

The `core-auth` crate defines a pluggable authentication system for vault
unlock. Each authentication factor (password, SSH agent, platform keyring) is a struct that
implements the `VaultAuthBackend` trait. This page describes how to implement
a new backend.

## The VaultAuthBackend Trait

The trait is defined in `core-auth/src/backend.rs`:

```rust
#[async_trait::async_trait]
pub trait VaultAuthBackend: Send + Sync {
    fn factor_id(&self) -> AuthFactorId;
    fn name(&self) -> &'static str;
    fn backend_id(&self) -> &'static str;
    fn is_enrolled(&self, profile: &TrustProfileName, layout: &Layout) -> Result<bool, AuthError>;
    async fn can_unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
    ) -> Result<bool, AuthError>;
    fn requires_interaction(&self) -> AuthInteraction;
    async fn unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
        keying: &VaultKeying,
    ) -> Result<UnlockOutcome, AuthError>;
    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        layout: &Layout,
        keying: &VaultKeying,
        credential: Option<&str>,
    ) -> Result<(), AuthError>;
    async fn revoke(&self, profile: &TrustProfileName, layout: &Layout) -> Result<(), AuthError>;
}
```

`layout` is the `core_layout::Layout` every vault file path derives from;
`keying` is the vault's `VaultKeying`, its salt and the algorithms its keys
derive under (`VaultMetadata::load_keying`).

### Method Descriptions

#### `factor_id()`

The `AuthFactorId` variant this backend provides. Used in policy evaluation,
in `FactorSubmit`, and in audit logging.

#### `name()`

Human-readable name for audit logs and overlay display (`"SSH Agent"`).

#### `backend_id()`

Short machine-readable identifier for IPC messages and configuration
(`"ssh-agent"`, `"password"`).

#### `is_enrolled(profile, layout)`

Whether the backend's enrollment file exists. A failure to determine it (for
example, a permission error) is an error, not `false`.

#### `can_unlock(profile, layout)`

Whether the backend can unlock now: it is enrolled and its external
dependency is present. Must complete in under 100 ms. The SSH agent backend
reads its enrollment and checks that a reachable agent holds the enrolled
key; an unreachable agent is `false`, an agent that answers and fails the
protocol is an error, and an unparseable enrollment is
`AuthError::InvalidBlob`, naming the file. The platform keyring backend is
ready when enrolled; reaching the store happens in `unlock()`, which may
raise the keyring's unlock prompt.

#### `requires_interaction()`

An `AuthInteraction` variant:

- `AuthInteraction::None` -- No user interaction (an SSH agent holding a
  software key, the platform keyring): clients submit the factor at once.
- `AuthInteraction::PasswordEntry` -- Keyboard input: clients ask for the
  password.
- `AuthInteraction::HardwareTouch` -- Physical touch on a hardware device. The
  CLI and the overlay report such a factor as unsupported.

#### `unlock(profile, layout, keying)`

Derives the backend's key-encrypting key, unwraps the master key from the
enrollment file, and returns an `UnlockOutcome`. A missing enrollment is
`AuthError::NotEnrolled`; a wrong key or tampered file is
`AuthError::UnwrapFailed`.

#### `enroll(profile, master_key, layout, keying, credential)`

Wraps `master_key` under the backend's key-encrypting key and writes the
enrollment file. `credential` names which of the backend's credentials to
enroll: the SSH agent backend requires the key fingerprint (with or without
the `SHA256:` prefix) and fails with `AuthError::BackendNotApplicable`
without one. A backend with a single credential ignores it.

#### `revoke(profile, layout)`

Zero-fills and removes the enrollment file. An absent enrollment is not an
error.

## UnlockOutcome

A successful `unlock()` returns:

```rust
pub struct UnlockOutcome {
    pub master_key: SecureBytes,
    pub audit_metadata: BTreeMap<String, String>,
    pub factor_id: AuthFactorId,
}
```

- **`master_key`** -- The unwrapped 32-byte master key, in `SecureBytes`
  (protected allocation, zeroized on drop).
- **`audit_metadata`** -- Key-value pairs for audit logging (the SSH agent
  backend records `backend`, `ssh_fingerprint`, and `key_type`).
- **`factor_id`** -- The factor this outcome represents.

`UnlockOutcome::into_factor_submit(profile)` produces the one unlock message,
`EventKind::FactorSubmit`, moving the master key into the message's protected
allocation without a heap copy. Every backend unlocks this way: the key is
unwrapped client-side, and daemon-secrets receives it as one factor of the
vault's auth policy.

## FactorContribution

The `FactorContribution` enum states how a factor's key material participates
in the vault's policy. `VaultMetadata::contribution_type()` derives it from
the policy:

- **`CompleteMasterKey`** (`Any` and `Policy` modes) -- Each factor unwraps a
  complete, independently valid master key.
- **`FactorPiece`** (`All` mode) -- Each factor contributes a piece; the master
  key is `combine_factor_pieces(profile, hkdf, pieces)`, the vault's `hkdf`
  derivation with `KeyContext::CombinedMasterKey(profile)` over the pieces
  concatenated in `AuthFactorId` order. Vault creation and unlock both derive
  it with that one function.

## Registration with AuthDispatcher

`AuthDispatcher::new(credential_store)` (`core-auth/src/dispatcher.rs`) is the
registry of backends, one per factor. A new backend is added to its list:

```rust
pub fn new(credential_store: Option<Arc<dyn CredentialStore>>) -> Self {
    let mut backends: Vec<Box<dyn VaultAuthBackend>> = vec![
        Box::new(SshAgentBackend::new()),
        Box::new(PasswordBackend::new()),
        Box::new(Fido2Backend::new()),
    ];
    if let Some(store) = credential_store {
        backends.push(Box::new(PlatformKeyringBackend::new(store)));
    }
    Self { backends }
}
```

A backend over a platform service does not reach the platform from
`core-auth`: it takes the service as a `core_types` interface, implemented by
the platform crate and passed in by the client, as `PlatformKeyringBackend`
takes the `CredentialStore` that `core_daemon::credential_store()` connects.
Without one, the factor has no backend, and a vault requiring it reports the
factor by name. A platform service a sandboxed daemon cannot reach (the
credential store is on the session D-Bus bus) is used through a broker
outside the sandbox, as daemon-wm has daemon-launcher submit the platform
keyring factor (`KeyringUnlockRequest`).

`AuthDispatcher::backend(factor)` finds the backend of each factor daemon-secrets
reports a vault still requires (`core_auth::remaining_factors`); the CLI and
the overlay act on its `requires_interaction()`. The dispatcher applies no
policy: daemon-secrets owns the vault's policy. See
[Factor Architecture](../authentication/factor-architecture.md#the-unlock-loop).

## Enrollment Files

A backend's enrollment file lives in the vault directory beside the vault's
other files, at a path the layout derives:
`Layout::vault_file(profile, VaultFile::<Kind>)`, which is
`<config dir>/vaults/<profile>.<extension>`. The existing kinds are
`PasswordWrap` (`.password-wrap`), `SshEnrollment` (`.ssh-enrollment`), and
`KeyringEnrollment` (`.keyring-enrollment`); a
new backend adds its own `VaultFile` variant in `core-layout`, so the code
that opens the file and the daemon sandboxes that grant access to it derive
the same path.

Enrollment files hold wrapped key material, so they are written, scrubbed,
and removed only through `core_layout::file`, the one writer of files PDS
owns:

- `write(path, contents, Mode::OwnerOnly)` -- creates missing parents `0700`,
  writes `<path>.tmp` with mode `0600`, syncs it, renames it over `path`, and
  syncs the directory. On error `path` is unchanged and no temporary remains.
- `destroy(path)` -- zero-fills the file in place, syncs, and removes it;
  `false` when it was absent. A file that cannot be scrubbed is not removed.
- `exists(path)` -- whether it exists; a failure to determine it is an error.

A backend whose file holds only the wrapped master key uses `WrappedKey`
(`core-auth/src/wrapped_key.rs`: version, nonce, AES-256-GCM ciphertext), as
the password and platform keyring backends do, choosing its file with the
`VaultFile` argument of `WrappedKey::load` and `WrappedKey::save`. A backend
that must also record a credential identifier defines its own format, as the
SSH agent backend's `EnrollmentBlob` records the key fingerprint and type.

The factor's command enrolls and revokes it through
`open-sesame/src/enrollment.rs`: the enrollment is proven by unlocking with it
before the vault metadata records the factor, and a failed enrollment is
revoked ([Factor Architecture](../authentication/factor-architecture.md#enrollment-and-revocation)).

## Example: Skeleton FIDO2 Backend

The skeleton below shows the structure of a hypothetical FIDO2 backend. It
assumes a `VaultFile::Fido2Enrollment` variant, an `Fido2Enrollment` blob
type, and platform helpers (`authenticator_present`, `make_credential`,
`hmac_secret`) that do not exist in the tree; it does not compile as is.

```rust
use core_auth::{AuthError, AuthInteraction, UnlockOutcome, VaultAuthBackend, VaultKeying};
use core_crypto::SecureBytes;
use core_layout::file::{self, Mode};
use core_layout::{Layout, VaultFile};
use core_types::{AuthFactorId, TrustProfileName};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub struct Fido2Backend;

impl Fido2Backend {
    fn enrollment_path(layout: &Layout, profile: &TrustProfileName) -> Result<PathBuf, AuthError> {
        Ok(layout.vault_file(profile, VaultFile::Fido2Enrollment)?)
    }
}

#[async_trait::async_trait]
impl VaultAuthBackend for Fido2Backend {
    fn factor_id(&self) -> AuthFactorId {
        AuthFactorId::Fido2
    }

    fn name(&self) -> &'static str {
        "FIDO2 Token"
    }

    fn backend_id(&self) -> &'static str {
        "fido2"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, layout: &Layout) -> Result<bool, AuthError> {
        Ok(file::exists(&Self::enrollment_path(layout, profile)?)?)
    }

    async fn can_unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
    ) -> Result<bool, AuthError> {
        // Enrolled, and an authenticator is present; within 100 ms.
        Ok(self.is_enrolled(profile, layout)? && authenticator_present().await)
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::HardwareTouch
    }

    async fn unlock(
        &self,
        profile: &TrustProfileName,
        layout: &Layout,
        keying: &VaultKeying,
    ) -> Result<UnlockOutcome, AuthError> {
        let data = std::fs::read(Self::enrollment_path(layout, profile)?)?;
        let enrollment = Fido2Enrollment::deserialize(&data)?;
        // The hmac-secret output (user touch) is the key-encrypting key.
        let kek = hmac_secret(&enrollment.credential_id, &keying.salt).await?;
        let master_key = core_crypto::EncryptionKey::from_bytes(kek.as_bytes())
            .map_err(|_| AuthError::UnwrapFailed)?
            .decrypt(&enrollment.nonce, &enrollment.ciphertext)
            .map_err(|_| AuthError::UnwrapFailed)?;
        Ok(UnlockOutcome {
            master_key,
            audit_metadata: BTreeMap::from([
                ("backend".into(), "fido2".into()),
                ("credential_id".into(), enrollment.credential_id_hex()),
            ]),
            factor_id: AuthFactorId::Fido2,
        })
    }

    async fn enroll(
        &self,
        profile: &TrustProfileName,
        master_key: &SecureBytes,
        layout: &Layout,
        keying: &VaultKeying,
        _credential: Option<&str>,
    ) -> Result<(), AuthError> {
        let credential_id = make_credential().await?;
        let kek = hmac_secret(&credential_id, &keying.salt).await?;
        let (nonce, ciphertext) =
            core_crypto::EncryptionKey::from_bytes(kek.as_bytes())?.seal(master_key.as_bytes())?;
        let blob = Fido2Enrollment { credential_id, nonce, ciphertext };
        file::write(&Self::enrollment_path(layout, profile)?, &blob.serialize()?, Mode::OwnerOnly)?;
        Ok(())
    }

    async fn revoke(&self, profile: &TrustProfileName, layout: &Layout) -> Result<(), AuthError> {
        file::destroy(&Self::enrollment_path(layout, profile)?)?;
        Ok(())
    }
}
```

## Testing a New Backend

Tests build a `Layout::under(tempdir)`, so every vault file lands beneath a
temporary root. A backend's tests cover:

1. **Enrollment round-trip** -- Enroll with a known master key; `is_enrolled()`
   is `true` and the enrollment file is mode `0600`.
2. **Unlock round-trip** -- After enrollment, `unlock()` returns the original
   master key.
3. **Wrong-key rejection** -- A tampered enrollment file or a different salt
   makes `unlock()` fail with `AuthError::UnwrapFailed`.
4. **Damaged enrollment** -- An unparseable enrollment file is
   `AuthError::InvalidBlob` naming the file from both `can_unlock()` and
   `unlock()`, not a silent `false`.
5. **Revocation** -- After `revoke()`, `is_enrolled()` is `false` and the file
   is gone; revoking again succeeds.
6. **Readiness** -- `can_unlock()` is `false` when the backing resource is
   unavailable (no agent socket, no token).
7. **Interaction declaration** -- `requires_interaction()` returns the right
   variant; the CLI and the overlay use it to decide whether to submit the
   factor at once, ask for a password, or report a touch as unsupported.
