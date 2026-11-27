# Factor Architecture

This page describes the pluggable authentication backend system in `core-auth`: one
`VaultAuthBackend` per factor, registered in `AuthDispatcher`, and the unlock loop every client
runs over the factors a vault still requires.

## AuthFactorId

The `AuthFactorId` enum in `core-types/src/auth.rs` identifies each authentication factor type.
Seven variants exist:

| Variant | Config string | Status |
| --- | --- | --- |
| `Password` | `password` | Implemented |
| `SshAgent` | `ssh-agent` | Implemented |
| `PlatformKeyring` | `platform-keyring` | Implemented on Linux ([Platform Keyring](./platform-keyring.md)) |
| `Fido2` | `fido2` | Defined, no backend |
| `Tpm` | `tpm` | Defined, no backend |
| `Fingerprint` | `fingerprint` | Defined, no backend |
| `Yubikey` | `yubikey` | Defined, no backend |

The enum derives `Serialize`, `Deserialize`, `Copy`, `Hash`, `Ord`, and uses
`#[serde(rename_all = "kebab-case")]`. A vault's auth policy may name a factor without a
backend; unlocking such a vault fails, naming the factor.

`AuthFactorId::from_config_str()` parses the config-file string form.
`AuthFactorId::as_config_str()` returns the static string. The `Display` implementation
delegates to `as_config_str()`.

## VaultAuthBackend Trait

Defined in `core-auth/src/backend.rs`, the `VaultAuthBackend` trait is the extension point for
adding new authentication methods. It requires `Send + Sync` and uses `#[async_trait]`.

### Required Methods

| Method | Signature | Purpose |
| --- | --- | --- |
| `factor_id` | `fn(&self) -> AuthFactorId` | Which factor this backend provides |
| `name` | `fn(&self) -> &'static str` | Human-readable name for audit logs and overlay display |
| `backend_id` | `fn(&self) -> &'static str` | Short identifier for IPC messages and config |
| `is_enrolled` | `fn(&self, profile, layout) -> Result<bool, AuthError>` | Whether the enrollment file exists |
| `can_unlock` | `async fn(&self, profile, layout) -> Result<bool, AuthError>` | Enrolled, and the external dependency (agent, entered password) present; must complete in under 100 ms |
| `requires_interaction` | `fn(&self) -> AuthInteraction` | What kind of user interaction is needed |
| `unlock` | `async fn(&self, profile, layout, keying) -> Result<UnlockOutcome, AuthError>` | Derive the KEK and unwrap the master key |
| `enroll` | `async fn(&self, profile, master_key, layout, keying, credential) -> Result<(), AuthError>` | Wrap the master key and write the enrollment file |
| `revoke` | `async fn(&self, profile, layout) -> Result<(), AuthError>` | Zero-fill and remove the enrollment file; absence is not an error |

`layout` is the `core_layout::Layout` every vault file path derives from. `keying` is the
vault's `VaultKeying`: its salt and the algorithms its keys derive under
(`VaultMetadata::load_keying`). `enroll` takes `credential: Option<&str>` naming which of the
backend's credentials to enroll: for the SSH agent, the key fingerprint, with or without the
`SHA256:` prefix. A backend with one credential (the password) ignores it.

### AuthInteraction

The `AuthInteraction` enum is what a client acts on for each factor a vault requires:

- `None` -- The backend unlocks without the user (an SSH agent holding a software key, the
  platform keyring): the client submits it at once.
- `PasswordEntry` -- Keyboard input: the client asks for the password.
- `HardwareTouch` -- Physical touch on a hardware token (FIDO2, PIV with a touch policy). No
  backend declares it yet; the CLI and the overlay report such a factor as unsupported.

### FactorContribution

The `FactorContribution` enum describes what a backend provides to the unlock process:

- `CompleteMasterKey` -- The backend independently unwraps a complete 32-byte master key. Used
  in `Any` and `Policy` modes.
- `FactorPiece` -- The backend provides a piece combined with the other factors' pieces by
  `combine_factor_pieces` (the vault's `hkdf` derivation, `KeyContext::CombinedMasterKey`, over
  the pieces concatenated in `AuthFactorId` order). Used in `All` mode. Vault creation and
  unlock both derive the combined key with that one function.

`VaultMetadata::contribution_type()` returns `FactorPiece` when `auth_policy` is `All`, and
`CompleteMasterKey` for `Any` and `Policy`.

### UnlockOutcome

The `UnlockOutcome` struct is returned by a successful `unlock()` call:

- `master_key: SecureBytes` -- The 32-byte master key (mlock'd, zeroize-on-drop).
- `audit_metadata: BTreeMap<String, String>` -- Backend-specific metadata for audit logging
  (e.g., `ssh_fingerprint`, `key_type`).
- `factor_id: AuthFactorId` -- Which factor this outcome represents.

`UnlockOutcome::into_factor_submit(profile)` turns the outcome into the one unlock message,
`FactorSubmit { factor_id, key_material, profile, audit_metadata }`; the master key moves into the
message's protected allocation without a heap copy. Every backend unlocks the same way: the
backend obtains its KEK and unwraps the master key client-side (the password backend with the
vault's password KDF, the SSH agent backend from a deterministic signature, the platform
keyring backend from the operating system's credential store), and daemon-secrets receives
the key material as one factor of the vault's auth policy.

The password and platform keyring factors store the wrapped master key in one format,
`WrappedKey` (`core-auth/src/wrapped_key.rs`; [Password](./password.md#the-wrapped-master-key)
documents it). A blob that does not parse is `AuthError::InvalidBlob`, naming its file.

## Reading daemon-secrets' Answers

`core-auth/src/progress.rs` is the one reader of daemon-secrets' unlock answers; the CLI and
the overlay both use it.

- `FactorProgress::from_response(response)` -- The answer to a `FactorSubmit`: `Unlocked`,
  `AlreadyUnlocked` (an `UnlockRejected { reason: AlreadyUnlocked }`), `MoreRequired` (the
  factor was accepted; the policy requires more), or `Rejected { reason }`.
  `FactorProgress::is_unlocked()` is true for the first two.
- `remaining_factors(response)` -- The factors a `VaultAuthQueryResponse` says the vault still
  requires, in enrollment order: its enrolled factors less those a partial unlock has received.
  A response carrying an error is `ResponseError::Requirements`.

Any other answer is `ResponseError::Unexpected`, carrying the answer's redacted form.

## AuthDispatcher

Defined in `core-auth/src/dispatcher.rs`, the `AuthDispatcher` is the registry of backends, one
per factor. `AuthDispatcher::new(credential_store)` registers `SshAgentBackend` and
`PasswordBackend`, and `PlatformKeyringBackend` over `credential_store` when it is `Some`.
The CLI passes `core_daemon::credential_store()`: the platform's store, connected, or `None`
when the platform has no implementation or the store cannot be reached (the platform keyring
factor then has no backend, and a vault requiring it reports the factor by name). The overlay
passes `None`: its sandbox grants no D-Bus bus, and daemon-launcher submits the platform
keyring factor for it ([Platform Keyring](./platform-keyring.md#who-reads-the-kek)).

**`backend(factor) -> Option<&dyn VaultAuthBackend>`** -- The backend that provides `factor`;
`None` when no registered backend implements it.

The dispatcher applies no policy: daemon-secrets owns the vault's policy and reports which
factors remain.

## The Unlock Loop

The CLI (`unlock_profile` in `open-sesame/src/unlock.rs`) and the overlay (`Runtime::resolve`
in `daemon-wm/src/commands_unlock.rs`) unlock a vault the same way:

1. Ask daemon-secrets for the factors the vault still requires (`VaultAuthQuery`,
   `remaining_factors`).
2. Look each one up (`AuthDispatcher::backend`). A factor without a backend fails the unlock,
   naming it.
3. Submit every factor whose backend needs no interaction and can unlock now. A factor that is
   unavailable, fails, or is rejected is reported and the next one is tried. A submission that
   completes the unlock ends it. In the overlay, the platform keyring factor is submitted by
   daemon-launcher (`KeyringUnlockRequest`).
4. Ask for the password when a remaining factor requires it, and submit it. If the policy
   requires more factors after the password, the vault's remaining factors are read again.

## VaultMetadata

Defined in `core-auth/src/vault_meta.rs`, `VaultMetadata` is the JSON-serialized record of a
vault's authentication state, stored at `<config dir>/vaults/<profile>.vault-meta`
(`Layout::vault_file(profile, VaultFile::Metadata)`) with mode `0600`.

### Fields

| Field | Type | Purpose |
| --- | --- | --- |
| `version` | `u32` | Format version (`VAULT_META_VERSION`, currently `2`) |
| `enrolled_factors` | `Vec<EnrolledFactor>` | Which auth methods are enrolled |
| `auth_policy` | `AuthCombineMode` | Unlock policy for this vault |
| `kdf`, `hkdf` | `VaultAlgorithms` (flattened) | The algorithms the vault's keys derive under, fixed at creation |
| `created_at` | `u64` | Unix epoch seconds of vault creation |
| `policy_changed_at` | `u64` | Unix epoch seconds of last policy change |

### EnrolledFactor

Each enrolled factor records:

- `factor_id: AuthFactorId` -- The factor type.
- `label: String` -- Human-readable label (e.g., SSH key fingerprint, "master password").
- `enrolled_at: u64` -- Unix epoch seconds.

### Version

`VaultMetadata::load()` reads the version first and refuses any version other than
`VAULT_META_VERSION`, naming the version and the reset command
(`sesame init --wipe-reset-destroy-all-data`). Metadata of the current version without the
algorithm fields is corrupt. Both are `AuthError::InvalidVaultFile`, naming the file.

### Persistence

JSON is used rather than TOML to distinguish machine-managed metadata from user-editable
configuration. `save()` writes through `core_layout::file::write` with `Mode::OwnerOnly`, the
one writer of files PDS owns: it creates `<path>.tmp` with mode `0600`, writes and syncs it,
renames it over the final name, and syncs the directory, so a reader never sees a partial
file and the rename survives a crash.

### Construction and Keying

- `new(factors, auth_policy, crypto)` -- One enrolled factor per `(AuthFactorId, label)` pair,
  all stamped with the creation time, under the algorithms `crypto` selects.
  `AuthError::Clock` when the system clock is before the Unix epoch, since enrollment and
  policy times are audit evidence.
- `keying(salt) -> VaultKeying` -- The vault's keying with `salt`.
- `load_keying(layout, profile)` -- The metadata and its keying, with the vault's salt
  (`salt::require`: an absent salt is `AuthError::NotInitialized`).

### Factor Management

- `has_factor(factor_id) -> bool` -- Check enrollment.
- `add_factor(factor_id, label) -> Result<()>` -- Idempotent add (no-op if already enrolled).
- `remove_factor(factor_id)` -- Remove by factor ID.
- `contribution_type() -> FactorContribution` -- Returns `FactorPiece` for `All` mode,
  `CompleteMasterKey` for `Any`/`Policy`.

## Enrollment and Revocation

Every factor command (`sesame ssh`, `sesame keyring`) enrolls and revokes through one
implementation, `open-sesame/src/enrollment.rs`.

Enrollment is a transaction:

1. The vault password derives the master key (`PasswordBackend::unlock`).
2. The factor's backend enrolls (`enroll`).
3. The new enrollment is proven: the backend unlocks with it, and the key it yields must be
   the vault's master key.
4. Only then is the factor recorded in the vault metadata (`add_factor`, `save`).

A failure after step 2 revokes what the backend wrote, so no half-made enrollment remains;
the error says whether the rollback succeeded.

Revocation removes the factor's metadata record and its enrollment together, whichever of the
two exists, so a factor left half-enrolled is repaired. A vault's last factor is never
revoked.

## Adding a New Factor

To add a new authentication factor (e.g., FIDO2):

1. The `AuthFactorId` variant already exists in `core-types/src/auth.rs` (e.g., `Fido2`).
2. Create a new module in `core-auth/src/` implementing a struct (e.g., `Fido2Backend`).
3. Implement `VaultAuthBackend` for the struct:
   - `factor_id()` returns the corresponding `AuthFactorId` variant.
   - `is_enrolled()` checks for the factor's enrollment artifact on disk.
   - `can_unlock()` checks whether the hardware or service is available.
   - `requires_interaction()` returns the appropriate `AuthInteraction` variant.
   - `unlock()` derives the KEK under the vault's keying and unwraps the 32-byte master key.
   - `enroll()` wraps the master key under the factor's KEK and writes an enrollment blob.
   - `revoke()` destroys the enrollment file with `core_layout::file::destroy` (zero-fill,
     then remove).
4. Add a `VaultFile` kind for the enrollment file in `core-layout`, so the path and the
   daemon sandboxes derive from one place.
5. Register the backend in `AuthDispatcher::new()`. A backend over a platform service takes
   it as an argument the platform crate supplies, as `PlatformKeyringBackend` takes the
   `CredentialStore`.
6. Add the factor's command, enrolling and revoking through `open-sesame/src/enrollment.rs`.
7. A backend that needs no interaction is submitted by the unlock loop as it is. One that needs
   a touch is the `AuthInteraction::HardwareTouch` arm of the CLI's and the overlay's loops,
   which report it as unsupported until a client shows a touch prompt before calling `unlock()`.

No changes to daemon-secrets are required -- the `FactorSubmit` IPC handler and
`PartialUnlock` state machine operate on `AuthFactorId` and `SecureBytes` generically.
