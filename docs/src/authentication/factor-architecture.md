# Factor Architecture

This page describes the pluggable authentication backend system in `core-auth`. The system defines a
trait-based dispatch mechanism that allows multiple authentication methods to coexist, with the
`AuthDispatcher` coordinating backend selection at unlock time.

## AuthFactorId

The `AuthFactorId` enum in `core-types/src/auth.rs` identifies each authentication factor type.
Six variants exist:

| Variant       | Config string   | Status        |
|---------------|-----------------|---------------|
| `Password`    | `password`      | Implemented   |
| `SshAgent`    | `ssh-agent`     | Implemented   |
| `Fido2`       | `fido2`         | Defined, no backend |
| `Tpm`         | `tpm`           | Defined, no backend |
| `Fingerprint` | `fingerprint`   | Defined, no backend |
| `Yubikey`     | `yubikey`       | Defined, no backend |

The enum derives `Serialize`, `Deserialize`, `Copy`, `Hash`, `Ord`, and uses
`#[serde(rename_all = "kebab-case")]`. The four future variants (`Fido2`, `Tpm`, `Fingerprint`,
`Yubikey`) are defined to permit forward-compatible policy configuration: a vault metadata file can
reference these factor types in its `auth_policy` before their backends are implemented.

`AuthFactorId::from_config_str()` parses the config-file string form.
`AuthFactorId::as_config_str()` returns the static string. The `Display` implementation
delegates to `as_config_str()`.

## VaultAuthBackend Trait

Defined in `core-auth/src/backend.rs`, the `VaultAuthBackend` trait is the extension point for
adding new authentication methods. It requires `Send + Sync` and uses `#[async_trait]`.

### Required Methods

| Method | Signature | Purpose |
|--------|-----------|---------|
| `factor_id` | `fn(&self) -> AuthFactorId` | Which factor this backend provides |
| `name` | `fn(&self) -> &str` | Human-readable name for audit logs and overlay display |
| `backend_id` | `fn(&self) -> &str` | Short identifier for IPC messages and config |
| `is_enrolled` | `fn(&self, profile, config_dir) -> bool` | Whether enrollment artifacts exist on disk |
| `can_unlock` | `async fn(&self, profile, config_dir) -> bool` | Whether unlock can currently succeed (must complete in <100ms) |
| `requires_interaction` | `fn(&self) -> AuthInteraction` | What kind of user interaction is needed |
| `unlock` | `async fn(&self, profile, config_dir, salt) -> Result<UnlockOutcome, AuthError>` | Derive or unwrap the master key |
| `enroll` | `async fn(&self, profile, master_key, config_dir, salt, selected_key_index) -> Result<(), AuthError>` | Create enrollment artifacts for a profile |
| `revoke` | `async fn(&self, profile, config_dir) -> Result<(), AuthError>` | Remove enrollment artifacts |

The `enroll` method accepts an optional `selected_key_index` for backends that offer multiple
eligible keys (e.g., SSH agent with multiple loaded keys). If `None`, the backend picks the
first eligible key.

### AuthInteraction

The `AuthInteraction` enum describes the interaction model:

- `None` -- Backend can unlock silently (SSH agent with a software key, future TPM, future keyring).
- `PasswordEntry` -- Keyboard input required.
- `HardwareTouch` -- Physical touch on a hardware token (future FIDO2, PIV with touch policy).

### FactorContribution

The `FactorContribution` enum describes what a backend provides to the unlock process:

- `CompleteMasterKey` -- The backend independently unwraps or derives a complete 32-byte master
  key. Used in `Any` and `Policy` modes.
- `FactorPiece` -- The backend provides a piece that must be combined with pieces from other
  factors via BLAKE3 `derive_key`. Used in `All` mode.

`VaultMetadata::contribution_type()` returns `FactorPiece` when `auth_policy` is `All`, and
`CompleteMasterKey` for `Any` and `Policy`.

### UnlockOutcome

The `UnlockOutcome` struct is returned by a successful `unlock()` call:

- `master_key: SecureBytes` -- The 32-byte master key (mlock'd, zeroize-on-drop).
- `audit_metadata: BTreeMap<String, String>` -- Backend-specific metadata for audit logging
  (e.g., `ssh_fingerprint`, `key_type`).
- `ipc_strategy: IpcUnlockStrategy` -- Which IPC message type to use (`PasswordUnlock` or
  `DirectMasterKey`).
- `factor_id: AuthFactorId` -- Which factor this outcome represents.

### IpcUnlockStrategy

- `PasswordUnlock` -- Use the `UnlockRequest` IPC message; daemon-secrets performs the KDF.
- `DirectMasterKey` -- Use the `SshUnlockRequest` or `FactorSubmit` IPC message with a
  pre-derived master key.

Both implemented backends (`PasswordBackend` and `SshAgentBackend`) use `DirectMasterKey`. The
password backend derives the KEK client-side via Argon2id and unwraps the master key before
sending it over IPC.

## AuthDispatcher

Defined in `core-auth/src/dispatcher.rs`, the `AuthDispatcher` holds a
`Vec<Box<dyn VaultAuthBackend>>` and provides methods for backend discovery and selection.

### Construction

`AuthDispatcher::new()` registers two backends in priority order:

1. `SshAgentBackend` (non-interactive)
2. `PasswordBackend` (interactive fallback)

### Methods

**`backends(&self) -> &[Box<dyn VaultAuthBackend>]`** -- Access all registered backends.

**`applicable_backends(profile, config_dir, meta) -> Vec<&dyn VaultAuthBackend>`** -- Returns
backends that are both enrolled in the vault metadata (`meta.has_factor(backend.factor_id())`)
AND can currently perform an unlock (`backend.can_unlock()`). Used by the CLI to determine
which factors to attempt.

**`find_auto_backend(profile, config_dir) -> Option<&dyn VaultAuthBackend>`** -- Returns the
first backend where `requires_interaction() == AuthInteraction::None`, `is_enrolled()` is true,
and `can_unlock()` is true. Does not consult vault metadata -- checks enrollment files directly
on disk.

**`can_auto_unlock(profile, config_dir, meta) -> bool`** -- Policy-aware auto-unlock
feasibility check:

- `Any` mode: delegates to `find_auto_backend()` -- a single non-interactive backend suffices.
- `All` or `Policy` mode: all applicable backends must be non-interactive. Returns `false`
  conservatively if any required factor needs interaction.

**`password_backend(&self) -> &dyn VaultAuthBackend`** -- Returns the password backend. Panics
if not registered (programming error -- the constructor always registers it).

## VaultMetadata

Defined in `core-auth/src/vault_meta.rs`, `VaultMetadata` is the JSON-serialized record of a
vault's authentication state. Stored at `{config_dir}/vaults/{profile}.vault-meta` with
permissions `0o600`.

### Fields

| Field | Type | Purpose |
|-------|------|---------|
| `version` | `u32` | Format version (currently `1`) |
| `init_mode` | `VaultInitMode` | How the vault was originally initialized |
| `enrolled_factors` | `Vec<EnrolledFactor>` | Which auth methods are enrolled |
| `auth_policy` | `AuthCombineMode` | Unlock policy for this vault |
| `created_at` | `u64` | Unix epoch seconds of vault creation |
| `policy_changed_at` | `u64` | Unix epoch seconds of last policy change |

### VaultInitMode

- `Password` -- Initialized with password only.
- `SshKeyOnly` -- Initialized with SSH key only (random master key, no password).
- `MultiFactor { factors: Vec<AuthFactorId> }` -- Initialized with multiple factors.

### EnrolledFactor

Each enrolled factor records:

- `factor_id: AuthFactorId` -- The factor type.
- `label: String` -- Human-readable label (e.g., SSH key fingerprint, "master password").
- `enrolled_at: u64` -- Unix epoch seconds.

### Version Gating

`VaultMetadata::load()` rejects metadata where `version > MAX_SUPPORTED_VERSION` (currently
`1`). This prevents a newer binary from silently misinterpreting a vault metadata format it
does not understand.

### Persistence

JSON is used rather than TOML to distinguish machine-managed metadata from user-editable
configuration. Writes use atomic rename via a `.vault-meta.tmp` intermediate file. File
permissions are set to `0o600` on Unix before the rename.

### Factory Methods

- `new_password(auth_policy)` -- Creates metadata with a single `Password` enrolled factor.
- `new_ssh_only(fingerprint, auth_policy)` -- Creates metadata with a single `SshAgent`
  enrolled factor.
- `new_multi_factor(factors, auth_policy)` -- Creates metadata with arbitrary enrolled factors.

### Factor Management

- `has_factor(factor_id) -> bool` -- Check enrollment.
- `add_factor(factor_id, label)` -- Idempotent add (no-op if already enrolled).
- `remove_factor(factor_id)` -- Remove by factor ID.
- `contribution_type() -> FactorContribution` -- Returns `FactorPiece` for `All` mode,
  `CompleteMasterKey` for `Any`/`Policy`.

## Adding a New Factor

To add a new authentication factor (e.g., FIDO2):

1. The `AuthFactorId` variant already exists in `core-types/src/auth.rs` (e.g., `Fido2`).
2. Create a new module in `core-auth/src/` implementing a struct (e.g., `Fido2Backend`).
3. Implement `VaultAuthBackend` for the struct:
   - `factor_id()` returns the corresponding `AuthFactorId` variant.
   - `is_enrolled()` checks for the factor's enrollment artifact on disk.
   - `can_unlock()` checks whether the hardware or service is available.
   - `requires_interaction()` returns the appropriate `AuthInteraction` variant.
   - `unlock()` derives or unwraps the 32-byte master key.
   - `enroll()` wraps the master key under the factor's KEK and writes an enrollment blob.
   - `revoke()` zeroizes and deletes the enrollment blob.
4. Register the backend in `AuthDispatcher::new()` at the appropriate priority position
   (non-interactive backends before interactive ones).
5. The CLI unlock flow in `open-sesame/src/unlock.rs` handles unknown factors by reporting
   that the factor is not yet supported. Adding a match arm in `try_auto_factor()` (for
   non-interactive factors) or the phase 3 loop (for interactive factors) enables CLI support.

No changes to daemon-secrets are required -- the `FactorSubmit` IPC handler and
`PartialUnlock` state machine operate on `AuthFactorId` and `SecureBytes` generically.
