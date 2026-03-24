# Policy Engine

This page describes the multi-factor authentication policy system. Policies are declared in
configuration, persisted in vault metadata, and enforced by daemon-secrets at unlock time through
a partial unlock state machine.

## AuthCombineMode

Defined in `core-types/src/auth.rs`, the `AuthCombineMode` enum determines both the key wrapping
scheme at initialization and the unlock policy evaluation at runtime. It derives `Serialize`,
`Deserialize`, and uses `#[serde(rename_all = "kebab-case")]`.

### Any (default)

```text
AuthCombineMode::Any
```

The master key is a random 32-byte value generated via `getrandom`. Each enrolled factor
independently wraps this master key under its own KEK (Argon2id-derived for password,
BLAKE3-derived for SSH). Any single enrolled factor can unlock the vault alone.

At unlock time in daemon-secrets, the first valid factor submitted completes the unlock
immediately. The `PartialUnlock` state machine clears all remaining requirements when `Any`
mode is detected:

```rust
if matches!(meta.auth_policy, AuthCombineMode::Any) {
    partial.remaining_required.clear();
    partial.remaining_additional = 0;
}
```

### All

```text
AuthCombineMode::All
```

Every enrolled factor must be provided at unlock time. Each factor contributes a "piece" (its
unwrapped key material). Once all pieces are collected, daemon-secrets combines them into the
master key via BLAKE3 `derive_key`:

1. Factor pieces are sorted by `AuthFactorId` (which derives `Ord`).
2. The sorted pieces are concatenated.
3. BLAKE3 `derive_key` is called with context
   `"pds v2 combined-master-key {profile_name}"` and the concatenated bytes as input.
4. The result is a 32-byte master key.

The KDF context constant is `ALL_MODE_KDF_CONTEXT` defined in `daemon-secrets/src/vault.rs`
as `"pds v2 combined-master-key"`.

The `VaultMetadata::contribution_type()` method returns `FactorContribution::FactorPiece` for
`All` mode. daemon-secrets checks this to decide whether to verify each factor's key material
against the vault DB independently (it does not -- verification only happens after
combination).

### Policy

```text
AuthCombineMode::Policy(AuthPolicy {
    required: Vec<AuthFactorId>,
    additional_required: u32,
})
```

A policy expression combining mandatory factors with a threshold of additional factors. Key
wrapping uses independent wraps (same as `Any` mode -- each factor wraps the same random
master key). Policy enforcement happens at the daemon level.

- `required`: Factors that must always succeed. Every factor in this list must be submitted.
- `additional_required`: How many additional enrolled factors (beyond those in `required`)
  must also succeed.

Example: `required: [Password], additional_required: 1` means the password is always required,
plus one more factor (e.g., SSH agent or a future FIDO2 token).

`FactorContribution` is `CompleteMasterKey` for `Policy` mode -- each factor independently
unwraps the same master key.

## Configuration

Auth policy is configured in `config.toml` under `[profiles.<name>.auth]`, defined by the
`AuthConfig` struct in `core-config/src/schema_secrets.rs`:

```toml
[profiles.default.auth]
mode = "any"                          # "any", "all", or "policy"
required = ["password", "ssh-agent"]  # For mode="policy" only
additional_required = 1               # For mode="policy" only
```

`AuthConfig::to_typed()` converts the string-based config representation to `AuthCombineMode`.
It validates that all factor names in `required` are recognized via
`AuthFactorId::from_config_str()`. The default `AuthConfig` uses mode `"any"` with empty
`required` and `additional_required = 0`.

## PartialUnlock State Machine

Defined in `daemon-secrets/src/vault.rs`, the `PartialUnlock` struct tracks in-progress
multi-factor unlocks. At most one `PartialUnlock` exists per profile, stored in
`VaultState::partial_unlocks`.

### State

| Field | Type | Purpose |
|-------|------|---------|
| `received_factors` | `HashMap<AuthFactorId, SecureBytes>` | Factor keys received so far |
| `remaining_required` | `HashSet<AuthFactorId>` | Factors still needed |
| `remaining_additional` | `u32` | Additional factors still needed beyond required |
| `deadline` | `tokio::time::Instant` | Expiration time |

### Lifecycle

1. **Creation**: A `PartialUnlock` is created on the first `FactorSubmit` for a profile. The
   `remaining_required` and `remaining_additional` fields are initialized from the vault's
   `AuthCombineMode`.

2. **Factor acceptance**: Each `FactorSubmit` records the factor's key material in
   `received_factors` and removes the factor from `remaining_required`. If the factor is not
   in the required set and `remaining_additional > 0`, the additional counter is decremented.

3. **Completion check**: `is_complete()` returns `true` when `remaining_required` is empty AND
   `remaining_additional == 0`.

4. **Promotion**: When complete, the partial state is removed from the map and the master key
   is either taken directly (for `Any`/`Policy` mode, the first received factor's key) or
   derived by combining all pieces (for `All` mode).

5. **Expiration**: `is_expired()` checks whether `tokio::time::Instant::now() >= deadline`.
   Expired partials are rejected on the next `FactorSubmit` and removed from the map.

### Timeouts

- `PARTIAL_UNLOCK_TIMEOUT_SECS`: 120 seconds. The deadline for collecting all required factors
  after the first factor is submitted.
- `PARTIAL_UNLOCK_SWEEP_INTERVAL_SECS`: 30 seconds. The interval at which daemon-secrets
  sweeps and discards expired partial unlock state.

### Key Combination (All Mode)

When all factors have been received in `All` mode, daemon-secrets combines them:

```rust
let mut pieces: Vec<_> = partial.received_factors.into_iter().collect();
pieces.sort_by_key(|(id, _)| *id);
let mut combined = Vec::new();
for (_id, piece) in &pieces {
    combined.extend_from_slice(piece.as_bytes());
}
let ctx_str = format!("{ALL_MODE_KDF_CONTEXT} {target}");
let derived: [u8; 32] = blake3::derive_key(&ctx_str, &combined);
combined.zeroize();
```

The sorting by `AuthFactorId` ensures deterministic ordering regardless of submission order.

## CLI Unlock Flow

The CLI unlock command in `open-sesame/src/unlock.rs` orchestrates factor submission in three
phases:

### Phase 1: Auto-Submit Non-Interactive Factors

The CLI iterates over all enrolled factors and calls `try_auto_factor()` for each. Currently,
only `AuthFactorId::SshAgent` is handled -- it checks `can_unlock()` on the `SshAgentBackend`,
and if available, calls `unlock()` to derive the master key client-side and submits it via
`FactorSubmit` IPC.

If the vault uses `Any` mode and the SSH agent succeeds, the vault is fully unlocked and no
further factors are needed.

### Phase 2: Query Remaining Factors

The CLI sends a `VaultAuthQuery` IPC message to daemon-secrets, which returns:

- `enrolled_factors`: All enrolled factor IDs.
- `auth_policy`: The vault's `AuthCombineMode`.
- `partial_in_progress`: Whether a `PartialUnlock` exists.
- `received_factors`: Which factors have already been accepted.

The CLI filters out already-received factors to determine what remains.

### Phase 3: Prompt Interactive Factors

The CLI iterates over remaining factors:

- `Password`: Prompts for password (via `dialoguer` if terminal, or reads from stdin), derives
  the master key client-side using `PasswordBackend::unlock()`, and submits via `FactorSubmit`.
- Other factors: The CLI reports that the factor is not yet supported and exits with an error.

Each `FactorSubmit` response includes `unlock_complete`, `remaining_factors`, and
`remaining_additional`, allowing the CLI to track progress.

### Factor Submission IPC

The `submit_factor()` function sends `EventKind::FactorSubmit` with:

- `factor_id`: Which factor type.
- `key_material`: The master key in a `SensitiveBytes` (mlock'd `ProtectedAlloc`).
- `profile`: Target profile name.
- `audit_metadata`: Backend-specific audit fields.

The daemon responds with `EventKind::FactorResponse` containing acceptance status, completion
status, and remaining factor information.

## Daemon-Side Verification

For `Any` and `Policy` modes (`CompleteMasterKey` contribution), daemon-secrets verifies each
submitted factor's key material against the vault database before accepting it. It derives the
vault key via `core_crypto::derive_vault_key()` and attempts to open the SQLCipher database. If
the open fails (wrong key, GCM authentication failure), the factor is rejected.

For `All` mode (`FactorPiece` contribution), individual pieces cannot be verified against the
vault database. Verification happens after all pieces are combined into the master key.
