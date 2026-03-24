# Cross-Profile Behavior

Open Sesame enforces strict per-profile isolation for secret storage while providing controlled
mechanisms for accessing secrets from multiple profiles in a single session.

## Profile Isolation Guarantees

Each trust profile is a cryptographically independent security domain. The following properties
hold:

### Independent Master Keys

Each profile has its own password, its own 16-byte random salt (stored at
`{config_dir}/vaults/{profile}.salt`), and its own Argon2id-derived master key. Knowing the
password for profile A reveals nothing about the master key for profile B, even if the user
chooses the same password for both, because the salts differ.

### Independent Vault Keys

The vault key for each profile is derived via
`core_crypto::derive_vault_key(master_key, profile_id)` using the BLAKE3 context string
`"pds v2 vault-key {profile_id}"`. Different profile IDs produce different vault keys even
from the same master key. The `different_profiles_produce_different_keys` test in
`core-crypto/src/hkdf.rs` verifies this property.

### Independent Database Files

Each profile's secrets are stored in a separate SQLCipher database file at
`{config_dir}/vaults/{profile_name}.db`. There is no shared database. Opening profile A's
database file with profile B's vault key fails at the
`SELECT count(*) FROM sqlite_master` verification step in `SqlCipherStore::open()`.

### Independent Unlock State

Each profile is unlocked independently via `UnlockRequest` with an optional `profile` field.
The `VaultState` struct in `daemon-secrets/src/vault.rs` maintains per-profile state in
several maps:

- `master_keys: HashMap<TrustProfileName, SecureBytes>` -- per-profile master keys.
- `vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>` -- per-profile open vault
  handles.
- `active_profiles: HashSet<TrustProfileName>` -- profiles authorized for secret access.
- `partial_unlocks: HashMap<TrustProfileName, PartialUnlock>` -- in-progress multi-factor
  unlock sessions.

Multiple profiles may be unlocked and active concurrently. There is no global "locked" state;
the daemon starts with empty maps and each profile is unlocked individually.

### Independent Deactivation

Locking a single profile (`LockRequest` with a `profile` field) removes only that profile's
master key, vault handle, partial unlock state, and keyring entry. Other profiles remain
unlocked and accessible.

## Cross-Profile Tag References

The profile spec format used by `sesame env` and `sesame export` supports an `org:vault`
syntax for referencing profiles with organizational namespaces:

```text
default                    --> ProfileSpec { org: None,                  vault: "default" }
braincraft:operations      --> ProfileSpec { org: Some("braincraft"),    vault: "operations" }
```

This parsing is implemented in `parse_profile_specs()` in `open-sesame/src/ipc.rs`. The `org`
field is currently informational -- it is included in the `SESAME_PROFILES` CSV injected into
child processes but does not affect vault lookup. The `vault` field is used as the
`TrustProfileName` for IPC requests.

The format is designed for future extension to container registry-style references
(e.g., `docker.io/project/org:vault@sha256`).

## Multi-Profile Secret Injection

The `sesame env` and `sesame export` commands accept a comma-separated list of profile specs:

```bash
sesame env -p "default,work" -- my-application
sesame export -p "default,work,braincraft:operations" --format json
```

The profile list can also be set via the `SESAME_PROFILES` environment variable, which is
checked when the `-p` flag is omitted. Resolution order is implemented in
`resolve_profile_specs()` in `open-sesame/src/ipc.rs`:

1. If `-p` is provided, use it.
2. Otherwise, read `SESAME_PROFILES` from the environment.
3. If neither is set, use the default profile name.

### Merge Behavior

`fetch_multi_profile_secrets()` iterates over the profile specs in order. For each profile, it
fetches all secret keys via `SecretList`, then fetches each value via `SecretGet`. Keys are
merged into the result with left-wins collision resolution: the first profile in the list that
contains a given key wins. A `HashSet<String>` tracks which key names have already been seen.

If a profile has no secrets, a warning is printed to stderr but processing continues with the
remaining profiles.

### Denylist Enforcement

After the secret key name is converted to an environment variable name (via
`secret_key_to_env_var()`), the result is checked against the denylist
(`is_denied_env_var()`). Denied variables are skipped with a warning on stderr. This check
applies identically regardless of which profile the secret originated from.

## What Crosses Profile Boundaries

| Resource | Crosses boundaries? | Mechanism |
|---|---|---|
| Secret values | No | Each profile's vault is encrypted with a unique key. |
| Secret key names | No | Key names are only visible within a single profile's `SecretList` response. |
| Master keys | No | Each profile has an independent master key derived from its own salt. |
| Environment variables | Yes, at injection time | `sesame env -p "a,b"` merges secrets from both profiles into a single child process environment. |
| Vault database files | No | Each profile has its own `.db` file. |
| Salt files | No | Each profile has its own `.salt` file. |
| JIT cache entries | No | `JitDelivery` instances are per-profile in the `vaults` map. |
| Rate limit buckets | No (per-daemon, not per-profile) | Rate limiting is keyed on daemon identity, not profile. |
| ACL rules | No | ACL rules are defined per-profile under `[profiles.<name>.secrets.access]`. |
| Platform keyring entries | No | Keyring operations are per-profile (`keyring_store_profile`, `keyring_delete_profile`). |

The only mechanism by which secrets from different profiles can coexist in the same memory
space is the `sesame env` / `sesame export` multi-profile merge, which operates in the CLI
process after secrets have been fetched via IPC from independently unlocked vaults.

## Multi-Profile Unlock

Each profile must be unlocked independently before its secrets can be accessed. The
`sesame unlock` command accepts a `-p` flag:

```bash
sesame unlock -p default
sesame unlock -p work
```

There is no batch unlock command that accepts multiple profiles in a single invocation. Each
`UnlockRequest` IPC message targets a single profile. If a profile is already unlocked, the
daemon rejects the request with `UnlockRejectedReason::AlreadyUnlocked`.

Locking supports both single-profile and all-profile modes:

```bash
sesame lock -p work          # Lock only the "work" profile
sesame lock                  # Lock all profiles
```

Lock-all removes all master keys, flushes all JIT caches, scrubs all C-level key buffers,
deletes all keyring entries, clears all partial unlock state, and resets the rate limiter.
