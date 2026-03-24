# SSH Agent Backend

This page describes the SSH agent authentication backend implemented in `core-auth/src/ssh.rs`
and `core-auth/src/ssh_types.rs`. The backend connects to the user's SSH agent, signs a
deterministic challenge, derives a KEK from the signature via BLAKE3, and wraps or unwraps
the vault master key using AES-256-GCM.

## SshAgentBackend

The `SshAgentBackend` struct is a zero-sized type. All state lives in the SSH agent process
and on-disk enrollment blobs.

### Trait Implementation

| Method | Behavior |
|--------|----------|
| `factor_id()` | Returns `AuthFactorId::SshAgent` |
| `name()` | Returns `"SSH Agent"` |
| `backend_id()` | Returns `"ssh-agent"` |
| `is_enrolled(profile, config_dir)` | Checks whether `{config_dir}/vaults/{profile}.ssh-enrollment` exists |
| `can_unlock(profile, config_dir)` | Enrolled, blob is parseable, and the enrolled key's fingerprint is present in the running agent |
| `requires_interaction()` | Returns `AuthInteraction::None` |

The `can_unlock()` check connects to the SSH agent via `spawn_blocking` (the
`ssh-agent-client-rs` crate uses synchronous Unix socket I/O) and searches the agent's
identity list for a key matching the fingerprint stored in the enrollment blob.

## Challenge Construction

The challenge is a deterministic 32-byte value derived from the profile name and salt:

```text
context = "pds v2 ssh-challenge {profile_name}"
challenge = BLAKE3::derive_key(context, salt)
```

The same profile name and salt always produce the same challenge. Different profiles or salts
produce different challenges. This determinism is essential because the backend must produce
the same challenge at both enrollment and unlock time.

## Signature to KEK Derivation

After the SSH agent signs the challenge, the raw signature bytes are fed into a second BLAKE3
`derive_key` call:

```text
context = "pds v2 ssh-vault-kek {profile_name}"
kek = BLAKE3::derive_key(context, signature_bytes)
```

The raw signature bytes are zeroized immediately after KEK derivation. The KEK is a 32-byte
value used as an AES-256-GCM key to wrap or unwrap the master key.

This two-step derivation (challenge from salt, KEK from signature) ensures:

- The KEK is bound to both the profile identity and the specific SSH key.
- The signature is never stored -- only the wrapped master key is persisted.
- The BLAKE3 derivation provides domain separation between the challenge and KEK contexts.

## Supported Key Types

Defined in `core-auth/src/ssh_types.rs`, the `SshKeyType` enum restricts which SSH key types
can be used:

| Type | Wire name | Determinism |
|------|-----------|-------------|
| `Ed25519` | `ssh-ed25519` | Deterministic by specification (RFC 8032) |
| `Rsa` | `ssh-rsa` | PKCS#1 v1.5 padding uses no randomness; `ssh-agent-client-rs` hard-codes SHA-512 |

**Excluded key types:**

- **ECDSA** (`ecdsa-sha2-nistp256`, etc.): Non-deterministic. Uses a random `k` value per
  signature. A different signature on each unlock would produce a different KEK and fail to
  unwrap the enrollment blob.
- **RSA-PSS**: Non-deterministic. Uses a random salt per signature.

`SshKeyType::from_algorithm()` converts from `ssh_key::Algorithm`, rejecting non-deterministic
types with `AuthError::UnsupportedKeyType`. `SshKeyType::from_wire_name()` parses the SSH wire
format string.

## EnrollmentBlob

The `EnrollmentBlob` struct persists the SSH-agent enrollment on disk at
`{config_dir}/vaults/{profile}.ssh-enrollment`.

### Binary Format

```text
Offset    Length  Field
0         1       Version byte (0x01)
1         2       Key fingerprint length N (big-endian u16)
3         N       Key fingerprint (ASCII, e.g. "SHA256:...")
3+N       1       Key type length M (u8)
4+N       M       Key type wire name (ASCII, e.g. "ssh-ed25519")
4+N+M     12      Nonce (random)
16+N+M    48      Ciphertext (32-byte master key + 16-byte GCM tag)
```

The version constant `ENROLLMENT_VERSION` is `0x01`.

### Security

- Fingerprint length is capped at 256 bytes during deserialization to prevent allocation
  attacks from malformed blobs.
- File permissions are set to `0o600` before atomic rename.
- Revocation overwrites the file with zeros before deletion.

## Unlock Flow

1. Read and deserialize the enrollment blob from disk.
2. Derive the 32-byte challenge:
   `BLAKE3::derive_key("pds v2 ssh-challenge {profile}", salt)`.
3. Connect to the SSH agent (via `spawn_blocking` to avoid blocking the tokio runtime).
4. Find the identity matching the enrolled fingerprint.
5. Sign the challenge with the enrolled key.
6. Derive the KEK:
   `BLAKE3::derive_key("pds v2 ssh-vault-kek {profile}", signature_bytes)`.
7. Zeroize the raw signature bytes.
8. Construct an `EncryptionKey` from the KEK, then zeroize the KEK bytes.
9. Decrypt the master key from the enrollment blob's ciphertext using AES-256-GCM.
10. Return an `UnlockOutcome` with `ipc_strategy: DirectMasterKey`,
    `factor_id: SshAgent`, and audit metadata including the SSH fingerprint and key type.

## Enrollment Flow

1. Connect to the SSH agent, list all identities, filter to eligible key types
   (Ed25519, RSA).
2. Select a key by `selected_key_index` (required -- `None` returns `NoEligibleKey`).
3. Sign the challenge with the selected key.
4. Derive the KEK from the signature (same derivation as unlock).
5. Zeroize the signature bytes.
6. Generate a 12-byte random nonce via `getrandom`.
7. Encrypt the master key with AES-256-GCM using the KEK and nonce.
8. Zeroize the KEK bytes.
9. Build and serialize the `EnrollmentBlob` with the key fingerprint, key type, nonce,
   and ciphertext.
10. Write to disk atomically via a `.ssh-enrollment.tmp` intermediate, with `0o600`
    permissions.

## Key Selection

The CLI `sesame ssh enroll` command in `open-sesame/src/ssh.rs` supports three methods for
selecting which SSH key to enroll:

### Fingerprint via --ssh-key Flag

```bash
sesame ssh enroll --ssh-key SHA256:abc123...
```

The fingerprint is matched against loaded agent keys, with or without the `SHA256:` prefix.

### Public Key File via --ssh-key Flag

```bash
sesame ssh enroll --ssh-key ~/.ssh/id_ed25519.pub
```

The file is read, parsed as an OpenSSH public key, and its SHA256 fingerprint is computed.
Path traversal via `~/` is resolved through `canonicalize()` and verified to remain within
`$HOME`. Files larger than 64 KB are rejected.

### Interactive Menu

When `--ssh-key` is omitted and stdin is a terminal, `dialoguer::Select` presents a menu of
eligible keys from the agent, showing fingerprint and algorithm. In non-interactive mode
(piped stdin), `--ssh-key` is required.

## Agent Connection

The `connect_agent()` function in `core-auth/src/ssh.rs` attempts two socket paths in order:

1. **`$SSH_AUTH_SOCK`**: The standard environment variable, set by `ssh-agent`, `sshd`
   forwarding, or systemd environment propagation.

2. **`~/.ssh/agent.sock`**: A fallback stable symlink path. On Konductor VMs,
   `/etc/profile.d/konductor-ssh-agent.sh` creates `~/.ssh/agent.sock` pointing to the
   forwarded agent socket (`/tmp/ssh-XXXX/agent.PID`) on each SSH login. This gives systemd
   user services a stable path to the forwarded agent, since `$SSH_AUTH_SOCK` points to a
   per-session temporary directory that changes on each login.

The function is intentionally synchronous -- local Unix socket connect is sub-millisecond.
All agent operations in the async `VaultAuthBackend` methods are wrapped in
`tokio::task::spawn_blocking` to avoid blocking the tokio runtime.

## Agent Forwarding

For remote or containerized environments where the SSH key lives on the operator's
workstation:

- The SSH agent socket is forwarded via `ssh -A` or `ForwardAgent yes` in SSH config.
- `$SSH_AUTH_SOCK` is set by `sshd` to the forwarded socket path.
- The stable symlink pattern (`~/.ssh/agent.sock`) provides systemd user services access to
  the forwarded agent, since systemd services do not inherit the per-session `$SSH_AUTH_SOCK`.
- The Konductor profile.d hook creates and maintains this symlink automatically on each SSH
  login.

This architecture allows vault unlock via SSH agent even when running inside a VM or
container, provided the SSH agent is forwarded from the host.
