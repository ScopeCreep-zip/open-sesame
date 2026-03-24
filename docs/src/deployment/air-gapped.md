# Air-Gapped Environments

> **Design Intent.** This page describes operating Open Sesame in air-gapped, SCIF, and
> offline environments (IL5/IL6 and above). Core vault operations require no network access
> today. The key ceremony procedures and audit export tooling described below are architectural
> targets grounded in the existing type system and cryptographic primitives.

## Offline-First Architecture

Open Sesame's core functionality requires no network access. The secrets daemon
(`daemon-secrets`) runs with `PrivateNetwork=yes` in its systemd unit, enforcing network
isolation at the kernel level. All inter-daemon communication occurs over a local Unix domain
socket via the Noise IK protocol.

Operations that work fully offline:

- Vault creation, unlock, lock.
- Secret read, write, delete, list.
- Profile activation and switching.
- Audit log generation and verification.
- Application launching with secret injection.
- Clipboard isolation.

The only operations that require network access are SSH agent forwarding (which requires an
SSH connection) and extension installation from OCI registries (which can be pre-staged).

## memfd_secret as Security Floor

Air-gapped environments operating at IL5/IL6 or within SCIFs require `memfd_secret(2)` as a
mandatory security control. The kernel must be compiled with `CONFIG_SECRETMEM=y`.

### Verification

```bash
# Verify kernel support
grep CONFIG_SECRETMEM /boot/config-$(uname -r)
# Expected: CONFIG_SECRETMEM=y

# Verify at runtime
sesame status --security-posture
```

On systems where `memfd_secret` is unavailable, Open Sesame logs at ERROR level with an
explicit compliance impact statement:

```text
ERROR memfd_secret unavailable: secrets remain on kernel direct map.
      Compliance impact: does not meet IL5/IL6, DISA STIG, PCI-DSS requirements
      for memory isolation. Remediation: enable CONFIG_SECRETMEM=y in kernel config.
```

For air-gapped deployments, `memfd_secret` availability should be a deployment gate. Do not
proceed with secret enrollment on systems that report this fallback.

### Kernel Configuration

Air-gapped systems should use a hardened kernel with at minimum:

```text
CONFIG_SECRETMEM=y          # memfd_secret(2) support
CONFIG_SECURITY_LANDLOCK=y  # Landlock filesystem sandboxing
CONFIG_SECCOMP=y            # seccomp-bpf syscall filtering
CONFIG_SECCOMP_FILTER=y     # BPF filter programs for seccomp
```

## Air-Gapped Key Ceremony

### Master Key Generation

In an air-gapped environment, the initial key ceremony is performed on a physically isolated
machine:

1. **Preparation.** Boot the ceremony machine from verified media. Verify kernel supports
   `memfd_secret`.

2. **Initialization.** Run `sesame init` to generate the `InstallationConfig`:
   - UUID v4 installation identifier.
   - Organization namespace (if enterprise-managed).
   - Machine binding via `/etc/machine-id` or TPM (`MachineBindingType` in
     `core-types/src/security.rs`).

3. **Factor Enrollment.** Enroll authentication factors per the site's `AuthCombineMode`
   policy (`core-types/src/auth.rs`):
   - `Password` -- Argon2id KDF with 19 MiB memory, 2 iterations.
   - `SshAgent` -- Deterministic SSH signature-derived KEK.
   - `Fido2`, `Tpm`, `Yubikey` -- Hardware factors (defined in `AuthFactorId`; backends
     not yet implemented).

4. **Policy Lock.** Deploy `/etc/pds/policy.toml` to enforce cryptographic algorithm
   selection:

   ```toml
   [[policy]]
   key = "crypto.kdf"
   value = "argon2id"
   source = "airgap-key-ceremony-2025"

   [[policy]]
   key = "crypto.minimum_peer_profile"
   value = "leading-edge"
   source = "airgap-key-ceremony-2025"
   ```

5. **Verification.** Run `sesame status` and `sesame audit verify` to confirm the
   installation is healthy and the audit chain has a valid genesis entry.

### Factor Enrollment for "All" Mode

For high-security environments, `AuthCombineMode::All` requires every enrolled factor to be
present at unlock time. The master key is derived from chaining all factor contributions:

```text
BLAKE3 derive_key("pds v2 combined-master-key {profile}", sorted_factor_pieces)
  --> Combined Master Key
```

This prevents any single compromised factor from unlocking the vault.

### Factor Enrollment for "Policy" Mode

The `AuthPolicy` struct (`core-types/src/auth.rs`) supports threshold-based unlock:

```toml
[auth]
mode = "policy"

[auth.policy]
required = ["password"]
additional_required = 1
# Enrolled: password, ssh-agent, fido2
# Unlock requires: password + (ssh-agent OR fido2)
```

## Audit Chain Export

The BLAKE3 hash-chained audit log provides tamper evidence that can be verified
independently. For air-gapped environments where logs cannot be streamed to a central
aggregator:

### Export Procedure

1. **Export.** Copy the audit chain from the air-gapped machine to removable media:

   ```bash
   cp -r ~/.config/pds/audit/ /media/audit-export/
   ```

2. **Transfer.** Move the removable media through the appropriate security boundary (data
   diode, manual review, or similar).

3. **Verify.** On the receiving side, verify the chain integrity:

   ```bash
   sesame audit verify --path /media/audit-export/
   ```

   Verification checks that each entry's BLAKE3 hash chains to the previous entry. Any
   modification, deletion, or reordering of entries breaks the chain.

### Chain Properties

Each audit entry contains:

- Timestamp.
- Operation type (unlock, lock, secret read/write/delete, profile switch).
- Profile name.
- BLAKE3 hash of the previous entry (chain link).
- BLAKE3 hash of the current entry's contents.

The chain starts from a genesis entry created at `sesame init`. The hash algorithm is
configurable via `CryptoConfigToml.audit_hash` (`core-config/src/schema_crypto.rs`):
BLAKE3 (default) or SHA-256 (governance-compatible).

## Compliance Mapping

### NIST 800-53

| Control | Open Sesame Mechanism |
|---------|----------------------|
| SC-28 (Protection of Information at Rest) | SQLCipher AES-256-CBC + HMAC-SHA512, Argon2id KDF |
| SC-12 (Cryptographic Key Establishment) | BLAKE3 domain-separated key derivation hierarchy |
| SC-13 (Cryptographic Protection) | Config-selectable algorithms via `CryptoConfig`; governance-compatible profile uses NIST-approved algorithms |
| AU-10 (Non-repudiation) | BLAKE3 hash-chained audit log |
| AC-3 (Access Enforcement) | Per-daemon SecurityLevel clearance, CapabilitySet authorization |
| IA-5 (Authenticator Management) | Multi-factor auth policy (`AuthCombineMode`), hardware factor support |

### DISA STIG

| STIG Control | Open Sesame Mechanism |
|--------------|----------------------|
| Encrypted storage at rest | SQLCipher vaults, per-profile encryption keys |
| Memory protection | `memfd_secret(2)`, guard pages, volatile zeroize |
| Audit trail integrity | BLAKE3 hash chain, tamper detection |
| Least privilege | Landlock, seccomp-bpf, per-daemon clearance levels |
| No core dumps | `LimitCORE=0`, `MADV_DONTDUMP` |

## Extension Pre-Staging

In air-gapped environments, WASI extensions cannot be fetched from OCI registries at runtime.
Extensions are pre-staged during the provisioning phase:

1. On a connected machine, fetch the extension OCI artifact. The `OciReference` type
   (`core-types/src/oci.rs`) captures registry, principal, scope, revision, and provenance
   digest:

   ```text
   registry.example.com/org/extension:1.0.0@sha256:abc123
   ```

2. Transfer the artifact to the air-gapped machine via removable media.

3. Install from the local artifact:

   ```bash
   sesame extension install --from-file /media/extensions/extension-1.0.0.wasm
   ```

The extension's content hash (`manifest_hash` in `AgentType::Extension`, defined in
`core-types/src/security.rs`) is verified at load time regardless of how the artifact
was delivered.
