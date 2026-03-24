# TPM 2.0 Backend

> **Status: Design Intent.** The `AuthFactorId::Tpm` variant exists in `core-types::auth` and
> the `VaultAuthBackend` trait is defined in `core-auth::backend`, but no struct implements
> this factor today. This page documents what the backend will do when built, grounded in the
> trait interface and TPM 2.0 standards.

The TPM backend enables vault unlock by sealing the master key to the platform's Trusted
Platform Module. The sealed blob can only be unsealed when the TPM's Platform Configuration
Registers (PCRs) match the values recorded at seal time, binding the vault to a specific
machine in a specific boot state. It maps to `AuthFactorId::Tpm` (config string `"tpm"`).

## Relevant Standards

| Specification | Role |
|--------------|------|
| **TPM 2.0 Library Specification** (TCG) | Defines the TPM command set, key hierarchies, sealing, and PCR operations. |
| **TCG PC Client Platform TPM Profile** (PTP) | Specifies PCR allocation and boot measurement conventions for PC platforms. |
| **tpm2-tss** (TCG Software Stack) | Userspace C library providing ESAPI, FAPI, and TCTI layers for TPM communication. |
| **tpm2-tools** | Command-line tools built on tpm2-tss, useful for enrollment scripting and debugging. |
| **Linux IMA** (Integrity Measurement Architecture) | Extends PCR 10 with file hashes during runtime. Optional extension point for runtime integrity. |

## Core Concept: Sealing to PCR State

TPM 2.0 sealing binds a data blob to an authorization policy that includes PCR values. The
TPM only unseals the blob if the current PCR values match the policy. This creates a
hardware-enforced link between the vault key and boot integrity state:

1. **At enrollment**, the backend reads the current PCR values, constructs an authorization
   policy from them, and seals the master key under the TPM's Storage Root Key (SRK) with
   that policy.
2. **At unlock**, the backend asks the TPM to unseal the blob. The TPM internally compares
   current PCR values against the sealed policy. If they match, the blob is released. If any
   measured component has changed, unsealing fails.

### PCR Selection

The default PCR selection for desktop Linux:

| PCR | Measures |
|-----|----------|
| 0 | UEFI firmware code |
| 1 | UEFI firmware configuration |
| 2 | Option ROMs / external firmware |
| 3 | Option ROM configuration |
| 7 | Secure Boot state (PK, KEK, db, dbx) |

PCRs 4-6 (boot manager, GPT, resume events) are intentionally excluded by default because
kernel updates would invalidate the seal on every update. The PCR set is configurable at
enrollment time.

Extending to PCR 11 (unified kernel image measurement, used by `systemd-stub`) or PCR 10
(IMA) is supported as an opt-in for higher-assurance configurations.

## Mapping to VaultAuthBackend

### `factor_id()`

Returns `AuthFactorId::Tpm`.

### `backend_id()`

Returns `"tpm"`.

### `name()`

Returns `"TPM 2.0"`.

### `requires_interaction()`

Returns `AuthInteraction::None`. TPM unsealing is a silent, non-interactive operation. The
TPM does not require user presence for unsealing (unlike FIDO2). If a TPM PIN (authValue) is
configured on the sealed object, the interaction type changes to
`AuthInteraction::PasswordEntry`.

### `is_enrolled(profile, config_dir)`

Checks whether `{config_dir}/profiles/{profile}/tpm.enrollment` exists and contains a valid
sealed blob with a recognized version byte.

### `can_unlock(profile, config_dir)`

1. Verify enrollment exists via `is_enrolled()`.
2. Open a connection to the TPM via the TCTI (typically `/dev/tpmrm0`, the kernel resource
   manager).
3. Return `true` if the TPM device is accessible.

PCR matching is not checked here -- a trial unseal could exceed the 100ms budget and may
trigger rate limiting on some TPM implementations.

### `enroll(profile, master_key, config_dir, salt, selected_key_index)`

1. Open a TPM context via tpm2-tss ESAPI.
2. Read the current PCR values for the configured PCR selection (default: 0, 1, 2, 3, 7).
3. Build a `PolicyPCR` authorization policy from the PCR digest.
4. Optionally, combine with `PolicyAuthValue` if the user wants a TPM PIN (defense-in-depth
   against evil-maid attacks where PCRs match but an attacker has physical access).
5. Create a sealed object under the SRK (Storage Hierarchy, persistent handle `0x81000001`
   or equivalent):
   - Object type: `TPM2_ALG_KEYEDHASH` with `seal` attribute.
   - Data: the 32-byte `master_key`.
   - Auth policy: the PCR policy (and optionally PIN policy).
6. Persist the sealed object to a TPM NV index, or serialize the public/private portions
   to disk.
7. Write the enrollment blob to `{config_dir}/profiles/{profile}/tpm.enrollment`.

`selected_key_index` is unused (there is one TPM per machine). It is ignored.

### `unlock(profile, config_dir, salt)`

1. Load the enrollment blob and deserialize the sealed object context.
2. Open a TPM context via ESAPI.
3. Load the sealed object into the TPM.
4. Start a policy session. Execute `PolicyPCR` with the enrolled PCR selection.
5. If a TPM PIN was configured, execute `PolicyAuthValue` and provide the PIN.
6. Call `TPM2_Unseal` with the policy session.
7. If unsealing succeeds, the TPM returns the 32-byte master key.
8. If unsealing fails (PCR mismatch), return `AuthError::UnwrapFailed`. The audit metadata
   should include which PCRs diverged, if determinable.
9. Return `UnlockOutcome`:
   - `master_key`: the unsealed 32-byte key.
   - `ipc_strategy`: `IpcUnlockStrategy::DirectMasterKey`.
   - `factor_id`: `AuthFactorId::Tpm`.
   - `audit_metadata`:
     `{"pcr_selection": "0,1,2,3,7", "tpm_manufacturer": "<vendor>"}`.

### `revoke(profile, config_dir)`

1. If the sealed object was persisted to a TPM NV index, evict it with `TPM2_EvictControl`.
2. Delete `{config_dir}/profiles/{profile}/tpm.enrollment`.

## Enrollment Blob Format

```text
Version: u8 (1)
PCR selection: u32 bitmask (bit N set = PCR N included)
PCR digest at seal time: 32 bytes (SHA-256)
Sealed object public area: length-prefixed bytes (TPM2B_PUBLIC)
Sealed object private area: length-prefixed bytes (TPM2B_PRIVATE)
SRK handle: u32
PIN flag: u8 (0 = no PIN, 1 = PolicyAuthValue included)
```

## FactorContribution

- **`AuthCombineMode::Any`** or **`AuthCombineMode::Policy`**: The backend provides
  `FactorContribution::CompleteMasterKey`. The TPM directly unseals the full 32-byte
  master key.
- **`AuthCombineMode::All`**: The backend provides `FactorContribution::FactorPiece`. At
  enrollment, a random 32-byte piece is sealed (not the master key itself). At unlock, the
  unsealed piece is contributed to the combined HKDF derivation.

## Measured Boot Chain

The security of this backend depends on the integrity of the measured boot chain:

1. **UEFI firmware** measures itself and boot configuration into PCRs 0-3.
2. **Shim / bootloader** (GRUB, systemd-boot) is measured by the firmware into PCR 4.
3. **Secure Boot** state (whether Secure Boot is enabled, which keys are enrolled) is
   reflected in PCR 7.
4. **Kernel and initramfs**, if using `systemd-stub` unified kernel images (UKI), are
   measured into PCR 11.

If an attacker modifies any component in this chain, the corresponding PCR value changes,
and the TPM refuses to unseal the vault key.

### Firmware and Kernel Updates

After a firmware or kernel update, PCR values change and the sealed blob becomes invalid.
Strategies to manage this:

- **Predictive re-sealing.** Before a kernel update, predict the new PCR values (using
  `systemd-pcrphase` or `systemd-measure`) and create a second sealed blob for the new
  values. Delete the old one after successful boot.
- **Fallback factor.** Always maintain a second enrolled factor (password, SSH agent) so
  access is not lost when PCR values change unexpectedly.
- **PCR selection trade-offs.** Excluding volatile PCRs (4, 5, 6) from the policy reduces
  re-enrollment frequency at the cost of reduced boot integrity coverage.

## Platform Binding

The TPM is a physical chip (or firmware TPM) soldered to the motherboard. The sealed blob is
bound to that specific TPM -- it cannot be moved to another machine. This provides:

- **Hardware binding.** The vault is tied to a specific physical device.
- **Anti-theft.** A stolen drive cannot be unlocked on another machine.
- **Anti-cloning.** TPM private keys cannot be extracted (the TPM is designed to resist
  physical attacks on the chip package).

## Integration Dependencies

| Dependency | Type | Purpose |
|-----------|------|---------|
| `tpm2-tss` >= 4.0 | System C library | ESAPI, FAPI, and TCTI for TPM communication |
| `tpm2-tss-devel` | System package | Build-time headers |
| Rust crate: `tss-esapi` | Cargo dependency | Safe Rust bindings to tpm2-tss ESAPI |
| `/dev/tpmrm0` | Kernel device | TPM resource manager (kernel >= 4.12) |
| `tpm2-abrmd` (optional) | System service | Userspace resource manager (alternative to kernel RM) |
| `tpm2-tools` (optional) | System package | Debugging and manual enrollment scripting |

The user must have read/write access to `/dev/tpmrm0` (typically via the `tss` group or a
udev rule).

## Threat Model Considerations

- **Evil-maid with matching PCRs.** If an attacker can reproduce the exact boot chain (same
  firmware, same bootloader, same Secure Boot keys), they can unseal the key. Adding a TPM
  PIN (`PolicyAuthValue`) mitigates this.
- **Firmware TPM (fTPM) vulnerabilities.** Firmware TPMs run inside the CPU or chipset
  firmware. Vulnerabilities in fTPM firmware (e.g., AMD fTPM voltage glitching) can
  potentially extract sealed data. Discrete TPM chips (e.g., Infineon SLB9670) offer
  stronger physical resistance.
- **Running-system compromise.** TPM sealing protects at-rest data. Once the system is
  booted and the vault is unlocked, an attacker with root access can read the master key
  from daemon-secrets process memory. TPM does not protect against runtime compromise.
- **PCR reset attacks.** On some platforms, a hardware reset of the TPM (e.g., via LPC bus
  manipulation) can reset PCRs to zero. Sealing to PCR 7 (Secure Boot state) partially
  mitigates this because Secure Boot measurements are replayed from firmware on reset.
- **vTPM in virtualized environments.** A virtual TPM provides no physical security. The
  hypervisor can read all sealed data. TPM enrollment in a VM is useful for binding a vault
  to a specific VM instance, not for hardware-level tamper resistance.

## See Also

- [Factor Architecture](./factor-architecture.md) -- `VaultAuthBackend` trait definition
  and dispatch
- [SED/Opal](./sed-opal.md) -- Drive-level hardware binding (complementary to TPM)
- [Policy Engine](./policy-engine.md) -- Multi-factor combination modes
- [FIDO2/WebAuthn](./fido2-webauthn.md) -- Alternative hardware factor (portable, not
  platform-bound)
