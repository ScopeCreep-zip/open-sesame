# Self-Encrypting Drive (SED) / TCG Opal Backend

> **Status: Design Intent.** No `AuthFactorId` variant exists for SED/Opal today. This
> backend is a future extension that would require adding an `AuthFactorId::SedOpal` variant
> to `core-types::auth`. The `VaultAuthBackend` trait in `core-auth::backend` defines the
> interface it would implement. This page documents the design intent.

The SED/Opal backend enables vault unlock by binding the master key to a Self-Encrypting
Drive's hardware encryption using the TCG Opal 2.0 specification. The drive's encryption
controller holds the key material, accessible only after the drive is unlocked with the
correct credentials. This provides protection against physical drive theft without relying
on software-layer full-disk encryption.

## Relevant Standards

| Specification | Role |
|--------------|------|
| **TCG Opal 2.0** (Trusted Computing Group) | Defines the SED management interface: locking ranges, authentication, band management, and the Security Protocol command set. |
| **TCG Opal SSC** (Security Subsystem Class) | Profile of TCG Storage that Opal-compliant drives implement. |
| **ATA Security Feature Set** | Legacy drive locking (ATA password). Opal supersedes this but some drives support both. |
| **NVMe Security Send/Receive** | Transport for TCG commands on NVMe drives. |
| **IEEE 1667** | Silo-based authentication for storage devices (used by some USB encrypted drives). |

## Core Concept: Drive-Bound Vault Keys

A Self-Encrypting Drive transparently encrypts all data written to it using a Media
Encryption Key (MEK) stored in the drive controller. The MEK is wrapped by a Key Encryption
Key (KEK) derived from the user's authentication credential. Without the correct credential,
the MEK cannot be unwrapped and the drive contents are cryptographically inaccessible.

The SED/Opal backend leverages this mechanism for vault key storage:

1. **At enrollment**, the backend stores the vault master key within an Opal locking range's
   DataStore table. The locking range is protected by an Opal credential that the backend
   manages.
2. **At unlock**, the backend authenticates to the Opal Security Provider (SP) using the
   stored credential, reads the master key from the DataStore, and provides it to
   daemon-secrets.

### Locking Range Architecture

Opal drives support multiple locking ranges. The backend uses a dedicated locking range for
Open Sesame, separate from the global locking range (which may be used for full-disk
encryption by the OS):

- **Global Range (Range 0)**: Managed by the OS or firmware for full-disk encryption (e.g.,
  `sedutil-cli`, BitLocker, `systemd-cryptenroll`).
- **Dedicated Range (Range N)**: A small range allocated for Open Sesame DataStore usage.
  Contains only the encrypted vault master key blob.

If a dedicated range cannot be allocated (drive does not support multiple ranges, or all
ranges are in use), the backend falls back to storing the wrapped key in the DataStore table
associated with the Admin SP.

## Mapping to VaultAuthBackend

### `factor_id()`

Returns `AuthFactorId::SedOpal` (to be added to the enum).

### `backend_id()`

Returns `"sed-opal"`.

### `name()`

Returns `"Self-Encrypting Drive"`.

### `requires_interaction()`

Returns `AuthInteraction::None`. SED unlock is non-interactive. The backend authenticates to
the drive controller programmatically using a credential derived from device-specific secrets,
not a user-entered password.

### `is_enrolled(profile, config_dir)`

Checks whether `{config_dir}/profiles/{profile}/sed-opal.enrollment` exists and contains a
valid enrollment blob identifying the drive (serial number, locking range, and Opal credential
reference).

### `can_unlock(profile, config_dir)`

1. Verify enrollment exists.
2. Identify the enrolled drive by serial number.
3. Check that the drive is present and accessible (block device exists or can be found by
   serial via sysfs).
4. Return `true` if the drive is present.

Does not attempt Opal authentication (may exceed 100ms and may trigger lockout counters on
failure).

### `enroll(profile, master_key, config_dir, salt, selected_key_index)`

1. Enumerate Opal-capable drives by sending TCG Discovery 0 to each block device.
2. If `selected_key_index` is `Some(i)`, select the i-th drive. Otherwise select the first
   Opal-capable drive.
3. Authenticate to the drive's Admin SP using the SID (Security Identifier) or a
   pre-configured admin credential.
4. Allocate or identify a locking range for Open Sesame use.
5. Generate a random Opal credential for the locking range (or derive one from `salt` and a
   device-specific secret).
6. Store the vault `master_key` in the DataStore table of the locking range.
7. Lock the range, binding it to the generated credential.
8. Write the enrollment blob to `{config_dir}/profiles/{profile}/sed-opal.enrollment`
   containing the drive serial, locking range index, and the Opal credential (encrypted
   under a key derived from `salt` and the machine ID).

### `unlock(profile, config_dir, salt)`

1. Load the enrollment blob.
2. Derive the Opal credential (decrypt using `salt` and machine ID).
3. Open a session to the drive's Locking SP.
4. Authenticate with the credential.
5. Read the master key from the DataStore table.
6. Return `UnlockOutcome`:
   - `master_key`: the 32-byte key read from the DataStore.
   - `ipc_strategy`: `IpcUnlockStrategy::DirectMasterKey`.
   - `factor_id`: `AuthFactorId::SedOpal`.
   - `audit_metadata`:
     `{"drive_serial": "<serial>", "locking_range": "<N>"}`.

### `revoke(profile, config_dir)`

1. Authenticate to the drive's Admin SP.
2. Erase the master key from the DataStore table (overwrite with zeros).
3. Optionally release the locking range allocation.
4. Delete `{config_dir}/profiles/{profile}/sed-opal.enrollment`.

## Enrollment Blob Format

```text
Version: u8 (1)
Drive serial: length-prefixed UTF-8
Drive model: length-prefixed UTF-8
Block device path at enrollment time: length-prefixed UTF-8 (informational; may change)
Locking range index: u16
Opal credential (encrypted): 12-byte nonce || ciphertext || 16-byte GCM tag
Machine binding hash: 32 bytes (SHA-256 of machine-id, used in credential derivation)
```

## FactorContribution

- **`AuthCombineMode::Any`** or **`AuthCombineMode::Policy`**: The backend provides
  `FactorContribution::CompleteMasterKey`. The drive hardware releases the full master key
  from the DataStore.
- **`AuthCombineMode::All`**: The backend provides `FactorContribution::FactorPiece`. A
  random 32-byte piece (not the master key) is stored in the DataStore and contributed to
  combined HKDF derivation.

## Pre-Boot Authentication

TCG Opal defines a Pre-Boot Authentication (PBA) mechanism: a small region of the drive (the
Shadow MBR) is presented to the BIOS/UEFI before the main OS boots. The PBA image
authenticates the user and unlocks the drive before the OS sees the encrypted data.

Open Sesame does not implement PBA. It operates entirely within the running OS. If the drive
is locked at boot by system-level SED management, Open Sesame assumes the drive is already
unlocked by the time daemon-secrets starts. The backend uses Opal only for its DataStore
facility (key storage with hardware-gated access), not for drive-level boot locking.

## Integration Dependencies

| Dependency | Type | Purpose |
|-----------|------|---------|
| `sedutil-cli` | System tool | Opal drive management (enrollment, locking range setup) |
| `libata` / kernel NVMe driver | Kernel | ATA Security / NVMe Security Send/Receive commands |
| Rust crate: `sedutil-rs` or direct ioctl | Cargo dependency | Programmatic Opal SP communication |
| `/dev/sdX` or `/dev/nvmeXnY` | Block device | Target drive |
| Root or `CAP_SYS_RAWIO` | Privilege | Required for TCG command passthrough via SG_IO / NVMe admin commands |

### Privilege Requirements

Opal commands require raw SCSI/ATA/NVMe command passthrough, which typically requires root
or `CAP_SYS_RAWIO`. Since daemon-secrets runs as a system service, this is consistent with
its privilege model. Enrollment and revocation also require admin-level Opal credentials
(SID or Admin1 authority).

## Threat Model

### Protects Against

- **Physical drive theft.** An attacker who steals the drive (but not the machine) cannot
  access the vault master key. The DataStore contents are encrypted by the drive's MEK,
  inaccessible without the Opal credential.
- **Offline forensic imaging.** Imaging the raw drive platters or flash chips yields only
  ciphertext.
- **Cold boot on different hardware.** Moving the drive to another machine does not help
  because the Opal credential is derived from the original machine's identity.

### Does Not Protect Against

- **Running-system compromise.** Once the OS is booted and the drive is unlocked, an
  attacker with root access can read the DataStore contents. SED encryption is transparent
  to the running OS after unlock.
- **DMA attacks.** An attacker with physical access to the running machine can use DMA
  (e.g., via Thunderbolt or FireWire) to read memory containing the unlocked master key.
- **SED firmware vulnerabilities.** Research has demonstrated that some SED implementations
  have firmware bugs allowing bypass of Opal locking without the credential (e.g., the 2018
  Radboud University disclosure affecting Crucial and Samsung drives). The backend cannot
  detect or mitigate firmware-level flaws.
- **Evil-maid with machine access.** If the attacker has access to the original machine (not
  just the drive), they can boot the machine, wait for the drive to be unlocked by the OS,
  and extract the master key.

## Complementary Use with TPM

SED/Opal and TPM provide complementary hardware binding:

- **TPM** binds the vault to the boot integrity state (firmware, bootloader, Secure Boot
  policy). Protects against software-level boot chain tampering.
- **SED/Opal** binds the vault to the physical drive. Protects against drive theft.

Using both factors in `AuthCombineMode::All` provides defense in depth: the vault is bound
to both the machine's boot state and the specific physical drive.

## See Also

- [Factor Architecture](./factor-architecture.md) -- `VaultAuthBackend` trait definition
  and dispatch
- [TPM](./tpm.md) -- Complementary platform-binding factor
- [Policy Engine](./policy-engine.md) -- Combining SED with other factors
