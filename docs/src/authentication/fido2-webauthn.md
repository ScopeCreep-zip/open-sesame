# FIDO2 / WebAuthn Backend

> **Status: Design Intent.** The `AuthFactorId::Fido2` variant exists in `core-types::auth`
> and the `VaultAuthBackend` trait is defined in `core-auth::backend`, but no struct implements
> this factor today. This page documents what the backend will do when built, grounded in the
> trait interface and FIDO2 standards.

The FIDO2 backend enables vault unlock using CTAP2-compliant authenticators -- USB security
keys, platform authenticators, and BLE/NFC tokens. It maps to `AuthFactorId::Fido2` (config
string `"fido2"`) and operates through `libfido2` directly, without a browser or the WebAuthn
JavaScript API.

## Relevant Standards

| Standard | Role |
|----------|------|
| **CTAP2** (Client to Authenticator Protocol 2.1) | Wire protocol between host and authenticator. Open Sesame acts as the CTAP2 platform (client). |
| **WebAuthn Level 2** (W3C) | Defines the relying party model, credential creation, and assertion ceremonies. Open Sesame borrows the data model (RP ID, credential ID, user handle) but does not use a browser. |
| **HMAC-secret extension** (CTAP2.1) | Allows the authenticator to compute a deterministic symmetric secret from a caller-provided salt, without exposing the credential private key. This is the primary key-derivation mechanism. |
| **credProtect extension** | Controls whether credentials are discoverable without user verification. Should be set to level 2 or 3 to prevent silent credential enumeration. |

## Mapping to VaultAuthBackend

### `factor_id()`

Returns `AuthFactorId::Fido2`.

### `backend_id()`

Returns `"fido2"`.

### `name()`

Returns `"FIDO2/WebAuthn"` (for overlay display and audit logs).

### `requires_interaction()`

Returns `AuthInteraction::HardwareTouch`. CTAP2 authenticators require user presence (UP) at
minimum; most also support user verification (UV) via on-device PIN or biometric. Both require
physical interaction.

### `is_enrolled(profile, config_dir)`

Checks whether a file `{config_dir}/profiles/{profile}/fido2.enrollment` exists and contains
a valid enrollment blob (see Enrollment Blob Format below). The enrollment record contains
the credential ID, relying party ID, and the wrapped master key blob. This is a synchronous
filesystem check with no device communication.

### `can_unlock(profile, config_dir)`

1. Verify enrollment exists via `is_enrolled()`.
2. Enumerate connected FIDO2 devices via `libfido2` device enumeration.
3. Return `true` if at least one device is present.

Device enumeration over HID typically completes in under 20ms, well within the 100ms trait
budget. This method does not verify that the connected device holds the enrolled credential
-- that requires a CTAP2 transaction and user interaction, which is deferred to `unlock()`.

### `enroll(profile, master_key, config_dir, salt, selected_key_index)`

Enrollment proceeds as follows:

1. Enumerate connected FIDO2 authenticators. If `selected_key_index` is `Some(i)`, select
   the i-th device; otherwise select the first.
2. Construct a relying party ID: `open-sesame:{profile}` (synthetic, not a web origin).
3. Generate a random 32-byte user ID and a random 16-byte challenge.
4. Perform `authenticatorMakeCredential` with:
   - Algorithm: ES256 (COSE -7) preferred, EdDSA (COSE -8) as fallback.
   - Extensions: `hmac-secret: true`, `credProtect: 2`, `rk: true` (resident key).
   - User verification: preferred (UV if the device supports it).
5. Store the attestation response (credential ID, public key, attestation object).
6. Immediately perform a `getAssertion` with the `hmac-secret` extension, passing `salt` as
   the HMAC-secret salt input. The authenticator returns a 32-byte HMAC output.
7. Use the HMAC output as a key-encryption key (KEK). Wrap `master_key` under this KEK using
   AES-256-GCM with a random 12-byte nonce.
8. Serialize and write the enrollment blob to
   `{config_dir}/profiles/{profile}/fido2.enrollment`.

### `unlock(profile, config_dir, salt)`

Unlock proceeds as follows:

1. Load and deserialize the enrollment blob.
2. Perform `authenticatorGetAssertion` for the enrolled RP ID and credential ID, with:
   - Extensions: `hmac-secret` with `salt` as input.
   - User verification: preferred.
3. The authenticator returns a 32-byte HMAC output (the KEK) and an assertion signature.
4. Unwrap the master key from the enrollment blob using the KEK (AES-256-GCM decrypt).
5. If unwrap fails (wrong device or tampered blob), return `AuthError::UnwrapFailed`.
6. Return `UnlockOutcome`:
   - `master_key`: the unwrapped 32-byte key.
   - `ipc_strategy`: `IpcUnlockStrategy::DirectMasterKey`.
   - `factor_id`: `AuthFactorId::Fido2`.
   - `audit_metadata`:
     `{"aaguid": "<hex>", "credential_id": "<hex>", "uv": "true|false"}`.

### `revoke(profile, config_dir)`

Deletes `{config_dir}/profiles/{profile}/fido2.enrollment`. Does not attempt to delete the
resident credential from the authenticator (CTAP2 does not guarantee remote deletion support
across all devices).

## Enrollment Blob Format

```text
Version: u8 (1)
RP ID: length-prefixed UTF-8
Credential ID: length-prefixed bytes
Public Key (COSE): length-prefixed bytes
Attestation Object: length-prefixed bytes (optional, for future policy use)
Wrapped Master Key: 12-byte nonce || ciphertext || 16-byte GCM tag
```

The blob is versioned to allow schema evolution. The version byte is checked on load; unknown
versions produce `AuthError::InvalidBlob`.

## FactorContribution

- **`AuthCombineMode::Any`** or **`AuthCombineMode::Policy`**: The backend provides
  `FactorContribution::CompleteMasterKey`. It independently unwraps the full 32-byte master
  key from its enrollment blob.
- **`AuthCombineMode::All`**: The backend provides `FactorContribution::FactorPiece`. The
  32-byte HMAC-secret output is contributed as one input to the combined HKDF derivation. In
  this mode, enrollment does not wrap the master key; it stores only the credential ID and
  RP ID. The HMAC-secret output itself is the piece.

## Platform Authenticator vs Roaming Authenticator

FIDO2 defines two authenticator attachment modalities:

- **Platform authenticators** are built into the host device (e.g., Windows Hello TPM-backed
  key, macOS Touch ID Secure Enclave key, Android biometric key). On Linux desktops, platform
  authenticators are uncommon.
- **Roaming authenticators** are external devices connected via USB HID, NFC, or BLE (e.g.,
  YubiKey 5, SoloKeys, Google Titan, Nitrokey).

This backend targets roaming authenticators. For platform biometric unlock on Linux, the
[Biometrics backend](./biometrics.md) (`AuthFactorId::Fingerprint`) is the appropriate
choice -- it uses `fprintd`/`polkit` rather than CTAP2.

## Browser-less Operation

Open Sesame communicates directly with authenticators via `libfido2`, the reference CTAP2 C
library maintained by Yubico. Consequences:

- **No origin binding.** The RP ID is a synthetic string (`open-sesame:{profile}`), not a
  web origin. There is no TLS channel binding.
- **No browser UI.** The daemon overlay prompts the user to touch the authenticator. The
  backend blocks on the CTAP2 transaction until UP/UV is satisfied or a timeout expires.
- **Attestation is informational.** The attestation object is stored for optional future
  policy enforcement (e.g., restricting enrollment to FIPS-certified authenticators via FIDO
  Metadata Service lookup) but is not verified during normal unlock.

## Integration Dependencies

| Dependency | Type | Purpose |
|-----------|------|---------|
| `libfido2` >= 1.13 | System C library | CTAP2 HID/NFC/BLE transport |
| `libfido2-dev` | System package | Build-time headers and pkg-config |
| Rust crate: `libfido2` or `ctap-hid-fido2` | Cargo dependency | Safe Rust bindings |
| udev rule or `plugdev` group | System config | User access to `/dev/hidraw*` devices |

## Threat Model Considerations

- **Deterministic KEK.** The HMAC-secret output is deterministic for a given (credential,
  salt) pair. Changing the vault salt invalidates the KEK; re-enrollment is required after
  re-keying.
- **Loss recovery.** If the authenticator is lost or destroyed, the enrollment blob is
  useless. Recovery requires another enrolled factor (password, SSH agent, etc.).
- **Clone resistance.** Depends on the authenticator hardware. Devices with a secure element
  (YubiKey 5, SoloKeys v2) resist cloning. Software-only CTAP2 implementations (e.g.,
  `libfido2` soft token) provide no clone resistance.
- **PIN brute-force.** CTAP2 authenticators implement per-device PIN retry counters with
  lockout. This is enforced by the authenticator firmware, not by Open Sesame.
- **Relay attacks.** An attacker with network access to the USB HID device could relay CTAP2
  messages. Physical proximity verification is delegated to the authenticator's UP mechanism.

## See Also

- [Factor Architecture](./factor-architecture.md) -- `VaultAuthBackend` trait definition
  and dispatch
- [Hardware Tokens](./hardware-tokens.md) -- YubiKey PIV/challenge-response (non-FIDO2
  protocols)
- [Biometrics](./biometrics.md) -- Platform biometric unlock via fprintd
- [Policy Engine](./policy-engine.md) -- Multi-factor combination modes (`Any`, `All`,
  `Policy`)
