# Biometrics Backend

> **Status: Design Intent.** The `AuthFactorId::Fingerprint` variant exists in
> `core-types::auth` and the `VaultAuthBackend` trait is defined in `core-auth::backend`, but
> no struct implements this factor today. This page documents what the backend will do when
> built, grounded in the trait interface and platform biometric APIs.

The biometrics backend enables vault unlock gated by fingerprint verification (and, in the
future, other biometric modalities such as face recognition). It maps to
`AuthFactorId::Fingerprint` (config string `"fingerprint"`). The critical design principle:
biometric data is never used as key material. Biometrics are authentication gates that release
a stored key, not secrets from which keys are derived.

## Design Principle: Biometrics Are Not Secrets

Biometric features (fingerprint minutiae, facial geometry) are not secret -- they can be
observed, photographed, or lifted from surfaces. They are also not stable -- they vary between
readings. For these reasons, the biometrics backend never derives cryptographic key material
from biometric data. Instead:

1. At enrollment, the master key (or a KEK) is encrypted and stored on disk.
2. The decryption key for that blob is held in a platform keystore that requires biometric
   verification to release.
3. At unlock, the platform biometric subsystem verifies the user, and if successful, releases
   the decryption key to the backend.

The biometric template (the mathematical representation of the fingerprint or face) never
leaves the platform biometric subsystem. Open Sesame never sees, stores, or transmits
biometric data.

## Platform Biometric APIs

### Linux: fprintd

On Linux, fingerprint authentication is mediated by `fprintd`, a D-Bus service that manages
fingerprint readers and templates. The authentication flow:

1. The backend calls `net.reactivated.Fprint.Device.VerifyStart` on the fprintd D-Bus
   interface.
2. `fprintd` communicates with the fingerprint sensor hardware via `libfprint`, acquires a
   fingerprint image, and matches it against enrolled templates.
3. On match, `fprintd` emits a `VerifyStatus` signal with `verify-match`. On failure,
   `verify-no-match` or `verify-retry-scan`.
4. The backend calls `VerifyStop` to end the session.

The backend uses the fprintd D-Bus API directly (not PAM) to avoid requiring a full PAM
session context.

### Future: macOS LocalAuthentication

On macOS (if platform support is added), `LocalAuthentication.framework` provides Touch ID
and Face ID gating of Keychain items. A Keychain item with
`kSecAccessControlBiometryCurrentSet` requires biometric verification before the Keychain
releases the stored secret. This maps directly to the "biometric gates release of a stored
key" model.

### Future: Windows Hello

On Windows, `Windows.Security.Credentials.KeyCredentialManager` and the Windows Hello
biometric subsystem provide similar gating. The TPM-backed key is released only after
Windows Hello verification succeeds.

## Mapping to VaultAuthBackend

### `factor_id()`

Returns `AuthFactorId::Fingerprint`.

### `backend_id()`

Returns `"fingerprint"`.

### `name()`

Returns `"Fingerprint"`.

### `requires_interaction()`

Returns `AuthInteraction::HardwareTouch`. The user must place their finger on the sensor.

### `is_enrolled(profile, config_dir)`

Checks two conditions:

1. An enrollment blob exists at
   `{config_dir}/profiles/{profile}/fingerprint.enrollment`.
2. At least one fingerprint is enrolled in `fprintd` for the current system user (queried
   via `net.reactivated.Fprint.Device.ListEnrolledFingers`).

Both must be true. If the system fingerprint enrollment is wiped (user re-enrolled fingers
in system settings), the Open Sesame enrollment blob still exists on disk but the platform
verification will match against different templates, making it effectively stale.

### `can_unlock(profile, config_dir)`

1. Verify enrollment exists via `is_enrolled()`.
2. Check that `fprintd` is running (D-Bus name `net.reactivated.Fprint` is available).
3. Check that at least one fingerprint reader device is present.

D-Bus name lookup and device enumeration complete well within the 100ms trait budget.

### `enroll(profile, master_key, config_dir, salt, selected_key_index)`

1. Verify that `fprintd` has at least one enrolled fingerprint for the current user. If not,
   return `AuthError::BackendNotApplicable("no fingerprints enrolled in fprintd; enroll via
   system settings first")`.
2. Generate a random 32-byte storage key.
3. Wrap `master_key` under the storage key using AES-256-GCM.
4. Store the storage key in a location protected by biometric gating:
   - **Primary strategy (Linux):** Store the storage key in the user's kernel keyring
     (`keyctl`) under a session-scoped key. The keyring entry is created with a timeout
     matching the user session. Biometric verification via fprintd acts as the authorization
     gate before the backend retrieves the keyring secret at unlock time.
   - **Fallback strategy:** Encrypt the storage key with a key derived from `salt` and a
     device-specific identifier (machine-id). Store the encrypted storage key in the
     enrollment blob itself. The biometric check acts as the sole authorization gate.
5. Write the enrollment blob to
   `{config_dir}/profiles/{profile}/fingerprint.enrollment`.

`selected_key_index` is unused (there is one biometric subsystem per machine). It is ignored.

### `unlock(profile, config_dir, salt)`

1. Load the enrollment blob.
2. Initiate fingerprint verification via fprintd D-Bus API (`VerifyStart`).
3. Wait for the `VerifyStatus` signal. The daemon overlay displays a "scan your fingerprint"
   prompt.
4. If verification fails (no match, timeout, or sensor error), return
   `AuthError::UnwrapFailed`.
5. If verification succeeds, retrieve the storage key from the kernel keyring (primary
   strategy) or decrypt it from the blob (fallback strategy).
6. Unwrap the master key using the storage key (AES-256-GCM decrypt).
7. Return `UnlockOutcome`:
   - `master_key`: the unwrapped 32-byte key.
   - `ipc_strategy`: `IpcUnlockStrategy::DirectMasterKey`.
   - `factor_id`: `AuthFactorId::Fingerprint`.
   - `audit_metadata`: `{"method": "fprintd", "finger": "<which_finger>"}` (if fprintd
     reports which finger matched).

### `revoke(profile, config_dir)`

1. Remove the storage key from the kernel keyring (if using primary strategy).
2. Delete `{config_dir}/profiles/{profile}/fingerprint.enrollment`.

Does not remove fingerprints from fprintd -- those are system-level enrollments managed by
the user outside of Open Sesame.

## Enrollment Blob Format

```text
Version: u8 (1)
Storage strategy: u8 (1 = kernel keyring, 2 = embedded encrypted key)
Wrapped master key: 12-byte nonce || ciphertext || 16-byte GCM tag
Embedded encrypted storage key (strategy 2 only): 12-byte nonce || ciphertext || 16-byte tag
Device binding hash: 32 bytes (SHA-256 of machine-id || profile name)
```

## FactorContribution

- **`AuthCombineMode::Any`** or **`AuthCombineMode::Policy`**: The backend provides
  `FactorContribution::CompleteMasterKey`. It unwraps the full master key after biometric
  verification succeeds.
- **`AuthCombineMode::All`**: The backend provides `FactorContribution::FactorPiece`. A
  random 32-byte piece (not the master key) is stored behind the biometric gate and
  contributed to HKDF derivation upon successful verification.

The biometric itself does not contribute entropy -- it is a gate. The piece is a random
value generated at enrollment time and stored behind the biometric gate.

## Liveness Detection

Fingerprint sensors vary in their resistance to spoofing:

| Sensor Type | Spoofing Resistance | Notes |
|------------|-------------------|-------|
| **Capacitive** (most laptop sensors) | Moderate | Detects electrical properties of skin. Gummy fingerprints with conductive material can sometimes fool them. |
| **Ultrasonic** (e.g., Qualcomm 3D Sonic) | High | Measures sub-dermal features. More resistant to printed or molded replicas. |
| **Optical** (common in USB readers) | Low | Easiest to spoof with printed or molded fingerprints. |

Open Sesame delegates liveness detection entirely to the sensor hardware and `fprintd`. The
backend does not attempt its own liveness checks. Deployment guidance: use capacitive or
ultrasonic sensors for security-sensitive configurations, and combine biometric with a second
factor via `AuthCombineMode::Policy`.

## Privacy Guarantees

1. **No template storage.** Open Sesame never stores, transmits, or processes biometric
   templates. Templates are managed exclusively by `fprintd` (stored in
   `/var/lib/fprint/`).
2. **No template access.** The backend never requests raw biometric data or template bytes.
   It uses only the verify/match API, which returns a boolean result.
3. **No cross-profile linkability.** The enrollment blob contains no biometric information.
   An attacker who obtains the blob cannot determine whose fingerprint unlocks the vault.
4. **User-controlled deletion.** Revoking the backend deletes only the encrypted key blob.
   Biometric templates remain under user control in fprintd.

## Integration Dependencies

| Dependency | Type | Purpose |
|-----------|------|---------|
| `fprintd` >= 1.94 | System service | Fingerprint verification via D-Bus |
| `libfprint` >= 1.94 | System library | Sensor driver layer (used by fprintd) |
| Rust crate: `zbus` | Cargo dependency | D-Bus client for fprintd communication |
| Rust crate: `keyutils` | Cargo dependency | Linux kernel keyring access (primary storage strategy) |
| Compatible fingerprint reader | Hardware | Any reader supported by libfprint |

## Threat Model Considerations

- **Biometric spoofing.** The backend is only as spoof-resistant as the sensor hardware. It
  should not be the sole factor for high-value vaults. Combining biometric with password or
  FIDO2 via `AuthCombineMode::Policy` is recommended.
- **Stolen enrollment blob.** The blob is useless without passing biometric verification
  (primary strategy) or without the device-specific derivation inputs (fallback strategy).
  The biometric gate is the critical protection.
- **fprintd compromise.** If an attacker can inject false D-Bus responses (by compromising
  fprintd or the user's D-Bus session), they can bypass biometric verification. Running
  fprintd as a system service (not user session) and using D-Bus mediation via AppArmor or
  SELinux mitigates this.
- **Irrevocable biometrics.** If a fingerprint is compromised (lifted from a surface), the
  user cannot change their fingerprint. Mitigation: re-enroll with a different finger and
  revoke the old enrollment, or add a second factor requirement via policy.
- **Fallback strategy weakness.** The embedded-key fallback strategy protects the storage key
  only with device-specific derivation (machine-id + salt). An attacker with the enrollment
  blob and knowledge of the machine-id can bypass the biometric gate entirely. The primary
  strategy (kernel keyring) is strongly preferred.

## See Also

- [Factor Architecture](./factor-architecture.md) -- `VaultAuthBackend` trait definition
  and dispatch
- [FIDO2/WebAuthn](./fido2-webauthn.md) -- Roaming authenticator with on-device biometric UV
- [Policy Engine](./policy-engine.md) -- Combining biometric with other factors
