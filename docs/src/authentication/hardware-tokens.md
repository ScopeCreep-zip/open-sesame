# Hardware Tokens Backend (YubiKey / Smart Cards / PIV)

> **Status: Design Intent.** The `AuthFactorId::Yubikey` variant exists in `core-types::auth`
> and the `VaultAuthBackend` trait is defined in `core-auth::backend`, but no struct implements
> this factor today. This page documents what the backend will do when built, grounded in the
> trait interface and relevant smart card standards.

The hardware tokens backend enables vault unlock using YubiKeys, PIV smart cards, and
PKCS#11-compatible cryptographic tokens. It maps to `AuthFactorId::Yubikey` (config string
`"yubikey"`). Despite the enum variant name referencing YubiKey specifically, the backend is
designed to support the broader category of challenge-response and certificate-based hardware
tokens.

This backend covers the non-FIDO2 capabilities of these devices. For FIDO2/CTAP2 operation,
see the [FIDO2/WebAuthn backend](./fido2-webauthn.md).

## Supported Protocols

### PIV (FIPS 201 / NIST SP 800-73)

Personal Identity Verification is a US government standard for smart card authentication. PIV
cards (and YubiKeys with the PIV applet) contain X.509 certificates and corresponding private
keys in hardware slots. The private key never leaves the card.

PIV slots relevant to Open Sesame:

| Slot | Purpose | PIN Policy | Touch Policy |
|------|---------|-----------|--------------|
| 9a | PIV Authentication | Once per session | Configurable |
| 9c | Digital Signature | Always | Configurable |
| 9d | Key Management | Once per session | Configurable |
| 9e | Card Authentication | Never | Never |

Slot 9d (Key Management) is the natural fit for vault unlock -- it is designed for key
agreement and encryption operations, has a reasonable PIN policy (once per session), and
supports touch policy configuration.

### HMAC-SHA1 Challenge-Response (YubiKey Slot 2)

YubiKeys support HMAC-SHA1 challenge-response in their OTP applet (slots 1 and 2). The host
sends a challenge, the YubiKey computes HMAC-SHA1 with a pre-programmed 20-byte secret, and
returns the 20-byte response. This is the same mechanism used by `ykman` and `ykchalresp`.

Slot 2 (long press) is conventionally used for challenge-response to avoid conflicts with
slot 1 (short press, often configured for OTP).

### PKCS#11

PKCS#11 is the generic smart card interface. Any token with a PKCS#11 module (OpenSC, YubiKey
YKCS11, Nitrokey, etc.) can be used. The backend loads the PKCS#11 shared library, finds a
suitable private key object, and performs a sign or decrypt operation.

## Mapping to VaultAuthBackend

### `factor_id()`

Returns `AuthFactorId::Yubikey`.

### `backend_id()`

Returns `"yubikey"`.

### `name()`

Returns `"Hardware Token"`.

### `requires_interaction()`

Returns `AuthInteraction::HardwareTouch` if the enrolled token has a touch policy enabled.
Returns `AuthInteraction::PasswordEntry` if the token requires a PIN but no touch. The
interaction type is recorded in the enrollment blob and returned by this method.

Most configurations require touch (physical presence), so `HardwareTouch` is the common case.

### `is_enrolled(profile, config_dir)`

Checks whether `{config_dir}/profiles/{profile}/yubikey.enrollment` exists and contains a
valid enrollment blob.

### `can_unlock(profile, config_dir)`

1. Verify enrollment exists.
2. Based on the enrolled protocol:
   - **HMAC-SHA1**: Enumerate USB HID devices matching YubiKey vendor/product IDs.
   - **PIV/PKCS#11**: Attempt to open a PCSC connection and verify that a card is present
     in a reader.
3. Return `true` if a device is detected.

No cryptographic operation is performed (must stay within 100ms).

### `enroll(profile, master_key, config_dir, salt, selected_key_index)`

The enrollment path depends on the protocol. The backend auto-detects the preferred protocol
based on the connected device, or the user specifies via configuration.

#### HMAC-SHA1 Path

1. Enumerate connected YubiKeys. If `selected_key_index` is `Some(i)`, select the i-th
   device.
2. Issue a challenge-response using `salt` as the challenge (hashed to fit the challenge
   length if needed).
3. The YubiKey returns a 20-byte HMAC-SHA1 response.
4. Derive a 32-byte KEK from the HMAC response using HKDF-SHA256:
   `KEK = HKDF-SHA256(ikm=hmac_response, salt=salt,
   info="open-sesame:yubikey:{profile}")`.
5. Wrap `master_key` under the KEK using AES-256-GCM.
6. Store the enrollment blob with the YubiKey serial number, slot number, and wrapped
   master key.

#### PIV Path

1. Open a PCSC connection to the smart card.
2. Select the PIV applet (AID `A0 00 00 03 08`).
3. Authenticate to the card (PIN prompt if required by slot policy).
4. Read the certificate from the selected slot (default: 9d).
5. Generate a random 32-byte challenge.
6. Encrypt the challenge using the public key from the certificate (RSA-OAEP or ECDH
   depending on key type).
7. Derive a KEK:
   `KEK = HKDF-SHA256(ikm=challenge, salt=salt,
   info="open-sesame:piv:{profile}")`.
8. Wrap `master_key` under the KEK.
9. Store the enrollment blob with the certificate fingerprint (SHA-256), slot number,
   encrypted challenge, and wrapped master key.

#### PKCS#11 Path

Follows the PIV path but uses the PKCS#11 API (`C_FindObjects`, `C_Decrypt` / `C_Sign`)
instead of raw APDU commands. The enrollment blob additionally stores the PKCS#11 module
path and token serial number.

### `unlock(profile, config_dir, salt)`

#### HMAC-SHA1 Path

1. Load enrollment blob.
2. Issue challenge-response with `salt` as the challenge.
3. Derive KEK from the HMAC response (same HKDF as enrollment).
4. Unwrap master key. If unwrap fails (different YubiKey or different slot 2 secret), return
   `AuthError::UnwrapFailed`.

#### PIV Path

1. Load enrollment blob, including the encrypted challenge.
2. Open PCSC connection, select PIV applet, authenticate (PIN if required).
3. Decrypt the encrypted challenge using the card's private key (slot 9d).
4. Derive KEK from the decrypted challenge (same HKDF as enrollment).
5. Unwrap master key.

#### Common Outcome

Return `UnlockOutcome`:

- `master_key`: the unwrapped 32-byte key.
- `ipc_strategy`: `IpcUnlockStrategy::DirectMasterKey`.
- `factor_id`: `AuthFactorId::Yubikey`.
- `audit_metadata`:
  `{"protocol": "hmac-sha1|piv|pkcs11", "serial": "<device_serial>", "slot": "<slot>"}`.

### `revoke(profile, config_dir)`

Delete `{config_dir}/profiles/{profile}/yubikey.enrollment`. Does not modify the token
itself (the HMAC secret or PIV keys remain on the device).

## Enrollment Blob Format

```text
Version: u8 (1)
Protocol: u8 (1 = HMAC-SHA1, 2 = PIV, 3 = PKCS#11)
Device serial: length-prefixed UTF-8
Slot/key identifier: length-prefixed UTF-8
Interaction type: u8 (maps to AuthInteraction variant)
--- Protocol-specific fields ---
[HMAC-SHA1]
  Wrapped master key: 12-byte nonce || ciphertext || 16-byte GCM tag
[PIV]
  Certificate fingerprint: 32 bytes (SHA-256)
  Encrypted challenge: length-prefixed bytes
  Wrapped master key: 12-byte nonce || ciphertext || 16-byte GCM tag
[PKCS#11]
  Module path: length-prefixed UTF-8
  Token serial: length-prefixed UTF-8
  Certificate fingerprint: 32 bytes
  Encrypted challenge: length-prefixed bytes
  Wrapped master key: 12-byte nonce || ciphertext || 16-byte GCM tag
```

## FactorContribution

- **`AuthCombineMode::Any`** or **`AuthCombineMode::Policy`**: The backend provides
  `FactorContribution::CompleteMasterKey`. It independently unwraps the full master key.
- **`AuthCombineMode::All`**: The backend provides `FactorContribution::FactorPiece`. For
  HMAC-SHA1, the HKDF output derived from the HMAC response is the piece (32 bytes). For
  PIV, the decrypted challenge is the piece. The piece is contributed to the combined HKDF
  derivation.

## Touch Requirement for Physical Presence

YubiKeys and some smart cards support a touch policy: the device requires the user to
physically touch a contact sensor before performing a cryptographic operation. This provides
proof of physical presence, mitigating malware that silently uses the token while plugged in.

| Policy | Behavior |
|--------|----------|
| Never | No touch required (default for HMAC-SHA1 on some firmware) |
| Always | Touch required for every operation |
| Cached | Touch required once, cached for 15 seconds |

The backend records the touch policy in the enrollment blob so that
`requires_interaction()` returns the correct `AuthInteraction` variant. The daemon overlay
displays a "touch your key" prompt when `AuthInteraction::HardwareTouch` is indicated.

## HMAC-SHA1 Key Derivation Detail

The HMAC-SHA1 response is only 20 bytes, insufficient for a 32-byte AES key directly. The
HKDF-SHA256 expansion step stretches this to 32 bytes:

- The HMAC-SHA1 secret on the YubiKey is 20 bytes (160 bits), programmed at configuration
  time.
- The challenge (vault salt) is up to 64 bytes.
- The 20-byte HMAC output has at most 160 bits of entropy.
- HKDF's security bound is `min(input_entropy, hash_output_length)` = 160 bits, which
  exceeds the 128-bit security target for the derived 256-bit KEK.

## Integration Dependencies

| Dependency | Type | Purpose |
|-----------|------|---------|
| `pcsc-lite` + `libpcsclite-dev` | System library | PCSC smart card access |
| `pcscd` | System service | Smart card daemon (must be running for PIV/PKCS#11) |
| `opensc` (optional) | System package | PKCS#11 module and generic smart card drivers |
| `ykpers` / `yubikey-manager` (optional) | System library/tool | YubiKey HID communication for HMAC-SHA1 |
| Rust crate: `pcsc` | Cargo dependency | PCSC bindings for PIV |
| Rust crate: `yubikey` | Cargo dependency | YubiKey PIV operations |
| Rust crate: `cryptoki` | Cargo dependency | PKCS#11 bindings |
| Rust crate: `yubico-manager` or `challenge-response` | Cargo dependency | HMAC-SHA1 challenge-response |

## Threat Model Considerations

- **HMAC-SHA1 secret extraction.** The HMAC secret on a YubiKey cannot be read back after
  programming. Extracting it requires destructive chip analysis.
- **PIN brute-force.** PIV PINs have a retry counter (default 3 attempts before lockout).
  After lockout, the PUK (PIN Unlock Key) is required. After PUK lockout, the PIV applet
  must be reset (destroying all keys).
- **Token loss.** If the token is lost, the enrollment blob is useless without the physical
  device. Recovery requires an alternative enrolled factor.
- **Relay attacks (HMAC-SHA1).** HMAC-SHA1 challenge-response over USB HID can be relayed
  over a network. Touch policy (set to "always") mitigates this by requiring physical
  presence.
- **Relay attacks (PIV).** Smart card operations over PCSC can be relayed using tools like
  `virtualsmartcard`. Touch policy on YubiKey PIV mitigates this.
- **SHA-1 and HMAC-SHA1.** HMAC-SHA1 is not affected by SHA-1 collision attacks. HMAC
  security depends on the PRF property of the compression function, not collision resistance.
  HMAC-SHA1 remains secure for key derivation.

## See Also

- [Factor Architecture](./factor-architecture.md) -- `VaultAuthBackend` trait definition
  and dispatch
- [FIDO2/WebAuthn](./fido2-webauthn.md) -- FIDO2 mode of the same hardware (different
  protocol)
- [TPM](./tpm.md) -- Platform-bound hardware factor (non-portable)
- [Policy Engine](./policy-engine.md) -- Multi-factor combination modes
