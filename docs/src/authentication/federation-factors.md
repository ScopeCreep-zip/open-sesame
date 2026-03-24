# Federation Factors

> **Status: Design Intent.** No `AuthFactorId` variant or `VaultAuthBackend` implementation
> exists for federation today. Federation is a future capability that builds on top of the
> existing factor backends. This page documents the design intent for cross-device factor
> delegation.

Federation factors allow a user to satisfy an authentication factor on one device and have
that satisfaction count toward unlocking a vault on a different device. This enables scenarios
such as unlocking a headless server's vault using a phone's fingerprint sensor, or centrally
managing vault unlock across a fleet of machines via an HSM.

## Core Concepts

### Factor Delegation

Factor delegation separates where a factor is satisfied from where the vault is unlocked:

- **Origin device**: The device where the user physically performs authentication (touches a
  FIDO2 key, scans a fingerprint, enters a password).
- **Target device**: The device where the vault resides and where daemon-secrets runs.
- **Delegation token**: A cryptographic proof that a specific factor was satisfied on the
  origin device, valid for a bounded time and scope.

The delegation token does not contain the master key. It is an authorization proof that
daemon-secrets on the target device accepts in lieu of direct local factor satisfaction.

### Trust Chain

Federation introduces a multi-hop trust chain:

```text
Device Attestation -> Factor Proof -> Delegation Token -> Vault Unlock
```

1. **Device attestation.** The origin device proves its identity and integrity to the target
   device. This may use TPM remote attestation, a pre-shared device certificate, or a Noise
   IK session where the origin device's static public key is pre-enrolled.
2. **Factor proof.** The origin device satisfies a factor locally (e.g., fingerprint
   verification via fprintd) and produces a signed statement: "factor F was satisfied by
   user U at time T on device D."
3. **Delegation token.** The factor proof is wrapped into a delegation token that specifies
   the target vault, permitted operations, expiration time, and scope restrictions.
4. **Vault unlock.** The target device's daemon-secrets receives the delegation token,
   verifies the full chain (device identity, factor proof signature, token validity, scope),
   and uses it to authorize the unlock.

## Delegation Token Structure

```text
Version: u8 (1)
Token ID: 16 bytes (random, for revocation and audit)
Origin device ID: 32 bytes (public key fingerprint or device certificate hash)
Factor ID: AuthFactorId (which factor was satisfied)
Factor proof signature: length-prefixed bytes (signed by origin device's attestation key)
Timestamp: u64 (Unix epoch seconds when factor was satisfied)
Expiry: u64 (Unix epoch seconds when token becomes invalid)
Target vault: length-prefixed UTF-8 (profile name on target device)
Scope: DelegationScope (see below)
Token signature: length-prefixed bytes (signed by origin device's delegation key)
```

### DelegationScope

Delegation tokens carry explicit scope restrictions that limit what the token can authorize:

```rust
struct DelegationScope {
    /// Which operations the token authorizes.
    allowed_operations: Vec<DelegatedOperation>,
    /// Maximum number of times the token can be used (None = unlimited within expiry).
    max_uses: Option<u32>,
    /// If set, token is only valid from these source IP addresses.
    source_addresses: Option<Vec<IpAddr>>,
}

enum DelegatedOperation {
    /// Unlock the vault (read access to secrets).
    VaultUnlock,
    /// Unlock and modify secrets.
    VaultUnlockWrite,
    /// Unlock a specific secret by path.
    SecretAccess(String),
}
```

### Scope Narrowing

A delegation token can only have equal or narrower scope than the factor it represents.
Scope narrowing is enforced at token creation time:

- A password factor with full vault access can delegate a token that only unlocks specific
  secrets.
- A biometric factor can delegate a token valid for 5 minutes instead of the session
  duration.
- A FIDO2 factor can delegate a token restricted to a single use.

Scope can never be widened. A token scoped to `SecretAccess("/ssh/id_ed25519")` cannot be
used to unlock the entire vault.

## Relationship to VaultAuthBackend

Federation does not implement `VaultAuthBackend` directly. Instead, it wraps existing
backends:

1. On the **origin device**, a standard `VaultAuthBackend` (fingerprint, FIDO2, password,
   etc.) performs the actual authentication.
2. The origin device's federation service creates a delegation token signed with the device's
   attestation key.
3. On the **target device**, a `FederationReceiver` component (a new daemon component, not a
   `VaultAuthBackend`) validates the token and translates it into an internal unlock
   authorization.

The target device's daemon-secrets treats a validated delegation token as equivalent to a
local factor satisfaction for policy evaluation purposes. If the vault's
`AuthCombineMode::Policy` requires `AuthFactorId::Fingerprint`, a delegation token proving
fingerprint satisfaction on a trusted origin device satisfies that requirement.

### IPC Flow

```text
Origin Device                          Target Device
─────────────                          ─────────────
User touches fingerprint sensor
    |
    v
FingerprintBackend.unlock() succeeds
    |
    v
FederationService creates
  delegation token
    |
    v
Noise IK session ──────────────────>  FederationReceiver
                                           |
                                           v
                                      Verify device attestation
                                      Verify factor proof signature
                                      Check token expiry and scope
                                           |
                                           v
                                      daemon-secrets accepts
                                      factor as satisfied
                                           |
                                           v
                                      Policy engine evaluates
                                      (may need more factors)
                                           |
                                           v
                                      Vault unlocked (if policy met)
```

### FactorContribution

Federation does not change the `FactorContribution` type of the underlying factor. If the
delegated factor provides `FactorContribution::CompleteMasterKey` locally, the delegation
token authorizes release of the same master key on the target device (which must have its
own wrapped copy from a prior enrollment of that factor type).

In `AuthCombineMode::All`, federation cannot provide a `FactorPiece` remotely because the
piece must be combined locally with other pieces on the target device. Federation in `All`
mode requires the origin device to contribute its piece to a multi-party key derivation
protocol. This is deferred to a future design iteration (see Open Questions).

## Use Cases

### Unlock Server Vault from Phone

A developer manages secrets on a headless server. The server vault requires fingerprint +
password (`AuthCombineMode::Policy`, both required). The developer:

1. Scans a fingerprint on their phone (origin device).
2. The phone creates a delegation token for the server vault, scoped to `VaultUnlock`,
   expiring in 60 seconds.
3. The token is sent to the server over a Noise IK session (phone's static public key is
   pre-enrolled on the server).
4. The server's daemon-secrets accepts the fingerprint factor as satisfied.
5. The developer enters a password directly on the server (or via SSH).
6. Both policy requirements are met; the vault unlocks.

### Fleet Unlock via Central HSM

An organization operates a fleet of machines, each with a vault. A central HSM holds a
master delegation key. An administrator:

1. Authenticates to the HSM management interface (FIDO2 + password).
2. The HSM creates delegation tokens for a set of target machines, each scoped to
   `VaultUnlock`, expiring in 5 minutes.
3. Tokens are distributed to target machines via the management plane.
4. Each machine's daemon-secrets validates the token against the HSM's pre-enrolled
   public key.
5. Vaults unlock. The HSM never sees the vault master keys.

### Emergency Break-Glass

A break-glass procedure for when normal factors are unavailable:

1. An administrator authenticates to a break-glass service using a hardware token.
2. The service creates a single-use delegation token (`max_uses: 1`) for the target vault.
3. The token is transmitted to the target device.
4. The vault unlocks once. The token is consumed and cannot be reused.
5. All break-glass events are audit-logged with the token ID, origin device, and
   administrator identity.

## Remote Attestation

Before a target device accepts a delegation token, it must verify that the origin device is
trustworthy. Remote attestation provides this assurance.

### Device Identity

Each device in the federation has a long-lived identity key pair. The public key is enrolled
on peer devices during a setup ceremony. Options for the identity key:

- **TPM-backed key.** The device's TPM generates a non-exportable attestation key. The
  public portion is enrolled on peers. This proves the origin device has not been cloned.
- **Noise IK static keypair.** The existing Open Sesame Noise IK transport provides mutual
  authentication. The origin device's static public key is already known to the target
  device from IPC bus enrollment.
- **X.509 certificate.** A CA-issued device certificate, validated against a pinned CA
  public key. Suitable for organizational deployments with existing PKI.

### Platform State Attestation

Optionally, the origin device can include a TPM quote (signed PCR values) in the delegation
token, proving its boot integrity at the time of factor satisfaction. The target device
verifies the quote against a known-good PCR policy. This prevents a compromised origin
device from generating fraudulent factor proofs.

## Time-Bounded Delegation Tokens

All delegation tokens have mandatory expiration:

- **Minimum expiry**: 10 seconds (prevents creation of tokens that expire before delivery).
- **Maximum expiry**: Configurable per-vault, default 300 seconds (5 minutes). Longer
  durations increase the window for token theft and replay.
- **Clock skew tolerance**: 30 seconds. The target device accepts tokens where
  `now - 30s <= timestamp <= now + 30s` and `now <= expiry + 30s`.

Token expiry is checked at the target device at time of use. A token that was valid when
created but has since expired is rejected. There is no renewal mechanism; a new factor
satisfaction and new token are required.

### Replay Prevention

Each token has a unique random 16-byte ID. The target device maintains a set of consumed
token IDs (in memory, persisted to disk for crash recovery). A token ID that has been seen
before is rejected, even if the token has not expired.

The consumed-ID set is pruned of entries older than `max_expiry + clock_skew_tolerance` to
bound memory usage.

## Security Considerations

- **Token theft.** A stolen delegation token can be used by an attacker within its validity
  window and scope. Mitigations: short expiry, single-use tokens (`max_uses: 1`), source
  address restrictions, and Noise IK transport encryption (tokens are never sent in
  plaintext).
- **Origin device compromise.** If the origin device is compromised, an attacker can
  generate arbitrary delegation tokens. Mitigations: TPM-backed attestation keys (attacker
  cannot extract the signing key without hardware attack), platform state attestation
  (compromised boot state is detected), and administrative revocation of the device's
  enrollment on all target devices.
- **Target device compromise.** If the target device is already compromised, delegation
  tokens are irrelevant -- the attacker already has access to the running system. Federation
  does not increase or decrease the attack surface of a compromised target.
- **Network partition.** If origin and target devices cannot communicate directly, the token
  must be relayed through an intermediary. The token's cryptographic signatures ensure
  integrity regardless of the relay path, but relay latency may cause expiry. Pre-generating
  tokens with longer expiry is an option for intermittently-connected environments.
- **Scope escalation.** The scope narrowing invariant (delegation can only narrow, never
  widen) is enforced at token creation on the origin device and verified at the target
  device. A malicious origin device could create a token with any scope up to the full
  permissions of the delegated factor -- this is inherent to the delegation model. Trust in
  the origin device is a prerequisite for accepting its tokens.

## Open Questions

- **`AuthCombineMode::All` support.** Federation in `All` mode requires multi-party key
  derivation where the origin device contributes its piece without revealing the combined
  master key. Threshold secret sharing or secure multi-party computation protocols may be
  needed.
- **Token revocation broadcast.** How does a target device learn that a token has been
  revoked before its natural expiry? Options include a revocation list pushed via the
  management plane, or making tokens short-lived enough that revocation is unnecessary.
- **Multi-hop delegation.** Can device A delegate to device B, which then re-delegates to
  device C? The current design does not support transitive delegation. Each token is signed
  by the origin device and validated against that device's enrolled key directly.
- **Offline token pre-generation.** For air-gapped environments, tokens may need to be
  generated in advance with longer validity. This increases the theft window and requires
  careful scope restriction.

## See Also

- [Factor Architecture](./factor-architecture.md) -- `VaultAuthBackend` trait definition
  and dispatch
- [Policy Engine](./policy-engine.md) -- How delegated factors interact with
  `AuthCombineMode`
- [Biometrics](./biometrics.md) -- Common delegation source (phone fingerprint)
- [TPM](./tpm.md) -- Remote attestation for device identity
