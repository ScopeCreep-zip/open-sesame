# Security Tests

Open Sesame includes targeted security tests that verify memory protection, cryptographic isolation,
IPC authentication, and authorization enforcement. These tests validate security invariants that, if
broken, would compromise secret confidentiality.

## Guard Page SIGSEGV Verification

**File**: `core-memory/tests/guard_page_sigsegv.rs`

`ProtectedAlloc` wraps sensitive data in page-aligned memory with guard pages on both sides. The
guard page tests verify that out-of-bounds access triggers SIGSEGV (signal 11) rather than silently
reading adjacent memory.

### Subprocess Harness Pattern

Direct SIGSEGV in a test process would kill the entire test runner. The tests use a subprocess
harness:

1. The **parent test** (`overflow_hits_trailing_guard_page`,
   `underflow_hits_leading_guard_page`) spawns the test binary as a child process, targeting a
   specific harness function with `--exact` and passing an environment variable
   `__GUARD_PAGE_HARNESS` to gate execution.
2. The **child harness** (`overflow_harness`, `underflow_harness`) checks for the environment
   variable. If absent, it returns immediately (no-op when run as part of the normal test suite).
   If present, it allocates a `ProtectedAlloc`, performs a deliberate out-of-bounds read, and
   calls `exit(1)` as unreachable fallback.
3. The parent inspects the child's exit status. On Unix, it checks `status.signal()` for SIGSEGV
   (11) or SIGBUS (7). As a fallback for platforms that encode signal death as exit code
   128+signal, it also checks the exit code.

### Test Coverage

- **Trailing guard page**: reads one byte past `ptr.add(len)`, triggering SIGSEGV on the guard
  page after the data region.
- **Leading guard page**: reads one full page before the data pointer (`ptr.sub(page_size)`), past
  any canary and padding, into the guard page between the metadata region and data region. Accepts
  both SIGSEGV (11) and SIGBUS (7).

## Canary Verification

**File**: `core-memory/src/alloc.rs` (unit tests)

`ProtectedAlloc` writes a canary value into the metadata region during allocation. Unit tests verify
canary behavior:

- `canary_is_consistent`: verifies that canary derivation is deterministic -- the same allocation
  size always produces the same canary.
- `alloc_canary_plus_data_spans_page_boundary`: verifies correct behavior when the canary plus user
  data cross a page boundary.

The canary is checked on `Drop`. If the canary has been corrupted (indicating a buffer underflow or
use-after-free into the metadata region), the allocator detects the tampering.

## Postcard Wire Format Compatibility

**File**: `core-types/src/sensitive.rs`

`SensitiveBytes` provides custom `Serialize` and `Deserialize` implementations to maintain wire
compatibility with postcard (the IPC serialization format). The serializer writes raw bytes directly
from protected memory via `serialize_bytes`. The deserializer implements a custom `Visitor` with two
paths:

- **Zero-copy path** (`visit_bytes`): copies directly from the deserializer's borrowed input buffer
  into a `ProtectedAlloc`. No intermediate heap `Vec<u8>` is created. This is the path postcard
  uses for in-memory deserialization.
- **Owned path** (`visit_byte_buf`): accepts an owned `Vec<u8>`, copies into `ProtectedAlloc`, then
  zeroizes the `Vec<u8>` before dropping it.

This ensures that `SensitiveBytes` and `Vec<u8>` produce identical wire representations, maintaining
backward compatibility with any code that previously used plain byte vectors.

## Cross-Profile Vault Isolation

**File**: `core-secrets/src/sqlcipher.rs` (unit tests)

SQLCipher vaults are encrypted with per-profile vault keys derived via BLAKE3 domain separation.
Three tests verify isolation:

- **`cross_profile_keys_are_independent`**: derives vault keys for profiles "work" and "personal"
  from the same master key. Asserts the derived keys differ. Opens a vault with the "work" key,
  stores a secret, then attempts to reopen the same database file with the "personal" key. The
  `SqlCipherStore::open` call must return an error because SQLCipher cannot decrypt pages with the
  wrong key.

- **`cross_profile_secret_access_returns_error`**: creates two separate vault databases for "work"
  and "personal" profiles. Stores a secret in the "work" vault, then attempts to read the same key
  name from the "personal" vault. The result must be `Err(core_types::Error::NotFound(_))`.

- **`vault_key_derivation_domain_separation`**: verifies that `core_crypto::derive_vault_key`
  produces distinct keys for different profile names, confirming the BLAKE3 domain separation
  functions correctly.

## IPC Authentication and Authorization

**File**: `core-ipc/tests/socket_integration.rs`

The IPC integration tests verify several security invariants of the Noise IK transport and bus
server:

### Noise Handshake Rejection

`noise_handshake_rejects_wrong_key`: a client connects expecting an incorrect server public key.
The Noise IK handshake fails because the client's static key lookup does not match the server's
actual identity.

### Clearance Escalation Blocking

`clearance_escalation_blocked`: a client registered at `SecurityLevel::Open` attempts to publish a
message at `SecurityLevel::Internal`. The bus server silently drops the frame. An
`Internal`-clearance receiver does not receive it.

### Sender Identity Binding

`sender_identity_change_blocked`: after a client's first message binds its `DaemonId` to the
connection, any subsequent message with a different `DaemonId` is dropped. This prevents a
compromised client from impersonating another daemon mid-session.

### Verified Sender Name Stamping

`verified_sender_name_stamped`: messages routed through the bus carry a `verified_sender_name` field
stamped by the server from the Noise IK registry lookup. The sender cannot self-declare this field.
The test verifies the stamped name matches the registry entry (`"test-client-0"`), not anything the
sender included in the message payload.

### Unicast Response Routing

`secret_response_not_received_by_bystander`: when a request/response pair uses correlation IDs, the
response is unicast-routed to the original requester only. A bystander client connected to the same
bus does not receive the correlated response.

### Orphan Response Dropping

`uncorrelated_response_is_dropped`: a message with a fabricated `correlation_id` (no matching
pending request) is silently dropped by the bus server and not broadcast to any client.

### Ephemeral Client UCred Validation

`ephemeral_client_gets_secrets_only_clearance`: an unregistered key (ephemeral CLI connection) that
passes UCred same-UID validation receives `SecretsOnly` clearance, allowing it to send unlock and
secret CRUD messages without being pre-registered in the key registry.

### Clearance-Level Message Filtering

`secrets_only_message_not_delivered_to_internal_daemon`: a message published at `SecretsOnly` level
is not delivered to `Internal`-clearance recipients, since `Internal < SecretsOnly` in the clearance
hierarchy.

## Keypair Persistence Security

**File**: `core-ipc/tests/daemon_keypair.rs`

This test verifies filesystem security invariants for daemon keypair storage:

- The keys directory has `0700` permissions.
- Private key files (`.key`) have `0600` permissions.
- Public key files (`.pub`) have `0644` permissions.
- Bus keypair files (`bus.key`, `bus.pub`, `bus.checksum`) have correct permissions.
- Corrupting the checksum file triggers a `TAMPER DETECTED` error on the next read, preventing use
  of tampered keypairs.

## Seccomp Allowlist

Each daemon applies a seccomp filter via `platform_linux::sandbox::apply_seccomp`. The function uses
`libseccomp` to install a BPF filter with a default-deny policy (`SCMP_ACT_ERRNO(EPERM)`), adding
only the syscalls required by each daemon's `SeccompProfile`. This prevents an attacker who gains
code execution within a daemon from making arbitrary system calls.

Seccomp is combined with Landlock filesystem restrictions in the `apply_sandbox` function, which
each daemon calls during initialization. Per-daemon sandbox configurations are defined in each
daemon's `sandbox.rs` module (e.g., `daemon-secrets/src/sandbox.rs`, `daemon-wm/src/sandbox.rs`).
Daemons that do not need network access (e.g., `daemon-secrets`) additionally set
`PrivateNetwork=true` at the systemd level.
