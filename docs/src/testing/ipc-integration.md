# IPC Integration Tests

The `core-ipc` crate includes a comprehensive integration test suite in
`core-ipc/tests/socket_integration.rs`. All tests exercise the full Noise IK
encrypted transport -- there is no plaintext transport path in the codebase.

## Test Infrastructure

### Helpers

The test suite provides three helper functions:

- **`start_server_with_clients(n)`** -- Creates a temporary directory,
  generates a server keypair, registers `n` client keypairs at
  `SecurityLevel::Internal` in a `ClearanceRegistry`, binds a `BusServer`
  to a Unix socket, and returns the server, temp directory, server public
  key, and client keypairs.

- **`start_server()`** -- Convenience wrapper that registers a single client
  at Internal clearance.

- **`connect_with_keypair(id, sock, server_pub, kp)`** -- Connects a
  `BusClient` via `connect_encrypted` with the given `DaemonId` and keypair.

All tests create isolated Unix sockets in `tempfile::TempDir` instances,
ensuring no shared state between tests.

## Test Coverage

### Server Lifecycle

**`server_bind_creates_socket_file`** -- Verifies that `BusServer::bind`
creates the Unix socket file on disk, including parent directory creation.

**`client_connect_and_server_accept`** -- Verifies that after a client
performs a Noise IK handshake, the server reports a connection count of 1.

### Publish-Subscribe

**`publish_subscribe_roundtrip`** -- Client A publishes a `DaemonStarted`
event at Internal level. Client B receives it and verifies the event kind
matches. Confirms that broadcast delivery works end-to-end over encrypted
transport.

**`sender_does_not_receive_own_message`** -- A client publishes a message
and then attempts to receive. The receive times out, confirming that the bus
server does not echo messages back to the sender.

**`multiple_clients_receive_broadcast`** -- One sender, two receivers. Both
receivers get the `ConfigReloaded` event, verifying fan-out broadcast.

### Request-Response

**`request_response_correlation`** -- Client A sends a `SecretList` request
via `client.request()`. Client B receives it, constructs a
`SecretListResponse` with `.with_correlation(request_msg.msg_id)`, and sends
it back. Client A's `request()` future resolves with the correlated response.
Verifies that correlation ID routing works correctly.

**`launch_execute_response_roundtrip`** -- End-to-end test of the
`LaunchExecute` / `LaunchExecuteResponse` request-response pair, simulating
the CLI sending a launch command and daemon-launcher responding with a PID.

**`launch_execute_error_roundtrip`** -- Same as above, but the launcher
responds with `error: Some("desktop entry 'nonexistent' not found")` and
`denial: Some(LaunchDenial::EntryNotFound)`. Verifies error propagation
through the correlated response path.

**`request_timeout`** -- A client sends a `StatusRequest` with a 100 ms
timeout. No responder exists. The `request()` call returns an error
containing "timed out".

### Unicast Routing

**`secret_response_not_received_by_bystander`** -- Three clients: a
requester, a bystander, and a simulated secrets daemon. The requester sends
a `SecretList` request. Both the bystander and the secrets daemon receive
the broadcast request. The secrets daemon responds with a correlated
`SecretListResponse`. The requester receives it, but the bystander does not.
This verifies that correlated responses are unicast-routed to the original
requester, not broadcast.

**`uncorrelated_response_is_dropped`** -- A client sends a response message
with a fabricated correlation ID that matches no pending request. The bus
server drops it; no other client receives it. This prevents response
injection attacks.

### Noise Handshake Security

**`noise_handshake_rejects_wrong_key`** -- A client attempts to connect
using a server public key that does not match the actual server. The Noise IK
handshake fails, and `connect_encrypted` returns an error. This is a
fundamental authentication property of the IK pattern: the initiator pins
the responder's static key.

**`client_connect_retry_on_missing_socket`** -- A client attempts to connect
to a nonexistent socket path. The connection fails with an error containing
"failed to connect" rather than hanging or panicking.

### Clearance Enforcement

**`clearance_escalation_blocked`** -- Two clients are registered: one at
`SecurityLevel::Open`, one at `SecurityLevel::Internal`. The Open-clearance
client publishes a message at Internal level. The Internal-clearance client
does not receive it. The bus server silently drops frames that exceed the
sender's clearance.

**`secrets_only_message_not_delivered_to_internal_daemon`** -- A client
registered at `SecurityLevel::SecretsOnly` publishes at SecretsOnly level.
A client registered at `SecurityLevel::Internal` does not receive it. This
verifies the lattice property: Internal clearance is below SecretsOnly, so
Internal recipients are excluded from SecretsOnly-level messages. This
isolation ensures that daemon-secrets traffic is partitioned from general
daemon traffic.

**`ephemeral_client_gets_secrets_only_clearance`** -- A client connects with
an unregistered keypair (not in the `ClearanceRegistry`). The connection
succeeds via UCred same-UID validation, and the server reports 1 connection.
Ephemeral clients (typically `sesame` CLI invocations) receive SecretsOnly
clearance, allowing them to interact with daemon-secrets without being
pre-registered.

### Sender Identity

**`sender_identity_change_blocked`** -- A client sends a first message with
`DaemonId(20)`, binding that identity to the connection. It then sends a
second message with `DaemonId(99)`. The receiver gets the first message but
not the second. The bus server drops messages where the sender's `DaemonId`
does not match the identity bound on the first message, preventing identity
spoofing mid-session.

**`verified_sender_name_stamped`** -- A client registered as
`"test-client-0"` sends a message. The receiver inspects
`msg.verified_sender_name` and finds it set to `Some("test-client-0")`. This
field is stamped by the server from the Noise IK registry lookup, not
self-declared by the sender. Recipients can trust this field for
authorization decisions.

### Cross-Daemon Routing

**`registered_client_overlay_reaches_daemon_wm`** -- A CLI client registered
at Internal clearance publishes `WmActivateOverlay`. A simulated daemon-wm
client receives it. Verifies the overlay activation path from CLI to window
manager.

### Graceful Shutdown

**`shutdown_flushes_publish_before_disconnect`** -- A CLI client publishes
`WmActivateOverlay` then calls `client.shutdown().await`. A daemon-wm
client receives the event after the CLI has disconnected. This verifies that
`shutdown()` flushes outbound frames before closing the connection.

**`drop_without_shutdown_may_lose_message`** -- A CLI client publishes then
immediately `drop`s the client handle without calling `shutdown()`. The test
documents that this races the I/O task and message delivery is
non-deterministic. This test exists as a regression companion to the
`shutdown_flushes` test: it demonstrates the data loss that `shutdown()` was
introduced to prevent.
