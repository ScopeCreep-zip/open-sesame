# IPC Bus Protocol

The `core-ipc` crate implements the inter-process communication protocol used by all Open Sesame
daemons and the `sesame` CLI.

## Bus Architecture

The IPC bus uses a star topology. `daemon-profile` hosts a `BusServer` that binds a Unix domain
socket at `$XDG_RUNTIME_DIR/pds/bus.sock`. All other daemons and the `sesame` CLI connect to this
socket as `BusClient` instances.

The server accept loop (`BusServer::run` in `server.rs`) listens for incoming connections, extracts
`UCred` credentials via `SO_PEERCRED`, enforces a same-UID policy (rejecting connections from
different users), and spawns a per-connection handler task. Each connection performs a mandatory
Noise IK handshake before any application data flows.

Per-connection state is tracked in `ConnectionState`, which holds:

- The daemon's `DaemonId` (set on first message)
- A registry-verified daemon name (`verified_name`, from Noise IK handshake)
- An outbound `mpsc::Sender<Vec<u8>>` channel (capacity 256)
- `SecurityLevel` clearance
- An optional `TrustVector` computed at connection time

An atomic `u64` counter assigns monotonically increasing connection IDs. Each connection runs three
stages in `handle_connection`:

1. **Accept and identify.** `noise::Connection::server` performs the handshake; `identify` looks the
   client's static key up in the registry and logs the outcome. Connection state is registered only
   after the handshake succeeds, so no frame is routed to a connection before a transport exists to
   encrypt it.
2. **Serve.** `serve` multiplexes encrypted reads (routed through `route_frame`) and writes of the
   frames routed to the connection.
3. **Close.** `close` removes the connection's state and daemon name. Unanswered requests are marked
   disconnected until their TTL expires.

Clients and the server share one `noise::Connection` type (transport, buffered reader, buffered
writer), constructed by `Connection::client` or `Connection::server`.

On `BusServer::drop`, the socket file is removed from the filesystem.

## Noise IK Handshake

All socket connections use the Noise Protocol Framework with the IK pattern:

```text
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

The primitives are:

- **X25519** Diffie-Hellman key agreement
- **ChaCha20-Poly1305** authenticated encryption (AEAD)
- **BLAKE2s** hashing

The IK pattern means the initiator (connecting daemon) transmits its static key encrypted in the
first message, and the responder's (bus server's) static key is pre-known to the initiator. This
provides mutual authentication in a single round-trip (2 messages).

From the **initiator** (client) perspective:

1. Write message 1 to responder (ephemeral key + encrypted static key)
2. Read message 2 from responder (responder's ephemeral key)
3. Transition to transport mode with forward-secret keys

From the **responder** (server) perspective:

1. Read message 1 from initiator (contains initiator's ephemeral + encrypted static)
2. Write message 2 to initiator (contains responder's ephemeral)
3. Transition to transport mode with forward-secret keys

The handshake has a 5-second timeout (`HANDSHAKE_TIMEOUT`) to prevent denial-of-service via slow
handshake. The `snow` crate provides the Noise implementation.

## Prologue Binding

The Noise prologue cryptographically binds OS-level transport identity to the encrypted channel.
Both sides construct an identical prologue from `UCred` credentials:

```text
PDS-IPC-v1:<lower_pid>:<lower_uid>:<higher_pid>:<higher_uid>
```

Canonical ordering is by PID (lower PID first), ensuring both sides produce identical bytes
regardless of which side is the server. If either side has incorrect peer credentials (e.g., due to
spoofing), the prologue mismatch causes the Noise handshake to fail cryptographically.

`PeerCredentials` are obtained via:

- `extract_ucred()`: calls `UnixStream::peer_cred()` (uses `SO_PEERCRED` on Linux) to get the remote
  peer's PID and UID.
- `local_credentials()`: calls `rustix::process::getuid()` and `std::process::id()` for the local
  process.

In-process subscribers (`BusServer::register`, used by daemon-profile for its own host channel)
perform no handshake and carry no peer credentials.

## Encrypted Transport

After handshake completion, `NoiseTransport` wraps a `snow::TransportState` and provides chunked
encrypted I/O.

Noise transport messages are limited to 65535 bytes. The maximum plaintext per Noise message is
65519 bytes (65535 minus the 16-byte AEAD tag). Application frames up to 16 MiB
(`MAX_FRAME_SIZE = 16 * 1024 * 1024`) are chunked into multiple Noise messages.

### Encrypted Frame Wire Format

```text
[4-byte BE chunk_count]     (length-prefixed, plaintext)
[length-prefixed encrypted chunk 1]
[length-prefixed encrypted chunk 2]
...
[length-prefixed encrypted chunk N]
```

Each chunk is individually encrypted by `snow::TransportState::write_message` and written via the
length-prefixed framing layer. The chunk count header is transmitted in the clear because it is not
sensitive and the reader needs it to know how many chunks to expect.

Zero-length payloads send one empty encrypted chunk. On the read path, the reassembled payload is
validated against `MAX_FRAME_SIZE`, and the intermediate decrypt buffer is zeroized via
`zeroize::Zeroize`.

A 200 KiB payload requires approximately 4 chunks (200 * 1024 / 65519). The maximum number of chunks
for a 16 MiB payload is validated on read to reject fabricated chunk counts.

### Mutual Exclusion

`snow::TransportState` requires `&mut self` for both encrypt and decrypt. Both the server and client
use `tokio::select!` to multiplex reads and writes in a single task rather than splitting into
separate reader/writer tasks with a `Mutex`. The `Mutex` approach would deadlock because the reader
would hold the lock while awaiting socket I/O, starving the writer.

Decrypted postcard buffers on the server side and plaintext outbound buffers on the client side are
zeroized after processing, as they may contain serialized secret values.

## Framing Layer

The framing layer (`framing.rs`) provides two independent services.

### Serialization

`encode_frame` and `decode_frame` convert between typed Rust values and postcard byte payloads:

- `encode_frame<T: Serialize>(value) -> Vec<u8>`: calls `postcard::to_allocvec`.
- `decode_frame<T: DeserializeOwned>(payload) -> T`: calls `postcard::from_bytes`.

These are symmetric: `decode_frame(encode_frame(v)) == v`.

### Wire I/O

`write_frame` and `read_frame` add and strip a 4-byte big-endian length prefix for socket transport:

- `write_frame(writer, payload)`: writes `[4-byte BE length][payload]`, then flushes.
- `read_frame(reader) -> Vec<u8>`: reads the 4-byte length, validates against `MAX_FRAME_SIZE` (16
  MiB), then reads the payload.

The length prefix is a wire-only concern. Internal channels (bus routing, `BusServer::publish`,
subscriber `mpsc` channels) carry raw postcard payloads without it.

```text
Socket wire format: [4-byte BE length][postcard payload]
```

Frames with a length exceeding `MAX_FRAME_SIZE` are rejected on read to prevent out-of-memory
conditions from malformed or malicious length prefixes.

## Message Envelope

Every IPC message is wrapped in `Message<T>` (`message.rs`). The current wire version is **5**
(`WIRE_VERSION = 5`).

| Field | Type | Description |
| --- | --- | --- |
| `wire_version` | `u8` | Wire format version, always serialized first. |
| `msg_id` | `Uuid` (v7) | Unique message identifier, time-ordered. |
| `correlation_id` | `Option<Uuid>` | Links a response to its originating request's `msg_id`. |
| `sender` | `DaemonId` | Sender daemon identity (UUID v7, `dmon-` prefix). |
| `timestamp` | `Timestamp` | Dual-clock timestamp: `monotonic_ns` since the sender started, and `wall_ms` since the Unix epoch (`None` when the sender's clock reads before the epoch). |
| `payload` | `T` | The event or request payload (typically `EventKind`). |
| `security_level` | `SecurityLevel` | Access control level for routing decisions. |
| `verified_sender_name` | `Option<String>` | Server-stamped name from Noise IK registry lookup. |
| `origin_installation` | `Option<InstallationId>` | v3: sender's installation identity. |
| `agent_id` | `Option<AgentId>` | v3: sender's agent identity. |
| `trust_snapshot` | `Option<TrustVector>` | v3: trust assessment at message creation time. |
| `expects_response` | `bool` | v4: the sender waits for a correlated response (`BusClient::request`). |

`MessageContext` carries per-client identity state so `Message::new()` can populate all fields. A
minimal context requires only a `DaemonId`; v3 fields default to `None`.

The bus stamps `verified_sender_name` from authenticated connections in `route_frame()` and as
`daemon-profile` for host announcements in `BusServer::publish()`. Caller-supplied values are
overwritten. `None` indicates an unregistered client. Postcard uses positional encoding, so all
`Option` fields must always be present on the wire; `skip_serializing_if` is deliberately not used.

`Message::new()` generates a UUID v7 for `msg_id` (time-ordered), leaves `correlation_id` at `None`,
and sets `expects_response` to `false`. The `with_correlation(id)` builder method sets the
correlation for response messages; `expecting_response()` marks a request whose sender waits for its
response.

## Clearance Model

### SecurityLevel Enum

`SecurityLevel` (`core-types/src/security.rs`) classifies message sensitivity for bus routing. The
variants, ordered from lowest to highest by their derived `Ord`:

| Level | Description |
| --- | --- |
| `Open` | Visible to all subscribers including extensions. |
| `Internal` | Visible to authenticated daemons only. This is the default. |
| `ProfileScoped` | Visible only to daemons holding the current profile's security context. |
| `SecretsOnly` | Visible only to the secrets daemon. |

Because `SecurityLevel` derives `PartialOrd` and `Ord`, clearance comparisons use standard Rust
ordering: `Open < Internal < ProfileScoped < SecretsOnly`.

### ClearanceRegistry

`ClearanceRegistry` (`registry.rs`) maps X25519 static public keys (`[u8; 32]`) to `DaemonClearance`
entries:

```rust
pub struct DaemonClearance {
    pub name: String,
    pub security_level: SecurityLevel,
    pub generation: u64,
}
```

The `generation` counter increments on every key change (rotation or crash-revocation). It is used
by two-phase rotation to detect concurrent revocations.

The registry is populated by `daemon-profile` at startup from per-daemon keypairs. It is wrapped in
`RwLock<ClearanceRegistry>` inside `ServerState` to allow runtime mutation.

After the Noise IK handshake, the server reads the client's static public key with
`Connection::remote_static_key()` (which calls `TransportState::get_remote_static()`). The Noise IK
pattern guarantees the remote static key is available after handshake. The 32-byte key is looked up
in the registry:

- **Found:** the connection receives the registered name and clearance level.
- **Not found:** the connection is treated as an ephemeral client with `SecretsOnly` clearance.

The registry supports `rotate_key(old, new)` (removes old entry, inserts new with incremented
generation), `revoke(pubkey)` (removes and returns the entry), `register_with_generation` (for
revoke-then-reregister flows), and `find_by_name` (linear scan, acceptable for fewer than 10
daemons).

### Routing Enforcement

`route_frame()` decodes the frame, admits it (`admit`: identity binding and sender clearance under
one lock acquisition), binds the daemon name on `DaemonStarted` (`bind_name`), stamps the verified
identity, and delivers the frame as a response (`deliver_response`) or as a request or broadcast
(`broadcast`). It enforces two clearance rules:

1. **Sender clearance:** A daemon may only emit messages at or below its own clearance level. If
   `conn.security_clearance < msg.security_level`, the frame is rejected and an `AccessDenied`
   response is sent back to the sender.
2. **Recipient clearance:** When broadcasting, the server skips subscribers whose
   `security_clearance` is below the message's `security_level`.

### Sender Identity Verification

On the first message from a connection, `route_frame()` records the self-declared `DaemonId`.
Subsequent messages must use the same `DaemonId`. A change mid-session is treated as an
impersonation attempt: the frame is dropped and an `AccessDenied` response is returned.

The server stamps `verified_sender_name` onto every routed message by re-encoding it after registry
lookup. If the connection's `trust_snapshot` field is not set on the message, the server also stamps
the connection-level `TrustVector`. This re-encode adds serialization overhead on every routed
frame, but for a local IPC bus with fewer than 10 daemons the cost is negligible (microseconds per
frame).

## Ephemeral Clients

Clients whose static public key is not in the `ClearanceRegistry` receive
`SecurityLevel::SecretsOnly` clearance. This applies to the `sesame` CLI and any other transient
tool.

Ephemeral clients are still authenticated: the same-UID check and Noise IK handshake both apply.
They simply lack a pre-registered identity in the registry. The audit log records these connections
as `ephemeral-client-accepted` events with the client's X25519 public key and PID/UID.

## Key Management

Key generation, persistence, and tamper detection are implemented in `noise_keys.rs`.

### Keypair Generation

`generate_keypair()` produces an X25519 static keypair via `snow::Builder::generate_keypair()`. Both
the public and private keys are 32 bytes. The returned `ZeroizingKeypair` wrapper guarantees private
key zeroization on drop (including during panics), since `snow::Keypair` has no `Drop`
implementation. `ZeroizingKeypair::into_inner()` transfers ownership using `mem::take` to zero the
wrapper's copy.

### Filesystem Layout

Keys are stored under `$XDG_RUNTIME_DIR/pds/`:

| File | Permissions | Content |
| --- | --- | --- |
| `bus.pub` | `0644` | Bus server X25519 public key (32 bytes). |
| `bus.key` | `0600` | Bus server private key (32 bytes). |
| `bus.checksum` | default | BLAKE3 keyed hash (32 bytes). |
| `keys/<daemon>.pub` | `0644` | Per-daemon public key (32 bytes). |
| `keys/<daemon>.key` | `0600` | Per-daemon private key (32 bytes). |
| `keys/<daemon>.checksum` | default | Per-daemon BLAKE3 keyed hash (32 bytes). |

The `keys/` directory is set to mode `0700` to prevent local users from enumerating registered
daemons.

### Atomic Writes

Private keys are written atomically: the key is written to a `.tmp` file with `0600` permissions set
at `open` time via `OpenOptionsExt::mode`, fsynced, then renamed to the final path. This prevents a
window where the key file exists with default (permissive) permissions. The write is performed
inside `tokio::task::spawn_blocking` to avoid blocking the async runtime.

### Tamper Detection Checksums

Each keypair has an accompanying `.checksum` file containing
`blake3::keyed_hash(public_key, private_key)` -- a BLAKE3 keyed hash using the 32-byte public key as
the key and the private key as the data. On read, the checksum is recomputed and compared to the
stored value. A mismatch produces a `TAMPER DETECTED` error with instructions to delete the affected
files and restart `daemon-profile`.

This detects partial corruption or partial tampering (e.g., private key replaced but checksum file
untouched). It does not prevent an attacker with full filesystem write access from replacing all
three files (private key, public key, checksum) with a self-consistent set. That threat model
requires a root-of-trust outside the filesystem such as TPM-backed attestation.

Missing checksum files (from older installations) produce a warning rather than an error, for
backward compatibility.

### Key Rotation

The `ClearanceRegistry` supports runtime key rotation via `rotate_key(old_pubkey, new_pubkey)`,
which atomically removes the old entry and inserts the new one with the same name and clearance
level but an incremented `generation` counter.

The rotation protocol uses `KeyRotationPending` and `KeyRotationComplete` events:

1. `daemon-profile` generates a new keypair for the target daemon, writes it to disk, and broadcasts
   `KeyRotationPending` with the new public key and a grace period.
2. The target daemon calls `BusClient::handle_key_rotation`, which reads the new keypair from disk,
   verifies the announced public key matches what is on disk (detecting tampering), reconnects to
   the bus with the new key, and re-announces via `DaemonStarted`.
3. On reconnection, if the server detects a `DaemonStarted` from a verified name that already has an
   active connection, it evicts the stale old connection and registers the new one in
   `name_to_conn`.

`connect_with_keypair_retry` supports crash-restart scenarios where `daemon-profile` may have
regenerated a daemon's keypair. Each retry re-reads the keypair from disk with exponential backoff.

## Request-Response Correlation

The bus supports three message routing patterns.

### Request-Response (Unicast Reply)

Request payloads have one owner in the bus routing contract. The bus unicasts each request to the
unique authenticated connection for that owner with sufficient clearance, including requests
published without waiting for a reply. Missing, ambiguous, or unavailable owners produce an explicit
refusal. `ConfigStatusRequest` names its target daemon.

When `expects_response` is set, `route_frame()` records the request ID, originating connection,
expected responder, and send time. A duplicate pending ID is refused without replacing its original
route. Requests that do not wait for replies and ordinary broadcasts create no entries. Each
insertion first forgets requests older than `PENDING_REQUEST_TTL` (2 minutes, longer than any client
request timeout), so requests whose answer never arrives do not accumulate. When a response arrives
(identified by having a `correlation_id`), the server checks the authenticated responder and the
allowed response variant before consuming the matching entry. Configuration status replies must also
name the requested daemon. Request ownership, response variants, and response classification share
the contract table in `core-ipc/src/rpc.rs`, which retains no request secrets. Invalid answers
preserve the pending route for a valid answer. Valid answers are delivered only to the originating
connection. Responses to expired, unknown, or disconnected requests are never broadcast.

On the client side, `BusClient::request()` marks the message with `expecting_response()`, registers
a `oneshot::channel` waiter keyed by `msg_id`, sends the message, and awaits the response with a
caller-specified timeout. If the timeout expires, the waiter is cleaned up and a typed `Timeout`
error is returned.

### Confirmed RPC

The server provides `register_confirmation(correlation_id, responder, request, mpsc::Sender)`, which
returns a fallible RAII `ConfirmationGuard`; duplicate registration is refused. When a correlated
response matching the registered ID, authenticated responder, and request's response schema arrives
at `route_frame()`, the route is consumed and the stamped frame is sent to the confirmation channel,
and also to the requesting connection when one waits for it. A dropped confirmation or response
frame (full channel) is logged. The `ConfirmationGuard` deregisters the route on drop, preventing
stale entries from accumulating if the caller times out or encounters an error. Cleanup identifies
the particular registration, so delayed cleanup cannot delete a replacement route reusing the ID.
Host-to-secrets confirmations name daemon-secrets as responder; external profile transition requests
remain owned by daemon-profile.

### Pub-Sub Broadcast

Messages without a `correlation_id` that are neither requests nor responses are broadcast to all
connected subscribers whose `security_clearance` meets or exceeds the message's `security_level`.
The sender's own connection is excluded to prevent feedback loops. The same echo-suppression applies
to `BusServer::publish()` for in-process subscribers (it decodes the frame to extract the `sender`
`DaemonId` and skips matching connections). Host publication accepts announcements only: malformed
frames, request and response payloads, correlated frames, response-waiting frames, and mismatched
envelope/security arguments are dropped. Host RPCs use named unicast and confirmation routes; host
replies use validated pending routes.

### Named Unicast

The server maintains a `name_to_conn: HashMap<String, u64>` mapping, populated when `route_frame()`
processes `DaemonStarted` events from connections with a `verified_sender_name`.
`send_to_named(daemon_name, frame)` resolves the daemon name to a connection ID for O(1) unicast
delivery without broadcasting.

## Socket Path Resolution

`socket_path()` in `transport.rs` resolves the platform-appropriate socket path:

| Platform | Path |
| --- | --- |
| Linux | `$XDG_RUNTIME_DIR/pds/bus.sock` |
| macOS | `~/Library/Application Support/pds/bus.sock` |
| Windows | `\\.\pipe\pds\bus` |

On Linux, `XDG_RUNTIME_DIR` must be set; its absence is a fatal error.

## Socket Permissions

The bus server applies defense-in-depth permissions on bind:

- The socket file is set to mode `0700`.
- The parent directory is set to mode `0700`.

The real security boundary is UCred UID validation (the same-UID check in the accept loop), but
restrictive filesystem permissions harden against misconfigured `XDG_RUNTIME_DIR` permissions.

## See Also

- [Protocol Evolution](./protocol-evolution.md) -- forward compatibility and wire versioning
- [Memory Protection](./memory-protection.md) -- zeroization and secret handling
