# Protocol Evolution

This page documents how the Open Sesame IPC protocol handles versioning,
forward compatibility, and the addition of new event types without
breaking existing daemons.

## EventKind and Unknown Variant Deserialization

The protocol schema is defined by the `EventKind` enum in
`core-types/src/events.rs`. This enum is marked `#[non_exhaustive]` and
contains a catch-all variant:

```rust
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EventKind {
    // ... all named variants ...

    #[serde(other)]
    Unknown,
}
```

The `#[serde(other)]` attribute on the `Unknown` variant is the
forward-compatibility mechanism. When a daemon receives a
postcard-encoded `EventKind` with a variant discriminant it does not
recognize (because the sender is running a newer version of the code),
serde deserializes it as `EventKind::Unknown` instead of returning a
deserialization error.

This means a daemon compiled against an older version of `core-types`
can receive messages containing event variants that did not exist when it
was compiled. The message deserializes successfully; the daemon sees
`EventKind::Unknown` and can choose to ignore it, log it, or pass it
through.

The `#[non_exhaustive]` attribute enforces at compile time that all
`match` arms on `EventKind` must include a wildcard or `Unknown` branch.
This prevents new variants from causing compile errors in downstream
crates that have not been updated.

## Postcard Encoding Properties

The IPC bus uses `postcard` (a `#[no_std]`-compatible, compact binary
serde format) for all serialization. Several properties of postcard's
encoding are relevant to protocol evolution.

### Externally-Tagged Enums

`EventKind` uses serde's default externally-tagged representation.
Postcard encodes externally-tagged enums as a varint discriminant
followed by the variant's fields in declaration order. The `events.rs`
source contains an explicit note:

> Externally-tagged enum (serde default) for postcard wire
> compatibility. Postcard does not support
> `#[serde(tag = "...", content = "...")]`.

This means:

- Each variant is identified by its position (index) in the enum
  declaration.
- Adding new variants at the end of the enum produces new discriminant
  values that older decoders do not recognize, triggering
  `#[serde(other)]` deserialization to `Unknown`.
- Reordering existing variants would change their discriminants and break
  all existing decoders. Variant ordering must be append-only.

### Positional Field Encoding

Postcard encodes struct fields positionally (by declaration order), not
by name. The `Message<T>` envelope in `message.rs` contains a comment
making this explicit:

> No `skip_serializing_if` -- postcard uses positional encoding, so the
> field must always be present in the wire format for decode
> compatibility.

This means:

- Every field in `Message<T>` must always be serialized, even if its
  value is `None`. Omitting an `Option` field via `skip_serializing_if`
  would shift all subsequent fields by one position, causing decode
  failures.
- New fields can only be appended to the end of the struct. The v3
  fields (`origin_installation`, `agent_id`, `trust_snapshot`) are
  explicitly commented as "v3 fields (appended for positional encoding
  safety)."
- Removing or reordering existing fields is a breaking change.

### Implications for Field Addition

When a v3 sender transmits a message with the three new trailing fields
to a v2 receiver, the v2 decoder reads only the fields it knows about
and ignores trailing bytes. Postcard's `from_bytes` does not require that
all input bytes be consumed -- it reads fields sequentially and stops
when the struct is fully populated. This means appending new `Option`
fields to `Message<T>` is backward-compatible as long as older decoders
were compiled without those fields.

When a v2 sender transmits a message missing the v3 trailing fields to
a v3 receiver, `postcard::from_bytes` encounters end-of-input when
trying to decode the missing fields. In practice, the codebase treats
wire version bumps as requiring atomic deployment of all binaries (see
the wire version section below).

## Wire Version Field

The `Message<T>` struct contains a `wire_version: u8` field, always
serialized first. The current value is `3`, defined as
`pub const WIRE_VERSION: u8 = 3` in `message.rs`.

The source code documents the wire version contract:

> WIRE FORMAT CONTRACT:
>
> v2 fields: `wire_version`, `msg_id`, `correlation_id`, `sender`,
> `timestamp`, `payload`, `security_level`, `verified_sender_name`
>
> All v2 binaries must be deployed atomically (single compilation unit).
> Adding fields requires incrementing this constant and updating the
> decode path to handle both old and new versions during rolling
> upgrades.

### What the Wire Version Encodes

The wire version tracks changes to the `Message<T>` envelope
structure -- specifically, which fields are present and in what order.
It does not track changes to `EventKind` variants (those are handled by
`#[serde(other)]`).

- **v2:** 8 fields (`wire_version` through `verified_sender_name`)
- **v3:** 11 fields (adds `origin_installation`, `agent_id`,
  `trust_snapshot`)

### Version Negotiation

The protocol does not perform explicit version negotiation. There is no
handshake phase where client and server agree on a wire version. Instead,
`Message::new()` always stamps the current `WIRE_VERSION`, and the source
code states that all binaries must be deployed atomically when the wire
version changes.

A receiver can inspect `msg.wire_version` after deserialization to
determine which generation of the protocol the sender used. The current
codebase does not implement version-conditional decode logic; all daemons
are expected to be at the same wire version. The comment about "updating
the decode path to handle both old and new versions during rolling
upgrades" describes an intended future capability, not current behavior.

## How New Event Variants Are Added

Adding a new `EventKind` variant follows this procedure:

1. **Append** the new variant to the end of the `EventKind` enum in
   `core-types/src/events.rs`. Inserting it in the middle would change
   the discriminant indices of all subsequent variants.
2. **Add a Debug arm** in the `impl_event_debug!` macro invocation at
   the bottom of `events.rs`. The macro enforces exhaustiveness --
   omitting a variant is a compile error. Sensitive variants (containing
   passwords or secret values) go in the `sensitive` section with
   explicit `REDACTED` annotations. All others go in the `transparent`
   section.
3. **No wire version bump is needed** for new `EventKind` variants. The
   `Unknown` catch-all handles unrecognized discriminants at the
   `EventKind` level. Wire version bumps are only needed for changes to
   the `Message<T>` envelope structure.

Daemons compiled against the old `core-types` deserialize the new
variant as `EventKind::Unknown`. Daemons compiled against the new
`core-types` see the fully typed variant. Both can coexist on the same
bus.

## How New Message Fields Are Added

Adding a new field to `Message<T>` is a more disruptive change:

1. **Append** the new field to the end of the `Message<T>` struct.
   Postcard's positional encoding means insertion or reordering breaks
   all existing decoders.
2. **Increment `WIRE_VERSION`** to signal the structural change.
3. **Deploy all binaries atomically.** The codebase does not currently
   implement multi-version decode logic. All daemons must be rebuilt and
   redeployed together.
4. **Update `MessageContext`** if the new field should be populated by
   the sender (as was done for `origin_installation`, `agent_id`, and
   `trust_snapshot` in v3).
5. **Do not use `skip_serializing_if`** on the new field. The field must
   always be present on the wire for positional decode compatibility.

## Practical Constraints

### Variant Stability

The `EventKind` enum currently contains over 80 variants spanning window
management, profile lifecycle, clipboard, input, secrets RPC, launcher
RPC, agent lifecycle, authorization, federation, device posture,
multi-factor auth, and bus-level errors. Each variant's position in the
enum declaration is its wire discriminant. Removing a variant or changing
its position is a breaking wire change.

### Enum Variant Field Changes

Postcard encodes variant fields positionally, the same as struct fields.
Adding a field to an existing variant, removing a field, or reordering
fields within a variant is a breaking wire change. New fields for
existing functionality should be introduced as new variants rather than
modifications to existing ones.

### Sensitivity Redaction

The `Debug` implementation for `EventKind` uses a compile-time
exhaustive macro (`impl_event_debug!`) that separates sensitive variants
from transparent ones. Sensitive variants (`SecretGetResponse`,
`SecretSet`, `UnlockRequest`, `SshUnlockRequest`, `FactorSubmit`) have
their secret-bearing fields rendered as `[REDACTED; N bytes]` in debug
output. Adding a new variant that carries secret material requires
placing it in the `sensitive` section of the macro.

### Forward Compatibility Boundaries

The `#[serde(other)]` mechanism provides forward compatibility only for
unknown enum *variants*. It does not help with:

- Unknown fields within a known variant (postcard has no field-skipping
  mechanism for positional encoding)
- Structural changes to the `Message<T>` envelope
- Changes to the framing layer (length-prefix format, encryption
  chunking)
- Changes to the Noise handshake parameters

These categories of change require coordinated deployment of all
binaries.

## See Also

- [IPC Bus Protocol](./ipc-protocol.md) -- transport, framing, and routing details
