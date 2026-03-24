# Identity Model

Open Sesame's identity model provides globally unique, collision-resistant identifiers for
installations, organizations, profiles, and vaults. The model supports federation across
devices and organizations without a central identity provider.

## InstallationId

Every Open Sesame installation has a unique identity, defined as `InstallationId` in
`core-types/src/security.rs`:

```rust
pub struct InstallationId {
    pub id: Uuid,                                    // UUID v4, generated at sesame init
    pub org_ns: Option<OrganizationNamespace>,       // Enterprise namespace
    pub namespace: Uuid,                             // Derived, for deterministic ID generation
    pub machine_binding: Option<MachineBinding>,     // Hardware attestation
}
```

The `id` field is a UUID v4 generated once at `sesame init` and persisted in
`~/.config/pds/installation.toml` (`InstallationConfig` in
`core-config/src/schema_installation.rs`). It never changes unless the user explicitly
re-initializes.

The `namespace` field is derived deterministically:

```text
namespace = uuid5(org_ns.namespace || PROFILE_NS, "install:{id}")
```

This derived namespace seeds deterministic `ProfileId` generation, ensuring that the same
profile name on two different installations produces different profile IDs.

### Properties

| Property | Value |
|----------|-------|
| Generation | UUID v4 for `InstallationId.id`; UUID v7 via `Uuid::now_v7()` for `ProfileId`, `AgentId`, and other `define_id!` types |
| Persistence | `~/.config/pds/installation.toml` |
| Scope | One per user per machine |
| Collision resistance | 122 bits of randomness (UUID v4) |

## Organization Namespace

The `OrganizationNamespace` (`core-types/src/security.rs`) groups installations by
organization:

```rust
pub struct OrganizationNamespace {
    pub domain: String,       // e.g., "braincraft.io"
    pub namespace: Uuid,      // uuid5(NAMESPACE_URL, domain)
}
```

The namespace UUID is derived deterministically from the domain string using UUID v5 with
the URL namespace. Any installation that specifies the same organization domain produces
the same namespace UUID, enabling cross-installation identity correlation without a central
registry.

### Enrollment

```bash
sesame init --org braincraft.io
```

This writes the `OrgConfig` to `installation.toml`:

```toml
[org]
domain = "braincraft.io"
namespace = "a1b2c3d4-..."   # uuid5(NAMESPACE_URL, "braincraft.io")
```

## Identity Hierarchy

The identity model forms a four-level hierarchy:

```text
Organization (OrganizationNamespace)
  +-- Installation (InstallationId)
        +-- Profile (TrustProfileName -> ProfileId)
              +-- Vault (SQLCipher DB, 1:1 with profile)
```

Each level narrows scope:

1. **Organization** -- optional grouping by domain. Two installations in the same org share
   a namespace for deterministic ID derivation.
2. **Installation** -- a single `sesame init` on a single machine for a single user.
   Identified by UUID v4.
3. **Profile** -- a trust context (e.g., `work`, `personal`, `ci-production`). The
   `TrustProfileName` type (`core-types/src/profile.rs`) is a validated, path-safe string:
   ASCII alphanumeric plus hyphens and underscores, max 64 bytes, no path traversal. The
   `ProfileId` is a UUID v7 generated via the `define_id!` macro
   (`core-types/src/ids.rs`).
4. **Vault** -- a SQLCipher database scoped to one profile. The vault file path is
   `vaults/{profile_name}.db`. The encryption key is derived via
   `BLAKE3 derive_key("pds v2 vault-key {profile}")` from the profile's master key.

## Device Identity

An installation can optionally be bound to a specific machine via `MachineBinding`
(`core-types/src/security.rs`):

```rust
pub struct MachineBinding {
    pub binding_hash: [u8; 32],            // BLAKE3 hash of machine identity material
    pub binding_type: MachineBindingType,  // MachineId or TpmBound
}
```

Two binding types are defined:

| Type | Source | Portability |
|------|--------|-------------|
| `MachineId` | BLAKE3 hash of `/etc/machine-id` + installation ID | Survives reboots, not disk clones |
| `TpmBound` | TPM-sealed key material | Survives reboots, tied to hardware TPM |

Machine binding serves two purposes:

1. **Attestation.** The `Attestation::DeviceAttestation` variant
   (`core-types/src/security.rs`) includes a `MachineBinding` and a verification timestamp.
   This allows federation peers to verify that an identity claim originates from a specific
   physical device.

2. **Migration detection.** If an `installation.toml` is copied to a different machine, the
   machine binding hash does not match `/etc/machine-id` on the new host. The system detects
   this and can require re-attestation.

## Cross-Device Identity Correlation

### Same Organization

Two installations in the same organization (same `org.domain`) share a derived namespace.
The `ProfileRef` type (`core-types/src/profile.rs`) fully qualifies a profile across
installations:

```rust
pub struct ProfileRef {
    pub name: TrustProfileName,
    pub id: ProfileId,
    pub installation: InstallationId,
}
```

A `ProfileRef` uniquely identifies a profile in a federation context. Two devices with the
same organization and the same profile name `work` produce different `ProfileRef` values
because their `installation.id` fields differ.

### Cross-Organization

Installations in different organizations have different namespace derivations.
Cross-organization identity correlation requires explicit trust establishment (out-of-band
key exchange or mutual attestation), not namespace collision.

## ID Generation

The `define_id!` macro in `core-types/src/ids.rs` generates typed ID wrappers over UUID v7:

```rust
define_id!(ProfileId, "prof");
define_id!(AgentId, "agent");
define_id!(DaemonId, "dmon");
define_id!(ExtensionId, "ext");
// ... and others
```

Each ID type:

- Wraps a `Uuid` (UUID v7 via `Uuid::now_v7()`).
- Displays with a type prefix (e.g., `prof-01234567-...`, `agent-89abcdef-...`).
- Implements `Serialize`/`Deserialize` as a transparent UUID.
- Is `Copy`, `Eq`, `Hash`, and `Ord`.

UUID v7 is time-ordered, so IDs generated later sort after IDs generated earlier. This
provides natural chronological ordering for audit logs and event streams without a separate
timestamp field.

## Installation Configuration on Disk

The `InstallationConfig` struct (`core-config/src/schema_installation.rs`) is the
TOML-serialized form of the installation identity:

```toml
# ~/.config/pds/installation.toml
id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
namespace = "fedcba98-7654-3210-fedc-ba9876543210"

[org]
domain = "braincraft.io"
namespace = "12345678-abcd-ef01-2345-6789abcdef01"

[machine_binding]
binding_hash = "a1b2c3d4e5f6..."  # hex-encoded BLAKE3 hash
binding_type = "machine-id"
```

The `org` and `machine_binding` sections are optional. A personal desktop installation
without enterprise management or hardware binding omits both:

```toml
id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
namespace = "fedcba98-7654-3210-fedc-ba9876543210"
```
