# Extension System

Open Sesame provides a WASM-based extension system composed of two crates: `extension-host` (the
runtime) and `extension-sdk` (the authoring toolkit). Extensions are distributed as OCI artifacts.

## Current Implementation Status

Both crates are in early scaffolding phase. The `extension-host` crate declares its module-level
documentation and dependency structure but contains no runtime logic. The `extension-sdk` crate
declares its module-level documentation and enforces `#![forbid(unsafe_code)]` but contains no
bindings or type definitions beyond the crate root. The architectural contracts (crate boundaries,
dependency selections, WIT/OCI integration points) are established; functional implementation is
pending.

## extension-host

The `extension-host` crate provides the Wasmtime-backed runtime for executing WASM component model
extensions with capability-based sandboxing. Each extension runs in its own `Store` with capabilities
enforced from its manifest.

### Dependencies

| Crate | Purpose |
|-------|---------|
| `wasmtime` | WebAssembly runtime engine with component model support |
| `wasmtime-wasi` | WASI preview 2 implementation for Wasmtime |
| `core-types` | Shared types for the extension/host boundary |
| `core-config` | Configuration loading for extension manifests |
| `core-ipc` | IPC bus client for extension-to-daemon communication |
| `extension-sdk` | Shared type definitions between host and guest |
| `tokio` | Async runtime for extension lifecycle management |
| `anyhow` | Error handling for Wasmtime operations |

### Planned Architecture

Based on the crate's declared dependencies and documentation, the extension host is designed around
these components:

- **Wasmtime engine with pooling allocator:** The `wasmtime` dependency provides the core WebAssembly
  execution engine. Pooling allocation pre-allocates memory slots for extension instances, reducing
  per-instantiation overhead.
- **WASI component model:** The `wasmtime-wasi` dependency provides WASI preview 2 support, giving
  extensions controlled access to filesystem, networking, clocks, and random number generation through
  capability handles.
- **Capability sandbox:** Each extension's `Store` is configured with capabilities declared in its
  manifest. Extensions cannot access resources beyond what their manifest declares.
- **IPC bus integration:** The `core-ipc` dependency allows extensions to communicate with daemon
  processes over the Noise IK encrypted bus, subject to clearance checks.

## extension-sdk

The `extension-sdk` crate provides the types, host function bindings, and WIT interface definitions
that extension authors use to build WASM component model extensions targeting the extension host.

### Dependencies

| Crate | Purpose |
|-------|---------|
| `core-types` | Shared types for the extension/host boundary |
| `wit-bindgen` | Code generation from WIT (WebAssembly Interface Type) definitions |
| `serde` | Serialization for extension configuration and data exchange |

### WIT Bindings

The `wit-bindgen` dependency generates Rust bindings from WIT interface definitions. WIT defines the
contract between extensions (guests) and the extension host: what functions the host exports to
extensions, what functions extensions must implement, and the types exchanged across the boundary.
The SDK crate enforces `#![forbid(unsafe_code)]` -- all unsafe operations are confined to the
generated bindings and the host runtime.

## OCI Distribution

Extensions are packaged and distributed as OCI (Open Container Initiative) artifacts. The
`OciReference` type in `core-types` (defined in `core-types/src/oci.rs`) provides the addressing
scheme:

```text
registry/principal/scope:revision[@provenance]
```

Examples:

- `registry.example.com/org/extension:1.0.0`
- `registry.example.com/org/extension:1.0.0@sha256:abc123`

The `OciReference` type parses and validates this format, requiring at least three path segments
(registry, principal, scope), a non-empty revision after `:`, and an optional provenance hash after
`@`. It implements `FromStr`, `Display`, `Serialize`, and `Deserialize`.

The OCI distribution model allows extensions to be:

- **Published** to any OCI-compliant registry (Docker Hub, GitHub Container Registry, self-hosted
  registries).
- **Content-addressed** via the optional provenance field for integrity verification.
- **Version-pinned** via the revision field for reproducible deployments.
- **Scoped** by principal (organization/user) and scope (extension name) for namespace isolation.

## Extension Lifecycle

The planned extension lifecycle follows five phases:

1. **Discover:** Resolve an `OciReference` to a registry, pull the extension artifact, and verify its
   provenance hash if present.
2. **Load:** Parse the WASM component from the artifact. Validate the component's WIT imports against
   what the host can provide.
3. **Sandbox:** Create a Wasmtime `Store` with WASI capabilities scoped to the extension's manifest.
   Configure resource limits (memory, fuel/instruction count, file descriptors).
4. **Execute:** Instantiate the component in the store. Call the extension's exported entry points.
   The extension communicates with daemons via host-provided IPC functions.
5. **Teardown:** Drop the store, releasing all resources. The pooling allocator reclaims the memory
   slot for reuse.
