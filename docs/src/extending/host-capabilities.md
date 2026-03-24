# Extension Host Capabilities

The `extension-host` crate provides the Wasmtime-backed runtime that executes
WASM component model extensions. Each extension runs in an isolated `Store`
with capabilities enforced from its manifest.

## Current Implementation Status

As of this writing, the extension host is scaffolded but not fully wired into
the daemon runtime. The crate declares dependencies on `wasmtime`,
`wasmtime-wasi`, `core-types`, `core-config`, `core-ipc`, and `extension-sdk`.
The public module (`extension-host/src/lib.rs`) contains documentation comments
describing the intended architecture but no exported functions or types yet.
The sections below describe the design that these crates are being built toward.

## Wasmtime Runtime Configuration

The extension host uses [Wasmtime](https://wasmtime.dev/) as its WebAssembly
runtime. The planned configuration includes:

- **Cranelift compiler backend** -- Wasmtime's default optimizing compiler.
  Extensions are compiled ahead of time on first load, then cached.
- **Component model** -- Extensions are WASM components (not core modules).
  This enables typed interfaces via WIT and structured capability passing.
- **Pooling allocator** -- When multiple extensions run concurrently, the
  pooling instance allocator pre-reserves virtual address space for all
  instances, avoiding per-instantiation `mmap` overhead. Configuration
  parameters (instance count, memory pages, table elements) are derived
  from the extension manifest's declared resource limits.

## WASI Sandbox

Each extension Store is configured with a WASI context that restricts what
the guest can access. The sandbox follows a deny-by-default model:

| Resource | Default | With Capability Grant |
|---|---|---|
| Filesystem read | Denied | Scoped to declared directories |
| Filesystem write | Denied | Scoped to declared directories |
| Network sockets | Denied | Denied (no current grant path) |
| Environment variables | Denied | Filtered set from manifest |
| Clock (monotonic) | Allowed | Allowed |
| Clock (wall) | Allowed | Allowed |
| Random (CSPRNG) | Allowed | Allowed |
| stdin/stdout/stderr | Redirected to host log | Redirected to host log |

Extensions cannot access the host filesystem, network, or other extensions'
memory unless the host explicitly grants a capability through the WIT
interface.

## Capability Grants

The host exposes functionality to extensions through WIT-defined interfaces.
An extension's manifest declares which capabilities it requires; the host
validates these at load time and links only the granted imports.

Planned capability categories:

- **secret-read** -- Read a named secret from the active vault (routed
  through daemon-secrets via IPC). The extension never receives the vault
  master key.
- **secret-write** -- Store or update a secret. Requires explicit user
  approval on first use.
- **config-read** -- Read configuration values from `core-config`.
- **ipc-publish** -- Publish an `EventKind` message to the IPC bus at the
  extension's clearance level.
- **clipboard-write** -- Write to the clipboard via daemon-clipboard.
- **notification** -- Display a desktop notification.

Each capability is a separate WIT interface. An extension that declares
`secret-read` but not `secret-write` receives a linker that provides only
the read import; the write import is left unresolved, causing instantiation
to fail if the guest attempts to call it.

## Resource Limits

The host enforces per-extension resource limits to prevent a misbehaving
extension from affecting system stability:

- **Memory** -- Maximum linear memory size, configured in the pooling
  allocator. The default is 64 MiB per extension instance.
- **Fuel (CPU)** -- Wasmtime's fuel metering limits the number of
  instructions an extension can execute per invocation. When fuel is
  exhausted, the call traps with a deterministic error.
- **Table elements** -- Maximum number of indirect function table entries.
- **Instances** -- Maximum number of concurrent component instances across
  all loaded extensions.
- **Execution timeout** -- A wall-clock deadline per invocation. Implemented
  via Wasmtime's epoch interruption mechanism: the host increments the
  epoch on a timer, and each Store is configured with a maximum epoch delta.

These limits are declared in the extension manifest and validated against
system-wide maximums set in `core-config`.
