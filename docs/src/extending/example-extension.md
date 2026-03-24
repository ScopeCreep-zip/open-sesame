# Example Extension

This page walks through creating a WASM component model extension for
Open Sesame, from WIT interface definition through OCI packaging. Because the
extension runtime is not yet fully wired, sections that describe design intent
rather than working code are marked accordingly.

## Prerequisites

- Rust toolchain with the `wasm32-wasip2` target:

  ```bash
  rustup target add wasm32-wasip2
  ```

- `wasm-tools` for component composition:

  ```bash
  cargo install wasm-tools
  ```

- An OCI-compatible registry (e.g., `ghcr.io`) for publishing.

## Step 1: Define the WIT Interface

> **Design intent.** No `.wit` files ship in the repository yet. The
> `extension-sdk` crate will provide canonical WIT definitions; what follows
> is the planned schema.

Create a `wit/` directory with the extension's world:

```wit
// wit/world.wit
package open-sesame:example@0.1.0;

world greeting {
  import open-sesame:host/config-read@0.1.0;
  export greet: func(name: string) -> string;
}
```

The `import` line declares that this extension requires the `config-read`
capability from the host. The `export` line declares the function the host
will call.

## Step 2: Implement the Guest in Rust

Create a new crate:

```bash
cargo new --lib greeting-extension
cd greeting-extension
```

Add dependencies to `Cargo.toml`:

```toml
[package]
name = "greeting-extension"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.41"
```

The `extension-sdk` crate (`extension-sdk/Cargo.toml`) depends on
`wit-bindgen` for generating Rust bindings from WIT definitions. Guest code
uses the `wit_bindgen::generate!` macro:

```rust
// src/lib.rs
wit_bindgen::generate!({
    world: "greeting",
    path: "../wit",
});

struct Component;

impl Guest for Component {
    fn greet(name: String) -> String {
        // Read a greeting template from config (host-provided import).
        let template = open_sesame::host::config_read::get("greeting.template")
            .unwrap_or_else(|| "Hello, {}!".to_string());
        template.replace("{}", &name)
    }
}

export!(Component);
```

## Step 3: Build the WASM Component

Compile to a core WASM module, then convert to a component:

```bash
cargo build --target wasm32-wasip2 --release

wasm-tools component new \
  target/wasm32-wasip2/release/greeting_extension.wasm \
  -o greeting.component.wasm
```

The resulting `greeting.component.wasm` is a self-describing component that
declares its imports and exports in the component model type system.

## Step 4: Package as an OCI Artifact

> **Design intent.** OCI distribution is defined in `core-types/src/oci.rs`
> as `OciReference` but the pull/push workflow is not yet implemented.

Open Sesame identifies extensions by OCI references with the format:

```text
registry/principal/scope:revision[@provenance]
```

For example:

```text
ghcr.io/my-org/greeting-extension:0.1.0@sha256:abcdef1234567890
```

The `OciReference` struct parses this into five fields:

| Field | Example | Required |
|---|---|---|
| `registry` | `ghcr.io` | Yes |
| `principal` | `my-org` | Yes |
| `scope` | `greeting-extension` | Yes |
| `revision` | `0.1.0` | Yes |
| `provenance` | `sha256:abcdef1234567890` | No |

Push the component to a registry using an OCI-compatible tool:

```bash
oras push ghcr.io/my-org/greeting-extension:0.1.0 \
  greeting.component.wasm:application/vnd.wasm.component.v1+wasm
```

## Step 5: Write the Extension Manifest

> **Design intent.** The manifest schema is not yet finalized.

The extension manifest declares metadata, capabilities, and resource limits:

```toml
[extension]
name = "greeting-extension"
version = "0.1.0"
oci = "ghcr.io/my-org/greeting-extension:0.1.0"

[capabilities]
config-read = true

[limits]
max_memory_mib = 16
max_fuel = 1_000_000
```

Place this file in `~/.config/pds/extensions/greeting-extension.toml`.

## Step 6: Load and Test

> **Design intent.** The CLI subcommand for extension management is not yet
> implemented.

Once the extension host runtime is wired, the intended workflow:

```bash
# Install from OCI
sesame extension install ghcr.io/my-org/greeting-extension:0.1.0

# List installed extensions
sesame extension list

# Invoke directly for testing
sesame extension call greeting-extension greet "World"
```

## Testing During Development

Until the full extension host is available, extensions can be tested with
standalone Wasmtime:

```bash
wasmtime run --wasm component-model greeting.component.wasm \
  --invoke greet "World"
```

For Rust-level unit tests, the `extension-sdk` crate includes `proptest` as
a dev-dependency for property-based testing of WIT type serialization.
