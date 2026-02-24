//! WASM extension host for PDS.
//!
//! Provides the wasmtime-backed runtime for executing WASM component model
//! extensions with capability-based sandboxing. Each extension runs in its
//! own `Store` with capabilities enforced from its manifest.
