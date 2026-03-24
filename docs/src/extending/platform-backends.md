# Adding Platform Backends

This page describes how to add a new operating system backend or a new compositor backend within an
existing platform crate.

## Platform Crate Structure

Open Sesame uses one platform crate per operating system:

| Crate | Target | Status |
|-------|--------|--------|
| `platform-linux` | `target_os = "linux"` | Implemented: compositor backends, evdev input, D-Bus, systemd, Landlock/seccomp sandbox |
| `platform-macos` | `target_os = "macos"` | Scaffolded: module declarations with no functional code |
| `platform-windows` | `target_os = "windows"` | Scaffolded: module declarations with no functional code |

Each crate compiles as an empty library on non-target platforms. All public modules are gated with
`#[cfg(target_os = "...")]`. Platform crates contain no business logic -- they provide safe Rust
abstractions consumed by daemon crates.

## Compositor Trait and Factory Pattern

The `platform-linux` crate demonstrates the reference pattern for abstracting over multiple backends
within a single platform.

### The Trait

The `CompositorBackend` trait in `platform-linux/src/compositor.rs` defines the interface:

```rust
pub trait CompositorBackend: Send + Sync {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>>;
    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>>;
    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn set_window_geometry(&self, id: &WindowId, geom: &Geometry)
        -> BoxFuture<'_, core_types::Result<()>>;
    fn move_to_workspace(&self, id: &WindowId, ws: &CompositorWorkspaceId)
        -> BoxFuture<'_, core_types::Result<()>>;
    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn name(&self) -> &str;
}
```

Methods return `BoxFuture` (`Pin<Box<dyn Future<Output = T> + Send>>`) instead of using `async fn`
in the trait. This is required for dyn-compatibility -- the factory function returns
`Box<dyn CompositorBackend>` for runtime backend selection.

### The Factory

`detect_compositor()` probes the runtime environment and returns the appropriate backend:

```rust
pub fn detect_compositor() -> core_types::Result<Box<dyn CompositorBackend>> {
    // 1. Try COSMIC-specific protocols (if cosmic feature enabled)
    // 2. Try wlr-foreign-toplevel-management-v1
    // 3. Return Error::Platform if nothing works
}
```

Detection order matters: more specific backends are tried first (COSMIC), with generic fallbacks last
(WLR). Each backend's `connect()` method probes for required protocols and returns an error if they
are unavailable, allowing the factory to fall through to the next candidate.

### Backend Implementations

Each backend is a `pub(crate)` module containing a struct that implements `CompositorBackend`:

- `backend_cosmic.rs` -- `CosmicBackend` using
  `ext_foreign_toplevel_list_v1` + `zcosmic_toplevel_{info,manager}_v1`
- `backend_wlr.rs` -- `WlrBackend` using `zwlr_foreign_toplevel_manager_v1`

Backends are `pub(crate)` because callers interact with them only through
`Box<dyn CompositorBackend>` returned by the factory. The concrete types are not part of the
public API.

## Adding a New Compositor Backend

To add support for a compositor that uses different protocols (e.g., GNOME/Mutter, KDE/KWin,
Hyprland IPC):

### Step 1: Create the Backend Module

Create `platform-linux/src/backend_<name>.rs` with a struct implementing `CompositorBackend`. The
struct must be `Send + Sync`.

For operations not supported by the compositor's protocols, return `Error::Platform` with a
descriptive message:

```rust
fn set_window_geometry(&self, _id: &WindowId, _geom: &Geometry)
    -> BoxFuture<'_, core_types::Result<()>>
{
    Box::pin(async {
        Err(core_types::Error::Platform(
            "set_window_geometry not supported by <name> protocol".into(),
        ))
    })
}
```

Provide a `connect()` constructor that probes for required protocols/interfaces and returns
`core_types::Result<Self>`.

### Step 2: Register the Module

Add the module declaration to `platform-linux/src/lib.rs`:

```rust
#[cfg(all(target_os = "linux", feature = "<name>"))]
pub(crate) mod backend_<name>;
```

### Step 3: Add the Detection Arm

Add a match arm to `detect_compositor()` in `platform-linux/src/compositor.rs`. Place it in the
detection order based on protocol specificity:

```rust
#[cfg(feature = "<name>")]
{
    match crate::backend_<name>::<Name>Backend::connect() {
        Ok(backend) => {
            tracing::info!("compositor backend: <name>");
            return Ok(Box::new(backend));
        }
        Err(e) => {
            tracing::info!("<name> backend unavailable, trying next: {e}");
        }
    }
}
```

### Step 4: Add the Feature Flag

In `platform-linux/Cargo.toml`, add a feature flag for the new backend:

```toml
[features]
<name> = [
    "desktop",
    "dep:<new-protocol-crate>",
]
```

If the new backend uses only existing dependencies (e.g., communicating via D-Bus with `zbus`), no
additional optional dependencies are needed.

## Feature Gating and Conditional Compilation

Platform crates use a layered feature flag model:

- **No features:** Headless-safe modules only (sandbox, security, systemd, dbus, cosmic_keys,
  cosmic_theme, clipboard trait). Suitable for server/container deployments.
- **`desktop`:** Wayland compositor integration, evdev input, focus monitoring. Pulls in
  `wayland-client`, `wayland-protocols`, `wayland-protocols-wlr`, `smithay-client-toolkit`, `evdev`.
- **`cosmic`:** COSMIC-specific protocols. Implies `desktop`. Pulls in `cosmic-client-toolkit` and
  `cosmic-protocols` (GPL-3.0).

This layering isolates build dependencies and license obligations. The `cosmic` feature flag
specifically isolates GPL-3.0 dependencies so that builds without COSMIC support remain under the
project's base license.

Conditional compilation uses `#[cfg(all(target_os = "linux", feature = "..."))]` on module
declarations in `lib.rs`. Backend modules are `pub(crate)` so they remain internal implementation
details.

## Adding a New OS Platform

To add a platform crate for a new operating system:

1. Create `platform-<os>/` with `Cargo.toml` and `src/lib.rs`.
2. Gate all modules with `#[cfg(target_os = "<os>")]`.
3. Depend on `core-types` for shared types (`Window`, `WindowId`, `Error`, `Result`).
4. Implement the same logical modules as the other platform crates (window management, clipboard,
   input, credential storage, daemon lifecycle). The specific API surface depends on what the OS
   provides.
5. Use `pub(crate)` for backend implementation modules; expose only traits and factory functions as
   the public API.
6. Add the crate to the workspace `Cargo.toml`.
7. Update daemon crates to conditionally depend on the new platform crate via
   `[target.'cfg(target_os = "<os>")'.dependencies]`.

The platform crate should contain no business logic. It provides safe wrappers over OS APIs, and
daemon crates compose these wrappers into application behavior.
