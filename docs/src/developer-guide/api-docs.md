# API Documentation

Open Sesame provides a library crate (`open_sesame`) with reusable components for building Wayland window management applications.

## Online API Reference

View the complete API documentation at:

**[https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/)**

## Building Documentation Locally

```bash
# Build API docs
cargo doc --no-deps --open

# Or via mise
mise run docs:api
```

This opens the documentation in your browser at `target/doc/open_sesame/index.html`.

## Module Overview

The `open_sesame` crate is organized into several modules:

### [`app`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/app/)

Application orchestration and event loop.

**Key types:**

- `App` - Main application coordinator
- `AppState` - UI state machine

**Responsibilities:**

- Wayland event loop integration
- State management (idle, showing overlay, window selected)
- Event dispatching to appropriate handlers
- Render coordination

**Example:**

```rust
use open_sesame::app::App;
use open_sesame::Config;

let config = Config::load()?;
let hints = vec![/* ... */];
let result = App::run(config, hints, None, true, None)?;
```

### [`config`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/config/)

Configuration loading and validation.

**Key types:**

- `Config` - Main configuration struct
- `Settings` - Global settings (delays, colors, etc.)
- `KeyBinding` - Per-key app associations
- `LaunchConfig` - Launch command configuration
- `Color` - RGBA color with hex serialization
- `ConfigValidator` - Configuration validation

**Responsibilities:**

- TOML parsing and serialization
- XDG config file discovery
- Layered configuration merging
- Schema validation

**Example:**

```rust
use open_sesame::Config;

// Load from default paths
let config = Config::load()?;

// Get key for app
if let Some(key) = config.key_for_app("firefox") {
    println!("Firefox is bound to '{}'", key);
}

// Generate default config
let default_toml = Config::default_toml();
```

### [`core`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/core/)

Domain types and business logic.

**Key types:**

- `Window` - Window information (ID, app ID, title, focused state)
- `WindowId` - Opaque window identifier
- `AppId` - Application identifier
- `WindowHint` - Assigned hint for a window
- `HintAssignment` - Complete hint assignment
- `HintMatcher` - Input matching logic
- `LaunchCommand` - Command execution abstraction

**Responsibilities:**

- Hint assignment algorithm (Vimium-style)
- Input matching and disambiguation
- Window filtering and sorting
- Launch command abstraction

**Example:**

```rust
use open_sesame::core::{HintAssignment, Window, AppId, WindowId};

let windows = vec![
    Window {
        id: WindowId::new("1"),
        app_id: AppId::new("firefox"),
        title: "Mozilla Firefox".to_string(),
        is_focused: false,
    },
];

let assignment = HintAssignment::assign(&windows, |app_id| {
    if app_id == "firefox" { Some('f') } else { None }
});

assert_eq!(assignment.hints[0].hint, "f");
```

### [`input`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/input/)

Keyboard input processing.

**Key types:**

- `InputBuffer` - Typed character buffer
- `InputHandler` - Key event processor
- `MatchResult` - Result of hint matching

**Responsibilities:**

- Key event handling
- Multi-key hint matching (g, gg, ggg)
- Backspace handling
- Arrow key navigation

**Example:**

```rust
use open_sesame::input::{InputBuffer, HintMatcher, MatchResult};

let mut buffer = InputBuffer::new();
buffer.push('g');

let matcher = HintMatcher::new(hints);
match matcher.match_input(&buffer) {
    MatchResult::Exact(idx) => println!("Matched window {}", idx),
    MatchResult::Partial => println!("Partial match, continue typing"),
    MatchResult::NoMatch => println!("No match"),
}
```

### [`platform`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/platform/)

Platform abstraction layer for Wayland and COSMIC.

**Key functions:**

- `enumerate_windows()` - List all windows via Wayland protocols
- `activate_window()` - Activate and focus a window
- `setup_keybinding()` - Configure COSMIC keybinding
- `remove_keybinding()` - Remove COSMIC keybinding
- `keybinding_status()` - Check keybinding configuration

**Wayland protocols:**

- `wlr-foreign-toplevel-management` - Window enumeration
- `cosmic-workspace` - Workspace information
- `cosmic-window-management` - Window activation

**Example:**

```rust
use open_sesame::platform;
use open_sesame::WindowId;

// Enumerate windows
let windows = platform::enumerate_windows()?;

// Activate a window
let window_id = WindowId::new("wayland-1");
platform::activate_window(&window_id)?;
```

### [`render`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/render/)

Software rendering pipeline.

**Key types:**

- `Renderer` - Main rendering coordinator
- `Buffer` - Wayland shared memory buffer
- `FontCache` - Cached font glyphs

**Rendering stack:**

- `fontdue` - Font rasterization
- `tiny-skia` - 2D graphics primitives
- `wayland-client` - Buffer management

**Responsibilities:**

- Overlay rendering
- Font rasterization and caching
- Primitive drawing (rectangles, text)
- Buffer management for Wayland

**Note:** Rendering is primarily internal and not exposed as public API.

### [`ui`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/ui/)

User interface components.

**Key types:**

- `Overlay` - Main overlay component
- `Theme` - Color scheme and styling
- `Layout` - Window card positioning

**Responsibilities:**

- Overlay window creation
- Layout calculations
- Theme management
- Component coordination

**Example:**

```rust
use open_sesame::ui::{Overlay, Theme};

let theme = Theme::from_config(&config.settings);
let overlay = Overlay::new(theme);
```

### [`util`](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/util/)

Shared utilities and helpers.

**Key types:**

- `InstanceLock` - Single-instance locking
- `IpcServer` / `IpcClient` - Inter-process communication
- `MruState` - Most Recently Used window tracking
- `Error` / `Result` - Error types

**Key functions:**

- `load_mru_state()` - Load MRU state from cache
- `save_activated_window()` - Save MRU state
- `load_env_files()` - Parse environment files
- `log::init()` - Initialize logging

**Example:**

```rust
use open_sesame::util::{InstanceLock, load_mru_state};

// Single-instance locking
let _lock = InstanceLock::acquire()?;

// MRU tracking
let mru = load_mru_state();
println!("Previous window: {:?}", mru.previous);
```

## Error Handling

Open Sesame uses custom error types for clear error reporting:

```rust
use open_sesame::{Error, Result};

fn example() -> Result<()> {
    let config = Config::load()
        .map_err(|e| Error::Config(e.to_string()))?;
    Ok(())
}
```

**Error types:**

- `Error::Config` - Configuration errors
- `Error::Platform` - Wayland/platform errors
- `Error::InvalidColor` - Color parsing errors
- `Error::Io` - I/O errors
- `Error::Other` - Other errors

## Re-exports

Commonly used types are re-exported at the crate root:

```rust
use open_sesame::{
    Config,            // Configuration
    Window,            // Window info
    WindowId,          // Window identifier
    AppId,             // App identifier
    HintAssignment,    // Hint assignment
    HintMatcher,       // Input matching
    Error,             // Error type
    Result,            // Result type
};
```

## Feature Flags

Current features:

- `default` - All default features
- `debug-logging` - Always enable debug logging (off by default)

**Example:**

```toml
# In Cargo.toml
[dependencies]
open-sesame = { version = "*", features = ["debug-logging"] }
```

## Examples

The repository includes example programs in the `examples/` directory:

```bash
# List examples
ls examples/

# Run an example
cargo run --example window_enumeration
```

**Available examples:**

- `window_enumeration` - Enumerate windows and print details
- `hint_assignment` - Demonstrate hint assignment algorithm
- `config_loading` - Load and display configuration

## Documentation Standards

All public APIs follow these documentation standards:

1. **Module docs** (`//!`) - Overview and examples
2. **Type docs** (`///`) - Purpose and usage
3. **Function docs** (`///`) - Parameters, returns, examples, errors
4. **Examples** - Working code examples in docs
5. **Links** - Cross-references to related types

**Example:**

```rust
/// Parse a color from hex string.
///
/// Supports both RGB (`#RRGGBB`) and RGBA (`#RRGGBBAA`) formats.
///
/// # Arguments
///
/// * `s` - Hex string (with or without leading `#`)
///
/// # Examples
///
/// ```
/// use open_sesame::config::Color;
///
/// let red = Color::from_hex("#ff0000").unwrap();
/// assert_eq!(red.r, 255);
///
/// let transparent = Color::from_hex("#00000080").unwrap();
/// assert_eq!(transparent.a, 128);
/// ```
///
/// # Errors
///
/// Returns [`Error::InvalidColor`] if the string is not valid hex.
///
/// # See Also
///
/// * [`Color::to_hex`] - Convert color to hex string
pub fn from_hex(s: &str) -> Result<Color> {
    // ...
}
```

## Building Documentation

### Standard Build

```bash
cargo doc --no-deps
```

### With Private Items

```bash
cargo doc --no-deps --document-private-items
```

### With All Features

```bash
cargo doc --no-deps --all-features
```

### Check for Warnings

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## Contributing to Documentation

See the [Contributing Guide](./contributing.md) for documentation standards and guidelines.

**Quick tips:**

- Document all public items
- Include examples for complex functionality
- Use intra-doc links for cross-references
- Keep examples short and focused
- Test examples with `cargo test --doc`

## Next Steps

- [Architecture Guide](./architecture.md) - Understand the design
- [Building Guide](./building.md) - Build from source
- [Testing Guide](./testing.md) - Run tests
- [Contributing Guide](./contributing.md) - Contribute code
