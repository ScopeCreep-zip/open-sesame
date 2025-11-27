# Architecture

Open Sesame is architected as a modular Rust application with clean separation of concerns and well-defined module boundaries.

## Design Principles

### 1. Zero External Dependencies at Runtime

Open Sesame uses software rendering (tiny-skia) instead of GPU acceleration, eliminating the need for graphics
drivers or OpenGL/Vulkan runtime dependencies.

**Benefits:**

- Works on any system with Wayland support
- No GPU-specific bugs or driver compatibility issues
- Smaller binary size
- Faster startup time

### 2. Single-Instance Execution

Only one instance of Open Sesame can run at a time. Multiple invocations communicate via IPC (Inter-Process Communication).

**Implementation:**

- File-based lock in `~/.cache/open-sesame/lock`
- Unix socket for IPC commands
- New instances signal existing instance to cycle forward/backward

**Use case:**

- Pressing Alt+Tab multiple times → signals running instance to cycle
- Prevents multiple overlays from appearing simultaneously

### 3. Fast Activation

Target: Sub-200ms window switching latency

**Optimizations:**

- Pre-computed hint assignments
- Efficient window enumeration via Wayland
- Minimal rendering (software rasterization)
- Event-driven architecture (no polling)

### 4. Graceful Degradation

Open Sesame handles failures gracefully:

- Falls back to stderr logging if file logging fails
- Continues without MRU state if cache is corrupted
- Works with minimal configuration (sensible defaults)

### 5. Secure by Default

- Proper file permissions on config and cache files
- No network access
- Cache directory isolation
- Input validation on all external data

## Module Overview

Open Sesame is organized into eight main modules:

### `app` - Application Orchestration

**Responsibility:** Event loop, state management, render coordination

**Key types:**

- `App` - Main application struct
- `AppState` - Current UI state (overlay shown, window selected, etc.)
- Event handlers for keyboard input, IPC commands, timers

**Flow:**

1. Initialize Wayland connection
2. Enumerate windows
3. Assign hints
4. Enter event loop
5. Handle input → update state → render
6. Exit on selection or cancellation

### `config` - Configuration System

**Responsibility:** Loading, parsing, validating TOML configuration

**Key types:**

- `Config` - Main configuration struct
- `Settings` - Global settings (delays, colors, etc.)
- `KeyBinding` - Per-key app associations
- `LaunchConfig` - Simple or advanced launch configuration

**Features:**

- XDG-compliant file locations
- Layered inheritance (system → user → overrides)
- Schema validation with helpful error messages
- Default configuration generation

**File locations:**

```text
/etc/open-sesame/config.toml              # System defaults
~/.config/open-sesame/config.toml         # User config
~/.config/open-sesame/config.d/*.toml     # Overrides (alphabetical)
```

### `core` - Domain Logic

**Responsibility:** Business logic, hint assignment algorithm, window types

**Key types:**

- `Window` - Window information (ID, app ID, title, focused state)
- `WindowHint` - Assigned hint for a window
- `HintAssignment` - Complete hint assignment for all windows
- `HintMatcher` - Input matching logic
- `LaunchCommand` - Command execution abstraction

**Hint assignment algorithm:**

1. Windows with configured keys get priority
2. Multiple instances get repeated letters (g, gg, ggg)
3. Remaining windows get sequential letters (a-z, excluding used keys)

**Example:**

```text
Windows: [Firefox, Firefox, Ghostty, Code]
Config:  f → Firefox, g → Ghostty, v → Code

Assignment:
  Firefox → f
  Firefox → ff
  Ghostty → g
  Code → v
```

### `input` - Keyboard Input Processing

**Responsibility:** Handling keyboard events, matching hints, buffer management

**Key types:**

- `InputBuffer` - Tracks typed characters
- `InputHandler` - Processes key events
- `KeyEvent` - Keyboard event representation

**Features:**

- Multi-key hint matching (g, gg, ggg)
- Alternative input (g1, g2, g3)
- Backspace handling
- Arrow key navigation

**Flow:**

1. Receive key event from Wayland
2. Update input buffer
3. Match against hints
4. Return action (activate, select, cancel, continue)

### `platform` - Platform Abstraction

**Responsibility:** Wayland protocol integration, COSMIC-specific features

**Key modules:**

- `wayland` - Window enumeration via Wayland protocols
- `cosmic` - COSMIC desktop integration (keybindings, protocols)
- `activation` - Window activation via COSMIC protocols

**Wayland protocols used:**

- `wlr-foreign-toplevel-management` - Window enumeration
- `cosmic-workspace` - Workspace-aware window listing
- `cosmic-window-management` - Window activation

**Features:**

- Workspace-aware window listing
- Window activation (focus and raise)
- Keybinding configuration via COSMIC settings
- Theme integration (future)

### `render` - Rendering Pipeline

**Responsibility:** Software rendering with tiny-skia, font rasterization

**Key types:**

- `Renderer` - Main rendering coordinator
- `Buffer` - Shared memory buffer for Wayland
- `FontCache` - Cached font rasterization

**Rendering stack:**

- `fontdue` - Font rasterization (TTF/OTF parsing and glyph rendering)
- `tiny-skia` - 2D graphics (paths, shapes, blending)
- `wayland-client` - Buffer sharing with compositor

**Primitives:**

- Rectangles with rounded corners
- Text rendering with anti-aliasing
- Color blending and transparency
- Borders and shadows

### `ui` - User Interface

**Responsibility:** Overlay layout, theme management, UI components

**Key types:**

- `Overlay` - Main overlay window component
- `Theme` - Color scheme and styling
- `Layout` - Window card positioning

**Features:**

- Centered overlay with window cards
- Hint badges overlaid on windows
- Selected window highlighting
- Border indicator for quick switch

**Layout algorithm:**

- Grid layout with dynamic columns
- Center alignment
- Responsive sizing based on window count
- Scroll support for many windows (future)

### `util` - Shared Utilities

**Responsibility:** Cross-cutting concerns, helpers

**Key modules:**

- `lock` - Single-instance locking
- `ipc` - Inter-process communication
- `mru` - Most Recently Used window tracking
- `env` - Environment file parsing
- `log` - Logging setup

**Features:**

- File-based instance locking
- Unix socket IPC
- MRU state persistence (JSON)
- direnv-style .env file parsing
- Structured logging with tracing

## Data Flow

### Window Switching Flow

```text
1. User presses Alt+Space
   ↓
2. COSMIC runs: sesame --launcher
   ↓
3. Open Sesame starts
   ↓
4. Check instance lock
   ├─ Locked? → Signal existing instance via IPC → exit
   └─ Not locked? → Acquire lock and continue
   ↓
5. Load configuration
   ↓
6. Enumerate windows via Wayland
   ↓
7. Assign hints (core::HintAssignment)
   ↓
8. Initialize Wayland surface for overlay
   ↓
9. Render overlay (render::Renderer)
   ↓
10. Enter event loop (app::App)
    ↓
11. Handle keyboard input (input::InputHandler)
    ├─ Match hint? → Activate window → exit
    ├─ Arrow key? → Update selection → re-render
    └─ Escape? → Cancel → exit
```

### Configuration Loading Flow

```text
1. Load system config: /etc/open-sesame/config.toml
   ↓
2. Merge user config: ~/.config/open-sesame/config.toml
   ↓
3. Merge overrides: ~/.config/open-sesame/config.d/*.toml (alphabetical)
   ↓
4. Validate configuration (config::ConfigValidator)
   ↓
5. Return Config struct
```

### Hint Assignment Flow

```text
1. Input: List of windows, config with key bindings
   ↓
2. For each window:
   ├─ Check config for matching key
   ├─ If match: Assign configured key
   └─ If no match: Assign next available letter
   ↓
3. Handle duplicates:
   ├─ First instance: single letter (g)
   ├─ Second instance: repeated letter (gg)
   └─ Third instance: triple letter (ggg)
   ↓
4. Return HintAssignment
```

## Concurrency Model

Open Sesame is primarily **single-threaded** with async I/O for Wayland events.

**Event loop:**

- Main thread runs Wayland event loop
- No multi-threading (avoids synchronization complexity)
- Async I/O via `wayland-client` non-blocking sockets

**Why single-threaded?**

- Simple to reason about (no race conditions)
- Fast enough for the use case (< 100ms latency)
- Avoids threading overhead

## Error Handling

Open Sesame uses Rust's `Result` type for error handling.

**Error strategy:**

- `anyhow::Result` for CLI and top-level errors
- Custom `util::Error` type for library code
- Graceful degradation (log errors, use fallbacks)
- Never panic in production code (except for unrecoverable bugs)

**Example:**

```rust
// Configuration loading
pub fn load_config() -> Result<Config> {
    let config = load_from_file().context("Failed to load config")?;
    validate(&config).context("Invalid configuration")?;
    Ok(config)
}
```

## Testing Strategy

### Unit Tests

Each module has unit tests for pure functions:

- `core::HintAssignment::assign` - Hint algorithm tests
- `config::Color::from_hex` - Color parsing tests
- `input::InputBuffer` - Input matching tests

### Integration Tests

Integration tests in `tests/` directory:

- Configuration loading and merging
- Hint assignment with real-world window lists
- IPC communication

### Manual Testing

Use `mise run dev` for manual testing:

- Window enumeration
- Overlay rendering
- Keyboard input
- Configuration changes

## Performance Characteristics

### Startup Time

**Target:** < 100ms from invocation to overlay display

**Breakdown:**

- Config loading: ~5ms
- Window enumeration: ~10ms
- Hint assignment: ~1ms
- Wayland setup: ~20ms
- Render first frame: ~30ms
- Total: ~66ms

### Memory Usage

**Typical:** 8-12 MB resident memory

**Breakdown:**

- Binary: ~4 MB
- Window list: ~100 KB (100 windows)
- Render buffers: ~2 MB (1920x1080 overlay)
- Font cache: ~1 MB

### Window Switching Latency

**Target:** < 200ms from key press to window activation

**Breakdown:**

- Input event: ~5ms
- Hint matching: ~1ms
- Wayland activation: ~10ms
- Compositor switch: ~50ms (depends on compositor)
- Total: ~66ms (typical)

## Security Considerations

### Input Validation

- All configuration is validated before use
- Color hex strings are parsed safely
- File paths are canonicalized
- Command execution uses explicit PATH resolution

### File Permissions

- Config files: `644` (readable by all, writable by owner)
- Cache files: `644` (MRU state, logs)
- Lock file: `644` (instance lock)

### No Network Access

Open Sesame never makes network connections:

- No telemetry
- No update checks
- No remote configuration

### Privilege Separation

Open Sesame runs as the user, not as root:

- No setuid/setgid
- No system-wide modifications (except via package manager)
- User-level configuration only

## Future Architecture Improvements

### Planned Enhancements

1. **Plugin System** - Allow custom hint assignment strategies
2. **Theme System** - Load themes from COSMIC desktop settings
3. **Window Previews** - Show window thumbnails in overlay
4. **Workspace Support** - Filter windows by workspace
5. **Multi-Monitor** - Show overlay on active monitor only

### Technical Debt

- Reduce coupling between `app` and `render` modules
- Extract IPC into a reusable crate
- Improve test coverage for Wayland interactions
- Add property-based testing for hint assignment

## See Also

- [Building Guide](./building.md) - How to build Open Sesame
- [Testing Guide](./testing.md) - How to run tests
- [Contributing Guide](./contributing.md) - How to contribute
- [API Documentation](./api-docs.md) - Rustdoc API reference
