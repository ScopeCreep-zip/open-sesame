# Open Sesame Source Architecture

> **Engineering documentation for developers working on the Open Sesame codebase**

Open Sesame is a Vimium-style window switcher for the COSMIC desktop environment. It displays a visual overlay
with letter hints, allowing users to quickly switch between windows by typing hint letters or using traditional
Alt+Tab navigation.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Module Map](#module-map)
- [Data Flow](#data-flow)
- [Core Concepts](#core-concepts)
- [Module Deep Dives](#module-deep-dives)
  - [app/ - Application Orchestration](#app---application-orchestration)
  - [config/ - Configuration System](#config---configuration-system)
  - [core/ - Domain Logic](#core---domain-logic)
  - [input/ - Input Processing](#input---input-processing)
  - [platform/ - Platform Abstraction](#platform---platform-abstraction)
  - [render/ - Graphics Pipeline](#render---graphics-pipeline)
  - [ui/ - User Interface](#ui---user-interface)
  - [util/ - Utilities](#util---utilities)
- [Key Design Decisions](#key-design-decisions)
- [Error Handling Philosophy](#error-handling-philosophy)
- [Platform Integration](#platform-integration)
- [Testing Strategy](#testing-strategy)
- [Contributing Guidelines](#contributing-guidelines)

---

## Architecture Overview

Open Sesame follows a layered architecture with clear separation of concerns:

```text
┌───────────────────────────────────────────────────────────────┐
│                           main.rs                             │
│                      (CLI & Entry Point)                      │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│                           lib.rs                              │
│                     (Public API Surface)                      │
└───────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   ┌──────────┐         ┌──────────┐         ┌──────────┐
   │   app    │◄───────►│  config  │         │    ui    │
   │          │         │          │         │          │
   └────┬─────┘         └──────────┘         └────┬─────┘
        │                                         │
        │          ┌──────────────────┐           │
        └─────────►│       core       │◄──────────┘
                   │  (domain logic)  │
                   └────────┬─────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   ┌──────────┐       ┌──────────┐       ┌──────────┐
   │  input   │       │ platform │       │  render  │
   │          │       │          │       │          │
   └──────────┘       └──────────┘       └──────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │       util       │
                   │  (cross-cutting) │
                   └──────────────────┘
```

### Design Philosophy

1. **Single Responsibility**: Each module owns one concern completely
2. **Dependency Inversion**: Core logic depends on abstractions, not platform specifics
3. **Fail Fast**: Invalid states are caught early with typed errors
4. **Platform Native**: Deep integration with COSMIC desktop, not portable abstractions

---

## Module Map

```text
src/
├── main.rs              # CLI entry point, argument parsing
├── lib.rs               # Public API, module re-exports
│
├── app/                 # Application orchestration
│   ├── mod.rs           # SesameApp: main event loop & state machine
│   ├── state.rs         # AppState: application state management
│   └── renderer.rs      # Render orchestration (bridges app ↔ render)
│
├── config/              # Configuration system
│   ├── mod.rs           # Re-exports, Config type
│   ├── schema.rs        # TOML schema, serde models
│   ├── loader.rs        # Multi-file loading, XDG paths
│   └── validator.rs     # Validation rules, color parsing
│
├── core/                # Domain logic (platform-agnostic)
│   ├── mod.rs           # Re-exports
│   ├── hint.rs          # Hint: letter assignment system
│   ├── window.rs        # Window, WindowId, AppId types
│   ├── matcher.rs       # HintMatcher: input → window resolution
│   └── launcher.rs      # Application launching
│
├── input/               # Input handling
│   ├── mod.rs           # Re-exports
│   ├── buffer.rs        # InputBuffer: keystroke accumulation
│   └── processor.rs     # InputAction: key → action mapping
│
├── platform/            # Platform-specific code
│   ├── mod.rs           # Re-exports
│   ├── cosmic_keys.rs   # COSMIC keybinding setup
│   ├── cosmic_theme.rs  # COSMIC theme integration
│   ├── fonts.rs         # Fontconfig resolution
│   └── wayland/         # Wayland protocol handling
│       ├── mod.rs       # Re-exports
│       └── protocols.rs # Window enumeration & activation
│
├── render/              # Graphics pipeline
│   ├── mod.rs           # Re-exports
│   ├── context.rs       # RenderContext: shared render state
│   ├── pipeline.rs      # RenderPipeline: composable passes
│   ├── primitives.rs    # Color, rounded_rect, fill ops
│   └── text.rs          # TextRenderer: fontdue text rasterization
│
├── ui/                  # User interface components
│   ├── mod.rs           # Re-exports
│   ├── overlay.rs       # Overlay: main window list UI
│   └── theme.rs         # Theme: color schemes, COSMIC integration
│
└── util/                # Cross-cutting utilities
    ├── mod.rs           # Re-exports
    ├── error.rs         # Error enum, Result type
    ├── env.rs           # Environment file parsing
    ├── ipc.rs           # Unix socket IPC
    ├── lock.rs          # Single-instance enforcement
    ├── log.rs           # Logging configuration
    ├── mru.rs           # Most-recently-used tracking
    ├── paths.rs         # XDG path management
    └── timeout.rs       # TimeoutTracker utility
```

---

## Data Flow

### Window Switching Flow

```text
User presses Alt+Tab
         │
         ▼
┌────────────────────┐
│ main.rs            │  Parse CLI, check for running instance
│ (entry point)      │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ IpcClient          │  If instance exists → send cycle command
│ (util/ipc.rs)      │  Otherwise → start new instance
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ SesameApp::run()   │  Initialize Wayland, create overlay
│ (app/mod.rs)       │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ enumerate_windows  │  Query COSMIC for all toplevels
│ (platform/wayland) │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ HintMatcher        │  Assign letter hints to windows
│ (core/matcher.rs)  │  (g, gg, ggg for multiple instances)
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Overlay::render    │  Draw window list with hints
│ (ui/overlay.rs)    │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Event Loop         │  Process keyboard input
│ (calloop)          │
└─────────┬──────────┘
          │
     User types "g"
          │
          ▼
┌────────────────────┐
│ InputProcessor     │  Map keycode → InputAction
│ (input/processor)  │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ HintMatcher        │  Find matching window(s)
│ ::find_match()     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ activate_window    │  Focus window via COSMIC protocol
│ (platform/wayland) │
└────────────────────┘
```

### Configuration Loading Flow

```text
┌──────────────────────────────────────────────────────┐
│                Configuration Sources                 │
│    (loaded in order, later overrides earlier)        │
├──────────────────────────────────────────────────────┤
│  1. /etc/open-sesame/config.toml      (system)       │
│  2. ~/.config/open-sesame/config.toml (user)         │
│  3. ~/.config/open-sesame/config.d/*.toml (layers)   │
└─────────────────────────┬────────────────────────────┘
                          │
                          ▼
                ┌─────────────────┐
                │ loader.rs       │
                │ load_layered()  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ schema.rs       │
                │ RawConfig       │  Deserialize TOML
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ validator.rs    │
                │ validate()      │  Check constraints
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Config          │
                │ (final type)    │
                └─────────────────┘
```

---

## Core Concepts

### Hints

A **Hint** represents a keyboard shortcut assigned to a window. The hint system uses repeated letters for multiple
windows of the same application:

| Pattern | Meaning |
|---------|---------|
| `g` | First Ghostty window |
| `gg` | Second Ghostty window |
| `ggg` | Third Ghostty window |
| `g1`, `g2` | Alternative numeric notation |

```rust
// core/hint.rs
pub struct Hint {
    base: char,      // The primary letter (e.g., 'g')
    count: usize,    // Repetition count (1, 2, 3...)
}

impl Hint {
    pub fn as_string(&self) -> String;     // "g", "gg", "ggg"
    pub fn matches_input(&self, input: &str) -> bool;
    pub fn equals_input(&self, input: &str) -> bool;
}
```

### Windows

The **Window** type represents a desktop window with its metadata:

```rust
// core/window.rs
pub struct Window {
    pub id: WindowId,      // Unique Wayland identifier
    pub app_id: AppId,     // Application identifier (e.g., "com.mitchellh.ghostty")
    pub title: String,     // Window title
    pub is_focused: bool,  // Currently focused window
}
```

### WindowHint

A **WindowHint** pairs a window with its assigned hint:

```rust
// core/hint.rs
pub struct WindowHint {
    pub hint: Hint,
    pub app_id: String,
    pub title: String,
    pub window_id: WindowId,
}
```

---

## Module Deep Dives

### app/ - Application Orchestration

The `app` module coordinates all application components and manages the main event loop.

#### SesameApp (mod.rs)

The central orchestrator implementing a state machine:

```text
┌───────────────────────────────────────────────────────────────┐
│                     SesameApp State Machine                   │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│   ┌──────────┐   overlay_delay   ┌──────────┐                │
│   │ Initial  │───────────────────►│   Full   │                │
│   │ (border  │                    │  (list)  │                │
│   │  only)   │                    │          │                │
│   └────┬─────┘                    └────┬─────┘                │
│        │                               │                      │
│        │         User input            │                      │
│        └───────────────────────────────┤                      │
│                                        ▼                      │
│                              ┌─────────────────┐              │
│                              │  Match Found    │              │
│                              │activation_delay │              │
│                              └────────┬────────┘              │
│                                       │                       │
│                                       ▼                       │
│                              ┌─────────────────┐              │
│                              │ Activate Window │              │
│                              │ Exit Application│              │
│                              └─────────────────┘              │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

Key responsibilities:

- Initialize Wayland connection and layer shell surface
- Set up keyboard grab for exclusive input
- Manage overlay phase transitions (Initial → Full)
- Process IPC commands from other instances
- Handle activation delays for disambiguation

#### AppState (state.rs)

Encapsulates mutable application state:

```rust
pub struct AppState {
    pub hints: Vec<WindowHint>,      // Available windows with hints
    pub input: InputBuffer,          // Accumulated keystrokes
    pub selection: usize,            // Arrow-key selection index
    pub phase: OverlayPhase,         // Initial or Full
    pub activation_timeout: TimeoutTracker,
    pub overlay_timeout: TimeoutTracker,
    pub origin_window: Option<String>, // Window user started from
}
```

#### Renderer (renderer.rs)

Bridges application state to the rendering pipeline:

```rust
pub struct AppRenderer {
    overlay: Overlay,
}

impl AppRenderer {
    pub fn render(&self, state: &AppState) -> Option<Pixmap>;
}
```

---

### config/ - Configuration System

The configuration system provides layered, validated configuration with XDG compliance.

#### Schema (schema.rs)

Defines the TOML structure using serde:

```rust
#[derive(Deserialize)]
pub struct RawConfig {
    pub settings: Option<RawSettings>,
    pub keys: HashMap<String, KeyBinding>,
}

#[derive(Deserialize)]
pub struct KeyBinding {
    pub apps: Vec<String>,           // App IDs to match
    pub launch: Option<LaunchConfig>, // Focus-or-launch command
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum LaunchConfig {
    Simple(String),           // "firefox"
    Advanced {
        command: String,
        args: Option<Vec<String>>,
        env: Option<HashMap<String, String>>,
        env_files: Option<Vec<String>>,
    },
}
```

#### Loader (loader.rs)

Implements multi-file configuration loading:

```rust
pub fn load_layered() -> Result<Config> {
    // 1. Start with defaults
    // 2. Merge /etc/open-sesame/config.toml
    // 3. Merge ~/.config/open-sesame/config.toml
    // 4. Merge ~/.config/open-sesame/config.d/*.toml (alphabetically)
    // 5. Validate and return
}
```

#### Validator (validator.rs)

Enforces configuration constraints:

- Color format validation (`#RRGGBB` or `#RRGGBBAA`)
- Numeric range checks (delays, border width)
- Key binding character validation (single lowercase letter)

---

### core/ - Domain Logic

Platform-agnostic business logic that could theoretically work on any window system.

#### Hint Assignment (hint.rs)

The hint assignment algorithm:

```rust
pub fn assign_hints(
    windows: &[Window],
    key_bindings: &HashMap<String, KeyBinding>,
) -> Vec<WindowHint> {
    // 1. Group windows by app_id
    // 2. For each app, find matching key binding
    // 3. Assign hints: first = "g", second = "gg", third = "ggg"
    // 4. Windows without bindings get auto-assigned letters
}
```

#### Matching (matcher.rs)

The `HintMatcher` resolves user input to windows:

```rust
impl HintMatcher {
    pub fn find_exact_match(&self, input: &str) -> Option<&WindowHint>;
    pub fn find_partial_matches(&self, input: &str) -> Vec<&WindowHint>;
    pub fn has_potential_matches(&self, input: &str) -> bool;
}
```

Match behavior:

- Input "g" with hints [g, gg, ggg] → partial match, waits for more input
- Input "g" with hints [g, f, v] → exact match, activates immediately
- Input "gg" with hints [g, gg, ggg] → exact match

#### Launcher (launcher.rs)

Spawns applications with environment configuration:

```rust
pub fn launch_app(config: &LaunchConfig, global_env_files: &[String]) -> Result<()> {
    // 1. Load global env files
    // 2. Load per-app env files
    // 3. Apply explicit env vars
    // 4. Spawn process with setsid (detached from terminal)
}
```

---

### input/ - Input Processing

Handles keyboard input with buffering for multi-character hints.

#### InputBuffer (buffer.rs)

Accumulates keystrokes for hint matching:

```rust
pub struct InputBuffer {
    content: String,
}

impl InputBuffer {
    pub fn push(&mut self, c: char);
    pub fn pop(&mut self) -> Option<char>;
    pub fn clear(&mut self);
    pub fn as_str(&self) -> &str;
}
```

#### InputProcessor (processor.rs)

Maps raw keycodes to semantic actions:

```rust
pub enum InputAction {
    Character(char),    // Hint character typed
    Backspace,          // Delete last character
    Enter,              // Confirm selection
    Escape,             // Cancel
    ArrowUp,            // Navigate selection
    ArrowDown,
    Tab,                // Cycle forward
    ShiftTab,           // Cycle backward
    None,               // Ignored key
}
```

---

### platform/ - Platform Abstraction

COSMIC desktop and Wayland-specific implementations.

#### Wayland Protocols (wayland/protocols.rs)

Implements window enumeration and activation using COSMIC protocols:

**Required Protocols:**

| Protocol | Purpose |
|----------|---------|
| `ext_foreign_toplevel_list_v1` | Window enumeration |
| `zcosmic_toplevel_info_v1` | COSMIC-specific window info |
| `zcosmic_toplevel_manager_v1` | Window activation |
| `wl_seat` | Keyboard input |

**Window Enumeration Flow:**

```text
┌───────────────────────────────────────────────────────────────┐
│                      enumerate_windows()                      │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│   1. Connect to Wayland display                               │
│   2. Bind ext_foreign_toplevel_list_v1                        │
│   3. Bind zcosmic_toplevel_info_v1                            │
│   4. Roundtrip #1: Receive toplevel events                    │
│      - Toplevel created → store handle                        │
│      - Identifier, AppId, Title events → accumulate           │
│      - Done event → finalize pending toplevel                 │
│   5. Request cosmic handles for each toplevel                 │
│   6. Roundtrip #2: Receive cosmic state events                │
│      - State event → extract is_activated flag                │
│   7. Convert to Window structs                                │
│   8. Reorder: focused window moved to end for MRU             │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

**Timeout Protection:**

All Wayland roundtrips use `roundtrip_with_timeout()` to prevent indefinite blocking:

```rust
fn roundtrip_with_timeout<D>(
    conn: &Connection,
    event_queue: &mut EventQueue<D>,
    state: &mut D,
) -> Result<()> {
    // Uses poll() with 100ms intervals
    // Total timeout: 2 seconds (configurable via SESAME_WAYLAND_TIMEOUT_MS)
}
```

#### COSMIC Theme (cosmic_theme.rs)

Reads COSMIC desktop theme configuration:

```rust
pub struct CosmicTheme {
    pub is_dark: bool,
    pub accent: ColorContainer,
    pub primary: ColorContainer,
    pub secondary: ColorContainer,
    pub background: ColorContainer,
    pub corner_radii: CornerRadii,
}

impl CosmicTheme {
    pub fn load() -> Option<Self> {
        // Reads from: ~/.config/cosmic/com.system76.CosmicTheme.Dark/v1/
        // or: ~/.config/cosmic/com.system76.CosmicTheme.Light/v1/
    }
}
```

#### COSMIC Keybindings (cosmic_keys.rs)

Sets up system-wide keybindings:

```rust
pub fn setup_keybinding(key_combo: &str) -> Result<()> {
    // Writes to: ~/.config/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom
    // Format: RON (Rusty Object Notation)
}
```

#### Font Resolution (fonts.rs)

Uses fontconfig for system font discovery:

```rust
pub fn resolve_font(family: &str) -> Option<ResolvedFont> {
    // 1. Try exact family match
    // 2. Fall back to "sans" generic
    // 3. Return None if no fonts available
}
```

---

### render/ - Graphics Pipeline

Software rendering using tiny-skia and fontdue.

#### Pipeline Architecture

```text
┌───────────────────────────────────────────────────────────────┐
│                        RenderPipeline                         │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  RenderContext ──► Pass 1 ──► Pass 2 ──► ... ──► Pixmap      │
│  (pixmap, scale,                                              │
│   config)                                                     │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

#### RenderPass Trait (pipeline.rs)

```rust
pub trait RenderPass {
    fn render(&self, context: &mut RenderContext) -> Result<()>;
}

pub struct RenderPipeline {
    passes: Vec<Box<dyn RenderPass>>,
}

impl RenderPipeline {
    pub fn add_pass<P: RenderPass + 'static>(self, pass: P) -> Self;
    pub fn render(&self, context: &mut RenderContext) -> Result<()>;
}
```

#### Text Rendering (text.rs)

Font rendering with fontdue:

```rust
pub struct TextRenderer;

impl TextRenderer {
    pub fn render_text(pixmap: &mut Pixmap, text: &str, x: f32, y: f32, size: f32, color: Color);
    pub fn measure_text(text: &str, size: f32) -> f32;
    pub fn truncate_to_width(text: &str, max_width: f32, size: f32) -> String;
}
```

**Font Loading Strategy:**

1. Query fontconfig for "sans" font
2. Load regular weight
3. Attempt to load semibold variant (Bold > SemiBold > Medium)
4. Cache fonts in `OnceLock<FontCache>`

#### Primitives (primitives.rs)

Low-level drawing operations:

```rust
pub struct Color { pub r: u8, pub g: u8, pub b: u8, pub a: u8 }

pub fn rounded_rect(x: f32, y: f32, width: f32, height: f32, radius: f32) -> Option<Path>;
pub fn fill_rounded_rect(pixmap: &mut Pixmap, ...);
pub fn stroke_rounded_rect(pixmap: &mut Pixmap, ...);
pub fn fill_background(pixmap: &mut Pixmap, color: Color);
```

---

### ui/ - User Interface

Visual components for the overlay.

#### Overlay (overlay.rs)

The main window list UI:

```rust
pub enum OverlayPhase {
    Initial,  // Border highlight only (during overlay_delay)
    Full,     // Complete window list
}

pub struct Overlay {
    width: u32,
    height: u32,
    scale: f32,
    theme: Theme,
    layout: Layout,
}
```

**Layout System:**

Uses Material Design spacing principles:

| Constant | Value | Purpose |
|----------|-------|---------|
| `BASE_PADDING` | 20px | Card edge padding |
| `BASE_ROW_HEIGHT` | 48px | Touch target minimum |
| `BASE_ROW_SPACING` | 8px | Dense spacing |
| `BASE_BADGE_WIDTH` | 48px | Hint badge width |
| `BASE_TEXT_SIZE` | 16px | Body text |

All values scale with display DPI.

**Rendering Phases:**

```rust
impl Overlay {
    // Phase 1: Border only (transparent center)
    pub fn render_initial(&self) -> Option<Pixmap>;

    // Phase 2: Full window list
    pub fn render_full(&self, hints: &[WindowHint], input: &str, selection: usize) -> Option<Pixmap>;
}
```

#### Theme (theme.rs)

Color scheme management with COSMIC integration:

```rust
pub struct Theme {
    pub background: Color,
    pub card_background: Color,
    pub card_border: Color,
    pub text_primary: Color,
    pub text_secondary: Color,
    pub badge_background: Color,
    pub badge_text: Color,
    pub badge_matched_background: Color,
    pub badge_matched_text: Color,
    pub border_width: f32,
    pub corner_radius: f32,
}
```

**Theme Resolution Order:**

1. Load COSMIC theme (if available)
2. Apply user config overrides
3. Fall back to hardcoded defaults

---

### util/ - Utilities

Cross-cutting concerns used throughout the codebase.

#### Error Handling (error.rs)

Typed error enum using thiserror:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to connect to Wayland compositor")]
    WaylandConnection(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Required Wayland protocol not available: {protocol}")]
    MissingProtocol { protocol: &'static str },

    #[error("Window not found: {identifier}")]
    WindowNotFound { identifier: String },

    // ... more variants
}

pub type Result<T> = std::result::Result<T, Error>;
```

#### IPC (ipc.rs)

Unix domain socket communication between instances:

```rust
pub enum IpcCommand {
    CycleForward,   // Alt+Tab
    CycleBackward,  // Alt+Shift+Tab
    Ping,           // Health check
}

pub struct IpcServer { /* ... */ }
pub struct IpcClient;

impl IpcClient {
    pub fn send(cmd: IpcCommand) -> io::Result<IpcResponse>;
    pub fn is_instance_running() -> bool;
}
```

**Protocol:**

- Single-byte commands: `F` (forward), `B` (backward), `P` (ping)
- Single-byte responses: `K` (ok), `O` (pong), `E` (error)

#### MRU Tracking (mru.rs)

Most-recently-used window tracking for Alt+Tab:

```rust
pub struct MruState {
    pub current: Option<String>,   // Window we just switched TO
    pub previous: Option<String>,  // Window for quick Alt+Tab back
}

pub fn save_activated_window(origin: Option<&str>, new: &str);
pub fn get_previous_window() -> Option<String>;
```

**File Format:**

```text
previous-window-id
current-window-id
```

Uses flock() for atomic read-modify-write.

#### Paths (paths.rs)

XDG-compliant path management:

```rust
pub fn cache_dir() -> Result<PathBuf>;   // ~/.cache/open-sesame/
pub fn config_dir() -> Result<PathBuf>;  // ~/.config/open-sesame/
pub fn lock_file() -> Result<PathBuf>;   // ~/.cache/open-sesame/instance.lock
pub fn mru_file() -> Result<PathBuf>;    // ~/.cache/open-sesame/mru
pub fn log_file() -> Result<PathBuf>;    // ~/.cache/open-sesame/debug.log
```

All cache directories are created with 700 permissions for security.

#### Logging (log.rs)

Centralized logging configuration:

```rust
pub fn init() {
    // CRITICAL: All output goes to stderr, never stdout
    // This allows: sesame --print-config > config.toml

    if cfg!(feature = "debug-logging") || env::var("RUST_LOG").is_ok() {
        // File logging to ~/.cache/open-sesame/debug.log
    } else {
        // Stderr at INFO level
    }
}
```

---

## Key Design Decisions

### 1. Why Software Rendering?

Open Sesame uses tiny-skia (software rasterizer) instead of GPU acceleration because:

- **Simplicity**: No GPU context management or shader compilation
- **Reliability**: Works on all systems regardless of GPU driver state
- **Latency**: For a simple overlay, CPU rendering is faster than GPU setup overhead
- **Portability**: No OpenGL/Vulkan dependencies

The overlay is typically rendered in <5ms on modern CPUs.

### 2. Why Repeated Letters Instead of Two-Character Hints?

Vimium uses `ga`, `gb`, etc. for multiple hints. Open Sesame uses `g`, `gg`, `ggg` because:

- **Muscle Memory**: Same finger, same key
- **Speed**: Repeated key is faster than switching keys
- **Cognitive Load**: "More g's = later window" is intuitive
- **Numeric Alternative**: `g1`, `g2`, `g3` available for preference

### 3. Why File-Based MRU Instead of In-Memory?

MRU state persists to disk because:

- **Process Lifetime**: Open Sesame exits after each window switch
- **Cross-Invocation Memory**: Quick Alt+Tab needs previous window from last run
- **Crash Recovery**: No state loss on unexpected termination

### 4. Why Unix Domain Sockets for IPC?

Chosen over signals (SIGUSR1/SIGUSR2) because:

- **Reliability**: Signals can be coalesced, sockets cannot
- **Bidirectional**: Can confirm command receipt
- **Debugging**: Socket traffic is inspectable
- **Semantics**: Named commands vs numbered signals

### 5. Why Single-Instance Design?

Only one instance runs at a time because:

- **Resource Efficiency**: Multiple overlays would be confusing
- **State Consistency**: Single MRU tracker
- **User Experience**: Alt+Tab while overlay is open should cycle, not spawn new

---

## Error Handling Philosophy

### Typed Errors Over Strings

```rust
// Bad: Error information lost
fn bad_example() -> Result<(), String> {
    Err("something went wrong".to_string())
}

// Good: Structured, matchable errors
fn good_example() -> Result<(), Error> {
    Err(Error::MissingProtocol { protocol: "zcosmic_toplevel_info_v1" })
}
```

### Recoverable vs Fatal

```rust
impl Error {
    pub fn is_recoverable(&self) -> bool {
        matches!(self,
            Error::WindowNotFound { .. } |  // User typo, show feedback
            Error::ConfigValidation { .. } // Bad config value, use default
        )
    }
}
```

### Fail Fast for Programming Errors

```rust
// Panics are used for impossible states
fn get_window(&self, index: usize) -> &Window {
    self.windows.get(index)
        .expect("index validated at creation time")
}
```

---

## Platform Integration

### COSMIC Desktop Integration

| Feature | Implementation |
|---------|----------------|
| Theme colors | `platform/cosmic_theme.rs` |
| Keybindings | `platform/cosmic_keys.rs` (RON format) |
| Window management | COSMIC Wayland protocols |
| Font resolution | Fontconfig (respects COSMIC font settings) |

### Required COSMIC Protocols

```text
ext-foreign-toplevel-list-v1.xml   # Standard Wayland extension
cosmic-toplevel-info-v1.xml        # COSMIC-specific
cosmic-toplevel-management-v1.xml  # COSMIC-specific
```

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SESAME_WAYLAND_TIMEOUT_MS` | Wayland roundtrip timeout | 2000 |
| `RUST_LOG` | Log level | `info` |

---

## Testing Strategy

### Unit Tests

Each module has embedded unit tests:

```bash
cargo test                    # All tests
cargo test core::hint         # Hint module tests
cargo test config::validator  # Validator tests
```

### Integration Tests

Located in `tests/`:

```bash
cargo test --test integration_mru  # MRU persistence tests
```

### Manual Testing

```bash
# View window list without switching
sesame --list

# Output merged configuration
sesame --view

# Debug logging to file
RUST_LOG=debug sesame
```

---

## Contributing Guidelines

### Module Boundaries

When adding features, respect module boundaries:

- **core/**: Platform-agnostic logic only
- **platform/**: All Wayland/COSMIC code here
- **ui/**: Visual components only
- **util/**: Truly generic utilities

### Code Style

- Use `tracing` macros, not `println!`
- All public items need doc comments
- Tests go in the same file as the code
- Error types go in `util/error.rs`

### Adding a New Key Binding

1. Update `config/schema.rs` if new fields needed
2. Update `config/validator.rs` for validation
3. Update `core/matcher.rs` for matching logic
4. Update `config.example.toml` with examples

### Adding Platform Support

The codebase is designed for COSMIC but could support other platforms:

1. Create `platform/other_desktop/` module
2. Implement `enumerate_windows()` and `activate_window()`
3. Add feature flag in `Cargo.toml`
4. Update `platform/mod.rs` with feature gates

---

## License

Open Sesame is licensed under GPL-3.0-only.

---

*This documentation is a living document. Update it when making architectural changes.*
