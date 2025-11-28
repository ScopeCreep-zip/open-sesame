# Open Sesame

## Vimium-style window switcher for COSMIC desktop

Open Sesame brings the efficiency of Vimium browser navigation to the entire COSMIC desktop. Type a letter to
instantly switch to any window, or launch an application if it isn't running. No mouse required.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/ScopeCreep-zip/open-sesame)](https://github.com/ScopeCreep-zip/open-sesame/releases)
[![CI](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml/badge.svg)](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml)

---

## Quick Start

**Install and configure in 30 seconds:**

```bash
# Add GPG key and repository (Pop!_OS 24.04+)
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list

# Install and configure
sudo apt update && sudo apt install -y open-sesame
sesame --setup-keybinding
```

**That's it.** Press `Alt+Space` to see all windows with letter hints. Type a letter to switch.

---

## Features

- **Vimium-style hints** - Every window gets a letter (g, gg, ggg for multiple instances)
- **Quick switch** - Tap Alt+Space to toggle between last two windows
- **Focus-or-launch** - Type a letter to focus an app or launch it if not running
- **Arrow navigation** - Use arrows and Enter as an alternative to typing letters
- **Zero configuration** - Works out-of-the-box with sensible defaults
- **COSMIC integration** - Automatic keybinding setup, native theme support
- **Instant activation** - Sub-200ms latency with smart disambiguation
- **Configurable** - Per-app key bindings, launch commands, and environment variables

---

## How It Works

### Two Modes

**Launcher Mode (Default: Alt+Space)**
Shows a centered overlay with all windows and letter hints. Type a letter to switch, or use arrows to navigate.

**Switcher Mode (Optional: Alt+Tab)**
Acts like traditional Alt+Tab but with letter hints for instant selection.

### Quick Switch Behavior

**Tap the keybinding** - Instantly switch to the previous window (MRU - Most Recently Used)

**Hold and type** - See the full overlay, type a letter or use arrows to select

### Focus-or-Launch

Configure key bindings for your favorite apps. If the app is running, Open Sesame focuses it. If not, it launches the app.

Example: Press `Alt+Space`, type `f` → switches to Firefox (or launches it)

---

## Installation

### From APT Repository (Recommended)

**Pop!_OS 24.04+ with COSMIC Desktop:**

```bash
# Add GPG key and repository
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list

# Install and configure
sudo apt update && sudo apt install -y open-sesame
sesame --setup-keybinding
```

### From GitHub Releases

Download the `.deb` package for your architecture from [Releases](https://github.com/ScopeCreep-zip/open-sesame/releases):

**Download (auto-detects architecture):**

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/latest/download/open-sesame-linux-$(uname -m).deb" -o /tmp/open-sesame.deb
```

**Verify and install:**

```bash
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
```

```bash
sudo dpkg -i /tmp/open-sesame.deb && sesame --setup-keybinding
```

### Verify Package Authenticity

All packages include [SLSA Build Provenance](https://slsa.dev/) attestations:

```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

### Building from Source

Requires COSMIC desktop environment and development tools.

**Prerequisites:**

```bash
# Install mise (https://mise.jdx.dev/)
curl https://mise.run | sh

# Clone repository
git clone https://github.com/ScopeCreep-zip/open-sesame.git
cd open-sesame

# Install dependencies
mise run setup
```

**Build and install:**

```bash
# Build .deb package
mise run build:deb

# Install
mise run install
```

**Development workflow:**

```bash
# Format code
mise run fmt

# Run tests and linters
mise run test

# Build debug binary and run
mise run dev

# Clean everything
mise run clean:all
```

See `mise run help` for all available tasks.

---

## Usage

### Basic Usage

```bash
# Launch the window switcher (default: Alt+Space from keybinding setup)
sesame

# Show all windows with letter hints
sesame --list-windows

# Run in backward cycle mode (for Alt+Shift+Tab)
sesame --backward

# Launcher mode with immediate overlay
sesame --launcher
```

### Keyboard Shortcuts

Once the overlay appears:

| Key | Action |
|-----|--------|
| **Letter keys** | Instantly switch to window with that hint |
| **Arrow keys** | Navigate through window list |
| **Enter** | Activate selected window |
| **Escape** | Cancel and return to origin window |
| **Repeat letter** | Type `gg`, `ggg` for multiple windows with same letter |

### Switcher Mode vs Launcher Mode

**Launcher Mode (`-l` flag):**

- Shows overlay immediately
- Used for Alt+Space style launchers
- Full window list with hints from the start

**Switcher Mode (default):**

- Quick switch on tap (< 250ms)
- Shows overlay after delay (720ms default)
- Used for Alt+Tab replacement

**Usage pattern:**

```bash
# Setup as Alt+Space (launcher mode, immediate overlay)
sesame --setup-keybinding alt+space

# Then bind Alt+Tab to: sesame
# And Alt+Shift+Tab to: sesame --backward
```

---

## Configuration

### Configuration File Location

Open Sesame uses XDG config directories with inheritance:

```text
/etc/open-sesame/config.toml              # System defaults
~/.config/open-sesame/config.toml         # User config (create this)
~/.config/open-sesame/config.d/*.toml     # Additional overrides (alphabetical)
```

### Generate Default Configuration

```bash
# Print default config to stdout
sesame --print-config

# Create user config from defaults
sesame --print-config > ~/.config/open-sesame/config.toml

# Edit config
$EDITOR ~/.config/open-sesame/config.toml

# Validate config
sesame --validate-config
```

### Example Configuration

```toml
[settings]
# Key combo for launching (used by --setup-keybinding)
activation_key = "alt+space"

# Delay (ms) before activating a match when multiple hints exist
# Allows time for typing gg, ggg without 'g' firing immediately
activation_delay = 200

# Delay (ms) before showing full overlay (0 = immediate)
# During this time, only a border shows around focused window
overlay_delay = 720

# Quick switch threshold (ms) - tap within this time = instant MRU switch
quick_switch_threshold = 250

# Focus indicator border
border_width = 3.0
border_color = "#b4a0ffb4"  # Soft lavender with transparency

# Overlay colors (hex: #RRGGBB or #RRGGBBAA)
background_color = "#000000c8"  # Semi-transparent black
card_color = "#1e1e1ef0"        # Dark gray card
text_color = "#ffffffff"        # White text
hint_color = "#646464ff"        # Gray hint badge
hint_matched_color = "#4caf50ff" # Green for matched hints

# Global environment files (direnv .env style)
env_files = [
    # "~/.config/open-sesame/global.env"
]


# === KEY BINDINGS ===
# Each [keys.<letter>] section defines one shortcut:
#   apps   = List of app_ids that match this key
#   launch = Command to run if no matching window exists

# Find your app_ids:
#   sesame --list-windows


# Terminal
[keys.g]
apps = ["ghostty", "com.mitchellh.ghostty"]
launch = "ghostty"

# Browser
[keys.f]
apps = ["firefox", "org.mozilla.firefox"]
launch = "firefox"

# Editor
[keys.v]
apps = ["code", "Code", "cursor", "Cursor"]
launch = "code"

# File manager
[keys.n]
apps = ["nautilus", "org.gnome.Nautilus", "com.system76.CosmicFiles"]
launch = "nautilus"

# Communication
[keys.s]
apps = ["slack", "Slack"]
launch = "slack"

[keys.d]
apps = ["discord", "Discord"]
launch = "discord"

# No launch command = focus only (won't launch if not running)
[keys.c]
apps = ["chromium", "google-chrome"]
```

### Advanced Launch Configuration

For complex launch scenarios with arguments and environment variables:

```toml
# Simple launch (just a command string)
[keys.g]
apps = ["ghostty"]
launch = "ghostty"

# Advanced launch with args and env
[keys.g]
apps = ["ghostty"]
[keys.g.launch]
command = "ghostty"
args = ["--config-file=/path/to/config"]
env_files = ["~/.config/ghostty/.env"]  # Load env vars from file
env = { TERM = "xterm-256color" }       # Explicit env vars (override env_files)

# Chrome with specific profile
[keys.w]
apps = ["google-chrome"]
[keys.w.launch]
command = "google-chrome"
args = ["--profile-directory=Work"]

# App with custom environment
[keys.x]
apps = ["myapp"]
[keys.x.launch]
command = "/opt/myapp/bin/myapp"
args = ["--mode=production"]
env_files = [
    "~/.config/myapp/base.env",
    "~/.config/myapp/secrets.env",
]
env = { DEBUG = "false" }
```

**Environment variable layering** (later overrides earlier):

1. Inherited process environment (WAYLAND_DISPLAY, XDG_*, PATH, etc.)
2. Global `env_files` from `[settings]`
3. Per-app `env_files` from `[keys.x.launch]`
4. Explicit `env` from `[keys.x.launch]`

**Env file format** (direnv .env style):

```bash
KEY=value
KEY="value with spaces"
KEY='literal value'
export KEY=value
# comments
```

### Adding New Key Bindings

```bash
# 1. Find your app_id
sesame --list-windows

# 2. Add to config
[keys.x]
apps = ["your-app-id"]
launch = "your-app-command"

# 3. Verify config is valid
sesame --validate-config
```

---

## CLI Reference

```text
sesame [OPTIONS]

OPTIONS:
  -c, --config <PATH>
      Use a custom configuration file instead of the default
      Example: sesame -c ~/my-config.toml

  --print-config
      Print default configuration to stdout and exit
      Example: sesame --print-config > ~/.config/open-sesame/config.toml

  --validate-config
      Validate configuration file and report any issues
      Checks for errors and warnings, exits with status code

  --list-windows
      List all current windows with assigned hints and exit
      Shows window IDs, app IDs, titles, and hint assignments
      Useful for debugging and finding app_ids for configuration

  --setup-keybinding [KEY_COMBO]
      Setup COSMIC keybinding for Open Sesame
      Uses activation_key from config if no key combo specified
      Examples:
        sesame --setup-keybinding           # Uses config default
        sesame --setup-keybinding alt+tab   # Custom combo

  --remove-keybinding
      Remove Open Sesame keybinding from COSMIC
      Cleans up any configured shortcuts

  --keybinding-status
      Show current keybinding configuration status
      Displays what key combo is currently bound

  -b, --backward
      Cycle backward through windows (for Alt+Shift+Tab)
      Used with switcher mode for reverse cycling

  -l, --launcher
      Launcher mode: show full overlay with hints immediately
      Without this flag, runs in switcher mode (Alt+Tab behavior)
      In switcher mode, tap = quick switch, hold = show overlay

  -h, --help
      Print help message and exit

  -V, --version
      Print version information and exit
```

**Common usage patterns:**

```bash
# Setup as Alt+Space launcher
sesame --setup-keybinding alt+space

# Then configure COSMIC shortcuts:
# Alt+Space:       sesame --launcher
# Alt+Tab:         sesame
# Alt+Shift+Tab:   sesame --backward

# Debug window detection
sesame --list-windows

# Test custom config
sesame -c ~/test-config.toml --list-windows
```

---

## Troubleshooting

### No Windows Appear

**Check if windows are detected:**

```bash
sesame --list-windows
```

If no windows appear, ensure you're running on COSMIC desktop with Wayland (not X11).

### Wrong App IDs

**Find the correct app_id:**

```bash
sesame --list-windows
```

Copy the exact `app_id` shown and use it in your configuration.

### Keybinding Not Working

**Check keybinding status:**

```bash
sesame --keybinding-status
```

**Re-setup keybinding:**

```bash
sesame --remove-keybinding
sesame --setup-keybinding
```

Ensure the key combo doesn't conflict with other COSMIC shortcuts.

### Configuration Errors

**Validate your config:**

```bash
sesame --validate-config
```

Common issues:

- Invalid color format (use `#RRGGBB` or `#RRGGBBAA`)
- Missing quotes around strings with spaces
- Duplicate key bindings
- Invalid TOML syntax

### Debug Logging

**Enable debug logging:**

```bash
# Set RUST_LOG environment variable
RUST_LOG=debug sesame --launcher

# View debug log (created automatically when RUST_LOG is set)
tail -f ~/.cache/open-sesame/debug.log
```

**Or build with debug logging always on:**

```bash
mise run install:debug
# Logs to ~/.cache/open-sesame/debug.log
```

### Performance Issues

If the overlay feels slow:

1. **Reduce overlay delay:**

   ```toml
   [settings]
   overlay_delay = 0  # Show immediately
   ```

2. **Reduce activation delay:**

   ```toml
   [settings]
   activation_delay = 100  # Faster activation (may skip gg, ggg)
   ```

### Launch Commands Not Working

**Check environment variables:**

```bash
# Verify app is in PATH
which firefox

# Test launch command directly
firefox

# Check debug logs for launch errors
RUST_LOG=debug sesame --launcher
```

**For apps not in PATH:**

```toml
[keys.x]
apps = ["myapp"]
[keys.x.launch]
command = "/full/path/to/binary"  # Use absolute path
```

---

## Requirements

- **COSMIC Desktop Environment** (Pop!_OS 24.04+ or other COSMIC-based distributions)
- **Wayland** (X11 not supported)
- **fontconfig** with at least one font installed
- **Rust 1.91+** (for building from source)

**Optional for development:**

- `mise` - Development task runner
- `cargo-deb` - Debian package builder
- `cross` - Cross-compilation for arm64

---

## Architecture

Open Sesame is architected as a modular Rust application with clean separation of concerns:

### Module Overview

- **`app`** - Application orchestration and event loop
  - State management
  - Event dispatching
  - Render coordination

- **`config`** - Configuration system
  - XDG-compliant file loading
  - Schema validation
  - TOML serialization

- **`core`** - Domain logic
  - Window hint assignment algorithm
  - Hint matching and disambiguation
  - Launch command abstraction

- **`input`** - Keyboard input processing
  - Input buffer management
  - Key event processing
  - Hint matching

- **`platform`** - Platform abstraction
  - Wayland window enumeration
  - COSMIC protocol integration
  - Window activation
  - Keybinding management
  - Theme integration

- **`render`** - Rendering pipeline
  - Software rendering with tiny-skia
  - Font rendering with fontdue
  - Primitive drawing operations
  - Buffer management

- **`ui`** - User interface
  - Overlay component
  - Theme management
  - Layout calculations

- **`util`** - Shared utilities
  - Instance locking
  - IPC (Inter-Process Communication)
  - MRU (Most Recently Used) tracking
  - Environment file parsing
  - Logging

### Design Principles

- **Zero external dependencies at runtime** - Software rendering, no GPU required
- **Single-instance execution** - IPC for signaling existing instances
- **Fast activation** - Sub-200ms window switching
- **Graceful degradation** - Falls back to stderr logging if file logging fails
- **Secure by default** - Proper file permissions, cache directory isolation

---

## Contributing

Contributions are welcome! This project values:

- **Quality over speed** - Take time to write excellent code
- **Clear documentation** - Code should be self-explanatory
- **Comprehensive testing** - All quality gates must pass
- **User empathy** - Features should solve real problems

Before contributing, run the quality gates:

```bash
# Format, lint, and test
mise run test

# Or individually
mise run fmt      # Format code
mise run lint     # Run clippy
mise run test     # Run tests
```

For larger contributions, please open an issue first to discuss the approach.

---

## License

Open Sesame is licensed under the [GNU General Public License v3.0](LICENSE).

```text
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

---

## Acknowledgments

Built with:

- [Rust](https://www.rust-lang.org/) - Systems programming language
- [Smithay](https://github.com/Smithay/client-toolkit) - Wayland client toolkit
- [COSMIC Protocols](https://github.com/pop-os/cosmic-protocols) - System76 COSMIC desktop protocols
- [tiny-skia](https://github.com/RazrFalcon/tiny-skia) - Software rendering
- [fontdue](https://github.com/mooman219/fontdue) - Font rasterization

Inspired by [Vimium](https://github.com/philc/vimium) - The browser extension that proves keyboard navigation is superior.

---

**Made with care for the COSMIC desktop community.**
