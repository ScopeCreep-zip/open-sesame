# Open Sesame

## Vimium-style window switcher for COSMIC desktop

Open Sesame brings the efficiency of Vimium browser navigation to the entire COSMIC desktop. Type a letter to
instantly switch to any window, or launch an application if it isn't running. No mouse required.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://github.com/ScopeCreep-zip/open-sesame/blob/main/LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/ScopeCreep-zip/open-sesame)](https://github.com/ScopeCreep-zip/open-sesame/releases)
[![CI](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml/badge.svg)](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml)

## Features

- **Vimium-style hints** - Every window gets a letter (g, gg, ggg for multiple instances)
- **Quick switch** - Tap Alt+Space to toggle between last two windows
- **Focus-or-launch** - Type a letter to focus an app or launch it if not running
- **Arrow navigation** - Use arrows and Enter as an alternative to typing letters
- **Zero configuration** - Works out-of-the-box with sensible defaults
- **COSMIC integration** - Automatic keybinding setup, native theme support
- **Instant activation** - Sub-200ms latency with smart disambiguation
- **Configurable** - Per-app key bindings, launch commands, and environment variables

## Quick Example

**Add APT repository (one-time setup):**

```bash
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
```

```bash
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list
```

**Install and configure:**

```bash
sudo apt update && sudo apt install -y open-sesame
```

```bash
sesame --setup-keybinding
```

Press **Alt+Space**, type a letter to switch windows.

See [Installation Guide](./user-guide/installation.md) for alternative methods.

## How It Works

Open Sesame displays a visual overlay showing all your open windows, each labeled with a letter hint. Type the
letter to instantly switch to that window. If you've configured an app with a key binding and it's not running,
Open Sesame will launch it for you.

### Two Modes

#### Launcher Mode (Default: Alt+Space)

- Shows a centered overlay with all windows and letter hints immediately
- Type a letter to switch, or use arrows to navigate
- Perfect for quick access to any window

#### Switcher Mode (Optional: Alt+Tab)

- Acts like traditional Alt+Tab but with letter hints for instant selection
- Tap to quickly switch to the previous window
- Hold to see the full overlay

## Next Steps

- [Quick Start Guide](./user-guide/quick-start.md) - Get up and running in 30 seconds
- [Installation Guide](./user-guide/installation.md) - Detailed installation instructions
- [Configuration Guide](./user-guide/configuration.md) - Customize key bindings and behavior
- [CLI Reference](./user-guide/cli-reference.md) - Complete command-line reference

## Requirements

- **COSMIC Desktop Environment** (Pop!_OS 24.04+ or other COSMIC-based distributions)
- **Wayland** (X11 not supported)
- **fontconfig** with at least one font installed

## Acknowledgments

Built with Rust and inspired by [Vimium](https://github.com/philc/vimium) - the browser extension that proves
keyboard navigation is superior.
