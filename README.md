# Open Sesame

## Programmable Desktop Suite for COSMIC/Wayland

Open Sesame is a multi-daemon desktop orchestration platform. It combines Vimium-style window switching, an application launcher with fuzzy search, encrypted per-profile secret vaults, clipboard management, input remapping, text snippet expansion, and workspace-scoped developer environments — all controlled through a single CLI.

Press `Alt+Space` to see all windows with letter hints. Type a letter to switch. Store secrets in encrypted vaults and inject them into your applications as environment variables. No mouse required.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/ScopeCreep-zip/open-sesame)](https://github.com/ScopeCreep-zip/open-sesame/releases)
[![CI](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml/badge.svg)](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

![Open Sesame Screenshot](docs/src/open-sesame-screenshot.png)

---

## Quick Start

```bash
# Install (see Installation below for full options)
sudo apt update && sudo apt install -y open-sesame

# Initialize: creates config, starts daemons, sets master password
sesame init

# Setup COSMIC keybindings (Alt+Tab, Alt+Shift+Tab, Alt+Space)
sesame setup-keybinding

# Check everything is running
sesame status
```

**That's it.** Press `Alt+Space` to see all windows with letter hints. Type a letter to switch.

---

## Features

### Window Manager
- **Vimium-style hints** — Every window gets a letter (g, gg, ggg for multiple instances)
- **Quick switch** — Tap Alt+Tab to toggle between last two windows (MRU)
- **Focus-or-launch** — Type a letter to focus an app or launch it if not running
- **Arrow navigation** — Use arrows and Enter as an alternative to typing letters
- **Instant activation** — Sub-200ms latency with smart disambiguation

### Encrypted Vaults
- **Per-profile secrets** — Each profile gets its own SQLCipher-encrypted vault
- **SSH agent unlock** — Enroll SSH keys for passwordless vault access (Ed25519, RSA)
- **Environment injection** — Run commands with secrets as env vars: `sesame env -p work -- aws s3 ls`
- **Export formats** — Shell eval, dotenv, JSON: `sesame export -p work -f dotenv > .env`

### Application Launcher
- **Fuzzy search** — `sesame launch search firefox` with frecency ranking
- **Desktop entry scanning** — Finds all installed applications automatically
- **Profile-scoped frecency** — Different ranking per profile

### Developer Workspaces
- **Canonical paths** — `/workspace/<user>/<server>/<org>/<repo>`
- **Profile linking** — Associate directories with profiles for automatic secret injection
- **Shell injection** — `sesame workspace shell` opens a shell with vault secrets

### Clipboard, Input, Snippets
- **Clipboard history** — Per-profile, sensitivity-aware with configurable TTL
- **Input remapping** — Layer-based keyboard remapping via evdev
- **Snippet expansion** — Text expansion triggers per profile

### Platform
- **COSMIC integration** — Automatic keybinding setup, native Wayland compositor support
- **Nix flake** — Full package with overlay, home-manager module, and headless variant
- **APT packaging** — `.deb` with systemd user services for all 7 daemons
- **Multi-platform staged** — Linux first, macOS and Windows platform crates scaffolded

---

## How It Works

### Two Modes

**Launcher Mode (Default: Alt+Space)**
Shows a centered overlay with all windows and letter hints. Type a letter to switch, or use arrows to navigate.

**Switcher Mode (Default: Alt+Tab)**
Acts like traditional Alt+Tab but with letter hints for instant selection.

### Quick Switch Behavior

**Tap the keybinding** — Instantly switch to the previous window (MRU - Most Recently Used)

**Hold and type** — See the full overlay, type a letter or use arrows to select

### Focus-or-Launch

Configure key bindings for your favorite apps. If the app is running, Open Sesame focuses it. If not, it launches the app.

Example: Press `Alt+Space`, type `f` → switches to Firefox (or launches it)

### Keyboard Shortcuts

Once the overlay appears:

| Key | Action |
|-----|--------|
| **Letter keys** | Instantly switch to window with that hint |
| **Arrow keys** | Navigate through window list |
| **Enter** | Activate selected window |
| **Escape** | Cancel and return to origin window |
| **Repeat letter** | Type `gg`, `ggg` for multiple windows with same letter |

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

# Install and initialize
sudo apt update && sudo apt install -y open-sesame
sesame init
```

The `.deb` package installs 8 binaries (`sesame` CLI + 7 daemons) and systemd user services that start automatically on login via `graphical-session.target`.

### From GitHub Releases

Download the `.deb` package for your architecture from [Releases](https://github.com/ScopeCreep-zip/open-sesame/releases):

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/latest/download/open-sesame-linux-$(uname -m).deb" -o /tmp/open-sesame.deb
```

**Verify and install:**

```bash
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame init
```

### Verify Package Authenticity

All packages include [SLSA Build Provenance](https://slsa.dev/) attestations:

```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

### Nix Flake (Recommended for NixOS/home-manager)

Add the flake input and enable the home-manager module:

```nix
# flake.nix
{
  inputs.open-sesame = {
    url = "github:ScopeCreep-zip/open-sesame";
    inputs.nixpkgs.follows = "nixpkgs";
  };
}
```

```nix
# home configuration
{ open-sesame, ... }:
{
  imports = [ open-sesame.homeManagerModules.default ];

  programs.open-sesame = {
    enable = true;
    settings = {
      key_bindings.g = {
        apps = [ "ghostty" "com.mitchellh.ghostty" ];
        launch = "ghostty";
        tags = [ "dev" "work:corp" ];
      };
      key_bindings.f = {
        apps = [ "firefox" "org.mozilla.firefox" ];
        launch = "firefox";
      };
      key_bindings.z = {
        apps = [ "zed" "dev.zed.Zed" ];
        launch = "zed-editor";
      };
    };
    profiles = {
      default = {
        launch_profiles.dev = {
          env = { RUST_LOG = "debug"; };
          secrets = [ "github-token" ];
        };
      };
      work = {
        launch_profiles.corp = {
          env = { CORP_ENV = "production"; };
          secrets = [ "corp-api-key" ];
        };
      };
    };
  };
}
```

The module generates `~/.config/pds/config.toml`, creates systemd user services for all 7 daemons, and configures `SSH_AUTH_SOCK` for SSH agent forwarding to systemd services.

A headless variant is available for servers (no GTK/Wayland deps):

```nix
programs.open-sesame.package = open-sesame.packages.${system}.open-sesame-headless;
```

### Building from Source

#### Nix (Recommended)

The flake provides a complete dev environment with all native dependencies:

```bash
nix develop
cargo check --workspace
```

#### Debian/Ubuntu/Pop!_OS (Bare Metal)

Install system library headers required by native crate dependencies:

```bash
# Required for all builds
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libpcsclite-dev

# Required for GTK4 UI crates (daemon-wm, daemon-launcher)
sudo apt-get install -y \
    libgtk-4-dev \
    libglib2.0-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgraphene-1.0-dev \
    libgdk-pixbuf-2.0-dev \
    libwayland-dev \
    libxkbcommon-dev \
    libseccomp-dev \
    libfontconfig1-dev

# gtk4-layer-shell C library (required for Wayland layer-shell overlays)
# NOT packaged in Ubuntu 24.04 -- must build from source:
#   https://github.com/wmww/gtk4-layer-shell
# Or skip GUI crates:
#   cargo check --workspace --exclude daemon-wm --exclude daemon-launcher
```

Minimum Rust toolchain: see `rust-toolchain.toml` (currently channel 1.91).

```bash
cargo check --workspace
```

#### What Each System Package Provides

| apt package | Crate(s) | Purpose |
|---|---|---|
| `libssl-dev` | `rusqlite` (bundled-sqlcipher) | OpenSSL headers for SQLCipher encryption |
| `libpcsclite-dev` | `pcsc` | Smart card reader access for hardware key profile activation |
| `libgtk-4-dev` | `gtk4` | GTK4 UI toolkit for overlay windows |
| `libgtk4-layer-shell` (from source) | `gtk4-layer-shell` | Wayland layer-shell protocol for overlay positioning |
| `libseccomp-dev` | `seccomp` | Landlock/seccomp sandboxing for daemons |

---

## Usage

### Initialization

```bash
# First-time setup: creates config directory, generates keypairs,
# starts daemons, and prompts for master password
sesame init

# With organization namespace (enterprise deployments)
sesame init --org braincraft.io

# Factory reset (destructive — requires typing "destroy all data")
sesame init --wipe-reset-destroy-all-data
```

### Vault Operations

```bash
# Unlock your default vault (prompts for password)
sesame unlock

# Unlock specific profiles
sesame unlock -p work
sesame unlock -p "default,work"

# Lock a vault (zeroizes cached key material)
sesame lock -p work

# Lock all vaults
sesame lock
```

### SSH Agent Unlock

Enroll SSH keys for passwordless vault unlock. Only Ed25519 and RSA keys are supported — their signatures are deterministic, which is required for KEK derivation.

```bash
# Enroll an SSH key (vault must be unlockable with password first)
sesame ssh enroll -p default

# List enrollments
sesame ssh list

# Revoke enrollment
sesame ssh revoke -p work
```

After enrollment, `sesame unlock` and the overlay will attempt SSH agent unlock automatically before falling back to password prompt.

### Secret Management

```bash
# Store a secret (prompts for value)
sesame secret set -p default AWS_SECRET_KEY

# Retrieve a secret
sesame secret get -p default AWS_SECRET_KEY

# List all keys in a profile (never shows values)
sesame secret list -p work

# Delete a secret
sesame secret delete -p work old-api-key
sesame secret delete -p work old-api-key --yes  # skip confirmation
```

### Environment Injection

Run commands with vault secrets injected as environment variables. Secret keys are uppercased with hyphens converted to underscores (`api-key` → `API_KEY`).

```bash
# Run a command with secrets from the work profile
sesame env -p work -- aws s3 ls

# With env var prefix
sesame env -p work --prefix MYAPP -- ./start.sh
# api-key → MYAPP_API_KEY
```

### Secret Export

```bash
# Shell eval (default) — for bash/zsh/direnv
eval "$(sesame export -p work)"

# Dotenv format — for Docker, docker-compose, node
sesame export -p work -f dotenv > .env.secrets

# JSON — for jq, CI/CD, programmatic use
sesame export -p work -f json | jq .

# With prefix
sesame export -p work --prefix MYAPP -f shell
```

### Profiles

```bash
# List configured profiles
sesame profile list

# Show profile configuration
sesame profile show work

# Activate/deactivate profiles
sesame profile activate work
sesame profile deactivate work

# Set default profile
sesame profile default work
```

### Window Manager

```bash
# Open the window switcher overlay
sesame wm overlay

# Launcher mode (full overlay immediately, no border-only phase)
sesame wm overlay --launcher

# Switch to next/previous window in MRU order
sesame wm switch
sesame wm switch --backward

# Focus a specific window
sesame wm focus firefox

# List windows known to daemon-wm
sesame wm list
```

### Application Launcher

```bash
# Fuzzy search for applications
sesame launch search firefox
sesame launch search "visual studio" -n 5

# Launch by desktop entry ID
sesame launch run org.mozilla.firefox
sesame launch run org.mozilla.firefox -p work
```

### Clipboard

```bash
# Show clipboard history
sesame clipboard history -p default
sesame clipboard history -p default -n 50

# Clear clipboard history
sesame clipboard clear -p work

# Get a specific entry
sesame clipboard get <entry-id>
```

### Audit Log

All vault operations are recorded in a hash-chained audit log.

```bash
# Verify hash chain integrity
sesame audit verify

# Show recent entries
sesame audit tail
sesame audit tail -n 50

# Follow new entries in real time
sesame audit tail -f
```

### COSMIC Keybindings

```bash
# Setup keybindings (Alt+Tab, Alt+Shift+Tab, launcher key)
sesame setup-keybinding              # default: alt+space
sesame setup-keybinding super+space  # custom launcher key

# Check status
sesame keybinding-status

# Remove keybindings
sesame remove-keybinding
```

### Workspaces

Workspaces are directory-scoped project environments with canonical paths.

```bash
# Initialize workspace root
sesame workspace init
sesame workspace init --root /mnt/workspace

# Clone to canonical path: /workspace/<user>/github.com/org/repo
sesame workspace clone https://github.com/org/repo
sesame workspace clone git@github.com:org/repo --depth 1

# Link workspace to a profile (enables automatic secret injection)
sesame workspace link -p work

# List workspaces
sesame workspace list
sesame workspace list --server github.com --org myorg
sesame workspace list -f json

# Show workspace status
sesame workspace status
sesame workspace status -v  # verbose with disk usage

# Open a shell with vault secrets injected
sesame workspace shell
sesame workspace shell -p work
sesame workspace shell -- make build  # run a command instead of interactive shell

# Show resolved config with provenance
sesame workspace config show

# Unlink profile association
sesame workspace unlink
```

### Input Remapping

```bash
# List configured input layers
sesame input layers

# Show input daemon status
sesame input status
```

### Snippets

```bash
# List snippets for a profile
sesame snippet list -p default

# Add a snippet
sesame snippet add -p default "@@sig" "Best regards,\nJohn"

# Expand a trigger
sesame snippet expand -p default "@@sig"
```

---

## Configuration

### Configuration File Locations

Open Sesame v2 uses `~/.config/pds/` as its config directory with layered inheritance:

```text
/etc/pds/policy.toml                       # System policy (enterprise, read-only)
~/.config/pds/config.toml                  # User config
~/.config/pds/config.d/*.toml              # Drop-in fragments (alphabetical)
~/.config/pds/profiles/{name}/config.toml  # Per-profile overrides
~/.config/pds/workspaces.toml              # Workspace-to-profile links
~/.config/pds/installation.toml            # Installation identity (generated by sesame init)
```

Additional data locations:

```text
~/.config/pds/vaults/                      # Encrypted SQLCipher vault databases
~/.config/pds/keys/                        # Noise IK daemon keypairs
~/.config/pds/enrollments/                 # SSH key enrollment blobs
```

### Example Configuration

```toml
config_version = 3

[global]
default_profile = "default"

[global.logging]
level = "info"
journald = true

# ── Profile: default ──────────────────────────────────────────────

[profiles.default]
name = "default"

[profiles.default.wm]
# Characters used for Vimium-style window hints
hint_keys = "asdfghjkl"

# Delay (ms) before showing full overlay (0 = immediate)
overlay_delay_ms = 150

# Delay (ms) before activating a match when multiple hints exist
# Allows time for typing gg, ggg without 'g' firing immediately
activation_delay_ms = 200

# Quick-switch threshold (ms) — tap within this time = instant MRU switch
quick_switch_threshold_ms = 250

# Focus indicator border
border_width = 4.0
border_color = "#89b4fa"

# Overlay colors (hex: #RRGGBB or #RRGGBBAA)
background_color = "#000000c8"
card_color = "#1e1e1ef0"
text_color = "#ffffff"
hint_color = "#646464"
hint_matched_color = "#4caf50"

# Maximum windows visible in the overlay
max_visible_windows = 20

# ── Key bindings ──────────────────────────────────────────────────
# Each key binding maps a letter to app IDs and an optional launch command.
# Find your app_ids with: sesame wm list

[profiles.default.wm.key_bindings.g]
apps = ["ghostty", "com.mitchellh.ghostty"]
launch = "ghostty"

[profiles.default.wm.key_bindings.f]
apps = ["firefox", "org.mozilla.firefox"]
launch = "firefox"

[profiles.default.wm.key_bindings.v]
apps = ["code", "Code", "cursor", "Cursor"]
launch = "code"

[profiles.default.wm.key_bindings.n]
apps = ["nautilus", "org.gnome.Nautilus", "com.system76.CosmicFiles"]
launch = "nautilus"

[profiles.default.wm.key_bindings.s]
apps = ["slack", "Slack"]
launch = "slack"

[profiles.default.wm.key_bindings.d]
apps = ["discord", "Discord"]
launch = "discord"

# No launch command = focus only (won't launch if not running)
[profiles.default.wm.key_bindings.c]
apps = ["chromium", "google-chrome"]

# ── Launch profiles ───────────────────────────────────────────────
# Named, composable environment injection profiles.
# Tag key bindings with launch profile names to compose at launch time.

[profiles.default.launch_profiles.dev-rust]
env = { RUST_LOG = "debug", CARGO_HOME = "/workspace/.cargo" }
secrets = ["github-token", "crates-io-token"]
devshell = "/workspace/myproject#rust"

# ── Key binding with launch profile tags ──────────────────────────
# Tags reference launch profiles. Cross-profile references use "profile:tag".

# [profiles.default.wm.key_bindings.g]
# apps = ["ghostty"]
# launch = "ghostty"
# tags = ["dev-rust", "work:corp"]
# launch_args = ["--working-directory=/workspace/user/github.com/org/repo"]

# ── Profile: work ────────────────────────────────────────────────

[profiles.work]
name = "work"
color = "#ff6b6b"

[profiles.work.launch_profiles.corp]
env = { CORP_ENV = "production" }
secrets = ["corp-api-key", "corp-database-url"]

# ── Clipboard ────────────────────────────────────────────────────

[profiles.default.clipboard]
max_history = 1000
sensitive_ttl_s = 30
detect_sensitive = true

# ── Audit ────────────────────────────────────────────────────────

[profiles.default.audit]
enabled = true
retention_days = 90

# ── Activation rules (contextual profile switching) ───────────────

# [profiles.work.activation]
# wifi_ssids = ["CorpNet", "CorpNet-5G"]
# usb_devices = ["1050:0407"]  # YubiKey
# require_security_key = true

# ── Cryptographic algorithms ──────────────────────────────────────

[crypto]
kdf = "argon2id"
hkdf = "blake3"
noise_cipher = "chacha-poly"
noise_hash = "blake2s"
audit_hash = "blake3"
minimum_peer_profile = "leading-edge"
```

### Advanced Launch Configuration

For complex launch scenarios with arguments, secrets, and Nix devshells:

```toml
# Simple launch (just a command string)
[profiles.default.wm.key_bindings.g]
apps = ["ghostty"]
launch = "ghostty"

# Launch with profile tags — secrets and env vars composed from named profiles
[profiles.default.wm.key_bindings.g]
apps = ["ghostty"]
launch = "ghostty"
tags = ["dev-rust", "work:corp"]
launch_args = ["--working-directory=/workspace/user/github.com/org/repo"]

[profiles.default.launch_profiles.dev-rust]
env = { RUST_LOG = "debug" }
secrets = ["github-token"]
devshell = "/workspace/project#rust"
cwd = "/workspace/user/github.com/org/repo"
```

### Per-Directory Configuration (`.sesame.toml`)

Place a `.sesame.toml` in any workspace or repo root for directory-scoped defaults:

```toml
# Default profile when working in this directory
profile = "work"

# Environment variables (non-secret)
[env]
RUST_LOG = "debug"
PROJECT_NAME = "my-project"

# Launch profile tags applied automatically
tags = ["dev-rust"]

# Prefix for secret injection
secret_prefix = "MYAPP"
```

### Workspace Configuration (`~/.config/pds/workspaces.toml`)

```toml
[settings]
root = "/workspace"
default_ssh = true

[links]
"/workspace/usrbinkat/github.com/corp" = "work"
"/workspace/usrbinkat/github.com/personal" = "default"
```

---

## Troubleshooting

### Daemons Not Running

```bash
# Check daemon status
sesame status

# Check systemd services
systemctl --user status open-sesame.target
systemctl --user status open-sesame-profile

# Restart all daemons
systemctl --user restart open-sesame.target

# View daemon logs
journalctl --user -u open-sesame-profile -f
journalctl --user -u open-sesame-wm -f
```

### No Windows Appear

```bash
# Check if windows are detected
sesame wm list
```

If no windows appear, ensure you're running on COSMIC desktop with Wayland (not X11).

### Wrong App IDs

```bash
# Find the correct app_id
sesame wm list
```

Copy the exact `app_id` shown and use it in your configuration.

### Keybinding Not Working

```bash
# Check keybinding status
sesame keybinding-status

# Re-setup keybinding
sesame remove-keybinding
sesame setup-keybinding
```

Ensure the key combo doesn't conflict with other COSMIC shortcuts.

### SSH Agent Unlock Not Working

```bash
# Check SSH agent is available
ssh-add -l

# Check enrollment exists
sesame ssh list -p default

# Re-enroll if needed (vault must be unlocked with password first)
sesame unlock -p default
sesame ssh enroll -p default
```

For SSH agent forwarding (remote VMs), ensure `SSH_AUTH_SOCK` is available to systemd user services. The home-manager module handles this automatically via `~/.ssh/agent.sock` stable symlink.

### Input Daemon Requires `input` Group

`daemon-input` needs `/dev/input/*` access for keyboard capture when no window is focused:

```bash
sudo usermod -aG input $USER
# Logout and login required
```

### Debug Logging

```bash
# Set RUST_LOG for all daemons
systemctl --user set-environment RUST_LOG=debug
systemctl --user restart open-sesame.target

# Or for a single daemon
systemctl --user stop open-sesame-wm
RUST_LOG=debug daemon-wm
```

### Performance Issues

If the overlay feels slow, reduce delays in your config:

```toml
[profiles.default.wm]
overlay_delay_ms = 0    # Show immediately
activation_delay_ms = 100  # Faster activation (may skip gg, ggg)
```

---

## Architecture

Open Sesame v2 is a multi-daemon system with 17 Rust crates communicating over a Noise IK encrypted IPC bus.

### Daemons

| Daemon | Type | Purpose |
|---|---|---|
| `daemon-profile` | `notify` | IPC bus host, key management, audit logging, profile activation |
| `daemon-secrets` | `notify` | SQLCipher vault operations, ACL enforcement, rate limiting |
| `daemon-wm` | `notify` | Window management, overlay rendering (COSMIC compositor) |
| `daemon-launcher` | `simple` | Application search, frecency ranking, desktop entry scanning |
| `daemon-clipboard` | `simple` | Clipboard monitoring and per-profile history |
| `daemon-input` | `simple` | Keyboard input capture and layer-based remapping |
| `daemon-snippets` | `simple` | Text snippet trigger detection and expansion |

All daemons start as systemd user services under `open-sesame.target`, which is pulled in by `graphical-session.target` on login. `daemon-profile` must start first — all other daemons `Requires` and `After` it.

### Core Libraries

| Crate | Purpose |
|---|---|
| `core-ipc` | Noise IK transport, BusServer/BusClient, clearance registry |
| `core-types` | Shared types, `EventKind` protocol schema, `DaemonId`, `SecurityLevel` |
| `core-crypto` | KDF (Argon2id), HKDF (BLAKE3), AES-256-GCM encryption |
| `core-config` | TOML configuration with XDG layered inheritance and hot-reload watcher |
| `core-auth` | Authentication backends: password (Argon2id), SSH agent (KEK wrapping) |
| `core-profile` | Profile context, hash-chained audit log |
| `core-secrets` | SQLCipher database operations |
| `core-fuzzy` | Fuzzy search (nucleo) with frecency scoring |

### Platform and Tooling

| Crate | Purpose |
|---|---|
| `open-sesame` | CLI binary (`sesame`) — all user interaction |
| `platform-linux` | Wayland/COSMIC compositor integration, Landlock sandbox, D-Bus |
| `platform-macos` | macOS platform abstractions (scaffolded for future) |
| `platform-windows` | Windows platform abstractions (scaffolded for future) |
| `sesame-workspace` | Workspace discovery, canonical path convention, git operations |
| `extension-host` | WASI extension runtime |
| `extension-sdk` | Extension development SDK |

### Security Model

- **Encrypted IPC** — All inter-daemon communication via Noise IK with static keypairs
- **Encrypted vaults** — SQLCipher (AES-256-CBC with HMAC-SHA512) with Argon2id key derivation
- **SSH agent unlock** — Master key wrapped under KEK derived from deterministic SSH signatures
- **Landlock sandboxing** — Filesystem access restricted per daemon on Linux
- **Hash-chained audit** — Tamper-evident logging of all vault operations
- **Rate limiting** — Vault unlock attempt throttling
- **Systemd hardening** — `NoNewPrivileges`, `ProtectSystem=strict`, memory limits

### Design Principles

- **Multi-daemon isolation** — Each concern in its own process with minimal privileges
- **Profile-scoped everything** — Secrets, clipboard, frecency, snippets all scoped to profiles
- **Fast activation** — Sub-200ms window switching, zero-config defaults
- **Graceful degradation** — SSH unlock falls back to password, missing daemons don't crash others
- **Composable configuration** — System policy → user config → drop-ins → profile overrides

---

## Requirements

- **COSMIC Desktop Environment** (Pop!_OS 24.04+ or other COSMIC-based distributions)
- **Wayland** (X11 not supported)
- **fontconfig** with at least one font installed
- **Rust 1.91+** (for building from source)

**Optional for development:**

- `nix` — Reproducible dev environment with all native deps
- `mise` — Development task runner (100+ tasks defined in `.mise.toml`)
- `cargo-deb` — Debian package builder

---

## Contributing

Contributions are welcome! This project values:

- **Quality over speed** — Take time to write excellent code
- **Clear documentation** — Code should be self-explanatory
- **Comprehensive testing** — All quality gates must pass
- **User empathy** — Features should solve real problems

Before contributing, run the quality gates:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --workspace
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

- [Rust](https://www.rust-lang.org/) — Systems programming language
- [Smithay](https://github.com/Smithay/client-toolkit) — Wayland client toolkit
- [COSMIC Protocols](https://github.com/pop-os/cosmic-protocols) — System76 COSMIC desktop protocols
- [snow](https://github.com/mcginty/snow) — Noise protocol framework
- [SQLCipher](https://www.zetetic.net/sqlcipher/) — Encrypted SQLite (via rusqlite bundled-sqlcipher)
- [GTK4](https://gtk.org/) — UI toolkit for overlay windows
- [gtk4-layer-shell](https://github.com/wmww/gtk4-layer-shell) — Wayland layer-shell protocol

Inspired by [Vimium](https://github.com/philc/vimium) — The browser extension that proves keyboard navigation is superior.
