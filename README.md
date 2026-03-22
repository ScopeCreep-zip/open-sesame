# Open Sesame

An Alt+Tab replacement, application launcher, and secret manager for Linux.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/ScopeCreep-zip/open-sesame)](https://github.com/ScopeCreep-zip/open-sesame/releases)
[![CI](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml/badge.svg)](https://github.com/ScopeCreep-zip/open-sesame/actions/workflows/test.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

![Open Sesame Screenshot](docs/src/open-sesame-screenshot.png)

Open Sesame replaces your Alt+Tab with a window switcher that shows letter hints on every window. Tap `Alt+Tab` to quick-switch to your previous window, or hold it to see all your windows and type a letter to jump directly. `Alt+Shift+Tab` cycles backward. `Alt+Space` opens the full launcher overlay where you can also fuzzy-search and launch applications. All key combos are configurable.

Each window can be bound to a letter in your config. If the app is already open, that letter focuses it. If it's not running, it launches it. Multiple windows of the same app get stacked hints: `g`, `gg`, `ggg`. You configure which apps map to which letters, what command to run if the app isn't open, and optionally which secrets and environment variables to inject at launch time.

Beyond window switching, Open Sesame manages encrypted secret vaults with per-profile trust boundaries, clipboard history with sensitivity detection, keyboard input capture for compositor-independent shortcuts, and text snippet expansion. Secrets can be injected into any command as environment variables (`sesame env -p work -- aws s3 ls`) or exported in shell, dotenv, or JSON format. Vault unlock supports passwords, SSH agent keys, or both with configurable auth policies.

Everything is scoped to trust profiles. A "work" profile has its own vault, its own secrets, its own clipboard history, its own frecency ranking, and its own launch configurations -- completely separate from "personal" or "default". Profiles activate based on context (WiFi network, connected hardware) or manually.

The system runs as seven cooperating daemons under systemd, communicating over a Noise IK encrypted IPC bus. Each daemon is sandboxed with Landlock filesystem restrictions and seccomp syscall filtering. The whole thing is controlled through one CLI: `sesame`.

### Two packages

| Package | What's inside | Where it runs |
|---------|--------------|---------------|
| **open-sesame** | `sesame` CLI, daemon-profile, daemon-secrets, daemon-launcher, daemon-snippets | Desktops, servers, containers, VMs -- anywhere with systemd |
| **open-sesame-desktop** | daemon-wm, daemon-clipboard, daemon-input | COSMIC and Wayland desktops (depends on open-sesame) |

Install `open-sesame-desktop` and it pulls in `open-sesame` automatically. On a server or in a container, install just `open-sesame` for encrypted secrets and application launching without any GUI dependencies.

---

## Quick Start

```bash
# Add the APT repository
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list
sudo apt update

# On a desktop
sudo apt install -y open-sesame open-sesame-desktop

# On a server (no GUI needed)
sudo apt install -y open-sesame
```

All daemons start automatically after install. Run `sesame init` to create your config directory, generate IPC keypairs, and set a master password for your first vault:

```bash
sesame init
sesame status
```

Press `Alt+Tab` to switch windows. Press `Alt+Space` to open the launcher overlay. Configure your key bindings in `~/.config/pds/config.toml` (see [Configuration](#configuration) below).

---

## Packages

Open Sesame ships as two composable `.deb` packages with automatic systemd user service lifecycle management.

| Package | Binaries | Systemd Target | Use Case |
|---------|----------|----------------|----------|
| **open-sesame** | `sesame` CLI, `daemon-profile`, `daemon-secrets`, `daemon-launcher`, `daemon-snippets` | `open-sesame-headless.target` (WantedBy `default.target`) | Servers, containers, VMs, CI/CD, bare metal, IoT |
| **open-sesame-desktop** | `daemon-wm`, `daemon-clipboard`, `daemon-input` | `open-sesame-desktop.target` (Requires `open-sesame-headless.target` + `graphical-session.target`) | COSMIC/Wayland desktops |

- Installing `open-sesame-desktop` automatically pulls in `open-sesame` via APT dependency resolution
- Removing `open-sesame-desktop` leaves headless daemons running undisturbed
- The desktop target composes on top of the headless target -- starting desktop starts headless first
- Stopping the desktop target does not stop headless daemons
- Package postinst scripts use `systemctl --global enable` for persistence across all users and `systemctl --user -M "$uid@"` for immediate service activation -- the same pattern used by systemd-update-helper

---

## Features

### Encrypted Secret Vaults
- **Per-profile vaults** -- Each trust profile gets its own SQLCipher-encrypted database (AES-256-CBC + HMAC-SHA512)
- **Multi-factor authentication** -- Password (Argon2id KDF), SSH agent (Ed25519/RSA deterministic signatures), or both
- **Auth policies** -- `any` (either factor unlocks independently), `all` (every enrolled factor required via BLAKE3 combined key), or `policy` (required factors + additional threshold)
- **Environment injection** -- Run any command with vault secrets as env vars: `sesame env -p work -- aws s3 ls`
- **Export formats** -- Shell eval for bash/zsh/direnv, dotenv for Docker/node, JSON for programmatic use
- **Zeroization** -- All key material is mlock'd to prevent swap exposure and zeroized on drop
- **Rate limiting** -- Vault unlock attempts are throttled to prevent brute-force attacks
- **Hash-chained audit** -- Every vault operation recorded in a BLAKE3 tamper-evident log

### Window Manager (desktop package)
- **Vimium-style hints** -- Every window gets a letter (`g`, `gg`, `ggg` for multiple instances of the same app)
- **Quick switch** -- Tap `Alt+Tab` to instantly toggle between last two windows (MRU ordering)
- **Focus-or-launch** -- Type a letter to focus a running app or launch it if not running
- **Launcher mode** -- `Alt+Space` opens the full overlay immediately with fuzzy search
- **Arrow navigation** -- Use arrows and Enter as an alternative to typing letters
- **Inline vault unlock** -- If secrets are needed for a launch, auto-attempts SSH agent unlock, then touch prompt, then password fallback -- all inline in the overlay
- **SCTK rendering** -- Native Wayland layer-shell overlay rendered with tiny-skia and cosmic-text, themed from COSMIC system settings
- **Sub-200ms activation** -- Smart disambiguation with configurable delay, staged commit model (keypress selects, modifier release commits)

### Application Launcher
- **Fuzzy search** -- `sesame launch search firefox` with nucleo-powered matching and frecency ranking
- **Desktop entry scanning** -- Automatic discovery of all installed applications from standard XDG directories
- **Profile-scoped frecency** -- Different ranking per trust profile
- **Secret injection** -- Launch profiles compose environment variables, vault secrets, and Nix devshells at launch time
- **systemd scoping** -- Child processes isolated via `systemd-run --user --scope` so they survive launcher restarts
- **Composable launch profiles** -- Tag key bindings with named profiles. Cross-profile references (`work:corp`) compose env vars from multiple trust boundaries

### Developer Workspaces
- **Canonical paths** -- `/workspace/<user>/<server>/<org>/<repo>` convention
- **Git-aware cloning** -- `sesame workspace clone <url>` resolves HTTPS and SSH URLs to canonical paths
- **Profile linking** -- `sesame workspace link -p work` associates a directory with a trust profile
- **Shell injection** -- `sesame workspace shell` opens a shell with vault secrets injected as env vars
- **Adopt mode** -- `sesame workspace clone --adopt` links pre-existing directories without re-cloning
- **Per-directory config** -- `.sesame.toml` in project roots for directory-scoped defaults

### Clipboard Management (desktop package)
- **Per-profile history** -- Clipboard entries scoped to the active trust profile
- **Sensitivity classification** -- Automatic detection of passwords, tokens, keys with configurable TTL auto-expiry
- **SQLite storage** -- Persistent history backed by per-profile databases
- **Wayland data-control** -- Native clipboard monitoring via Wayland protocol

### Input Capture (desktop package)
- **Compositor-independent shortcuts** -- evdev keyboard capture works regardless of focused window
- **XKB keysym translation** -- Full keymap support with modifier tracking
- **IPC key forwarding** -- Key events routed to daemon-wm over the encrypted IPC bus
- **Layer-based remapping** -- Configurable keyboard layers per profile (roadmap)

### Snippet Expansion
- **Per-profile snippets** -- Text triggers scoped to trust profiles
- **Template variables** -- Variable substitution in snippet bodies
- **In-memory store** -- Fast lookup with config-driven templates

### Platform Support
- **Two-package architecture** -- Headless core + desktop addon with proper systemd user service lifecycle
- **COSMIC integration** -- Automatic keybinding setup for Alt+Tab/Alt+Space, native Wayland compositor protocol support
- **Nix flake** -- Full packages, overlay, home-manager module with `headless` option for servers
- **APT repository** -- GPG-signed, SLSA build provenance attestations on all packages
- **Sandbox hardening** -- Landlock filesystem restrictions + seccomp-bpf syscall filtering per daemon
- **systemd hardening** -- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateNetwork` (secrets daemon), memory limits, `LimitCORE=0`
- **Multi-platform scaffolded** -- macOS and Windows platform crates exist with trait definitions; Linux is the active implementation

---

## How It Works

### Two Modes

**Launcher Mode (Default: `Alt+Space`)**

Shows a centered overlay with all windows and letter hints. Type a letter to switch, or type to fuzzy-search applications and launch them. This is the primary interaction mode.

**Switcher Mode (Default: `Alt+Tab`)**

Acts like traditional Alt+Tab but with letter hints visible for instant selection. Designed for muscle memory compatibility.

### Quick Switch Behavior

**Tap the keybinding** -- Instantly switch to the previous window (MRU - Most Recently Used). If Alt is released within the quick-switch threshold (default 250ms), the switch commits immediately without showing the overlay.

**Hold and type** -- See the full overlay, type a letter or use arrows to select a window. The overlay appears after a configurable delay (default 150ms) to prevent flicker on fast switches.

### Focus-or-Launch

Configure key bindings for your favorite apps. If the app is running, Open Sesame focuses it. If not, it launches the app with the configured launch profile (env vars, secrets, devshell).

Example: Press `Alt+Space`, type `f` --> switches to Firefox (or launches it)

### Keyboard Shortcuts

Once the overlay appears:

| Key | Action |
|-----|--------|
| **Letter keys** | Instantly switch to window with that hint |
| **Arrow keys** | Navigate through window list |
| **Enter** | Activate selected window |
| **Escape** | Cancel and return to origin window |
| **Space** | Toggle launcher mode (fuzzy search) |
| **Repeat letter** | Type `gg`, `ggg` for multiple windows with the same letter |
| **Alt release** | Commit the current selection (staged commit model) |

---

## Installation

### From APT Repository (Recommended)

**Pop!_OS 24.04+ / Ubuntu 24.04+ with COSMIC Desktop:**

```bash
# Add GPG key and repository
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list
sudo apt update

# Full desktop install (pulls in headless automatically)
sudo apt install -y open-sesame open-sesame-desktop

# Initialize configuration and start services
sesame init
```

**Headless / Server / Container:**

```bash
# Same repository setup as above, then:
sudo apt install -y open-sesame
sesame init --no-keybinding
```

The `open-sesame` package installs 5 binaries (`sesame` CLI + 4 headless daemons) and systemd user services that start automatically via `open-sesame-headless.target`. The `open-sesame-desktop` package adds 3 GUI daemons under `open-sesame-desktop.target` which requires `graphical-session.target`.

### From GitHub Releases

```bash
# Auto-detect architecture
ARCH=$(uname -m)

# Download both packages
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/latest/download/open-sesame-linux-${ARCH}.deb" \
  -o /tmp/open-sesame.deb
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/latest/download/open-sesame-desktop-linux-${ARCH}.deb" \
  -o /tmp/open-sesame-desktop.deb

# Verify build provenance
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
gh attestation verify /tmp/open-sesame-desktop.deb --owner ScopeCreep-zip

# Install (headless first, then desktop)
sudo dpkg -i /tmp/open-sesame.deb /tmp/open-sesame-desktop.deb

# Initialize
sesame init
```

### Verify Package Authenticity

All packages include [SLSA Build Provenance](https://slsa.dev/) attestations generated by GitHub Actions:

```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
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
    # headless = true;  # servers/containers: only headless daemons
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

The module generates `~/.config/pds/config.toml`, creates systemd user services with dual targets (`open-sesame-headless.target` always, `open-sesame-desktop.target` when `headless = false`), configures `SSH_AUTH_SOCK` for SSH agent forwarding to systemd services, and sets up tmpfiles.d rules for runtime directories.

Available Nix packages:

| Package | Description |
|---------|-------------|
| `packages.open-sesame` | Headless: 5 binaries, no GUI deps (`openssl` + `libseccomp` only) |
| `packages.open-sesame-desktop` | Desktop: 3 GUI daemons + CLI with keybinding commands (propagates headless via `propagatedBuildInputs`) |
| `packages.default` | Desktop (alias) |

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
    libseccomp-dev

# Required for desktop crates (daemon-wm, daemon-clipboard, daemon-input)
sudo apt-get install -y \
    libwayland-dev \
    libxkbcommon-dev \
    libfontconfig1-dev
```

Minimum Rust toolchain: see `rust-toolchain.toml`.

```bash
cargo check --workspace
```

#### What Each System Package Provides

| apt package | Crate(s) | Purpose |
|---|---|---|
| `libssl-dev` | `rusqlite` (bundled-sqlcipher) | OpenSSL headers for SQLCipher encryption |
| `libseccomp-dev` | `libseccomp` | seccomp-bpf syscall filtering for daemon sandboxes |
| `libwayland-dev` | `wayland-client`, `smithay-client-toolkit` | Wayland protocol for overlay rendering and clipboard |
| `libxkbcommon-dev` | `xkbcommon` | Keyboard keymap handling for input capture |
| `libfontconfig1-dev` | `fontconfig` | Font discovery for overlay text rendering |

---

## Usage

### Initialization

```bash
# First-time setup: creates config directory, generates Noise IK keypairs,
# starts daemons, and prompts for master password
sesame init

# With organization namespace (enterprise deployments)
sesame init --org braincraft.io

# SSH-only vault (no password, random master key wrapped under SSH KEK)
sesame init --ssh-key

# Specific SSH key by fingerprint or file path
sesame init --ssh-key SHA256:abc123...
sesame init --ssh-key ~/.ssh/id_ed25519.pub

# Dual-factor vault (password + SSH key)
sesame init --ssh-key --password

# Dual-factor with "all" policy (both factors required to unlock)
sesame init --ssh-key --password --auth-policy all

# Factory reset (destructive -- requires typing "destroy all data")
sesame init --wipe-reset-destroy-all-data
```

### Vault Operations

```bash
# Unlock your default vault (auto-tries SSH agent, then prompts for password)
sesame unlock

# Unlock specific profiles
sesame unlock -p work
sesame unlock -p "default,work"

# Lock a vault (zeroizes cached key material from memory)
sesame lock -p work

# Lock all vaults
sesame lock
```

### SSH Agent Unlock

Enroll SSH keys for passwordless vault unlock. Only Ed25519 and RSA keys are supported -- their signatures are deterministic, which is required for consistent KEK derivation.

```bash
# Enroll an SSH key (interactive selection from agent)
sesame ssh enroll -p default

# Enroll a specific key by fingerprint
sesame ssh enroll -p work -k SHA256:abc123...

# Enroll by public key file path
sesame ssh enroll -p work -k ~/.ssh/id_ed25519.pub

# List enrollments
sesame ssh list
sesame ssh list -p work

# Revoke enrollment
sesame ssh revoke -p work
```

After enrollment, `sesame unlock` and the window switcher overlay attempt SSH agent unlock automatically before falling back to password prompt. This enables fully non-interactive vault access for SSH sessions, forwarded agents, and headless environments.

### Secret Management

```bash
# Store a secret (prompts for value on stdin)
sesame secret set -p default github-token

# Retrieve a secret value (prints to stdout)
sesame secret get -p default github-token

# List all keys in a profile (never shows values)
sesame secret list -p work

# Delete a secret
sesame secret delete -p work old-api-key
sesame secret delete -p work old-api-key --yes  # skip confirmation (scripted use)
```

### Environment Injection

Run commands with vault secrets injected as environment variables. Secret keys are uppercased with hyphens converted to underscores (`api-key` becomes `API_KEY`).

```bash
# Run a command with secrets from the work profile
sesame env -p work -- aws s3 ls

# With env var prefix (api-key becomes MYAPP_API_KEY)
sesame env -p work --prefix MYAPP -- ./start.sh

# Multi-profile injection
sesame env -p "default,work" -- make deploy
```

A runtime denylist prevents injection of dangerous variables (`LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `JAVA_TOOL_OPTIONS`, etc.) across all major language runtimes.

### Secret Export

```bash
# Shell eval (default) -- for bash/zsh/direnv
eval "$(sesame export -p work)"

# Dotenv format -- for Docker, docker-compose, node, python-dotenv
sesame export -p work -f dotenv > .env.secrets

# JSON -- for jq, CI/CD, programmatic consumers
sesame export -p work -f json | jq .

# With prefix
sesame export -p work --prefix MYAPP -f shell
```

### Profiles

Trust profiles scope secrets, clipboard history, frecency ranking, audit logs, and launch configurations. Each profile can have its own vault with independent authentication.

```bash
# List configured profiles
sesame profile list

# Show profile configuration
sesame profile show work

# Activate/deactivate profiles (opens/closes vault, registers namespace)
sesame profile activate work
sesame profile deactivate work

# Set default profile
sesame profile default work
```

### Window Manager (desktop package)

```bash
# Open the window switcher overlay
sesame wm overlay

# Launcher mode (full overlay immediately, no border-only phase)
sesame wm overlay --launcher

# Backward direction (start from previous window in MRU)
sesame wm overlay --backward

# Switch to next/previous window in MRU order (without overlay)
sesame wm switch
sesame wm switch --backward

# Focus a specific window by ID or app ID
sesame wm focus firefox

# List all windows known to daemon-wm
sesame wm list
```

### Application Launcher

```bash
# Fuzzy search for applications
sesame launch search firefox
sesame launch search "visual studio" -n 5

# Launch by desktop entry ID
sesame launch run org.mozilla.firefox

# Launch with profile context (for frecency ranking and secret injection)
sesame launch run org.mozilla.firefox -p work
```

### Clipboard (desktop package)

```bash
# Show clipboard history for a profile
sesame clipboard history -p default
sesame clipboard history -p default -n 50

# Clear clipboard history for a profile
sesame clipboard clear -p work

# Get a specific clipboard entry by ID
sesame clipboard get <entry-id>
```

### Audit Log

All vault operations are recorded in a BLAKE3 hash-chained audit log. Each entry includes a hash of the previous entry, making the chain tamper-evident -- modifying, deleting, or reordering any entry breaks the chain.

```bash
# Verify hash chain integrity
sesame audit verify

# Show recent entries
sesame audit tail
sesame audit tail -n 50

# Follow new entries in real time
sesame audit tail -f
```

### COSMIC Keybindings (desktop package)

```bash
# Setup keybindings (Alt+Tab, Alt+Shift+Tab, launcher key)
sesame setup-keybinding              # default: alt+space
sesame setup-keybinding super+space  # custom launcher key

# Check keybinding status
sesame keybinding-status

# Remove keybindings
sesame remove-keybinding
```

### Workspaces

Workspaces are directory-scoped project environments with canonical paths and automatic secret injection.

```bash
# Initialize workspace root directory
sesame workspace init
sesame workspace init --root /mnt/workspace

# Clone to canonical path: /workspace/<user>/github.com/org/repo
sesame workspace clone https://github.com/org/repo
sesame workspace clone git@github.com:org/repo --depth 1

# Adopt a pre-existing directory (links without re-cloning)
sesame workspace clone https://github.com/org/repo --adopt true

# Link workspace to a profile (enables automatic secret injection)
sesame workspace link -p work

# List all discovered workspaces
sesame workspace list

# Show workspace status and metadata
sesame workspace status

# Open a shell with vault secrets injected as environment variables
sesame workspace shell
sesame workspace shell -p work
sesame workspace shell -- make build  # run a command instead of interactive shell
sesame workspace shell --prefix MYAPP # prefix for env var names

# Show resolved workspace configuration
sesame workspace config show

# Unlink profile association
sesame workspace unlink
```

### Input Remapping (desktop package)

```bash
# List configured input layers
sesame input layers

# Show input daemon status (active layer, grabbed devices)
sesame input status
```

### Snippets

```bash
# List snippets for a profile
sesame snippet list -p default

# Add a new snippet
sesame snippet add -p default "@@sig" "Best regards,\nJohn"

# Expand a snippet trigger
sesame snippet expand -p default "@@sig"
```

---

## Configuration

### Configuration File Locations

Open Sesame uses `~/.config/pds/` as its config directory with layered inheritance:

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
~/.config/pds/audit.jsonl                  # Hash-chained audit log
$XDG_RUNTIME_DIR/pds/                      # Runtime: IPC socket, bus public key
```

### Example Configuration

```toml
config_version = 3

[global]
default_profile = "default"

[global.ipc]
# channel_capacity = 1024
# slow_subscriber_timeout_ms = 5000

[global.logging]
level = "info"
# json = false
# journald = true

# ── Profile: default ──────────────────────────────────────────────

[profiles.default]
name = "default"

# Authentication: how vault unlock factors combine
# "any"    — any single enrolled factor unlocks (password OR ssh-agent)
# "all"    — all enrolled factors required (BLAKE3 combined key)
# "policy" — required factors + threshold of additional enrolled factors
[profiles.default.auth]
mode = "any"
# required = ["password", "ssh-agent"]  # for mode = "policy"
# additional_required = 0               # for mode = "policy"

# Window Manager settings
[profiles.default.wm]
hint_keys = "asdfghjkl"
overlay_delay_ms = 150          # ms before full overlay appears
activation_delay_ms = 200       # ms delay before committing a hint match
quick_switch_threshold_ms = 250 # Alt+Tab released within this = instant switch
border_width = 4.0
border_color = "#89b4fa"
background_color = "#000000c8"
card_color = "#1e1e1ef0"
text_color = "#ffffff"
hint_color = "#646464"
hint_matched_color = "#4caf50"
show_title = true
show_app_id = false
max_visible_windows = 20

# ── Key Bindings ──────────────────────────────────────────────────
# Each section maps a letter to app IDs and an optional launch command.
# Multiple windows of the same app get repeated keys: g, gg, ggg
# Find your app_ids: sesame wm list

# Terminals
[profiles.default.wm.key_bindings.g]
apps = ["ghostty", "com.mitchellh.ghostty"]
launch = "ghostty"

# Browsers
[profiles.default.wm.key_bindings.f]
apps = ["firefox", "org.mozilla.firefox", "Firefox"]
launch = "firefox"

[profiles.default.wm.key_bindings.e]
apps = ["microsoft-edge", "com.microsoft.Edge", "Microsoft-edge"]
launch = "microsoft-edge"

[profiles.default.wm.key_bindings.v]
apps = ["vivaldi", "vivaldi-stable"]
launch = "vivaldi"

[profiles.default.wm.key_bindings.c]
apps = ["chromium", "google-chrome", "Chromium", "Google-chrome"]
# No launch — just focus existing windows

# Editors
[profiles.default.wm.key_bindings.z]
apps = ["zed", "dev.zed.Zed"]
launch = "zed-editor"

# File Managers
[profiles.default.wm.key_bindings.n]
apps = ["nautilus", "org.gnome.Nautilus", "com.system76.CosmicFiles"]
launch = "nautilus"

# Communication
[profiles.default.wm.key_bindings.s]
apps = ["slack", "Slack"]
launch = "slack"

[profiles.default.wm.key_bindings.d]
apps = ["discord", "Discord"]
launch = "discord"

[profiles.default.wm.key_bindings.t]
apps = ["thunderbird", "Thunderbird"]
launch = "thunderbird"

# Media
[profiles.default.wm.key_bindings.m]
apps = ["spotify", "Spotify"]
launch = "spotify"

# ── Launch Profiles ───────────────────────────────────────────────
# Named, composable environment bundles applied via the `tags` field on
# key bindings. Tags support cross-profile references: "work:corp" resolves
# the "corp" launch profile in the "work" trust profile.
#
# When multiple tags are applied, env vars merge (later tag wins on conflict),
# secrets accumulate, and last devshell/cwd wins.

[profiles.default.launch_profiles.dev]
env = { RUST_LOG = "debug" }
secrets = ["github-token"]
# devshell = "/workspace/myproject#rust"
# cwd = "/workspace/usrbinkat/github.com/org/repo"

# Launcher settings
[profiles.default.launcher]
max_results = 20
frecency = true

# Clipboard settings
[profiles.default.clipboard]
max_history = 1000
sensitive_ttl_s = 30
detect_sensitive = true

# Audit settings
[profiles.default.audit]
enabled = true
retention_days = 90

# ── Profile: work ────────────────────────────────────────────────

# [profiles.work]
# name = "work"
#
# [profiles.work.auth]
# mode = "all"
#
# [profiles.work.launch_profiles.corp]
# env = { CORP_ENV = "production" }
# secrets = ["corp-api-key", "corp-signing-key"]
# cwd = "/workspace/usrbinkat/github.com/acme-corp"
#
# # Tag a key binding with a cross-profile launch profile:
# # [profiles.default.wm.key_bindings.g]
# # apps = ["ghostty"]
# # launch = "ghostty"
# # tags = ["dev", "work:corp"]
# #
# # This composes: "dev" from default profile + "corp" from work profile.
# # Environment merges, secrets accumulate, last devshell/cwd wins.

# ── Cryptographic Algorithms ──────────────────────────────────────

[crypto]
kdf = "argon2id"             # or "pbkdf2-sha256"
hkdf = "blake3"              # or "hkdf-sha256"
noise_cipher = "chacha-poly" # or "aes-gcm"
noise_hash = "blake2s"       # or "sha256"
audit_hash = "blake3"        # or "sha256"
minimum_peer_profile = "leading-edge"  # or "governance-compatible", "custom"
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
env = { RUST_LOG = "debug", CARGO_HOME = "/workspace/.cargo" }
secrets = ["github-token", "crates-io-token"]
devshell = "/workspace/myproject#rust"
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
systemctl --user list-units "open-sesame-*"

# Check specific daemon logs
journalctl --user -u open-sesame-profile -f
journalctl --user -u open-sesame-wm -f
journalctl --user -u open-sesame-secrets -f
```

### No Windows Appear

```bash
# Check if windows are detected
sesame wm list
```

If no windows appear, ensure you're running on COSMIC desktop with Wayland (not X11). Open Sesame uses the `ext-foreign-toplevel` and `zcosmic-toplevel` Wayland protocols which require compositor support.

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

For SSH agent forwarding (remote VMs), ensure `SSH_AUTH_SOCK` is available to systemd user services. The home-manager module handles this automatically via `~/.ssh/agent.sock` stable symlink and `systemd.user.sessionVariables`.

### Input Daemon Requires `input` Group

`daemon-input` needs `/dev/input/*` access for keyboard capture when no window is focused:

```bash
sudo usermod -aG input $USER
# Logout and login required
```

### Debug Logging

```bash
# Set RUST_LOG for all daemons via systemd environment
systemctl --user set-environment RUST_LOG=debug
systemctl --user restart open-sesame-headless.target
systemctl --user restart open-sesame-desktop.target

# Or run a single daemon manually with debug logging
systemctl --user stop open-sesame-wm
RUST_LOG=debug daemon-wm
```

### Performance Issues

If the overlay feels slow, reduce delays in your config:

```toml
[profiles.default.wm]
overlay_delay_ms = 0       # Show immediately
activation_delay_ms = 100  # Faster activation (may skip gg, ggg disambiguation)
```

---

## Architecture

Open Sesame is a multi-daemon system with 21 Rust crates communicating over a Noise IK encrypted IPC bus.

### IPC Bus

All inter-daemon communication flows through `daemon-profile` which hosts a `BusServer` on a Unix domain socket at `$XDG_RUNTIME_DIR/pds/bus.sock`. Every connection is authenticated via Noise Protocol Framework (IK pattern) with X25519 key exchange and ChaChaPoly AEAD. Peer identity is bound via UCred (PID, UID) in the Noise prologue. Messages are postcard-encoded with security level enforcement -- a daemon can only send messages at or below its registered clearance level.

### Systemd Targets

| Target | WantedBy | Daemons |
|--------|----------|---------|
| `open-sesame-headless.target` | `default.target` | profile, secrets, launcher, snippets |
| `open-sesame-desktop.target` | `graphical-session.target` | wm, clipboard, input |

The desktop target `Requires` the headless target. Starting desktop starts headless first. Stopping desktop leaves headless running.

### Daemons

| Daemon | Package | Type | Sandbox | Purpose |
|--------|---------|------|---------|---------|
| `daemon-profile` | headless | `notify` | Landlock + seccomp | IPC bus host, Noise IK key management, profile lifecycle, hash-chained audit logging, SSID/focus context monitors |
| `daemon-secrets` | headless | `notify` | Landlock + seccomp + `PrivateNetwork` | SQLCipher vault CRUD, multi-factor unlock state machine, ACL enforcement, rate limiting, keyring caching |
| `daemon-launcher` | headless | `notify` | Kernel control-plane hardening | Desktop entry scanning, nucleo fuzzy search, frecency ranking, `systemd-run --scope` child isolation |
| `daemon-snippets` | headless | `notify` | Landlock + seccomp | In-memory snippet store, template expansion, profile-scoped namespaces |
| `daemon-wm` | desktop | `notify` | Landlock + seccomp | SCTK layer-shell overlay, COSMIC compositor integration, MRU window ordering, inline vault unlock UX |
| `daemon-clipboard` | desktop | `notify` | Landlock + seccomp | Wayland data-control clipboard monitoring, SQLite history, sensitivity classification |
| `daemon-input` | desktop | `notify` | Landlock + seccomp | evdev keyboard capture, XKB keysym translation, IPC key forwarding to daemon-wm |

All daemons use `Type=notify` with `WatchdogSec=30` for health monitoring. `daemon-profile` must start first -- all other daemons `Requires` and `After` it.

### Core Libraries

| Crate | Purpose |
|-------|---------|
| `core-ipc` | Noise IK transport (X25519 + ChaChaPoly + BLAKE2s), BusServer/BusClient, clearance registry, postcard framing, UCred binding |
| `core-types` | Canonical type system: `EventKind` protocol schema, `DaemonId`, `SecurityLevel`, `TrustProfileName`, `SensitiveBytes` with mlock |
| `core-crypto` | Argon2id KDF, BLAKE3 HKDF, AES-256-GCM encryption, `SecureBytes`/`SecureVec` with mlock + zeroize-on-drop |
| `core-config` | TOML configuration schema with XDG layered inheritance, inotify hot-reload watcher, config validation |
| `core-auth` | Multi-factor authentication: `PasswordBackend` (Argon2id KEK wrapping), `SshAgentBackend` (deterministic signature KEK), `AuthDispatcher`, `VaultMetadata` persistence |
| `core-secrets` | SQLCipher database abstraction, `KeyLocker` trait, JIT secret cache |
| `core-profile` | Profile context evaluation, hash-chained BLAKE3 audit logger |
| `core-fuzzy` | Nucleo fuzzy matching engine with frecency scoring backed by SQLite |

### Platform and Tooling

| Crate | Purpose |
|-------|---------|
| `open-sesame` | CLI binary (`sesame`) -- all user-facing commands |
| `platform-linux` | Wayland/COSMIC compositor backends (`CosmicBackend`, `WlrBackend`), Landlock sandbox, seccomp-bpf, D-Bus (SSID monitor, Secret Service), COSMIC key injection, systemd notify |
| `platform-macos` | macOS platform abstractions (scaffolded: accessibility, keychain, launch agents) |
| `platform-windows` | Windows platform abstractions (scaffolded: credential vault, hotkeys, UI automation) |
| `sesame-workspace` | Workspace discovery, canonical path convention, git operations, platform-specific root resolution |
| `extension-host` | WASI extension runtime (Wasmtime + component model) |
| `extension-sdk` | Extension development SDK (WIT bindings) |

### Key Hierarchy

```text
User Password
  |
  v
Argon2id(password, per-profile-salt) --> Master Key (32 bytes, mlock'd SecureBytes)
  |
  +--> BLAKE3 derive_key("pds v2 vault-key {profile}")          --> SQLCipher page key
  +--> BLAKE3 derive_key("pds v2 clipboard-key {profile}")       --> Clipboard encryption key
  +--> BLAKE3 derive_key("pds v2 ipc-auth-token {profile}")      --> IPC auth token
  +--> BLAKE3 derive_key("pds v2 ipc-encryption-key {profile}")  --> IPC field encryption key

SSH Agent (alternative/additional factor):
  SSH sign(challenge) --> BLAKE3 derive_key("pds v2 ssh-vault-kek {profile}") --> KEK
    KEK wraps Master Key via AES-256-GCM --> EnrollmentBlob on disk

All-mode (both factors required):
  BLAKE3 derive_key("pds v2 combined-master-key {profile}", sorted_factor_pieces) --> Combined Key
```

### Security Model

- **Noise IK encrypted IPC** -- All inter-daemon communication authenticated and encrypted with forward secrecy
- **SQLCipher encrypted vaults** -- AES-256-CBC with HMAC-SHA512 per page, Argon2id key derivation (19 MiB memory, 2 iterations)
- **SSH agent unlock** -- Master key wrapped under KEK derived from deterministic SSH signatures (Ed25519/RSA PKCS#1 v1.5)
- **mlock'd key material** -- `SecureBytes` and `SecureVec` use `mlock(2)` to prevent swap exposure, `MADV_DONTDUMP` to exclude from core dumps, and zeroize all bytes on drop
- **Landlock filesystem sandboxing** -- Per-daemon path-based access control. Daemons can only access their specific runtime directories. Partially enforced Landlock is treated as a fatal error -- no degradation
- **seccomp-bpf syscall filtering** -- Per-daemon allowlists. Unallowed syscalls terminate the offending thread (`SECCOMP_RET_KILL_THREAD`) with a SIGSYS handler for visibility
- **Hash-chained audit log** -- BLAKE3 hash chain provides tamper evidence for all vault operations. `sesame audit verify` detects modifications, deletions, and reorderings
- **Rate limiting** -- Vault unlock attempts throttled via governor token bucket
- **systemd hardening** -- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateNetwork` (secrets daemon), `LimitCORE=0`, memory limits, capability bounding
- **Environment injection denylist** -- Blocks `LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `JAVA_TOOL_OPTIONS`, and 30+ other injection vectors across all major runtimes

### Design Principles

- **Multi-daemon isolation** -- Each concern in its own process with minimal privileges and tailored sandbox
- **Profile-scoped everything** -- Secrets, clipboard, frecency, snippets, audit all scoped to trust profiles
- **Fast activation** -- Sub-200ms window switching with staged commit model
- **Headless-first** -- Every CLI command works from explicit primitives without interactive prompts
- **Composable configuration** -- System policy --> user config --> drop-ins --> profile overrides --> workspace overrides
- **Zero graceful degradation** -- Security controls that fail are fatal. No silent fallbacks to weaker modes
- **Deterministic security** -- No race conditions in lock/unlock. No "should never happen" code paths

---

## Requirements

**Headless (`open-sesame`):**
- Linux with systemd (255+)
- libc6, libseccomp2

**Desktop (`open-sesame-desktop`):**
- COSMIC Desktop Environment or Wayland compositor with `ext-foreign-toplevel` protocol support
- libwayland-client0, libxkbcommon0, libfontconfig1, libfreetype6, fonts-dejavu-core
- `input` group membership for daemon-input keyboard capture

**Optional for development:**

- `nix` -- Reproducible dev environment with all native deps
- `mise` -- Development task runner (100+ tasks defined in `.mise.toml`)
- `cargo-deb` -- Debian package builder

---

## Contributing

Contributions are welcome! This project values:

- **Quality over speed** -- Take time to write excellent code
- **Clear documentation** -- Code should be self-explanatory
- **Comprehensive testing** -- All quality gates must pass
- **User empathy** -- Features should solve real problems

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

- [Rust](https://www.rust-lang.org/) -- Systems programming language
- [smithay-client-toolkit](https://github.com/Smithay/client-toolkit) -- Wayland client toolkit for SCTK layer-shell overlay
- [COSMIC Protocols](https://github.com/pop-os/cosmic-protocols) -- System76 COSMIC desktop Wayland protocols
- [snow](https://github.com/mcginty/snow) -- Noise Protocol Framework implementation
- [SQLCipher](https://www.zetetic.net/sqlcipher/) -- Encrypted SQLite (via rusqlite bundled-sqlcipher-vendored-openssl)
- [tiny-skia](https://github.com/nickel-corp/tiny-skia) -- 2D rendering for overlay
- [cosmic-text](https://github.com/nickel-corp/cosmic-text) -- Text layout and rendering
- [nucleo](https://github.com/helix-editor/nucleo) -- Fuzzy matching engine (from Helix editor)
- [argon2](https://crates.io/crates/argon2) -- Memory-hard password hashing
- [blake3](https://github.com/BLAKE3-team/BLAKE3) -- HKDF and audit hash chain
- [aes-gcm](https://crates.io/crates/aes-gcm) -- Authenticated encryption for key wrapping

Inspired by [Vimium](https://github.com/philc/vimium) -- The browser extension that proves keyboard navigation is superior.
