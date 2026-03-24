# Nix Packaging

Open Sesame provides a Nix flake (`flake.nix`) that produces two packages, an overlay, a Home Manager
module, and a development shell. The flake targets `x86_64-linux` and `aarch64-linux`.

## Flake Structure

The flake uses `nixpkgs` (nixos-unstable) as its sole input. It exposes the following outputs:

| Output | Description |
|--------|-------------|
| `packages.<system>.open-sesame` | Headless package (CLI + 4 daemons) |
| `packages.<system>.open-sesame-desktop` | Desktop package (3 GUI daemons); depends on headless |
| `packages.<system>.default` | Alias for `open-sesame-desktop` |
| `overlays.default` | Nixpkgs overlay adding both packages |
| `homeManagerModules.default` | Home Manager module for declarative configuration |
| `devShells.<system>.default` | Development shell with Rust toolchain and native dependencies |

## Headless Package (`nix/package.nix`)

The headless package builds five binary crates with `--no-default-features`, disabling all
desktop/GUI code paths:

| Crate | Binary |
|-------|--------|
| `open-sesame` | `sesame` |
| `daemon-profile` | `daemon-profile` |
| `daemon-secrets` | `daemon-secrets` |
| `daemon-launcher` | `daemon-launcher` |
| `daemon-snippets` | `daemon-snippets` |

Build dependencies:

- **nativeBuildInputs**: `pkg-config`, `installShellFiles`
- **buildInputs**: `openssl`, `libseccomp`

The install phase copies the five binaries, the example configuration file, and five systemd user
units (the headless target plus four service files) into `$out`.

Source filtering uses `lib.fileset.unions` to include only `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml`, `config.example.toml`, `.cargo/`, `contrib/`, and all crate directories
(matched by prefix: `core-*`, `daemon-*`, `platform-*`, `extension-*`, `sesame-*`, `open-sesame`,
`xtask`). Documentation, analysis files, and CI configuration are excluded.

## Desktop Package (`nix/package-desktop.nix`)

The desktop package builds four binary crates with default features (desktop enabled):

| Crate | Binary |
|-------|--------|
| `open-sesame` | `sesame` (rebuilt with desktop features) |
| `daemon-wm` | `daemon-wm` |
| `daemon-clipboard` | `daemon-clipboard` |
| `daemon-input` | `daemon-input` |

Additional build dependencies beyond the headless set:

- **nativeBuildInputs**: adds `makeWrapper`
- **buildInputs**: adds `fontconfig`, `wayland`, `wayland-protocols`, `libxkbcommon`
- **propagatedBuildInputs**: `open-sesame` (the headless package)

The `propagatedBuildInputs` declaration ensures the headless binaries (`sesame`, `daemon-profile`,
`daemon-secrets`, `daemon-launcher`, `daemon-snippets`) appear on `PATH` when the desktop package
is installed.

The `daemon-wm` binary is wrapped with `wrapProgram` to set `XKB_CONFIG_ROOT` to
`${xkeyboard-config}/etc/X11/xkb`. This is required because `libxkbcommon` needs evdev keyboard
rules at runtime, and the Nix store path differs from the system default.

The install phase copies the three desktop systemd user units (the desktop target plus wm, clipboard,
and input service files) into `$out`.

## cargoLock.outputHashes

Both packages declare `outputHashes` for three git dependencies that Cargo.lock references:

```nix
outputHashes = {
  "cosmic-client-toolkit-0.2.0" = "sha256-ymn+BUTTzyHquPn4hvuoA3y1owFj8LVrmsPu2cdkFQ8=";
  "cosmic-protocols-0.2.0" = "sha256-ymn+BUTTzyHquPn4hvuoA3y1owFj8LVrmsPu2cdkFQ8=";
  "nucleo-0.5.0" = "sha256-Hm4SxtTSBrcWpXrtSqeO0TACbUxq3gizg1zD/6Yw/sI=";
};
```

The headless package includes these hashes even though it does not build the COSMIC crates, because
Cargo.lock references workspace members and Cargo resolves the entire lock file before building.

## Home Manager Module

The Home Manager module is available at `homeManagerModules.default`. It configures Open Sesame
declaratively under `programs.open-sesame`.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | `bool` | `false` | Enable the Open Sesame desktop suite |
| `headless` | `bool` | `false` | Headless mode: only starts profile, secrets, launcher, and snippets daemons. Omits GUI daemons and graphical-session dependency. |
| `package` | `package` | auto-selected | Defaults to `open-sesame-desktop` or `open-sesame` depending on `headless` |
| `settings` | TOML attrset | `{}` | WM key bindings and settings for the default profile |
| `profiles` | `attrsOf (tomlFormat.type)` | `{}` | Additional profile configuration keyed by trust profile name |
| `logLevel` | enum | `"info"` | `RUST_LOG` level for all daemons. One of: `error`, `warn`, `info`, `debug`, `trace` |

### Generated Configuration

When `settings` or `profiles` are non-empty, the module generates
`~/.config/pds/config.toml` (via `xdg.configFile."pds/config.toml"`) with `config_version = 3`.
The `settings` option populates `profiles.default.wm`, while `profiles` allows defining additional
trust profiles with launch profiles and vault configuration.

### Systemd Service Generation

The module generates two systemd user targets and up to seven services:

**Headless target** (`open-sesame-headless`):

- `WantedBy = [ "default.target" ]` -- starts on login regardless of graphical session
- Four services: `open-sesame-profile`, `open-sesame-secrets`, `open-sesame-launcher`,
  `open-sesame-snippets`
- All services declare `PartOf = [ "open-sesame-headless.target" ]`

**Desktop target** (`open-sesame-desktop`, omitted in headless mode):

- `Requires = [ "open-sesame-headless.target" "graphical-session.target" ]`
- `WantedBy = [ "graphical-session.target" ]`
- Three services: `open-sesame-wm`, `open-sesame-clipboard`, `open-sesame-input`

All services share common hardening directives:

- `Type = "notify"` with `WatchdogSec = 30`
- `Restart = "on-failure"` with `RestartSec = 5`
- `NoNewPrivileges = true`
- `LimitMEMLOCK = "64M"` (required for `mlock`-backed `ProtectedAlloc`)
- `LimitCORE = 0` (disables core dumps to prevent secret leakage)
- `Environment = [ "RUST_LOG=${cfg.logLevel}" ]`

Per-service hardening varies. For example, `daemon-secrets` sets `PrivateNetwork = true` and
`MemoryMax = "256M"`, while `daemon-launcher` sets `CapabilityBoundingSet = ""` and
`SystemCallArchitectures = "native"`.

The `daemon-profile` service uses `ProtectHome = "read-only"`, `ProtectSystem = "strict"`, and
`ReadWritePaths = [ "%t/pds" "%h/.config/pds" ]` to restrict filesystem access.

### tmpfiles.d Rules

The module creates tmpfiles.d rules to ensure runtime directories exist before services start:

```text
d %t/pds 0700 - - -
d %h/.config/pds 0700 - - -
d %h/.cache/open-sesame 0700 - - -
```

In desktop mode, an additional rule is added:

```text
d %h/.cache/fontconfig 0755 - - -
```

These directories must exist on the real filesystem because `ProtectSystem=strict` bind-mounts
`ReadWritePaths` into each service's mount namespace, and the source directory must already exist.

### SSH Agent Integration

The module sets `systemd.user.sessionVariables.SSH_AUTH_SOCK = "${HOME}/.ssh/agent.sock"` to provide
a stable socket path for systemd user services. The `daemon-profile` and `daemon-wm` services
additionally load `EnvironmentFile = [ "-%h/.config/pds/ssh-agent.env" ]` (the leading `-` makes
the file optional).

## Cachix Binary Cache

The flake declares a Cachix binary cache in its `nixConfig`:

```nix
nixConfig = {
  extra-substituters = [ "https://scopecreep-zip.cachix.org" ];
  extra-trusted-public-keys = [
    "scopecreep-zip.cachix.org-1:LPiVDsYXJvgljVfZPN43zBWB7ZCGFr2jZ/lBinnPGvU="
  ];
};
```

Users who pass `--accept-flake-config` (or have the substituter trusted) automatically pull
pre-built binaries for both `x86_64-linux` and `aarch64-linux`.

CI pushes to the Cachix cache on every release via the `nix.yml` workflow using
`cachix/cachix-action@v15` with the `SCOPE_CREEP_CACHIX_PRIVATE_KEY` secret. The same workflow
runs on pull requests for cache warming (build only, no push without the secret).

## preCheck

Both packages set `preCheck = "export HOME=$(mktemp -d)"` to provide test isolation. Tests that
create configuration or runtime directories write to a temporary home instead of interfering with
the build sandbox.
