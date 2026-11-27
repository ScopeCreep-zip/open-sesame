# Nix Packaging

Open Sesame provides a Nix flake (`flake.nix`) that produces two packages, an overlay, a Home Manager
module, and a development shell. The flake targets `x86_64-linux` and `aarch64-linux`.

## Flake Structure

The flake uses `nixpkgs` (nixos-unstable) as its sole input. It exposes the following outputs:

| Output | Description |
| --- | --- |
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
| --- | --- |
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
| --- | --- |
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
| --- | --- | --- | --- |
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

### Systemd Units

The module installs the packages' own units: the files under `$out/lib/systemd/user` of
`open-sesame` (the headless target and the profile, secrets, launcher, and snippets services) and,
unless `headless` is set, of `open-sesame-desktop` (the desktop target and the wm, clipboard, and
input services). These are `contrib/systemd`, with `ExecStart` patched to the store path: the same
units the `.deb`, `.rpm`, and Arch packages ship, that `tests/protocol_validation.sh` runs every
daemon under, and that CI installs in its systemd containers. Every sandboxing directive
(`ProtectSystem`, `ProtectHome`, `ReadWritePaths`, `RestrictAddressFamilies`,
`InaccessiblePaths`, the `*Directory=` settings, limits, `Type`) is the unit's own; the module
writes none.

The unit files are linked into `~/.config/systemd/user`, where Home Manager links the units it
generates, together with the links `systemctl enable` creates from their `[Install]` sections:

| Link | Unit |
| --- | --- |
| `default.target.wants/` | `open-sesame-headless.target` |
| `open-sesame-headless.target.wants/` | the four headless services |
| `graphical-session.target.wants/` | `open-sesame-desktop.target` (desktop mode) |
| `open-sesame-desktop.target.wants/` | the three desktop services (desktop mode) |

sd-switch starts and restarts them on activation as it does Home Manager's own units.

`logLevel` is a drop-in, `<unit>.d/50-log-level.conf`, setting `Environment=RUST_LOG=<level>` over
the unit's `RUST_LOG=info`.

The flake's `checks.<system>.home-manager-module` (`nix/home-manager-check.nix`, run by
`nix flake check`, `mise run test:nix`, and the Test workflow's `nix` job) evaluates the module
through `homeManagerConfiguration` in desktop and headless mode. It fails if the module generates
an `open-sesame` unit of its own, links anything that is not a unit file of the mode's packages,
leaves a shipped unit unlinked, enables a unit for a target other than its `[Install] WantedBy=`, or
omits a service's `logLevel` drop-in.

### tmpfiles.d Rules

The units' `ReadWritePaths` are bind-mounted into each service's mount namespace, so each source
directory must exist on the real filesystem. daemon-profile's unit declares
`ConfigurationDirectory=pds`, `CacheDirectory=open-sesame`, and `RuntimeDirectory=pds`; the other
daemons' units do not, and fail with `226/NAMESPACE` until those directories exist. The module
creates them owner-only, as the daemons keep them:

```text
d %t/pds 0700 - - -
d ${config.xdg.configHome}/pds 0700 - - -
d ${config.xdg.cacheHome}/open-sesame 0700 - - -
```

In desktop mode, an additional rule creates fontconfig's cache, which `open-sesame-wm.service`
grants optionally (`ReadWritePaths=-%C/fontconfig`):

```text
d ${config.xdg.cacheHome}/fontconfig 0755 - - -
```

### SSH Agent Integration

The module sets `systemd.user.sessionVariables.SSH_AUTH_SOCK = "${HOME}/.ssh/agent.sock"` to provide
a stable socket path for systemd user services. The `daemon-profile` and `daemon-wm` units
additionally load `EnvironmentFile=-%E/pds/ssh-agent.env` (the leading `-` makes the file
optional).

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
`cachix/cachix-action@v17` with the `SCOPE_CREEP_CACHIX_PRIVATE_KEY` secret. The same workflow
runs on pull requests for cache warming (build only, no push without the secret).

## preCheck

Both packages set `preCheck = "export HOME=$(mktemp -d)"` to provide test isolation. Tests that
create configuration or runtime directories write to a temporary home instead of interfering with
the build sandbox.
