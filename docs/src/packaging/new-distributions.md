# Packaging for New Distributions

This guide covers the requirements and considerations for packaging Open
Sesame on Linux distributions beyond the officially supported Debian/Ubuntu
`.deb` packages, Fedora/RHEL `.rpm` packages, and Nix flake.

## Common Requirements

Regardless of distribution, all packages must satisfy the following.

### Two-Package Split

Open Sesame ships as two logical packages:

- **open-sesame** (headless) -- Contains the `sesame` CLI, `daemon-profile`,
  `daemon-secrets`, `daemon-launcher`, `daemon-snippets`, and their systemd
  user service units. Has no GUI dependencies.
- **open-sesame-desktop** (requires open-sesame) -- Contains `daemon-wm`,
  `daemon-clipboard`, `daemon-input`, and the COSMIC/Wayland compositor
  integration. Depends on `libwayland-client`, `libxkbcommon`, and
  `cosmic-protocols`.

### systemd User Services

All daemons run as systemd user services (`systemctl --user`). Packages must
install unit files to `/usr/lib/systemd/user/`. The services use:

- `Type=notify` with `sd_notify` readiness.
- `Restart=on-failure` with `RestartSec=2`.
- Ordering via `After=` and `Requires=` (daemon-profile starts first as the
  IPC bus host; all others depend on it).

### LimitMEMLOCK

daemon-secrets requires `mlock` for secret memory. The systemd unit sets
`LimitMEMLOCK=64M`. Packages that install systemd overrides or distributions
that set system-wide limits below this threshold will cause vault operations
to fail. The corresponding PAM/security limit is:

```text
# /etc/security/limits.d/open-sesame.conf
*  soft  memlock  65536
*  hard  memlock  65536
```

### Binary Paths

All binaries install to `/usr/bin/`. Configuration lives under
`~/.config/pds/` (per XDG Base Directory specification).

## AUR (Arch Linux)

Arch packaging is officially supported via split PKGBUILDs and a self-hosted pacman
repository on GitHub Pages. Full documentation is in [Arch Packaging](arch.md).

Two AUR pkgbases are maintained:

- `open-sesame-bin` — split binary package from release tarballs, installs
  `open-sesame-bin` and `open-sesame-desktop-bin`
- `open-sesame` — split source-build package from release source tarball,
  installs `open-sesame` and `open-sesame-desktop`

Both use split `package_*()` functions for the headless/desktop split.
`conflicts=('sesame')` avoids file collision with the AUR `sesame` package.
Systemd user presets are shipped per package (no `.install`-based enablement).
`check()` in the source pkgbase self-skips when `RLIMIT_MEMLOCK` is insufficient
for `memfd_secret` test allocations.

aarch64 packages serve Arch Linux ARM (ALARM) users. Apple Silicon users should
use the DNF repository via Fedora Asahi Remix.

## RPM (Fedora / RHEL)

RPM packaging is officially supported via `cargo-generate-rpm`. Full documentation is in
[RPM Packaging](rpm.md). The following is a summary for packagers familiar with RPM conventions.

### Build Tool

Open Sesame uses `cargo-generate-rpm` (not `rpmbuild` with spec files). Package metadata lives
in `[package.metadata.generate-rpm]` sections in `open-sesame/Cargo.toml` and
`daemon-wm/Cargo.toml`. The tool reads Cargo metadata, embeds scriptlets verbatim, and produces
`.rpm` files using the `rpm` crate. No spec file, no rpmbuild dependency.

### Dependencies

- **Headless requires**: `glibc`, `libgcc`, `libseccomp`
- **Headless recommends**: `openssh-clients`
- **Desktop requires**: `glibc`, `libgcc`, `libseccomp`, `libxkbcommon`, `libwayland-client`,
  `fontconfig`, `freetype`
- **Desktop recommends**: `xdg-utils`, `dejavu-sans-fonts`
- **License tag**: `GPL-3.0-only` (from `workspace.package.license`)
- **auto-req**: Disabled (`auto-req = "no"`). CI builds on Ubuntu runners produce Debian-style
  soname deps via `ldd`; Fedora package names are declared explicitly in `[requires]`.

### Systemd Integration

- **Scriptlets**: `%post`, `%preun`, `%postun`, `%posttrans` call
  `/usr/lib/systemd/systemd-update-helper` directly. RPM macros like `%systemd_user_post` cannot
  be used because `cargo-generate-rpm` embeds scripts verbatim without rpmbuild's macro parser.
- **Preset file**: `/usr/lib/systemd/user-preset/90-open-sesame.preset` enables all services and
  targets by default, integrating with Fedora's preset policy. Administrators override via
  higher-priority presets in `/etc/systemd/user-preset/`.
- **BindsTo**: `open-sesame-desktop.target` uses `BindsTo=graphical-session.target` (not
  `Requires=`) to ensure desktop services tear down when the compositor exits unexpectedly.

### SELinux

daemon-secrets performs `mlock` and reads `SSH_AUTH_SOCK`. On SELinux-enforcing systems with
confined users, the `mlock` syscall may require the `allow_mlock` boolean or a custom policy
module. The base package does not ship a `.te` policy file — document the required booleans
in deployment guides for confined environments.

### Vendor Dependencies

Fedora policy requires vendored dependencies to be audited for bundled library packaging.
`cargo-generate-rpm` produces a binary RPM from pre-built binaries; it does not run `cargo build`
or vendor sources. For Fedora review submission, run `cargo vendor` and include the vendor tarball
as a secondary source in a spec file wrapper around the `cargo-generate-rpm` output.

## Alpine Linux

### Static Linking and musl

Alpine uses musl libc. Open Sesame compiles against musl with the
`x86_64-unknown-linux-musl` target. Considerations:

- **SQLCipher**: Must be compiled against musl. Alpine's `sqlcipher` package
  provides this.
- **OpenSSL vs. rustls**: If the build uses OpenSSL for TLS, link against
  Alpine's `openssl-dev` (which is musl-compatible). Alternatively,
  `rustls` avoids the system OpenSSL dependency entirely.
- **Static binary**: For maximum portability, build fully static binaries
  with `RUSTFLAGS='-C target-feature=+crt-static'`. This produces binaries
  that run on any Linux kernel >= 3.17 (for `mlock2` and Landlock).
- **No systemd**: Alpine uses OpenRC by default. Provide OpenRC init scripts
  as an alternative to systemd user services. The init scripts must set
  the `MEMLOCK` ulimit and run daemons as the logged-in user, not root.

### APKBUILD

The APKBUILD follows the same two-package split. Use `subpackages` for
the desktop variant. Alpine's Rust packaging infrastructure supports
`cargo auditable build` for SBOM embedding.

## Flatpak

### Sandbox Implications

Flatpak introduces a second layer of sandboxing on top of Open Sesame's own
Noise IK IPC isolation and Landlock filesystem restrictions.

Key issues:

- **Nested sandboxing**: daemon-secrets uses `mlock`, `seccomp`, and Landlock.
  Inside a Flatpak sandbox, `seccomp` filters compose (the stricter filter
  wins), but Landlock may conflict with Flatpak's own filesystem portals.
- **Unix socket access**: The IPC bus uses a Unix domain socket under
  `$XDG_RUNTIME_DIR`. Flatpak must be configured to expose this path, or the
  socket must use a portal.
- **SSH agent**: Flatpak does not expose `SSH_AUTH_SOCK` by default. The
  `--socket=ssh-auth` permission is required for SSH agent unlock.
- **Wayland**: The desktop package requires `--socket=wayland` and access to
  the COSMIC compositor protocols, which may not be available through the
  standard Wayland portal.

For these reasons, Flatpak packaging is considered lower priority. The
recommended approach is native packaging for distributions that target
the COSMIC desktop.

## Homebrew (macOS)

### When platform-macos Is Implemented

Open Sesame currently targets Linux with COSMIC/Wayland. A `platform-macos`
crate is planned but not yet implemented. When it becomes available:

- **Formula structure**: A single formula covering the headless components
  (there is no separate desktop package on macOS; window management uses
  native Accessibility APIs).
- **launchd**: Replace systemd user services with `launchd` plist files
  installed to `~/Library/LaunchAgents/`.
- **Keychain integration**: The macOS keychain can serve as an auth backend
  (similar to SSH agent), replacing `mlock`-based secret memory with Secure
  Enclave operations where available.
- **Dependencies**: `sqlcipher` is available via Homebrew. No Wayland
  dependencies are needed.

This section will be expanded when `platform-macos` reaches a functional
state.
