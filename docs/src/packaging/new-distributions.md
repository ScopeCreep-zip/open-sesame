# Packaging for New Distributions

This guide covers the requirements for packaging Open Sesame on distributions
not yet officially supported. For existing packages see:
[Debian](deb.md), [RPM](rpm.md), [Arch](arch.md), [Nix](nix.md).

## Common Requirements

Regardless of distribution, all packages must satisfy the following.

### Two-Package Split

Open Sesame ships as two logical packages:

- **open-sesame** (headless) -- Contains the `sesame` CLI, `daemon-profile`,
  `daemon-secrets`, `daemon-launcher`, `daemon-snippets`, and their systemd
  user service units. Has no GUI dependencies.
- **open-sesame-desktop** (requires open-sesame) -- Contains `daemon-wm`,
  `daemon-clipboard`, `daemon-input`, and the COSMIC/Wayland compositor
  integration. Depends on `libwayland-client`, `libxkbcommon`, `fontconfig`,
  `freetype`.

### systemd User Services

All daemons run as systemd user services (`systemctl --user`). Packages must
install unit files to `/usr/lib/systemd/user/`. The services use:

- `Type=notify` with `sd_notify` readiness.
- `Restart=on-failure` with `RestartSec=2`.
- Ordering via `After=` and `Requires=` (daemon-profile starts first as the
  IPC bus host; all others depend on it).
- `BindsTo=graphical-session.target` on the desktop target (not `Requires=`)
  to tear down desktop services when the compositor exits unexpectedly.

Preset files ship under `/usr/lib/systemd/user-preset/` -- one per package
to avoid file conflicts between headless and desktop.

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

### Scriptlet Helpers

Deb and RPM scriptlets share a common helper library at
`scripts/common/scriptlet-helpers.sh` containing `active_user_uids()` and
`reload_user_managers()`. New packaging formats that need systemd lifecycle
management during install/upgrade/removal should use the same functions.
The helpers are concatenated into scriptlets at build time by the
`cargo:assemble-scriptlets` mise task. `SESAME_BUS_TIMEOUT=15s` matches the
upstream systemd-update-helper default (`UPDATE_HELPER_USER_TIMEOUT_SEC`).

### Patchelf (nix devShell builds only)

Binaries built inside the nix devShell have nix store interpreters and RPATHs.
The `cargo:patchelf` mise task strips these before packaging. CI builds use
rustup and produce FHS-standard binaries. New packaging formats that build
from the nix devShell must run patchelf; formats that build from rustup or
system Rust do not.

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

## Flatpak: Not Applicable

Open Sesame is a host-level system integration tool. The Flatpak sandbox model
is architecturally incompatible with the project's design:

1. **Wayland privileged protocols.** `daemon-wm` requires toplevel-info/management,
   layer-shell, keyboard-shortcut-inhibit, and `ext_background_effect_v1` (blur).
   Flatpak 1.16+ routes sandboxed clients through a security-context-tagged
   Wayland socket so compositors can filter these privileged globals.
2. **No systemd user units.** Flatpak exports `.desktop` files and D-Bus services
   but never installs systemd unit files. Open Sesame's lifecycle model (targets,
   presets, `BindsTo=`, per-user restart on upgrade) has no Flatpak equivalent.
3. **`/dev/input` access.** `daemon-input` requires `/dev/input` for keyboard
   capture. Flatpak's `--device=input` permission exposes this but defeats the
   sandbox's purpose.
4. **IPC in `XDG_RUNTIME_DIR`.** The `sesame` CLI communicates with daemons via
   Unix sockets in `XDG_RUNTIME_DIR`. Flatpak remaps this path inside the sandbox.
   The CLI would require `flatpak run --command=sesame` invocations, which is
   unusable for a CLI-first tool without host-side wrappers that reintroduce
   host packaging.

The correct relationship between Open Sesame and Flatpak is provider, not tenant.
Future work: implement `org.freedesktop.impl.portal.Secret` backed by
`daemon-secrets` so sandboxed Flatpak apps get per-app secrets from the vault
through the XDG Secret portal. That is a host-installed D-Bus service shipped by
existing deb/rpm/pacman/nix packages.

Users on immutable desktops (Fedora Silverblue/Kinoite) can layer the RPM package
via `rpm-ostree install` from the DNF repository.

See [issue #34](https://github.com/ScopeCreep-zip/open-sesame/issues/34) for the
full evaluation.

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
