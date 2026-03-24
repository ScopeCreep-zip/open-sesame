# Packaging for New Distributions

This guide covers the requirements and considerations for packaging Open
Sesame on Linux distributions beyond the officially supported Debian/Ubuntu
`.deb` packages and Nix flake.

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

Arch packaging uses `PKGBUILD` files. Two packages are needed.

### open-sesame

```bash
pkgname=open-sesame
pkgver=1.6.3
pkgrel=1
pkgdesc='Programmable desktop suite - headless daemons and CLI'
arch=('x86_64' 'aarch64')
url='https://github.com/ScopeCreep-zip/open-sesame'
license=('GPL-3.0-only')
depends=('gcc-libs' 'sqlcipher' 'openssl')
makedepends=('cargo' 'pkg-config')

build() {
    cd "$srcdir/$pkgname-$pkgver"
    cargo build --release \
        --bin sesame \
        --bin daemon-profile \
        --bin daemon-secrets \
        --bin daemon-launcher \
        --bin daemon-snippets
}

package() {
    cd "$srcdir/$pkgname-$pkgver"
    for bin in sesame daemon-profile daemon-secrets daemon-launcher daemon-snippets; do
        install -Dm755 "target/release/$bin" "$pkgdir/usr/bin/$bin"
    done
    install -Dm644 dist/systemd/*.service -t "$pkgdir/usr/lib/systemd/user/"
    install -Dm644 dist/limits.conf "$pkgdir/etc/security/limits.d/open-sesame.conf"
}
```

### open-sesame-desktop

```bash
pkgname=open-sesame-desktop
pkgver=1.6.3
pkgrel=1
pkgdesc='Programmable desktop suite - COSMIC/Wayland compositor integration'
arch=('x86_64' 'aarch64')
depends=('open-sesame' 'wayland' 'libxkbcommon' 'cosmic-protocols')
makedepends=('cargo' 'pkg-config')

build() {
    cd "$srcdir/open-sesame-$pkgver"
    cargo build --release \
        --bin daemon-wm \
        --bin daemon-clipboard \
        --bin daemon-input
}

package() {
    cd "$srcdir/open-sesame-$pkgver"
    for bin in daemon-wm daemon-clipboard daemon-input; do
        install -Dm755 "target/release/$bin" "$pkgdir/usr/bin/$bin"
    done
    install -Dm644 dist/systemd/daemon-wm.service -t "$pkgdir/usr/lib/systemd/user/"
    install -Dm644 dist/systemd/daemon-clipboard.service -t "$pkgdir/usr/lib/systemd/user/"
    install -Dm644 dist/systemd/daemon-input.service -t "$pkgdir/usr/lib/systemd/user/"
}
```

## RPM (Fedora / RHEL)

### Spec File Considerations

- **BuildRequires**: `cargo`, `rust-packaging`, `pkg-config`, `sqlcipher-devel`,
  `openssl-devel`, `wayland-devel`, `libxkbcommon-devel`.
- **License tag**: `GPL-3.0-only`.
- **Subpackages**: Use `%package desktop` for the GUI subpackage with
  `Requires: %{name} = %{version}-%{release}`.
- **systemd macros**: Use `%systemd_user_post`, `%systemd_user_preun`, and
  `%systemd_user_postun` for service lifecycle.
- **Vendor dependencies**: Fedora policy requires vendored dependencies to be
  audited. Run `cargo vendor` and include the vendor tarball as a secondary
  source.
- **SELinux**: daemon-secrets performs `mlock` and reads `SSH_AUTH_SOCK`. A
  custom SELinux policy module may be required for confined users. The base
  package should include a `.te` policy file or document the required booleans.

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
