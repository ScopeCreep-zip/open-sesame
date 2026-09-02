# RPM Packaging

Open Sesame ships as two `.rpm` packages built with `cargo-generate-rpm`. The two-package model
mirrors the Nix and Debian splits: a headless package for servers and containers, and a desktop
package that adds GUI daemons for COSMIC/Wayland.

## Package Overview

### open-sesame (headless)

Defined in `open-sesame/Cargo.toml` under `[package.metadata.generate-rpm]`.

| Field | Value |
|-------|-------|
| Package name | `open-sesame` |
| Vendor | `scopecreep.zip` |
| Requires | `glibc`, `libgcc`, `libseccomp` |
| Recommends | `openssh-clients` |
| Suggests | `open-sesame-desktop` |

**Installed binaries** (to `/usr/bin/`):

- `sesame` (CLI)
- `daemon-profile`
- `daemon-secrets`
- `daemon-launcher`
- `daemon-snippets`

**Installed systemd units** (to `/usr/lib/systemd/user/`):

- `open-sesame-headless.target`
- `open-sesame-profile.service`
- `open-sesame-secrets.service`
- `open-sesame-launcher.service`
- `open-sesame-snippets.service`

**Installed preset** (to `/usr/lib/systemd/user-preset/`):

- `90-open-sesame.preset`

**Additional assets**:

- Man page: `/usr/share/man/man1/sesame.1.gz`
- Shell completions: bash, zsh (`site-functions`), fish
- Example config: `/usr/share/doc/open-sesame/config.example.toml`

### open-sesame-desktop

Defined in `daemon-wm/Cargo.toml` under `[package.metadata.generate-rpm]`.

| Field | Value |
|-------|-------|
| Package name | `open-sesame-desktop` |
| Vendor | `scopecreep.zip` |
| Requires | `glibc`, `libgcc`, `libseccomp`, `libxkbcommon`, `libwayland-client`, `fontconfig`, `freetype` |
| Recommends | `xdg-utils`, `dejavu-sans-fonts` |

**Installed binaries** (to `/usr/bin/`):

- `daemon-wm`
- `daemon-clipboard`
- `daemon-input`

**Installed systemd units** (to `/usr/lib/systemd/user/`):

- `open-sesame-desktop.target`
- `open-sesame-wm.service`
- `open-sesame-clipboard.service`
- `open-sesame-input.service`

## cargo-generate-rpm

Open Sesame uses `cargo-generate-rpm` instead of `rpmbuild` with spec files. This tool reads
package metadata from `[package.metadata.generate-rpm]` in `Cargo.toml` and produces `.rpm` files
directly using the `rpm` crate. No spec file, no rpmbuild dependency.

Key configuration:

- `auto-req = "no"` disables automatic shared library dependency detection. CI builds run on
  Ubuntu runners where `ldd` produces Debian-style soname dependencies rather than Fedora package
  names. Dependencies are declared explicitly in `[package.metadata.generate-rpm.requires]`.
- Payload compression defaults to zstd (compatible with Fedora 30+ / rpm 4.14+).
- Scriptlet fields accept file paths to external scripts under `scripts/rpm/`.

Build workflow:

```bash
cargo build --release
cargo generate-rpm -p open-sesame
cargo generate-rpm -p daemon-wm
```

Output location: `target/generate-rpm/*.rpm`. With `--target x86_64-unknown-linux-gnu`:
`target/x86_64-unknown-linux-gnu/generate-rpm/*.rpm`.

## RPM Scriptlet Semantics

RPM scriptlets receive a numeric `$1` argument indicating the package count after the operation
completes. This differs from Debian maintainer scripts which receive string arguments like
`configure` or `remove`.

### $1 Values

| Scriptlet | Install | Upgrade | Remove |
|-----------|---------|---------|--------|
| `%pre` | 1 | 2 | (N/A) |
| `%post` | 1 | 2 | (N/A) |
| `%preun` | (N/A) | 1 | 0 |
| `%postun` | (N/A) | 1 | 0 |
| `%posttrans` | 0 | 0 | (N/A) |

### Upgrade Transaction Ordering

During a single-package upgrade, scriptlets execute in this order:

1. `%pretrans` of new package
2. `%pre` of new package
3. (install new files)
4. `%post` of new package
5. `%preun` of old package
6. (remove old files)
7. `%postun` of old package
8. `%posttrans` of new package

New `%post` runs BEFORE old `%preun`. This means during upgrade, new services are enabled before
old services are stopped. The `%posttrans` slot runs after all packages in the transaction
complete, making it the correct place for service restarts.

### systemd-update-helper

Open Sesame RPM scriptlets call `/usr/lib/systemd/systemd-update-helper` directly. This is the
same helper that Fedora's `%systemd_user_post` / `%systemd_user_preun` macros expand to.
cargo-generate-rpm embeds scriptlets verbatim without rpmbuild's macro parser, so RPM macros
like `%systemd_user_post` would be inserted as literal non-functional text.

The helper manages preset-based enablement via `install-user-units`, removal via
`remove-user-units`, and restart marking via `mark-restart-user-units`. The `[ -x ... ]` guard
ensures graceful no-op on non-Fedora systems where the helper does not exist.

### Scriptlet Design

- `%post`: calls `install-user-units` on first install (`$1 -eq 1`), reloads user managers,
  restarts services for all active users via per-uid `systemctl --user -M "$uid@"` loop
- `%preun`: stops services for all active users in reverse dependency order, then calls
  `remove-user-units` on final removal (`$1 -eq 0`)
- `%postun`: reloads user managers on final removal
- `%posttrans`: calls `mark-restart-user-units` to restart services after transaction completes

All scriptlets exit zero unconditionally (trailing `:`). Non-zero exits from RPM scriptlets
stop processing of that package in the transaction with no rollback capability.

## Preset File

Each package ships its own preset file to avoid RPM file conflicts:

| Preset | Package | Units |
|--------|---------|-------|
| `90-open-sesame.preset` | `open-sesame` | profile, secrets, launcher, snippets, headless target |
| `90-open-sesame-desktop.preset` | `open-sesame-desktop` | wm, clipboard, input, desktop target |

Both install to `/usr/lib/systemd/user-preset/`. `systemd-update-helper install-user-units`
reads these files to determine default enablement state. Administrators override via
higher-priority presets in `/etc/systemd/user-preset/`.

## DNF Repository

The DNF repository is hosted on GitHub Pages alongside the APT repository and documentation.
Generated by the `ci:release:rpm-repo` mise task during the publish job.

### Repository Structure

```text
gh-pages/
  repo/
    *.rpm
    repodata/
      repomd.xml
      primary.xml.gz
      filelists.xml.gz
      other.xml.gz
    manifest.txt
    RPM-GPG-KEY
    index.html
  RPM-GPG-KEY
```

### Client Configuration

Create `/etc/yum.repos.d/open-sesame.repo`:

```ini
[open-sesame]
name=Open Sesame RPMs (GitHub Pages)
baseurl=https://scopecreep-zip.github.io/open-sesame/repo/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-open-sesame
```

Import the GPG key:

```bash
sudo curl -fsSL https://scopecreep-zip.github.io/open-sesame/RPM-GPG-KEY \
  -o /etc/pki/rpm-gpg/RPM-GPG-KEY-open-sesame
```

Install:

```bash
sudo dnf install -y open-sesame open-sesame-desktop
```

### Signing

RPM packages are signed at build time using `cargo-generate-rpm --signing-key`, which produces
V4 RSA/SHA256 header+payload signatures via the `rpm` crate's `signature-pgp` feature. The same
GPG key used for APT Release signing is exported to a temporary file and passed to
`cargo generate-rpm` in the CI build job. The `scripts/rpm/sign-rpms.sh` script provides an
alternative `rpmsign`-based signing path for environments where native cargo-generate-rpm signing
is unavailable (e.g., re-signing after the fact).

### Metadata Generation

Repository metadata is generated by `createrepo_c` (installed from Ubuntu's `universe`
repository). Version 0.17.3 defaults to gzip compression for metadata. All RPMs regardless of
architecture are indexed into a single `repodata/` set — DNF filters by `$basearch` at install
time from each package's arch tag.

## Verification

### Package Signature

```bash
rpm --checksig -v open-sesame-linux-x86_64.rpm
```

### SLSA Build Provenance

```bash
gh attestation verify open-sesame-linux-x86_64.rpm --owner ScopeCreep-zip
```

### Checksum

```bash
sha256sum -c SHA256SUMS.txt
```

## Comparison with Debian Scriptlets

| Concern | Debian (dpkg) | RPM |
|---------|---------------|-----|
| Argument type | String (`configure`, `remove`, `upgrade`) | Numeric (`$1`: package count) |
| Install detection | `case "$1" in configure)` | `if [ "$1" -eq 1 ]` |
| Remove detection | `case "$1" in remove)` | `if [ "$1" -eq 0 ]` |
| Upgrade ordering | old prerm → new postinst | new %post → old %preun |
| End-of-transaction | (none) | `%posttrans` |
| Failure behavior | Configurable via `set -e` | Non-zero stops package processing, no rollback |
| Macro expansion | Debhelper `#DEBHELPER#` | rpmbuild `%macros` (not available in cargo-generate-rpm) |
