# Arch Linux Packaging

Open Sesame provides binary packages for Arch Linux via the AUR and a self-hosted
pacman repository on GitHub Pages. The two-package split mirrors the Debian, RPM,
and Nix distributions.

## Package Overview

### open-sesame-bin (AUR)

Split pkgbase producing two packages from release tarballs:

| Package | Description |
|---------|-------------|
| `open-sesame-bin` | Headless: sesame CLI, 4 daemon binaries, systemd units, preset, man page, completions |
| `open-sesame-desktop-bin` | Desktop: 3 GUI daemons, systemd units, preset. Depends on `open-sesame` (satisfied by either `-bin` or source) |

`provides=('open-sesame')` / `provides=('open-sesame-desktop')` and
`conflicts=('open-sesame' 'sesame')` / `conflicts=('open-sesame-desktop')`.

The `sesame` conflict is declared because AUR package `sesame` (an xdg-open replacement)
installs `/usr/bin/sesame` at the same path.

### Dependencies

| Dependency | Arch package |
|-----------|-------------|
| C library | `glibc` |
| GCC runtime | `gcc-libs` |
| seccomp | `libseccomp` |
| Wayland client | `wayland` |
| XKB | `libxkbcommon` |
| fontconfig | `fontconfig` |
| freetype | `freetype2` |
| SSH client | `openssh` (optional) |
| DejaVu font | `ttf-dejavu` (optional) |

## Installation

### AUR (recommended)

Using an AUR helper:

```bash
yay -S open-sesame-bin open-sesame-desktop-bin
```

Or manually:

```bash
git clone https://aur.archlinux.org/open-sesame-bin.git
cd open-sesame-bin
makepkg -si
```

### Self-hosted pacman repository

Import the GPG key:

```bash
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key | sudo pacman-key --add -
sudo pacman-key --lsign-key $(curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key | gpg --show-keys --with-colons 2>/dev/null | awk -F: '/^pub/{print $5; exit}')
```

Add to `/etc/pacman.conf`:

```ini
[open-sesame]
SigLevel = Required DatabaseRequired
Server = https://scopecreep-zip.github.io/open-sesame/arch/$arch
```

Install:

```bash
sudo pacman -Syu open-sesame-bin open-sesame-desktop-bin
```

### Direct download

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/ScopeCreep-zip/open-sesame/releases/latest | jq -r .tag_name | sed 's/^v//')
sudo pacman -U "https://github.com/ScopeCreep-zip/open-sesame/releases/download/v${VERSION}/open-sesame-bin-${VERSION}-1-x86_64.pkg.tar.zst"
```

## Systemd Integration

Arch's `systemd` package ships a pacman hook that runs `systemctl --user daemon-reload`
for installed user units. No `.install` scriptlet is needed for unit reload.

The `.install` file prints setup instructions:
- `post_install`: `sesame init`, `systemctl --user enable --now open-sesame-headless.target`
- `post_upgrade`: `systemctl --user restart open-sesame-headless.target`
- `post_remove`: config preservation note

Arch policy does not auto-enable services from `.install`. The preset file
(`90-open-sesame.preset`) declares default enablement for users who run
`systemctl --user preset-all`.

## Release Tarballs

Each release produces standalone tarballs with FHS-standard directory layout:

```
open-sesame-v<ver>-x86_64.tar.gz
  usr/bin/{sesame,daemon-profile,daemon-secrets,daemon-launcher,daemon-snippets}
  usr/lib/systemd/user/{*.service,*.target}
  usr/lib/systemd/user-preset/90-open-sesame.preset
  usr/share/man/man1/sesame.1.gz
  usr/share/bash-completion/completions/sesame
  usr/share/zsh/site-functions/_sesame
  usr/share/fish/vendor_completions.d/sesame.fish
  usr/share/doc/open-sesame/config.example.toml
  usr/share/licenses/open-sesame/LICENSE
```

These tarballs serve the AUR `-bin` PKGBUILD and are also usable for manual
installation on any Linux distribution.

## Self-hosted Repository Structure

```text
gh-pages/arch/
  x86_64/
    open-sesame-bin-<ver>-1-x86_64.pkg.tar.zst
    open-sesame-bin-<ver>-1-x86_64.pkg.tar.zst.sig
    open-sesame-desktop-bin-<ver>-1-x86_64.pkg.tar.zst
    open-sesame-desktop-bin-<ver>-1-x86_64.pkg.tar.zst.sig
    open-sesame.db
    open-sesame.db.tar.gz
    open-sesame.files
    open-sesame.files.tar.gz
  aarch64/
    (same structure)
```

`repo-add` generates `open-sesame.db` and `open-sesame.files`. Symlinks are
replaced with copies before GitHub Pages deployment (Pages serves via tar
artifact, symlinks do not resolve).

## Verification

### Package signature

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/ScopeCreep-zip/open-sesame/releases/latest | jq -r .tag_name | sed 's/^v//')
pacman-key --verify "open-sesame-bin-${VERSION}-1-x86_64.pkg.tar.zst.sig"
```

### SLSA build provenance

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/ScopeCreep-zip/open-sesame/releases/latest | jq -r .tag_name | sed 's/^v//')
gh attestation verify "open-sesame-v${VERSION}-x86_64.tar.gz" --owner ScopeCreep-zip
```

### Checksum

```bash
sha256sum -c SHA256SUMS.txt
```
