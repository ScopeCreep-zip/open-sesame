## Quick Install

### APT Repository (Pop!_OS / Ubuntu / Debian)

```bash
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list
sudo apt update
```

**Desktop** (window switcher + clipboard + input + headless):
```bash
sudo apt install -y open-sesame open-sesame-desktop
```

**Headless** (secrets, profiles, launcher, snippets — no GUI):
```bash
sudo apt install -y open-sesame
```

### DNF Repository (Fedora / RHEL)

```bash
sudo curl -fsSL https://scopecreep-zip.github.io/open-sesame/RPM-GPG-KEY \
  -o /etc/pki/rpm-gpg/RPM-GPG-KEY-open-sesame
sudo tee /etc/yum.repos.d/open-sesame.repo << 'EOF'
[open-sesame]
name=Open Sesame RPMs (GitHub Pages)
baseurl=https://scopecreep-zip.github.io/open-sesame/repo/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-open-sesame
EOF
```

**Desktop** (window switcher + clipboard + input + headless):
```bash
sudo dnf install -y open-sesame open-sesame-desktop
```

**Headless** (secrets, profiles, launcher, snippets — no GUI):
```bash
sudo dnf install -y open-sesame
```

### AUR (Arch Linux)

```bash
yay -S open-sesame-bin open-sesame-desktop-bin
```

Or from the self-hosted pacman repo:
```bash
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key | sudo pacman-key --add -
sudo pacman-key --lsign-key 2B8C6081C58479B3FB7DA66F8581D8C7DCEF93E3
# Add to /etc/pacman.conf:
# [open-sesame]
# SigLevel = Required DatabaseRequired
# Server = https://scopecreep-zip.github.io/open-sesame/arch/$arch
sudo pacman -Syu open-sesame-bin open-sesame-desktop-bin
```

### Direct Download

See release assets below for `.deb` and `.rpm` packages (amd64/arm64) with SHA256 checksums.

## What You Get

### open-sesame (headless)
- **Encrypted secret vaults** with multi-factor auth (password + SSH agent)
- **Trust profiles** with context-driven activation
- **Application launcher** with fuzzy search and secret injection
- **Snippet expansion** with variable substitution

### open-sesame-desktop (requires open-sesame)
- **Alt+Space** — Window switcher overlay with Vimium-style letter hints
- **Alt+Tab** — Quick-switch to previous window
- **Clipboard manager** with security classification
- **Keyboard input capture** for compositor-independent shortcuts

## Documentation

- **[User Guide](https://scopecreep-zip.github.io/open-sesame/book/)** — Configuration, keybindings, theming
- **[API Docs](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/)** — Library reference

## Supply Chain Security

All release artifacts include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-linux-$(uname -m).rpm" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).rpm" --owner ScopeCreep-zip
gh attestation verify "open-sesame-v${TAG#v}-$(uname -m).tar.gz" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-v${TAG#v}-$(uname -m).tar.gz" --owner ScopeCreep-zip
```

---

