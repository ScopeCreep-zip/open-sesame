## Quick Install

### APT Repository (recommended)

```bash
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list
sudo apt update && sudo apt install -y open-sesame
sesame --setup-keybinding
```

### Direct Download

See release assets below for `.deb` packages (amd64/arm64) with SHA256 checksums.

## What You Get

- **Alt+Space** - Window switcher overlay with Vimium-style letter hints
- **Alt+Tab** - Quick-switch to previous window

## Documentation

- **[User Guide](https://scopecreep-zip.github.io/open-sesame/book/)** - Configuration, keybindings, theming
- **[API Docs](https://scopecreep-zip.github.io/open-sesame/doc/open_sesame/)** - Library reference

## Supply Chain Security

All `.deb` packages include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

---

