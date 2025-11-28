
---

## Download Checksums

| File | SHA256 |
|------|--------|
| `open-sesame-linux-x86_64.deb` | `${SHA256_X86_64}` |
| `open-sesame-linux-aarch64.deb` | `${SHA256_AARCH64}` |

### Quick Install (auto-detects architecture)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-$(uname -m).deb" -o /tmp/open-sesame.deb
```

```bash
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
```

```bash
sudo dpkg -i /tmp/open-sesame.deb && sesame --setup-keybinding
```

### x86_64 (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-x86_64.deb" -o /tmp/open-sesame.deb
```

```bash
echo "${SHA256_X86_64}  /tmp/open-sesame.deb" | sha256sum -c -
```

```bash
sudo dpkg -i /tmp/open-sesame.deb && sesame --setup-keybinding
```

### aarch64 (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-aarch64.deb" -o /tmp/open-sesame.deb
```

```bash
echo "${SHA256_AARCH64}  /tmp/open-sesame.deb" | sha256sum -c -
```

```bash
sudo dpkg -i /tmp/open-sesame.deb && sesame --setup-keybinding
```
