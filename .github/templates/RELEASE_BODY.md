
---

## Download Checksums

| File | SHA256 |
|------|--------|
| `open-sesame-linux-x86_64.deb` | `${SHA256_X86_64}` |
| `open-sesame-linux-aarch64.deb` | `${SHA256_AARCH64}` |

### Direct Download Commands

**Automatic architecture detection:**
```bash
ARCH=$(uname -m)
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-${ARCH}.deb" \
  -o /tmp/open-sesame.deb
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame --setup-keybinding
```

**x86_64 (Intel/AMD):**
```bash
curl -fsSL https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-x86_64.deb \
  -o /tmp/open-sesame.deb
echo "${SHA256_X86_64}  /tmp/open-sesame.deb" | sha256sum -c -
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame --setup-keybinding
```

**aarch64 (Raspberry Pi, ARM servers):**
```bash
curl -fsSL https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-aarch64.deb \
  -o /tmp/open-sesame.deb
echo "${SHA256_AARCH64}  /tmp/open-sesame.deb" | sha256sum -c -
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame --setup-keybinding
```
