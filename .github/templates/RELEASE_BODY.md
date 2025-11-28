
---

## Download Checksums

| File | SHA256 |
|------|--------|
| `open-sesame_${VERSION}_amd64.deb` | `${SHA256_AMD64}` |
| `open-sesame_${VERSION}_arm64.deb` | `${SHA256_ARM64}` |

### Direct Download Commands

**amd64 (Intel/AMD):**
```bash
curl -fsSL https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame_${VERSION}_amd64.deb \
  -o /tmp/open-sesame.deb
echo "${SHA256_AMD64}  /tmp/open-sesame.deb" | sha256sum -c -
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame --setup-keybinding
```

**arm64 (Raspberry Pi, ARM servers):**
```bash
curl -fsSL https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame_${VERSION}_arm64.deb \
  -o /tmp/open-sesame.deb
echo "${SHA256_ARM64}  /tmp/open-sesame.deb" | sha256sum -c -
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame --setup-keybinding
```
