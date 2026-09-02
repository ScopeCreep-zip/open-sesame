
---

## Download Checksums

### open-sesame DEB (headless)

| File | SHA256 |
|------|--------|
| `open-sesame-linux-x86_64.deb` | `${SHA256_HEADLESS_X86_64}` |
| `open-sesame-linux-aarch64.deb` | `${SHA256_HEADLESS_AARCH64}` |

### open-sesame-desktop DEB

| File | SHA256 |
|------|--------|
| `open-sesame-desktop-linux-x86_64.deb` | `${SHA256_DESKTOP_X86_64}` |
| `open-sesame-desktop-linux-aarch64.deb` | `${SHA256_DESKTOP_AARCH64}` |

### open-sesame RPM (headless)

| File | SHA256 |
|------|--------|
| `open-sesame-linux-x86_64.rpm` | `${SHA256_RPM_HEADLESS_X86_64}` |
| `open-sesame-linux-aarch64.rpm` | `${SHA256_RPM_HEADLESS_AARCH64}` |

### open-sesame-desktop RPM

| File | SHA256 |
|------|--------|
| `open-sesame-desktop-linux-x86_64.rpm` | `${SHA256_RPM_DESKTOP_X86_64}` |
| `open-sesame-desktop-linux-aarch64.rpm` | `${SHA256_RPM_DESKTOP_AARCH64}` |

### Quick Install DEB (auto-detects architecture)

**Desktop (full suite):**
```bash
ARCH=$(uname -m)
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-${ARCH}.deb" -o /tmp/open-sesame.deb
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-${ARCH}.deb" -o /tmp/open-sesame-desktop.deb
sudo dpkg -i /tmp/open-sesame.deb /tmp/open-sesame-desktop.deb
```

**Headless only:**
```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-$(uname -m).deb" -o /tmp/open-sesame.deb
sudo dpkg -i /tmp/open-sesame.deb
```

### Quick Install RPM (auto-detects architecture)

**Desktop (full suite):**
```bash
ARCH=$(uname -m)
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-${ARCH}.rpm" -o /tmp/open-sesame.rpm
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-${ARCH}.rpm" -o /tmp/open-sesame-desktop.rpm
sudo dnf install -y /tmp/open-sesame.rpm /tmp/open-sesame-desktop.rpm
```

**Headless only:**
```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-$(uname -m).rpm" -o /tmp/open-sesame.rpm
sudo dnf install -y /tmp/open-sesame.rpm
```

### x86_64 DEB (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-x86_64.deb" -o /tmp/open-sesame.deb
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-x86_64.deb" -o /tmp/open-sesame-desktop.deb
echo "${SHA256_HEADLESS_X86_64}  /tmp/open-sesame.deb" | sha256sum -c -
echo "${SHA256_DESKTOP_X86_64}  /tmp/open-sesame-desktop.deb" | sha256sum -c -
sudo dpkg -i /tmp/open-sesame.deb /tmp/open-sesame-desktop.deb
```

### aarch64 DEB (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-aarch64.deb" -o /tmp/open-sesame.deb
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-aarch64.deb" -o /tmp/open-sesame-desktop.deb
echo "${SHA256_HEADLESS_AARCH64}  /tmp/open-sesame.deb" | sha256sum -c -
echo "${SHA256_DESKTOP_AARCH64}  /tmp/open-sesame-desktop.deb" | sha256sum -c -
sudo dpkg -i /tmp/open-sesame.deb /tmp/open-sesame-desktop.deb
```

### x86_64 RPM (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-x86_64.rpm" -o /tmp/open-sesame.rpm
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-x86_64.rpm" -o /tmp/open-sesame-desktop.rpm
echo "${SHA256_RPM_HEADLESS_X86_64}  /tmp/open-sesame.rpm" | sha256sum -c -
echo "${SHA256_RPM_DESKTOP_X86_64}  /tmp/open-sesame-desktop.rpm" | sha256sum -c -
sudo dnf install -y /tmp/open-sesame.rpm /tmp/open-sesame-desktop.rpm
```

### aarch64 RPM (with checksum verification)

```bash
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-linux-aarch64.rpm" -o /tmp/open-sesame.rpm
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/${TAG}/open-sesame-desktop-linux-aarch64.rpm" -o /tmp/open-sesame-desktop.rpm
echo "${SHA256_RPM_HEADLESS_AARCH64}  /tmp/open-sesame.rpm" | sha256sum -c -
echo "${SHA256_RPM_DESKTOP_AARCH64}  /tmp/open-sesame-desktop.rpm" | sha256sum -c -
sudo dnf install -y /tmp/open-sesame.rpm /tmp/open-sesame-desktop.rpm
```
