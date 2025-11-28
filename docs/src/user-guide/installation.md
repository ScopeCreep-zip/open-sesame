# Installation

Open Sesame can be installed via APT repository, from GitHub releases, or built from source.

## From APT Repository (Recommended)

**For Pop!_OS 24.04+ with COSMIC Desktop:**

```bash
# Add GPG key and repository
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg
echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
  | sudo tee /etc/apt/sources.list.d/open-sesame.list

# Install and configure
sudo apt update && sudo apt install -y open-sesame
sesame --setup-keybinding
```

This method provides automatic updates through the standard APT package manager.

## From GitHub Releases

Download the `.deb` package for your architecture from the [Releases page](https://github.com/ScopeCreep-zip/open-sesame/releases):

**amd64 (Intel/AMD):**
```bash
# Get latest version
VERSION=$(curl -s https://api.github.com/repos/ScopeCreep-zip/open-sesame/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d 'v')

# Download, verify, and install
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/v${VERSION}/open-sesame_${VERSION}_amd64.deb" \
  -o /tmp/open-sesame.deb
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame --setup-keybinding
```

**arm64 (Raspberry Pi, ARM servers):**
```bash
# Get latest version
VERSION=$(curl -s https://api.github.com/repos/ScopeCreep-zip/open-sesame/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d 'v')

# Download, verify, and install
curl -fsSL "https://github.com/ScopeCreep-zip/open-sesame/releases/download/v${VERSION}/open-sesame_${VERSION}_arm64.deb" \
  -o /tmp/open-sesame.deb
gh attestation verify /tmp/open-sesame.deb --owner ScopeCreep-zip
sudo dpkg -i /tmp/open-sesame.deb
sesame --setup-keybinding
```

**Available architectures:**

- `amd64` - x86_64 / Intel/AMD 64-bit
- `arm64` - ARM 64-bit (Raspberry Pi 4+, ARM servers)

## Verify Package Authenticity

All packages include [SLSA Build Provenance](https://slsa.dev/) attestations for supply chain security.

**Verify with GitHub CLI:**
```bash
gh attestation verify open-sesame_*.deb --owner ScopeCreep-zip
```

**Verify SHA256 checksums:**

Each release includes a `SHA256SUMS.txt` file. Download it from the release page and verify:
```bash
sha256sum -c SHA256SUMS.txt
```

## Building from Source

Requires COSMIC desktop environment and development tools.

### Prerequisites

```bash
# Install mise (task runner and toolchain manager)
curl https://mise.run | sh

# Clone repository
git clone https://github.com/ScopeCreep-zip/open-sesame.git
cd open-sesame

# Install dependencies (Rust toolchain, cargo-deb, etc.)
mise run setup
```

### Build and Install

```bash
# Build .deb package
mise run build:deb

# Install the package
mise run install
```

The `.deb` package will be created in `target/debian/`.

### Development Workflow

If you want to contribute or modify Open Sesame:

```bash
# Format code
mise run fmt

# Run tests and linters
mise run test

# Build debug binary and run
mise run dev

# Clean everything
mise run clean:all
```

See `mise tasks` for all available commands.

## System Requirements

### Required

- **COSMIC Desktop Environment** (Pop!_OS 24.04+ or other COSMIC-based distributions)
- **Wayland** compositor (X11 is NOT supported)
- **fontconfig** with at least one font installed

### Optional (for building from source)

- **Rust 1.91+** (installed automatically via mise)
- **cargo-deb** (for building .deb packages)
- **cross** (for cross-compilation to arm64)

## Post-Installation

After installation, you need to set up a keybinding:

```bash
# Setup default keybinding (Alt+Space)
sesame --setup-keybinding

# Or specify a custom key combo
sesame --setup-keybinding alt+tab
```

This configures COSMIC desktop to launch Open Sesame when you press the key combination.

## Uninstallation

To remove Open Sesame:

```bash
# Remove keybinding first (optional but recommended)
sesame --remove-keybinding

# Uninstall package
sudo apt remove open-sesame

# Optional: Remove configuration files
rm -rf ~/.config/open-sesame
```

## Troubleshooting Installation

### Package Not Found

If `apt install open-sesame` fails with "package not found":

1. Verify the repository was added correctly:

   ```bash
   cat /etc/apt/sources.list.d/open-sesame.list
   ```

2. Check that the GPG key exists:

   ```bash
   ls -la /usr/share/keyrings/open-sesame.gpg
   ```

3. Update package lists:

   ```bash
   sudo apt update
   ```

### Dependency Errors

If installation fails due to missing dependencies:

```bash
# Install dependencies manually
sudo apt install --fix-broken
```

### Build Failures

If building from source fails:

1. Ensure all system dependencies are installed:

   ```bash
   sudo apt install build-essential pkg-config libfontconfig1-dev libxkbcommon-dev
   ```

2. Check Rust toolchain version:

   ```bash
   rustc --version  # Should be 1.91 or newer
   ```

3. Clean and retry:

   ```bash
   mise run clean:all
   mise run build:deb
   ```

## Next Steps

- [Basic Usage](./basic-usage.md) - Learn how to use Open Sesame
- [Configuration](./configuration.md) - Customize key bindings and settings
- [CLI Reference](./cli-reference.md) - Explore all command-line options
