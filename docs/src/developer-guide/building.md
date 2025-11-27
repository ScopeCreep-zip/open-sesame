# Building

Complete guide to building Open Sesame from source.

## Quick Start

```bash
# Install mise (task runner)
curl https://mise.run | sh

# Clone repository
git clone https://github.com/scopecreep-zip/opensesame.git
cd opensesame

# Install dependencies
mise run setup

# Build and run
mise run dev
```

## Prerequisites

### Required

- **Git** - Version control
- **mise** - Task runner and toolchain manager (replaces rustup, cargo, etc.)
- **Build essentials** - C compiler, make, etc.

### System Dependencies

Open Sesame requires several system libraries for building:

```bash
# Ubuntu/Debian (Pop!_OS)
sudo apt install \
    build-essential \
    pkg-config \
    libfontconfig1-dev \
    libxkbcommon-dev \
    liblzma-dev
```

**Library purposes:**

- `libfontconfig1-dev` - Font discovery and loading
- `libxkbcommon-dev` - Keyboard layout handling
- `liblzma-dev` - Compression support

### Mise Installation

Mise is a unified toolchain manager that replaces rustup, nvm, rbenv, etc.

```bash
# Install mise
curl https://mise.run | sh

# Add to shell (bash)
echo 'eval "$(mise activate bash)"' >> ~/.bashrc

# Or zsh
echo 'eval "$(mise activate zsh)"' >> ~/.zshrc

# Reload shell
exec $SHELL
```

**What mise does:**

- Installs Rust toolchain automatically
- Manages project-specific tools
- Provides task runner (replaces Makefile)
- Ensures consistent build environment

## Repository Setup

### Clone Repository

```bash
git clone https://github.com/scopecreep-zip/opensesame.git
cd opensesame
```

### Install Dependencies

```bash
# mise automatically reads .mise.toml and installs required tools
mise run setup
```

This installs:

- Rust toolchain (version specified in `rust-toolchain.toml`)
- `cargo-deb` - Debian package builder
- `cross` - Cross-compilation tool

## Building

### Development Build

For development and testing:

```bash
# Build debug binary
mise run build

# Or use cargo directly
cargo build

# Binary location:
./target/debug/sesame
```

**Debug build characteristics:**

- Fast compilation
- Includes debug symbols
- No optimizations
- Larger binary size

### Release Build

For production use:

```bash
# Build optimized binary
mise run build:release

# Or use cargo directly
cargo build --release

# Binary location:
./target/release/sesame
```

**Release build characteristics:**

- Slower compilation
- Optimized code (smaller, faster)
- No debug symbols (unless explicitly enabled)
- Typical size: ~4 MB

### Debian Package

Build a `.deb` package for distribution:

```bash
# Build .deb package
mise run build:deb

# Package location:
./target/debian/open-sesame_*_amd64.deb
```

**What's included:**

- Optimized binary (`/usr/bin/sesame`)
- Example configuration (`/usr/share/doc/open-sesame/config.example.toml`)
- Man page (`/usr/share/man/man1/sesame.1.gz`) - future
- Shell completions (`/usr/share/bash-completion/completions/sesame`) - future

### Cross-Compilation

Build for ARM64 (e.g., Raspberry Pi):

```bash
# Build ARM64 .deb package
mise run build:cross-arm64

# Package location:
./target/aarch64-unknown-linux-gnu/debian/open-sesame_*_arm64.deb
```

**Requirements:**

- Docker (for cross-compilation environment)
- `cross` tool (installed by `mise run setup`)

## Running

### Development Mode

Run directly from source with debug logging:

```bash
# Run in development mode
mise run dev

# This is equivalent to:
RUST_LOG=debug cargo run --release
```

**Development mode features:**

- Debug logging enabled
- Uses release build (faster than debug)
- Logs to stderr and `~/.cache/open-sesame/debug.log`

### Installed Binary

After building:

```bash
# Run from target directory
./target/release/sesame --launcher

# Or install system-wide
mise run install
sesame --launcher
```

### With Custom Config

Test with a custom configuration:

```bash
cargo run -- -c /path/to/config.toml --list-windows
```

## Build Variants

### Debug with Logging

Debug build with logging always enabled:

```bash
# Build debug variant with logging
mise run build:debug

# Or manually:
cargo build --features debug-logging

# Install debug variant
mise run install:debug
```

**Use case:** Troubleshooting issues in production

### Minimal Build

Smallest possible binary:

```bash
# Build with minimal features
cargo build --release --no-default-features

# Binary size: ~2.5 MB (instead of ~4 MB)
```

**Trade-offs:**

- Smaller binary
- May lack some features
- Not recommended for general use

## Build Configuration

### Cargo.toml

Build configuration is in `Cargo.toml`:

```toml
[package]
name = "open-sesame"
version = "X.Y.Z"  # Managed by semantic-release
edition = "2024"

[profile.release]
opt-level = 3          # Maximum optimization
lto = true             # Link-time optimization
codegen-units = 1      # Single codegen unit (slower compile, faster runtime)
strip = true           # Strip symbols (smaller binary)
```

**Optimization levels:**

- `opt-level = 0` - No optimization (debug)
- `opt-level = 1` - Basic optimization
- `opt-level = 2` - Good optimization
- `opt-level = 3` - Maximum optimization (release)
- `opt-level = "s"` - Optimize for size
- `opt-level = "z"` - Aggressively optimize for size

### Build Features

Control build features via Cargo:

```bash
# Default features
cargo build

# All features
cargo build --all-features

# Specific features
cargo build --features "debug-logging"

# No default features
cargo build --no-default-features
```

**Available features:**

- `debug-logging` - Always enable debug logging (default: off)

## Mise Tasks Reference

All available build tasks:

```bash
# View all tasks
mise tasks
```

**Build tasks:**

- `build` - Build debug binary
- `build:release` - Build release binary
- `build:deb` - Build Debian package
- `build:cross-arm64` - Cross-compile for ARM64

**Development tasks:**

- `dev` - Run with debug logging
- `fmt` - Format code
- `lint` - Run clippy linter
- `test` - Run all tests

**Installation tasks:**

- `install` - Install release binary system-wide
- `install:debug` - Install debug binary system-wide
- `uninstall` - Remove installed binary

**Cleanup tasks:**

- `clean` - Remove target directory
- `clean:all` - Remove target and cache

## Build Troubleshooting

### Missing System Dependencies

**Error:**

```text
error: failed to run custom build command for `fontconfig-sys`
```

**Solution:**

```bash
sudo apt install libfontconfig1-dev pkg-config
```

### Rust Toolchain Issues

**Error:**

```text
error: toolchain '1.91-x86_64-unknown-linux-gnu' is not installed
```

**Solution:**

```bash
# mise automatically installs the correct toolchain
mise install

# Or manually with rustup
rustup install 1.91
```

### Build Fails with Optimization Errors

**Error:**

```text
error: could not compile `open-sesame` due to previous error
```

**Solution:**
Try debug build first to isolate the issue:

```bash
cargo build  # Debug build
cargo build --release  # Release build
```

### Cross-Compilation Fails

**Error:**

```text
error: failed to execute docker
```

**Solution:**
Ensure Docker is installed and running:

```bash
sudo apt install docker.io
sudo usermod -aG docker $USER
# Log out and log back in
```

### Out of Disk Space

**Error:**

```text
error: no space left on device
```

**Solution:**
Clean build artifacts:

```bash
mise run clean:all
cargo clean
```

**Check disk usage:**

```bash
du -sh target/
# Typical: 2-4 GB for full build
```

## Build Performance

### Compilation Times

Typical build times on modern hardware (AMD Ryzen 5):

| Build Type | Time | Binary Size |
|------------|------|-------------|
| Debug (clean) | 45s | 8 MB |
| Debug (incremental) | 3s | 8 MB |
| Release (clean) | 90s | 4 MB |
| Release (incremental) | 15s | 4 MB |

**Incremental builds:**
Rust caches previous compilations. Subsequent builds are much faster.

### Speeding Up Builds

**Use release build for development:**

```bash
mise run dev  # Uses --release (faster runtime)
```

**Parallel compilation:**

```bash
# Use all CPU cores (default)
cargo build -j $(nproc)
```

**Cache dependencies:**

```bash
# sccache caches compiled dependencies
cargo install sccache
export RUSTC_WRAPPER=sccache
```

**Disable LTO for faster iteration:**

```toml
# In Cargo.toml
[profile.release]
lto = false  # Faster compile, larger binary
```

## Build Environment

### Environment Variables

Useful environment variables:

```bash
# Rust log level
export RUST_LOG=debug

# Cargo build jobs
export CARGO_BUILD_JOBS=8

# Rust backtrace on panic
export RUST_BACKTRACE=1
```

### Rust Toolchain

Open Sesame specifies its Rust version in `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.91"
components = ["rustfmt", "clippy"]
```

**Why 1.91?**

- Stable release with all required features
- Edition 2024 support
- Performance improvements

## Continuous Integration

GitHub Actions builds Open Sesame automatically:

```yaml
# .github/workflows/ci.yml
- name: Build
  run: cargo build --release

- name: Run tests
  run: cargo test

- name: Build .deb package
  run: cargo deb
```

**CI checks:**

- Compiles on Ubuntu 24.04
- All tests pass
- Clippy lints pass
- Formatting check passes

## Next Steps

- [Testing Guide](./testing.md) - Run tests and benchmarks
- [Contributing Guide](./contributing.md) - Contribute to Open Sesame
- [Architecture](./architecture.md) - Understand the codebase structure
