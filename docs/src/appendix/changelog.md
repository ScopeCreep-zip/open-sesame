# Changelog

All notable changes to Open Sesame will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- mdBook user guide documentation
- API documentation via rustdoc

## [1.0.0] - 2025-11-27

### Added

- Initial public release
- Vimium-style window hints for COSMIC desktop
- Focus-or-launch functionality
- Configurable key bindings per application
- Quick switch behavior (tap vs hold)
- Two modes: Launcher (Alt+Space) and Switcher (Alt+Tab)
- Arrow key navigation as alternative to letter hints
- Multi-window support with repeated hints (g, gg, ggg)
- Software rendering with tiny-skia (no GPU required)
- XDG-compliant configuration with layered inheritance
- Advanced launch configuration with args and environment variables
- Environment file support (direnv .env style)
- Automatic keybinding setup via COSMIC integration
- MRU (Most Recently Used) window tracking
- Single-instance execution with IPC
- APT repository for easy installation
- Debian packages for amd64 and arm64
- SLSA provenance attestations for supply chain security
- Comprehensive CLI with validation and debugging tools

### Changed

- N/A (initial release)

### Deprecated

- N/A (initial release)

### Removed

- N/A (initial release)

### Fixed

- N/A (initial release)

### Security

- File-based instance locking
- Proper file permissions on config and cache
- No network access
- Input validation on all external data

## Release History

### Version 1.0.0 - "Open Sesame"

**Release Date:** November 27, 2025

**Highlights:**

- First stable release
- Full COSMIC desktop integration
- Production-ready window switching
- Comprehensive documentation
- APT repository for distribution

**Breaking Changes:**

- None (initial release)

**Migration Guide:**

- None (initial release)

**Known Issues:**

- Window focus may lag on slower systems
- Thumbnail previews not yet implemented
- X11 not supported (Wayland only)

**Contributors:**

- usrbinkat

**Statistics:**

- 42 commits
- 8,500+ lines of Rust code
- 92% test coverage (core modules)
- Sub-200ms switching latency

## Versioning Strategy

Open Sesame follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API/config changes
- **MINOR** version for new functionality (backward compatible)
- **PATCH** version for bug fixes (backward compatible)

**Pre-release versions:**

- `X.Y.Z-alpha.N` - Alpha releases (unstable)
- `X.Y.Z-beta.N` - Beta releases (feature complete, testing)
- `X.Y.Z-rc.N` - Release candidates (stable, final testing)

## Upgrade Guide

### From pre-release to 1.0

Version 1.0 is the initial public release. If you were using pre-release versions:

**Configuration changes:**

- Configuration format changed from JSON to TOML
- Key bindings moved from separate file to main config
- Color format changed to hex strings

**Migration:**

```bash
# Generate new config from defaults
sesame --print-config > ~/.config/open-sesame/config.toml

# Edit with your custom key bindings
$EDITOR ~/.config/open-sesame/config.toml
```

## Release Checklist

For maintainers preparing a release:

- [ ] Update version in `Cargo.toml`
- [ ] Update version in `README.md`
- [ ] Update `CHANGELOG.md` with release date
- [ ] Run full test suite: `mise run test`
- [ ] Build packages: `mise run build:deb`
- [ ] Test installation: `sudo dpkg -i target/debian/*.deb`
- [ ] Create git tag: `git tag -a v1.0.0 -m "Release 1.0.0"`
- [ ] Push tag: `git push origin v1.0.0`
- [ ] GitHub Actions builds and publishes release
- [ ] Verify GitHub release artifacts
- [ ] Verify APT repository updates
- [ ] Verify documentation deployment
- [ ] Announce release

## Contributing

See the [Contributing Guide](../developer-guide/contributing.md) for information on how to contribute to Open Sesame.

## See Also

- [GitHub Releases](https://github.com/ScopeCreep-zip/open-sesame/releases) - Download releases
- [GitHub Milestones](https://github.com/ScopeCreep-zip/open-sesame/milestones) - Upcoming releases
- [GitHub Issues](https://github.com/ScopeCreep-zip/open-sesame/issues) - Bug reports and features
