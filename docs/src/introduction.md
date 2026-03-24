# Introduction

Open Sesame is a trust-scoped secret and identity fabric for the desktop. It manages encrypted secret
vaults with per-profile trust boundaries, provides window switching with letter-hint overlays, clipboard
history with sensitivity detection, keyboard input capture, and text snippet expansion. Everything is
scoped to trust profiles that activate based on context or manual selection.

## Packages

Open Sesame ships as two packages:

**`open-sesame`** (headless core) contains the `sesame` CLI, daemon-profile, daemon-secrets,
daemon-launcher, and daemon-snippets. It runs anywhere with systemd: desktops, servers, containers,
and VMs. This package provides encrypted vaults, secret management, environment variable injection,
application launching, and profile management without any GUI dependencies.

**`open-sesame-desktop`** (GUI layer) depends on `open-sesame` and adds daemon-wm, daemon-clipboard,
and daemon-input. It requires a COSMIC or Wayland desktop. This package provides the window switcher
overlay, clipboard history, and keyboard input capture.

Installing `open-sesame-desktop` pulls in `open-sesame` automatically. On a server or in a container,
install just `open-sesame` for encrypted secrets and application launching.

## Audience

This documentation is written for:

- **Contributors** working on the Open Sesame codebase. The architecture and platform sections describe
  internal design, crate structure, IPC protocols, and implementation patterns.
- **Extension authors** building WASM component model extensions. The extending section covers the
  extension host runtime, SDK, WIT interfaces, and OCI distribution.
- **Platform implementors** adding support for new operating systems or compositor backends. The platform
  section documents the trait abstractions, factory patterns, and feature gating used across platform
  crates.
- **Security auditors** reviewing the trust model, cryptographic primitives, sandbox enforcement, and key
  hierarchy. The secrets, authentication, and compliance sections provide the relevant detail.
- **Deployment engineers** operating Open Sesame in production. The deployment and packaging sections
  cover systemd integration, service topology, and package structure.

## Navigating the Documentation

- **[Architecture](./architecture/overview.md)** -- internal design: crate map, daemon topology, IPC
  bus, data flows. Start here for a structural understanding of the system.
- **[Secrets](./secrets/overview.md)** -- vault system: SQLCipher storage, key hierarchy, Argon2id KDF,
  key-encryption keys, per-profile isolation.
- **[Authentication](./authentication/overview.md)** -- unlock mechanisms: password, SSH agent,
  multi-factor auth policy engine.
- **[Platform](./platform/linux.md)** -- OS abstraction layer: Linux (Wayland, D-Bus, evdev, systemd),
  macOS (Accessibility, Keychain, launchd), Windows (UI Automation, Credential Manager, Task Scheduler).
- **[Extending](./extending/getting-started.md)** -- extension system: Wasmtime host, WASI component
  model, WIT bindings, OCI packaging.
- **[Desktop](./desktop/overview.md)** -- window management: compositor integration, overlay rendering,
  focus tracking.
- **[Deployment](./deployment/overview.md)** -- operations: systemd units, service readiness, watchdog,
  packaging.
- **[Compliance](./compliance/overview.md)** -- security posture: Landlock, seccomp, mlock, guard pages,
  audit logging.

For user-facing quick start instructions, CLI reference, and configuration guide, see the
[README](https://github.com/ScopeCreep-zip/open-sesame#readme).
