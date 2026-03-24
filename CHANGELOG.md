## Quick Install

### APT Repository (recommended)

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

### Direct Download

See release assets below for `.deb` packages (amd64/arm64) with SHA256 checksums.

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

All `.deb` packages include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

---

## [1.6.1](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.6.0...v1.6.1) (2026-03-24)

### 🐛 Bug Fixes

* **nix:** system openssl, ExecStart paths, Cachix binary cache ([bbab414](https://github.com/ScopeCreep-zip/open-sesame/commit/bbab4143605af4d3434b4b70aea5187471d0bb58))

## Quick Install

### APT Repository (recommended)

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

### Direct Download

See release assets below for `.deb` packages (amd64/arm64) with SHA256 checksums.

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

All `.deb` packages include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

---

## [1.6.0](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.5.2...v1.6.0) (2026-03-24)

### ✨ Features

* **core-memory:** page-aligned secure memory allocator with guard pages ([ffad7e0](https://github.com/ScopeCreep-zip/open-sesame/commit/ffad7e00252b7c391c4c92b98f7edd7894182a76))
* **security:** memfd_secret backend, zero-copy deserialization, structured audit logging ([901d236](https://github.com/ScopeCreep-zip/open-sesame/commit/901d236d348eafff2223c34a6358723330666dbe))

### 🐛 Bug Fixes

* **ci:** raise RLIMIT_MEMLOCK for ProtectedAlloc tests and builds ([1668a79](https://github.com/ScopeCreep-zip/open-sesame/commit/1668a7950b959133240b7854ae0a77bca0f9650d))
* **docs:** update GitHub Pages landing page for two-package model ([c43229c](https://github.com/ScopeCreep-zip/open-sesame/commit/c43229c9369b1c7c6e088b80a1f0a4687bc07278))
* remove unused zeroize import from daemon-secrets crud ([0a17f35](https://github.com/ScopeCreep-zip/open-sesame/commit/0a17f351de83668aca61835692ac869fa96ae71e))
* **security:** eliminate all heap exposure paths for secret-carrying types ([bb19ea6](https://github.com/ScopeCreep-zip/open-sesame/commit/bb19ea65fbbdafc7e8d5b74e2dc438eebcea0464))
* **security:** eliminate heap exposure in SecureBytes-to-SensitiveBytes transfer ([4786eb1](https://github.com/ScopeCreep-zip/open-sesame/commit/4786eb137d2a3a5557d5a722deb652e05e485974))
* **security:** eliminate remaining heap copies in daemon-secrets unlock and CRUD ([7d04627](https://github.com/ScopeCreep-zip/open-sesame/commit/7d0462725e91be2ea73668112cd569f9ac556a80))
* **security:** require memfd_secret, remove soft-mlock, zero-copy serde visitor ([889d1c6](https://github.com/ScopeCreep-zip/open-sesame/commit/889d1c6db4aaa79b02a0aeff517cd66195d90221))
* **systemd:** add LimitMEMLOCK=64M to all daemon units, improve postinst output ([4692f28](https://github.com/ScopeCreep-zip/open-sesame/commit/4692f2823590ca48c84255106f09ccfd32dc38a9))

### 📚 Documentation

* comprehensive README with visual composition and progressive disclosure ([118fca3](https://github.com/ScopeCreep-zip/open-sesame/commit/118fca35b103a3178b10fe910c9ba9b805457753))
* replace packages table with blockquotes for GitHub rendering ([fadd531](https://github.com/ScopeCreep-zip/open-sesame/commit/fadd5317938f7b56904aea313863cb36bf0b769d))
* rewrite README intro for progressive disclosure ([ca8c65c](https://github.com/ScopeCreep-zip/open-sesame/commit/ca8c65c6bca1294adc2be0fe627a8ac1d7985fb1))
* split Quick Start into one-command-per-codeblock for copy/paste ([865e68e](https://github.com/ScopeCreep-zip/open-sesame/commit/865e68e40f330109d512b0c6c39790f794641012))

## Quick Install

### APT Repository (recommended)

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

### Direct Download

See release assets below for `.deb` packages (amd64/arm64) with SHA256 checksums.

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

All `.deb` packages include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

---

## [1.5.2](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.5.1...v1.5.2) (2026-03-22)

### 🐛 Bug Fixes

* **license:** correct Cargo.toml to GPL-3.0-only, overhaul README ([fb593de](https://github.com/ScopeCreep-zip/open-sesame/commit/fb593de7fc63c4e9b9a6841caae87a9d8de399ad))

## Quick Install

### APT Repository (recommended)

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

### Direct Download

See release assets below for `.deb` packages (amd64/arm64) with SHA256 checksums.

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

All `.deb` packages include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

---

## [1.5.1](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.5.0...v1.5.1) (2026-03-22)

### 🐛 Bug Fixes

* **ci:** strip dpkg-deb trailing blank lines from APT Packages index ([eefcf27](https://github.com/ScopeCreep-zip/open-sesame/commit/eefcf27638a949c3239c76ad24d04cc433f99f91))

## Quick Install

### APT Repository (recommended)

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

### Direct Download

See release assets below for `.deb` packages (amd64/arm64) with SHA256 checksums.

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

All `.deb` packages include [SLSA Build Provenance](https://slsa.dev/) attestations. Verify with:
```bash
gh attestation verify "open-sesame-linux-$(uname -m).deb" --owner ScopeCreep-zip
gh attestation verify "open-sesame-desktop-linux-$(uname -m).deb" --owner ScopeCreep-zip
```

---

## [1.5.0](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.4.2...v1.5.0) (2026-03-22)

### ✨ Features

* **packaging:** split into open-sesame (headless) and open-sesame-desktop packages ([627f7a8](https://github.com/ScopeCreep-zip/open-sesame/commit/627f7a8e2292924091b200e8846e9dc1eccc4d4f))

### 🐛 Bug Fixes

* **security:** harden memory protection, IPC clearance, and sandbox resilience ([1601fb4](https://github.com/ScopeCreep-zip/open-sesame/commit/1601fb4e857e31c554142979cd60255c8d80af56))
* **wm,launcher:** audit remediations, launch pipeline, overlay rewrite ([0108d77](https://github.com/ScopeCreep-zip/open-sesame/commit/0108d779abc1016b2237ff3bd405879b059cf257))

### ♻️ Code Refactoring

* **core-config:** decompose schema and loader into domain modules ([b828345](https://github.com/ScopeCreep-zip/open-sesame/commit/b8283452f1a62cb275569ad2aa90b1de476181f7))
* **core-ipc:** split noise.rs into protocol transport and key management ([284f947](https://github.com/ScopeCreep-zip/open-sesame/commit/284f947b07c53378904b0e70c4ceb43c0604e375))
* **core-types:** decompose monolithic lib.rs into flat module structure ([ccbe8d2](https://github.com/ScopeCreep-zip/open-sesame/commit/ccbe8d2c46d84719a784f36646d00d2e3a49e685))
* **daemon-launcher,daemon-wm:** final decomposition wave ([b96b231](https://github.com/ScopeCreep-zip/open-sesame/commit/b96b2317980e152a8baf630409cb9b47c5975b8e))
* **daemon-profile:** decompose monolithic main.rs into flat module structure ([5eb22c3](https://github.com/ScopeCreep-zip/open-sesame/commit/5eb22c3000de3a10193b16f5d146e78331d47ea0))
* **daemon-secrets:** decompose monolithic main.rs into flat module structure ([3fc9000](https://github.com/ScopeCreep-zip/open-sesame/commit/3fc9000c195bdf62262b09ab6b2b9637e2084a04))
* **daemon-wm:** extract commands, sandbox, and ipc_keys from main.rs ([dca7522](https://github.com/ScopeCreep-zip/open-sesame/commit/dca75229c4d1d9d2c6cc20768db7695738f935d1))
* **open-sesame:** decompose monolithic main.rs into flat module structure ([b504ed8](https://github.com/ScopeCreep-zip/open-sesame/commit/b504ed81df079c7b6b351c706de9fc7f7ee0cece))
* **platform-linux:** decompose compositor.rs for multi-backend support ([346630d](https://github.com/ScopeCreep-zip/open-sesame/commit/346630d88743ec2e6befc4ebec3c667091afab12))

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

## [1.4.2](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.4.1...v1.4.2) (2026-03-20)

### 🐛 Bug Fixes

* **ci:** remove trailing blank line from apt Packages file ([86187cb](https://github.com/ScopeCreep-zip/open-sesame/commit/86187cb55c262b35710c562b7356cf85488632f2))

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

## [1.4.1](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.4.0...v1.4.1) (2026-03-17)

### 🐛 Bug Fixes

* **auth:** match All-mode vault key derivation between init and daemon-secrets ([71d63b5](https://github.com/ScopeCreep-zip/open-sesame/commit/71d63b5d13d6adc0f03a2a47019e2bcc76565b73))
* **auth:** unwrap real master key from PasswordWrapBlob during SSH enrollment ([dd63caa](https://github.com/ScopeCreep-zip/open-sesame/commit/dd63caac8e916c496a45ed458e0d0cf5e806821e))
* **security:** audit remediations, centralize UUID and profile constants ([eec1a04](https://github.com/ScopeCreep-zip/open-sesame/commit/eec1a04ea859b88ed7a167ddb4bb7f40bbe1f772))

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

## [1.4.0](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.3.2...v1.4.0) (2026-03-17)

### ✨ Features

* **auth:** multi-factor vault auth policy engine ([957d113](https://github.com/ScopeCreep-zip/open-sesame/commit/957d1135ecd97731fdddb95c804940a9d6ea17e5))
* **auth:** multi-factor vault auth policy engine ([b908f80](https://github.com/ScopeCreep-zip/open-sesame/commit/b908f80e23328dfdb4bb785997827ab8e9e5abdf))
* **cli,auth:** require explicit SSH key selection for enrollment ([4ad176c](https://github.com/ScopeCreep-zip/open-sesame/commit/4ad176c58de7120a39f6f14263a3a49b8ed48bf4))
* **sandbox:** resolve nix store symlinks for Landlock config access ([aed1a9d](https://github.com/ScopeCreep-zip/open-sesame/commit/aed1a9d265a465354a539456d4d31fd742dbb8f9))

### 🐛 Bug Fixes

* **init:** bootstrap runtime dir before starting systemd services ([17df9c4](https://github.com/ScopeCreep-zip/open-sesame/commit/17df9c4f54a24fd2406857f7fbeea04a4676fa4c))
* **ipc:** evict stale connection on key rotation reconnect ([b89cfa8](https://github.com/ScopeCreep-zip/open-sesame/commit/b89cfa888cba533ef161eaf4a18ddf833428d50d))
* **nix:** update outputHashes keys for cosmic-protocols 0.2.0 ([37767f5](https://github.com/ScopeCreep-zip/open-sesame/commit/37767f5e578338c017a5a244209dbe6141d30728))
* **sandbox:** add NOTIFY_SOCKET Landlock rule to daemon-wm, add sd_notify diagnostics ([f147dc4](https://github.com/ScopeCreep-zip/open-sesame/commit/f147dc40204b733e7ada7153e0f45b7a629f360c))
* **sandbox:** add SIGSYS handler for seccomp violation visibility ([2a4e84f](https://github.com/ScopeCreep-zip/open-sesame/commit/2a4e84fc6a5b4255ba0f30e1df5bf9bf23775d4d))
* **sandbox:** complete seccomp allowlists for daemon-wm and daemon-secrets ([3eaf332](https://github.com/ScopeCreep-zip/open-sesame/commit/3eaf33227cc1b8a8bd5cda44b68cd9cfd14005f1))
* **seccomp:** add fsync to daemon-secrets, launcher, clipboard allowlists ([02803bd](https://github.com/ScopeCreep-zip/open-sesame/commit/02803bd98e1777333695063f1de513e38ebe02db))
* **seccomp:** add inotify syscalls for config hot-reload, add watchdog visibility ([302d347](https://github.com/ScopeCreep-zip/open-sesame/commit/302d3477de1134348501b0781bc95bf972ff7835))
* **seccomp:** add readlink to 4 daemon allowlists (strace-verified) ([2a6167a](https://github.com/ScopeCreep-zip/open-sesame/commit/2a6167a98a84e59cd143e66cfb87547db3b7f720))
* **secrets:** add missing SQLite WAL syscalls, application-owned bootstrap ([6bad5ca](https://github.com/ScopeCreep-zip/open-sesame/commit/6bad5ca02aaeb5a3c76c352f2a6e28cc70f046a5))
* **systemd:** add missing ReadWritePaths for clipboard cache and fontconfig ([43baa4a](https://github.com/ScopeCreep-zip/open-sesame/commit/43baa4aae2f19eff8033caeb400c7e97adc22004))
* **systemd:** add RuntimeDirectory=pds to all units for mount namespace bootstrap ([7ba4869](https://github.com/ScopeCreep-zip/open-sesame/commit/7ba4869d7c94769c2db2c35901786f3ebcafe854))
* **systemd:** align all units — Type=notify, watchdog, hardening, correct paths ([a3d9d10](https://github.com/ScopeCreep-zip/open-sesame/commit/a3d9d104bc45f53db50d92ede547705855d34314))
* **systemd:** use tmpfiles.d for runtime dir, drop broken RuntimeDirectory ([080ff4d](https://github.com/ScopeCreep-zip/open-sesame/commit/080ff4d6bc0c878b41321ed0ffa94ba5a96a40dd))

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

## [1.3.2](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.3.1...v1.3.2) (2026-03-16)

### 🐛 Bug Fixes

* **sandbox:** add D-Bus and Wayland syscalls to daemon-profile seccomp allowlist ([f63e7a6](https://github.com/ScopeCreep-zip/open-sesame/commit/f63e7a6ffd97c01e6f73fe91bec07be8ac25bda6))

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

## [1.3.1](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.3.0...v1.3.1) (2026-03-16)

### 🐛 Bug Fixes

* **sandbox,packaging:** enforce seccomp KillProcess, update v2 paths and metadata ([eae00c0](https://github.com/ScopeCreep-zip/open-sesame/commit/eae00c0ca354be227f10d001e406b651d22d04f0))

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

## [1.3.0](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.2.0...v1.3.0) (2026-03-16)

### ✨ Features

* **auth,sandbox:** SSH agent forwarding support for multi-user VMs ([c6ebf0f](https://github.com/ScopeCreep-zip/open-sesame/commit/c6ebf0ff39fae1296cd91c6dd71873e991f04b36))
* **auth,wm,secrets:** add core-auth crate, inline vault unlock UX, and SSH unlock handler ([b6546fb](https://github.com/ScopeCreep-zip/open-sesame/commit/b6546fbc19a613f12d0b2fa8582dbc094af10719))
* **cli:** add `sesame export` command with env var security denylist ([10546d9](https://github.com/ScopeCreep-zip/open-sesame/commit/10546d94643e6ff50fc2018105a8a01543a0a9f7))
* **cli:** multi-profile CSV support with SESAME_PROFILES env var ([dcdfc7a](https://github.com/ScopeCreep-zip/open-sesame/commit/dcdfc7a08c1aef885d1c2d61e038fe61b81c0c3c))
* **cli:** resident fast-path for overlay activation (~2ms vs ~160ms) ([b432357](https://github.com/ScopeCreep-zip/open-sesame/commit/b432357dcbaff6ef1a110b9376744bf6838b4249))
* **compositor:** implement CosmicBackend with ext_foreign_toplevel + zcosmic_toplevel protocols ([caa15d9](https://github.com/ScopeCreep-zip/open-sesame/commit/caa15d93cf4049bd2fd951638984c49a5092a3e0))
* **core:** implement Phase 1 foundation — types, config, ipc, crypto, profile schema ([536f0ea](https://github.com/ScopeCreep-zip/open-sesame/commit/536f0ea309693bb5ba7dd05a94fb43a7030815a1))
* **core:** pre-work for vault unlock UX and auth backend ([e3d0b91](https://github.com/ScopeCreep-zip/open-sesame/commit/e3d0b918a8b3d8305ed48908e8d5d13712c40874))
* **crypto,profile:** add dual-algorithm KDF/HKDF and audit action variants ([bbb7e24](https://github.com/ScopeCreep-zip/open-sesame/commit/bbb7e24a7748b274267873a784e3e84456bf4c59))
* **deps:** add ssh-key and ssh-agent-client-rs for SSH agent vault unlock ([1cd2818](https://github.com/ScopeCreep-zip/open-sesame/commit/1cd2818f38241666a5d083545bf928ff25166fe9))
* **init,crypto,ipc:** installation ceremony, SHA-256 audit, trust vectors ([64c25cf](https://github.com/ScopeCreep-zip/open-sesame/commit/64c25cf7a32959950eab240488b9c90c4b6fcbb4))
* **init:** add `sesame init` OOBE command, fix daemon-wm sandbox for GTK4 ([3ffa5cc](https://github.com/ScopeCreep-zip/open-sesame/commit/3ffa5cce458983c62bba9d654014727390c5b8be))
* **input,wm:** route keyboard events via daemon-input IPC for compositor-independent overlay input ([8f26e53](https://github.com/ScopeCreep-zip/open-sesame/commit/8f26e5317609b26ae4d6f3d122dd0374dcb53cd2))
* **launcher:** composable launch profiles with secret injection and devshell wrapping ([d346510](https://github.com/ScopeCreep-zip/open-sesame/commit/d346510663d441181c0e73aa3424cd91a10951c6))
* **nix:** add flake with rustPlatform.buildRustPackage derivation and home-manager module ([63001f3](https://github.com/ScopeCreep-zip/open-sesame/commit/63001f3da7d6012c23e96f1c39f6bd23f147ba93))
* **nix:** add multi-profile and launch profiles support to home-manager module ([a7af80e](https://github.com/ScopeCreep-zip/open-sesame/commit/a7af80e74a4f439d2c9643d97dc58c14462cd647))
* **packaging:** v2 multi-daemon apt/deb packaging and CI pipeline ([66d6ede](https://github.com/ScopeCreep-zip/open-sesame/commit/66d6edee49ff0ca40d1e1bdf61c3ad8becfd73a1))
* **platform:** feature-gate GUI deps behind `desktop` for headless builds ([bcfc62e](https://github.com/ScopeCreep-zip/open-sesame/commit/bcfc62e0645adb46b072d5df353888ef55aaef8f))
* **platform:** implement Phase 1 platform layer skeletons — Linux traits, macOS/Windows module declarations ([d180c3c](https://github.com/ScopeCreep-zip/open-sesame/commit/d180c3c6de4ecaad177dac181bf23d94511f723e))
* **profile,audit,init:** namespace scoping, audit agent threading, installation event ([f806762](https://github.com/ScopeCreep-zip/open-sesame/commit/f806762521ac1ee28a2fce53bad35d69197cbb4c))
* **secrets:** per-vault independent password unlock ([04afea3](https://github.com/ScopeCreep-zip/open-sesame/commit/04afea32a49f0f46cf9a88c957d37df89b9eda8e))
* **security:** harden secret operations and clean up spec references ([d854e55](https://github.com/ScopeCreep-zip/open-sesame/commit/d854e555d7b0a75a8c7b102f84757336e377b31b))
* **security:** implement full protocol hardening omnibus D-001 through D-008 ([c3b21ac](https://github.com/ScopeCreep-zip/open-sesame/commit/c3b21ac9faf01044702c539f9ee40481c77faa8b))
* **types:** add v2.1 type system substrate ([8df9b85](https://github.com/ScopeCreep-zip/open-sesame/commit/8df9b850b03c54e3038b9899cc2a6d0041f0729a))
* v2 programmable desktop suite — IPC hardening, daemon lifecycle, window management, security architecture ([9649507](https://github.com/ScopeCreep-zip/open-sesame/commit/96495070ec6f5ba27c4e075cdfae84303e1fbe4c))
* **wire:** upgrade to wire protocol v3 and expand event schema ([9bb3d12](https://github.com/ScopeCreep-zip/open-sesame/commit/9bb3d12af461586981aa24200858e911d1660bd9))
* **wm:** dynamic KeyboardMode, re-activation cycling, MRU seeding, space key ([f56e160](https://github.com/ScopeCreep-zip/open-sesame/commit/f56e1608362114268665aea677d055452fd82c25))
* **wm:** structured launch error feedback with overlay toast ([a72d4e5](https://github.com/ScopeCreep-zip/open-sesame/commit/a72d4e5c31177ac9c72946392153f5eb76c59080))
* **wm:** wire COSMIC keybindings to daemon-wm overlay activation ([1f14f2f](https://github.com/ScopeCreep-zip/open-sesame/commit/1f14f2fbd23944d54408853226c0348f04671991))
* **wm:** wire inline vault unlock UX with SecureVec password buffer ([a0e5282](https://github.com/ScopeCreep-zip/open-sesame/commit/a0e5282fd189ec7d76cd0e0ae9c0566668e53fbd))
* **workspace:** add --adopt flag to clone for pre-existing directories ([8dc96f9](https://github.com/ScopeCreep-zip/open-sesame/commit/8dc96f92ce5c73da0a1f95d9ffec59bf9838db93))
* **workspace:** add sesame-workspace crate with full CLI integration ([62565ec](https://github.com/ScopeCreep-zip/open-sesame/commit/62565ec8416e9ff522f37380349b94e729c827ca))
* **workspace:** prepare all crates for sesame-workspace integration ([61f75d9](https://github.com/ScopeCreep-zip/open-sesame/commit/61f75d98d108dab5254d887089872af4042a0d39))
* **workspace:** scaffold v2 21-crate workspace with nix devShell ([e28d2a5](https://github.com/ScopeCreep-zip/open-sesame/commit/e28d2a5e2268d1ad2dd13d1020ac366d64002335))

### 🐛 Bug Fixes

* **auth:** resolve all SSH-agent vault unlock post-implementation risks ([b3c5c24](https://github.com/ScopeCreep-zip/open-sesame/commit/b3c5c241cb109dd993d86e2cf316c6556b0e5cea))
* **ci:** correct apt deps, build gtk4-layer-shell from source ([2a1093f](https://github.com/ScopeCreep-zip/open-sesame/commit/2a1093f9ea2d83ceecd0b5ed9851be11c1a31812))
* **ci:** correct xtask cargo alias, downgrade ci:test to debug build ([7f9a290](https://github.com/ScopeCreep-zip/open-sesame/commit/7f9a290ee5b11d11e9acfc2f7916d8136eb97395))
* **ci:** disable vapi in gtk4-layer-shell build ([a402d27](https://github.com/ScopeCreep-zip/open-sesame/commit/a402d273bd98019d0a8c269d8c32e3b67ebc8fbb))
* **ci:** downgrade gtk4 feature from v4_16 to v4_14 ([5b3f606](https://github.com/ScopeCreep-zip/open-sesame/commit/5b3f606851bbdb1f4895a45180df291c08fed034))
* **cli:** accept piped stdin for unlock and secret-set commands ([18a5749](https://github.com/ScopeCreep-zip/open-sesame/commit/18a5749b5db15250809a5f87fd24af310036fdee))
* **compositor:** remove activate() protocol cleanup that crashes cosmic-comp ([be4e3c3](https://github.com/ScopeCreep-zip/open-sesame/commit/be4e3c3443515f317d5409a675e79f4133411939))
* **compositor:** serialize Wayland protocol operations, reduce poll rate ([d513030](https://github.com/ScopeCreep-zip/open-sesame/commit/d513030c20de3f5a2f9bd0a691c75b56252c2286))
* **compositor:** use proper Wayland roundtrip, clean up dead code ([291e7c8](https://github.com/ScopeCreep-zip/open-sesame/commit/291e7c8d872f86383d991fa3b84c856ab809b668))
* **config:** filter watcher events to config files only, prevent CPU spin feedback loop ([110eb8f](https://github.com/ScopeCreep-zip/open-sesame/commit/110eb8f93c44a0096e0e7af1fcb9744f03859d1c))
* **daemon-wm:** add GTK4/GLib/Wayland syscalls to seccomp allowlist ([722a59c](https://github.com/ScopeCreep-zip/open-sesame/commit/722a59c778d3a090a029732960db02d8cfd6ce47))
* **docs:** resolve all rustdoc broken and private intra-doc links ([8cd0ebc](https://github.com/ScopeCreep-zip/open-sesame/commit/8cd0ebcb6ff8ca0b0927221952321c7b7cb24801))
* **init:** recover from systemd failed state after wipe-reset cycle ([39dfc28](https://github.com/ScopeCreep-zip/open-sesame/commit/39dfc28d94a2ca215fc7c3ea1d74bbeb1ab8aa02))
* **init:** support non-TTY stdin for wipe confirmation prompt ([f838c5a](https://github.com/ScopeCreep-zip/open-sesame/commit/f838c5af8bbfbd487e708b0567701c40fcfba795))
* **input:** drain evdev buffer before synthetic Alt-release on grab activation ([90f4a7a](https://github.com/ScopeCreep-zip/open-sesame/commit/90f4a7a9cc69ecacc2bf524339b54fea4988da25))
* **input:** forward Alt/Meta releases unconditionally, remove synthetic ([1f43e1f](https://github.com/ScopeCreep-zip/open-sesame/commit/1f43e1fe1875981c87b4d03a21a2886de6e2c9c0))
* **input:** remove synthetic Alt-release on grab activation ([f938807](https://github.com/ScopeCreep-zip/open-sesame/commit/f938807dc9933ad62415abea8b8bf9fcdf5e0ae7))
* **ipc,compositor:** eliminate silent RPC timeouts, fix Wayland protocol object lifecycle ([f3f8d0b](https://github.com/ScopeCreep-zip/open-sesame/commit/f3f8d0b5d8f65e6064b0955628933c937e7ca30b))
* **ipc:** add BusClient::shutdown() to flush outbound frames before disconnect ([ad6e29c](https://github.com/ScopeCreep-zip/open-sesame/commit/ad6e29cb2eed11a4029107cb3ae6f9145d56cb16))
* **ipc:** eliminate status/profile response race between daemon-profile and daemon-secrets ([a0883c1](https://github.com/ScopeCreep-zip/open-sesame/commit/a0883c1fd862c0faa20ca43f95a000e53a77bcde))
* **ipc:** handle outbound channel close in I/O task select loop ([44be47b](https://github.com/ScopeCreep-zip/open-sesame/commit/44be47b09555ef098f2cd071555bd2978526ce9c))
* **ipc:** prevent message feedback loops with self-sender guards ([4560ca5](https://github.com/ScopeCreep-zip/open-sesame/commit/4560ca5213acb5d2e33660b4d00ff62bb31b3733))
* **ipc:** remove skip_serializing_if from postcard-encoded LaunchExecuteResponse ([b11d375](https://github.com/ScopeCreep-zip/open-sesame/commit/b11d375c7440bc60e55a21b8a1abe7d72b736d5d))
* **ipc:** resolve daemon-secrets bus race after home-manager rebuild ([bcf395f](https://github.com/ScopeCreep-zip/open-sesame/commit/bcf395fc5d4aa66538a50de8a7e1cf63206f6d61))
* **keybindings:** write to correct COSMIC shortcuts path ([52d05bb](https://github.com/ScopeCreep-zip/open-sesame/commit/52d05bb26f4f8f7eb39d6851b66a859463f3a01d))
* **launcher,secrets,nix:** omnibus bug/UX remediation from manual test sweep ([65fe720](https://github.com/ScopeCreep-zip/open-sesame/commit/65fe7200211abe1248d6eb10eb1f2e45f211a5bc))
* **launcher:** resolve desktop entry IDs with fallback matching ([bad595c](https://github.com/ScopeCreep-zip/open-sesame/commit/bad595cd64e29b279b39ca8b69a438c86944c31d))
* **launcher:** skip Landlock entirely so spawned apps inherit clean sandbox ([1ef7a18](https://github.com/ScopeCreep-zip/open-sesame/commit/1ef7a18349bcd9533ff9636e066facec8cf11658))
* **nix:** add GTK4/Cairo/Pango/glib build inputs to package.nix ([a363132](https://github.com/ScopeCreep-zip/open-sesame/commit/a3631326087f50fc8e3b84b7ce451a2d938e1af4))
* **nix:** HM module places settings directly under profiles.default.wm ([e00ceca](https://github.com/ScopeCreep-zip/open-sesame/commit/e00cecadac74e7c01b2e245365f654be86972123))
* **nix:** include sesame-workspace crate in nix source filter ([ce46f7f](https://github.com/ScopeCreep-zip/open-sesame/commit/ce46f7f9e54d8afd2ee84211ec839333ee46d6c6))
* **platform:** override COSMIC system_actions for Alt+Tab instead of competing Spawn bindings ([2c2ef5d](https://github.com/ScopeCreep-zip/open-sesame/commit/2c2ef5d9c57afa3359c5a566fedfd7b539db5cc7))
* **profile,nix:** validate profile names and fix HM config path ([444568c](https://github.com/ScopeCreep-zip/open-sesame/commit/444568ce39ba548a9e68830edf258362ea6f3105))
* resolve all clippy warnings across workspace ([18a4e43](https://github.com/ScopeCreep-zip/open-sesame/commit/18a4e439dd50eda8b7bd362bf7f5b7578955bd00))
* **sandbox:** add getdents64 syscall, use WAYLAND_DISPLAY for wm ([e7c6bde](https://github.com/ScopeCreep-zip/open-sesame/commit/e7c6bde80b9c8b854c8cfe102eb08f75eb3a42d3))
* **sandbox:** add getuid syscall, revert seccomp to KillProcess ([faad0b3](https://github.com/ScopeCreep-zip/open-sesame/commit/faad0b3332dae3dc11ea4ae36f8947b3ae737cca))
* **sandbox:** add missing tokio-essential syscalls to seccomp profiles ([d1d62cb](https://github.com/ScopeCreep-zip/open-sesame/commit/d1d62cb8166fb7f3e183515fdb3033b9cca4b61a))
* **sandbox:** complete seccomp allowlists for all sandboxed daemons ([25ae51d](https://github.com/ScopeCreep-zip/open-sesame/commit/25ae51d24c7e000530e7f3dc7af70ea74bfd1e31))
* **sandbox:** ensure runtime dir exists before Landlock PathFd ([b94f11f](https://github.com/ScopeCreep-zip/open-sesame/commit/b94f11fbf71d0db681b808155ca58f4ea4d143c0))
* **sandbox:** force Nix rebuild — Landlock V6 with AccessNet + Scope ([2ea1e24](https://github.com/ScopeCreep-zip/open-sesame/commit/2ea1e244dfb79a09d866807d49788bb8396cd6eb))
* **sandbox:** fstat PathFd to strip directory-only flags on non-directory inodes ([23ed397](https://github.com/ScopeCreep-zip/open-sesame/commit/23ed3978f631603f752a74e0379d3690acc19970))
* **sandbox:** revert seccomp to Log mode until allowlists are complete ([64314a9](https://github.com/ScopeCreep-zip/open-sesame/commit/64314a9bb24d0af74c639b2d9279c5547dfb420e))
* **sandbox:** upgrade Landlock ABI V3 to V6 for kernel 6.12+ compatibility ([b1232ae](https://github.com/ScopeCreep-zip/open-sesame/commit/b1232aea463be2d02edff4f61c8a7d228e8cdb79))
* **sandbox:** use directory-level Landlock rules for key rotation, gate activation log on success ([20ba9ed](https://github.com/ScopeCreep-zip/open-sesame/commit/20ba9edeb1671529b0825bff7f618d7ad711669d))
* **sandbox:** use file-only landlock access rights for non-directory paths ([9fc502a](https://github.com/ScopeCreep-zip/open-sesame/commit/9fc502acf1c9f1c40ad03bd8e29ad7a6828ebd90))
* **sandbox:** use ReadWriteFile for D-Bus socket in daemon-secrets ([26faaa2](https://github.com/ScopeCreep-zip/open-sesame/commit/26faaa207baa0e537dafd218d1f324d9abdafb02))
* **secrets:** broadcast lock state changes so daemon-profile can track them ([2bd9604](https://github.com/ScopeCreep-zip/open-sesame/commit/2bd960453d5e26d84604b999d7d6552125d15f0a))
* **secrets:** return Ok(true) to continue event loop when ignoring non-profile senders ([c13ca1f](https://github.com/ScopeCreep-zip/open-sesame/commit/c13ca1f1a797f95dda33681aae95e141202793f8))
* **systemd:** preserve NOTIFY_SOCKET for watchdog keepalives ([d3b130b](https://github.com/ScopeCreep-zip/open-sesame/commit/d3b130b23a78af2082bc747ef629f6e716edcfe8))
* **wm:** activate profiles after vault unlock before retry launch ([a20156f](https://github.com/ScopeCreep-zip/open-sesame/commit/a20156fabde1d704c5629a28e7bcf2658e68be31))
* **wm:** add landlock rules for vaults dir and SSH agent socket ([68bbed3](https://github.com/ScopeCreep-zip/open-sesame/commit/68bbed391aebb079ebeefacff20f4f99d7090a9a))
* **wm:** add modifier poll grace period and launcher mode ignores Alt release ([f500133](https://github.com/ScopeCreep-zip/open-sesame/commit/f500133d5b857a80fe532b0463e078ffdccbc740))
* **wm:** Alt release commits selection in all modes including launcher ([d59fe22](https://github.com/ScopeCreep-zip/open-sesame/commit/d59fe229371a197f3833069d1b0461ec48533bff))
* **wm:** commit only on Alt release, never on keypress ([2b2e278](https://github.com/ScopeCreep-zip/open-sesame/commit/2b2e278295700b989b1c58a0e6300f9dc113a186))
* **wm:** defer overlay display for invisible quick-switch on fast alt+tab ([516953a](https://github.com/ScopeCreep-zip/open-sesame/commit/516953a6eee8216c0139561f9a0ffb0164d64ece))
* **wm:** derive hint keys from app name first letter, not home row ([a759c55](https://github.com/ScopeCreep-zip/open-sesame/commit/a759c55d4a44509b511f7a60fd0c33737b3f46f9))
* **wm:** dispatch unlock flow commands from launch result, re-acquire keyboard grab ([a17414d](https://github.com/ScopeCreep-zip/open-sesame/commit/a17414d68d69091b6d2b510adc1e9473fd42d191))
* **wm:** empty input region on hidden overlay, fix MRU origin and stale frame ([4a07e51](https://github.com/ScopeCreep-zip/open-sesame/commit/4a07e51eedd9c207fec10bcf792ef6084ba3ca2a))
* **wm:** isolate activation connection and allow GPU access in sandbox ([1a21f48](https://github.com/ScopeCreep-zip/open-sesame/commit/1a21f4839bf16dc91bb8f691e46f07d48368130b))
* **wm:** keep layer surface permanently mapped to prevent cosmic-comp disconnect ([f1348df](https://github.com/ScopeCreep-zip/open-sesame/commit/f1348df3c547a92362ea8987e1bcc70230d21bb3))
* **wm:** launcher activates with zero windows ([e4148e5](https://github.com/ScopeCreep-zip/open-sesame/commit/e4148e525c51ba9dff54c569282ac50ece4d6ee6))
* **wm:** move window list polling to dedicated OS thread ([a1ca7a8](https://github.com/ScopeCreep-zip/open-sesame/commit/a1ca7a80f7b347659159661184d0c393fc2f5dbc))
* **wm:** MRU stack ordering and clippy lint on reorder signature ([a3d0942](https://github.com/ScopeCreep-zip/open-sesame/commit/a3d094249486bbf58faff02dbd842019c577138a))
* **wm:** poll modifier state to detect Alt release missed during compositor race ([2e16314](https://github.com/ScopeCreep-zip/open-sesame/commit/2e16314501c23bd823afbe099f4e99a8151d5294))
* **wm:** prevent modifier poll premature commit on IPC re-activation ([053f287](https://github.com/ScopeCreep-zip/open-sesame/commit/053f287bd89b7be80a2d744e6963b1f3047bd189))
* **wm:** prevent overlay freeze during launch IPC and stale activations ([16c08b0](https://github.com/ScopeCreep-zip/open-sesame/commit/16c08b067b4da9f3426ab71ca888dfa837b9eb16))
* **wm:** promote auto-unlock failure logs from debug to info/warn ([2e8b7fb](https://github.com/ScopeCreep-zip/open-sesame/commit/2e8b7fb5600b3e8738ad726ad8c9cf41b224e413))
* **wm:** publish overlay events at Internal level, add backward overlay variant ([e08262f](https://github.com/ScopeCreep-zip/open-sesame/commit/e08262f651c7cde33f2c67d02d6a4e341a1b6b8b))
* **wm:** quick-switch on fast alt release, non-blocking border hint ([336eea0](https://github.com/ScopeCreep-zip/open-sesame/commit/336eea0b682988267c15c9a2f1b008bba519770a))
* **wm:** reliable keyboard focus acquisition for launcher without focused window ([410e1bf](https://github.com/ScopeCreep-zip/open-sesame/commit/410e1bfca87db95bcaade9f4ec4456f92404b523))
* **wm:** resolve unlock UX rendering, feedback, and AlreadyUnlocked loop ([9d2fbd0](https://github.com/ScopeCreep-zip/open-sesame/commit/9d2fbd0d8216abcc23d6e5c408b0684609fcdc8f))
* **wm:** rotate origin window to bottom of picker display order ([b510a72](https://github.com/ScopeCreep-zip/open-sesame/commit/b510a7207778934eba8b3cd91bf8453811ae270a))
* **wm:** send ShowBorder immediately on activation, defer only picker ([5a9d199](https://github.com/ScopeCreep-zip/open-sesame/commit/5a9d19959ef3cd9399928066c466e4282bc07f38))
* **wm:** show "Launch <app>" instead of "No matches" for staged launches ([bfb2c42](https://github.com/ScopeCreep-zip/open-sesame/commit/bfb2c42b4bbb4a1a3bb7bcb03846d3a00c176ce4))
* **wm:** skip border-only phase, go directly to FullOverlay on activate ([2b79a26](https://github.com/ScopeCreep-zip/open-sesame/commit/2b79a266e726c391a1df73be5a66ea3e0dd5122b))
* **wm:** skip modifier poll when keyboard focus is confirmed ([c2070e1](https://github.com/ScopeCreep-zip/open-sesame/commit/c2070e1a504cefdd7c718af5c98338dc94a0f5a2))
* **wm:** support in-flight direction change during Alt+Tab cycling ([3d2b5be](https://github.com/ScopeCreep-zip/open-sesame/commit/3d2b5be604a1db02ef2e914955e896ecf2b8c1cf))
* **wm:** suppress GTK4 modifier poll when IPC keyboard active, keep launch toast visible ([44c8620](https://github.com/ScopeCreep-zip/open-sesame/commit/44c86209599a104a332e987e96c65ee8a4a2a14d))
* **wm:** sync layer-shell unmap before activation and add sysfs Landlock rules ([44a52b0](https://github.com/ScopeCreep-zip/open-sesame/commit/44a52b0cc0484bf8a20d5009329b3ea672dd9884))
* **wm:** use brief Armed dwell in launcher mode for keyboard focus acquisition ([fcbe789](https://github.com/ScopeCreep-zip/open-sesame/commit/fcbe789f477518e21a1ec503f5ef8e78b0e6e50d))
* **wm:** use imported UnlockRejectedReason instead of fully qualified path ([203e222](https://github.com/ScopeCreep-zip/open-sesame/commit/203e222f5639ed4ebd3d8fc5bbdbcabbe390beea))
* **wm:** use Internal security level for SshUnlockRequest IPC ([217cb64](https://github.com/ScopeCreep-zip/open-sesame/commit/217cb6498678ece70050b0fc4081b0ef999ee12a))

### 📚 Documentation

* rewrite README for v2 multi-daemon architecture ([e93917a](https://github.com/ScopeCreep-zip/open-sesame/commit/e93917ab4f4e8d2ba0831f62c30892bd68aa5704))

### ♻️ Code Refactoring

* **wm:** origin-aware snapshot with tested forward/backward/launcher modes ([f466c5a](https://github.com/ScopeCreep-zip/open-sesame/commit/f466c5a0d9f5212685222537da5de19fefd27c83))
* **wm:** replace imperative state machine with deterministic controller ([83a6225](https://github.com/ScopeCreep-zip/open-sesame/commit/83a622599d919a10b06f12a9458b4502adbf1c75))

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

## [1.2.0](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.1.0...v1.2.0) (2025-11-28)

### ✨ Features

* add screenshot to readme and docs ([1ec2b2f](https://github.com/ScopeCreep-zip/open-sesame/commit/1ec2b2f9894ad9040148c6d8a3433c7b2c3863d9))

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

## [1.1.0](https://github.com/ScopeCreep-zip/open-sesame/compare/v1.0.0...v1.1.0) (2025-11-28)

### ✨ Features

* add slsa level 3 badge to readme and docs ([f85b938](https://github.com/ScopeCreep-zip/open-sesame/commit/f85b93800e336a10fb0167460ff4e6e1a7c699b1))

### 📚 Documentation

* add apt repo setup to quick example in introduction.md ([eb6c60c](https://github.com/ScopeCreep-zip/open-sesame/commit/eb6c60c280de397f0fcdfa5323e9476716569d7e))

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

## 1.0.0 (2025-11-28)

### ✨ Features

* add CLI binary with argument parsing ([a336281](https://github.com/ScopeCreep-zip/open-sesame/commit/a336281e058674aa8a9362020f3084dc1e36d13f))
* add example configuration file ([594e1ec](https://github.com/ScopeCreep-zip/open-sesame/commit/594e1ec602139a9bffc3761c2d4d169cb0e752a6))
* add library crate with public API ([3a88754](https://github.com/ScopeCreep-zip/open-sesame/commit/3a887548f47b160f3612814435de93d467655b78))
* **app:** add application module exports ([511ece4](https://github.com/ScopeCreep-zip/open-sesame/commit/511ece4ca2d6ac7a7e899ea95ff5838bf4b79477))
* **app:** add application state machine ([3ea528d](https://github.com/ScopeCreep-zip/open-sesame/commit/3ea528dacd6f2889aa147ab167a9b39bb3b733b6))
* **app:** add frame renderer ([20cf2ec](https://github.com/ScopeCreep-zip/open-sesame/commit/20cf2eca903d8a32fabae3eb81610172a27e5ef2))
* **ci:** implement semantic-release for automated versioning ([b8777cc](https://github.com/ScopeCreep-zip/open-sesame/commit/b8777ccf7c8efc57aa1fc45e025f696ede6cd27a))
* **ci:** prepend install instructions to semantic-release notes ([ffa85db](https://github.com/ScopeCreep-zip/open-sesame/commit/ffa85dbc583e88f79fc1e7362939f7d4b2f60daf))
* **config:** add configuration loading and validation ([aa847a6](https://github.com/ScopeCreep-zip/open-sesame/commit/aa847a65d892d7a99cca8f84f6d5e5c7529260b3))
* **config:** add configuration schema and types ([55ad2c8](https://github.com/ScopeCreep-zip/open-sesame/commit/55ad2c8f87d4990527e1c3db5d68cd0d63e53b30)), closes [#b4a0ffb4](https://github.com/ScopeCreep-zip/open-sesame/issues/b4a0ffb4)
* **core:** add hint matching and filtering ([13a8bb5](https://github.com/ScopeCreep-zip/open-sesame/commit/13a8bb5ee41a1eb42aa9a75fce84676c1f9ec9e7))
* **core:** add hint sequence and assignment logic ([18d9060](https://github.com/ScopeCreep-zip/open-sesame/commit/18d90605ad6139cc604213547923b6e2d77dfaa5))
* **core:** add launch command abstraction ([992f80d](https://github.com/ScopeCreep-zip/open-sesame/commit/992f80d221ff37ee2ac38c551b90df9f307d8a01))
* **core:** add window and app identifier types ([15b0305](https://github.com/ScopeCreep-zip/open-sesame/commit/15b0305db1d4cea45644e6ba6e6f8b2fba24245f))
* **input:** add input buffer for typed characters ([e007486](https://github.com/ScopeCreep-zip/open-sesame/commit/e007486bfdc36a64c346af65b61048a0d8af76c6))
* **input:** add keyboard input processor ([f0b555b](https://github.com/ScopeCreep-zip/open-sesame/commit/f0b555becdc581631c1fad7075ebb41edac86459))
* **platform:** add COSMIC keybinding management ([a0ffd66](https://github.com/ScopeCreep-zip/open-sesame/commit/a0ffd665cd0e038dcc7c76390f33e2089d6d0dc7))
* **platform:** add COSMIC theme integration and font resolution ([fa18bbf](https://github.com/ScopeCreep-zip/open-sesame/commit/fa18bbfd30116e1bc3007cbc8e3c5608275ee8ad))
* **platform:** add Wayland protocol integration ([7b00982](https://github.com/ScopeCreep-zip/open-sesame/commit/7b0098210464330f3e726df7ac2c2676eabe98cf))
* **release:** add comprehensive release body with install instructions ([9235505](https://github.com/ScopeCreep-zip/open-sesame/commit/9235505502bf096c6799fab6627af438b76e7490))
* **render:** add render context and pipeline ([d7ead27](https://github.com/ScopeCreep-zip/open-sesame/commit/d7ead27211018634161c18266827cb2d93d11227))
* **render:** add rendering primitives and color types ([690bb48](https://github.com/ScopeCreep-zip/open-sesame/commit/690bb48c434fc6940afa3c3f57d81be41fdfdca2))
* **render:** add text rendering with fontconfig ([5ae04bd](https://github.com/ScopeCreep-zip/open-sesame/commit/5ae04bdd1dbc07ff7b6c3627e081f149a04e405f))
* **ui:** add overlay window component ([b3d5f0d](https://github.com/ScopeCreep-zip/open-sesame/commit/b3d5f0db0de6cb8cbf9b8a4aa1987fcc74ce3929))
* **ui:** add theme configuration ([15cf44e](https://github.com/ScopeCreep-zip/open-sesame/commit/15cf44e4dbc99af1567a931e78130f6d6e6d6c13))
* **util:** add centralized logging handler ([6ca9619](https://github.com/ScopeCreep-zip/open-sesame/commit/6ca961989f9362642bb0a1f9aeb4605da4edbf43))
* **util:** add environment variable loading ([084ff82](https://github.com/ScopeCreep-zip/open-sesame/commit/084ff8286f88d488cc57082a5b61e5688d685bf1))
* **util:** add error types and result helpers ([efabbd3](https://github.com/ScopeCreep-zip/open-sesame/commit/efabbd300277074d88a023b896f6edbbbaaceac9))
* **util:** add instance lock for single-instance enforcement ([1ca174c](https://github.com/ScopeCreep-zip/open-sesame/commit/1ca174c5c88445582bad4c5dcacd783aa9d83c71))
* **util:** add IPC server and client ([c2f9c81](https://github.com/ScopeCreep-zip/open-sesame/commit/c2f9c818eabdbeb199996720704935e7e0f4ba2a))
* **util:** add MRU state persistence ([4c39ddd](https://github.com/ScopeCreep-zip/open-sesame/commit/4c39ddd3ea996b0f3f4c8f64d290eedd28c9c07b))
* **util:** add path utilities for XDG directories ([b3ce5c8](https://github.com/ScopeCreep-zip/open-sesame/commit/b3ce5c80264ee15b555c6e753133c262dad4339e))
* **util:** add timeout utilities ([9dc5f29](https://github.com/ScopeCreep-zip/open-sesame/commit/9dc5f2948775e1f0b656375a9df94e6dca24ce0a))

### 🐛 Bug Fixes

* **build:** consolidate npm packages into setup:npm task for dependency resolution ([0715b7b](https://github.com/ScopeCreep-zip/open-sesame/commit/0715b7b1f14b582d07054f9c990ccfddf2eb005c))
* **ci:** add bash -x tracing and fix SIGPIPE in apt-repo task ([4b2e5d9](https://github.com/ScopeCreep-zip/open-sesame/commit/4b2e5d9104f85f29044bea8be098045912703f21))
* **ci:** add rustfmt/clippy components and disable auto-install ([fbf4c10](https://github.com/ScopeCreep-zip/open-sesame/commit/fbf4c103e04f2b6ec65149f419098cd254dce5f7))
* **ci:** use install_args to install only required tools ([2a9b22a](https://github.com/ScopeCreep-zip/open-sesame/commit/2a9b22aea7edaf9fac8ba96217392a5e65538d07))
* **ci:** use npm install for semantic-release plugins ([774c79b](https://github.com/ScopeCreep-zip/open-sesame/commit/774c79bf4b43b97b35d3f95611fda589121d3a68))
* **ci:** use relative paths for apt repository filename field ([7d6a181](https://github.com/ScopeCreep-zip/open-sesame/commit/7d6a181121bedbced9f4851ff46b443feb401fec))
* **release:** use uname -m compatible package naming and fix badges ([b2d21d0](https://github.com/ScopeCreep-zip/open-sesame/commit/b2d21d03153df4075d8a9678593b51512408bcaa))

### 📚 Documentation

* add mdBook developer guide ([15bd764](https://github.com/ScopeCreep-zip/open-sesame/commit/15bd764f993657079499a67281cf97e8bd1f0308))
* add mdBook user guide ([b842be7](https://github.com/ScopeCreep-zip/open-sesame/commit/b842be7fa2e49e2f16942985ef581cbe33b71901))
* add project README ([839d5b1](https://github.com/ScopeCreep-zip/open-sesame/commit/839d5b148063dfa83e34910d4bea0755a09ff845))
* add security policy ([c9f9324](https://github.com/ScopeCreep-zip/open-sesame/commit/c9f9324b4c93ed9fdc5ae1544c6acb6bb0c00ac7))
* add source code architecture README ([176f535](https://github.com/ScopeCreep-zip/open-sesame/commit/176f53514eb7ffc57e0dbe6788e39669b53e4a9e))
* add versioning strategy documentation ([782a985](https://github.com/ScopeCreep-zip/open-sesame/commit/782a9856c4b885e616df3a7ae412a0ade34e05ef))

### ♻️ Code Refactoring

* **ci:** unify release workflow with semantic-release ([df140c7](https://github.com/ScopeCreep-zip/open-sesame/commit/df140c77cf78f5b47783741553cd11d153f0efbc))

### 📦 Build System

* add Cargo.lock for reproducible builds ([d8de7bc](https://github.com/ScopeCreep-zip/open-sesame/commit/d8de7bc57ff0043ae3a3ca61e3a3e16ce9b1c600))
* add Debian postinst script ([a883f81](https://github.com/ScopeCreep-zip/open-sesame/commit/a883f81f919f14bf2b5b95c3791fc3cfcb0e39c8))
* add mise task runner configuration ([c048c11](https://github.com/ScopeCreep-zip/open-sesame/commit/c048c11f1d39d269632ea7e291b628a64a67b439))
* add xtask for documentation generation ([39c70cd](https://github.com/ScopeCreep-zip/open-sesame/commit/39c70cd3f9b6a7114c33e7c7d1e726a1a09656fd))

### 👷 CI/CD

* add continuous integration workflow ([b8c1200](https://github.com/ScopeCreep-zip/open-sesame/commit/b8c1200f3dce430cc5eacc4c753b65761cc0ed31))
* add GitHub Pages template ([015a0e4](https://github.com/ScopeCreep-zip/open-sesame/commit/015a0e4c38460d51a10ff34d3b486d12d8acd0ce)), closes [#f4f4f4](https://github.com/ScopeCreep-zip/open-sesame/issues/f4f4f4) [#0066cc](https://github.com/ScopeCreep-zip/open-sesame/issues/0066cc) [#0055aa](https://github.com/ScopeCreep-zip/open-sesame/issues/0055aa)
* add release workflow with APT repository ([a2c8570](https://github.com/ScopeCreep-zip/open-sesame/commit/a2c857044d6815bdf6d20810991cae001bd7b0e2))
* migrate workflows to jdx/mise-action@v3 ([1d4b4b1](https://github.com/ScopeCreep-zip/open-sesame/commit/1d4b4b18ddf71eb72187b8615c56f8de3e118a0c))

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

## 1.0.0 (2025-11-28)

### ✨ Features

* add CLI binary with argument parsing ([a336281](https://github.com/ScopeCreep-zip/open-sesame/commit/a336281e058674aa8a9362020f3084dc1e36d13f))
* add example configuration file ([594e1ec](https://github.com/ScopeCreep-zip/open-sesame/commit/594e1ec602139a9bffc3761c2d4d169cb0e752a6))
* add library crate with public API ([3a88754](https://github.com/ScopeCreep-zip/open-sesame/commit/3a887548f47b160f3612814435de93d467655b78))
* **app:** add application module exports ([511ece4](https://github.com/ScopeCreep-zip/open-sesame/commit/511ece4ca2d6ac7a7e899ea95ff5838bf4b79477))
* **app:** add application state machine ([3ea528d](https://github.com/ScopeCreep-zip/open-sesame/commit/3ea528dacd6f2889aa147ab167a9b39bb3b733b6))
* **app:** add frame renderer ([20cf2ec](https://github.com/ScopeCreep-zip/open-sesame/commit/20cf2eca903d8a32fabae3eb81610172a27e5ef2))
* **ci:** implement semantic-release for automated versioning ([b8777cc](https://github.com/ScopeCreep-zip/open-sesame/commit/b8777ccf7c8efc57aa1fc45e025f696ede6cd27a))
* **ci:** prepend install instructions to semantic-release notes ([ffa85db](https://github.com/ScopeCreep-zip/open-sesame/commit/ffa85dbc583e88f79fc1e7362939f7d4b2f60daf))
* **config:** add configuration loading and validation ([aa847a6](https://github.com/ScopeCreep-zip/open-sesame/commit/aa847a65d892d7a99cca8f84f6d5e5c7529260b3))
* **config:** add configuration schema and types ([55ad2c8](https://github.com/ScopeCreep-zip/open-sesame/commit/55ad2c8f87d4990527e1c3db5d68cd0d63e53b30)), closes [#b4a0ffb4](https://github.com/ScopeCreep-zip/open-sesame/issues/b4a0ffb4)
* **core:** add hint matching and filtering ([13a8bb5](https://github.com/ScopeCreep-zip/open-sesame/commit/13a8bb5ee41a1eb42aa9a75fce84676c1f9ec9e7))
* **core:** add hint sequence and assignment logic ([18d9060](https://github.com/ScopeCreep-zip/open-sesame/commit/18d90605ad6139cc604213547923b6e2d77dfaa5))
* **core:** add launch command abstraction ([992f80d](https://github.com/ScopeCreep-zip/open-sesame/commit/992f80d221ff37ee2ac38c551b90df9f307d8a01))
* **core:** add window and app identifier types ([15b0305](https://github.com/ScopeCreep-zip/open-sesame/commit/15b0305db1d4cea45644e6ba6e6f8b2fba24245f))
* **input:** add input buffer for typed characters ([e007486](https://github.com/ScopeCreep-zip/open-sesame/commit/e007486bfdc36a64c346af65b61048a0d8af76c6))
* **input:** add keyboard input processor ([f0b555b](https://github.com/ScopeCreep-zip/open-sesame/commit/f0b555becdc581631c1fad7075ebb41edac86459))
* **platform:** add COSMIC keybinding management ([a0ffd66](https://github.com/ScopeCreep-zip/open-sesame/commit/a0ffd665cd0e038dcc7c76390f33e2089d6d0dc7))
* **platform:** add COSMIC theme integration and font resolution ([fa18bbf](https://github.com/ScopeCreep-zip/open-sesame/commit/fa18bbfd30116e1bc3007cbc8e3c5608275ee8ad))
* **platform:** add Wayland protocol integration ([7b00982](https://github.com/ScopeCreep-zip/open-sesame/commit/7b0098210464330f3e726df7ac2c2676eabe98cf))
* **release:** add comprehensive release body with install instructions ([9235505](https://github.com/ScopeCreep-zip/open-sesame/commit/9235505502bf096c6799fab6627af438b76e7490))
* **render:** add render context and pipeline ([d7ead27](https://github.com/ScopeCreep-zip/open-sesame/commit/d7ead27211018634161c18266827cb2d93d11227))
* **render:** add rendering primitives and color types ([690bb48](https://github.com/ScopeCreep-zip/open-sesame/commit/690bb48c434fc6940afa3c3f57d81be41fdfdca2))
* **render:** add text rendering with fontconfig ([5ae04bd](https://github.com/ScopeCreep-zip/open-sesame/commit/5ae04bdd1dbc07ff7b6c3627e081f149a04e405f))
* **ui:** add overlay window component ([b3d5f0d](https://github.com/ScopeCreep-zip/open-sesame/commit/b3d5f0db0de6cb8cbf9b8a4aa1987fcc74ce3929))
* **ui:** add theme configuration ([15cf44e](https://github.com/ScopeCreep-zip/open-sesame/commit/15cf44e4dbc99af1567a931e78130f6d6e6d6c13))
* **util:** add centralized logging handler ([6ca9619](https://github.com/ScopeCreep-zip/open-sesame/commit/6ca961989f9362642bb0a1f9aeb4605da4edbf43))
* **util:** add environment variable loading ([084ff82](https://github.com/ScopeCreep-zip/open-sesame/commit/084ff8286f88d488cc57082a5b61e5688d685bf1))
* **util:** add error types and result helpers ([efabbd3](https://github.com/ScopeCreep-zip/open-sesame/commit/efabbd300277074d88a023b896f6edbbbaaceac9))
* **util:** add instance lock for single-instance enforcement ([1ca174c](https://github.com/ScopeCreep-zip/open-sesame/commit/1ca174c5c88445582bad4c5dcacd783aa9d83c71))
* **util:** add IPC server and client ([c2f9c81](https://github.com/ScopeCreep-zip/open-sesame/commit/c2f9c818eabdbeb199996720704935e7e0f4ba2a))
* **util:** add MRU state persistence ([4c39ddd](https://github.com/ScopeCreep-zip/open-sesame/commit/4c39ddd3ea996b0f3f4c8f64d290eedd28c9c07b))
* **util:** add path utilities for XDG directories ([b3ce5c8](https://github.com/ScopeCreep-zip/open-sesame/commit/b3ce5c80264ee15b555c6e753133c262dad4339e))
* **util:** add timeout utilities ([9dc5f29](https://github.com/ScopeCreep-zip/open-sesame/commit/9dc5f2948775e1f0b656375a9df94e6dca24ce0a))

### 🐛 Bug Fixes

* **ci:** add bash -x tracing and fix SIGPIPE in apt-repo task ([4b2e5d9](https://github.com/ScopeCreep-zip/open-sesame/commit/4b2e5d9104f85f29044bea8be098045912703f21))
* **ci:** add rustfmt/clippy components and disable auto-install ([fbf4c10](https://github.com/ScopeCreep-zip/open-sesame/commit/fbf4c103e04f2b6ec65149f419098cd254dce5f7))
* **ci:** use install_args to install only required tools ([2a9b22a](https://github.com/ScopeCreep-zip/open-sesame/commit/2a9b22aea7edaf9fac8ba96217392a5e65538d07))
* **ci:** use npm install for semantic-release plugins ([774c79b](https://github.com/ScopeCreep-zip/open-sesame/commit/774c79bf4b43b97b35d3f95611fda589121d3a68))
* **ci:** use relative paths for apt repository filename field ([7d6a181](https://github.com/ScopeCreep-zip/open-sesame/commit/7d6a181121bedbced9f4851ff46b443feb401fec))
* **release:** use uname -m compatible package naming and fix badges ([b2d21d0](https://github.com/ScopeCreep-zip/open-sesame/commit/b2d21d03153df4075d8a9678593b51512408bcaa))

### 📚 Documentation

* add mdBook developer guide ([15bd764](https://github.com/ScopeCreep-zip/open-sesame/commit/15bd764f993657079499a67281cf97e8bd1f0308))
* add mdBook user guide ([b842be7](https://github.com/ScopeCreep-zip/open-sesame/commit/b842be7fa2e49e2f16942985ef581cbe33b71901))
* add project README ([839d5b1](https://github.com/ScopeCreep-zip/open-sesame/commit/839d5b148063dfa83e34910d4bea0755a09ff845))
* add security policy ([c9f9324](https://github.com/ScopeCreep-zip/open-sesame/commit/c9f9324b4c93ed9fdc5ae1544c6acb6bb0c00ac7))
* add source code architecture README ([176f535](https://github.com/ScopeCreep-zip/open-sesame/commit/176f53514eb7ffc57e0dbe6788e39669b53e4a9e))
* add versioning strategy documentation ([782a985](https://github.com/ScopeCreep-zip/open-sesame/commit/782a9856c4b885e616df3a7ae412a0ade34e05ef))

### ♻️ Code Refactoring

* **ci:** unify release workflow with semantic-release ([df140c7](https://github.com/ScopeCreep-zip/open-sesame/commit/df140c77cf78f5b47783741553cd11d153f0efbc))

### 📦 Build System

* add Cargo.lock for reproducible builds ([d8de7bc](https://github.com/ScopeCreep-zip/open-sesame/commit/d8de7bc57ff0043ae3a3ca61e3a3e16ce9b1c600))
* add Debian postinst script ([a883f81](https://github.com/ScopeCreep-zip/open-sesame/commit/a883f81f919f14bf2b5b95c3791fc3cfcb0e39c8))
* add mise task runner configuration ([c048c11](https://github.com/ScopeCreep-zip/open-sesame/commit/c048c11f1d39d269632ea7e291b628a64a67b439))
* add xtask for documentation generation ([39c70cd](https://github.com/ScopeCreep-zip/open-sesame/commit/39c70cd3f9b6a7114c33e7c7d1e726a1a09656fd))

### 👷 CI/CD

* add continuous integration workflow ([b8c1200](https://github.com/ScopeCreep-zip/open-sesame/commit/b8c1200f3dce430cc5eacc4c753b65761cc0ed31))
* add GitHub Pages template ([015a0e4](https://github.com/ScopeCreep-zip/open-sesame/commit/015a0e4c38460d51a10ff34d3b486d12d8acd0ce)), closes [#f4f4f4](https://github.com/ScopeCreep-zip/open-sesame/issues/f4f4f4) [#0066cc](https://github.com/ScopeCreep-zip/open-sesame/issues/0066cc) [#0055aa](https://github.com/ScopeCreep-zip/open-sesame/issues/0055aa)
* add release workflow with APT repository ([a2c8570](https://github.com/ScopeCreep-zip/open-sesame/commit/a2c857044d6815bdf6d20810991cae001bd7b0e2))
* migrate workflows to jdx/mise-action@v3 ([1d4b4b1](https://github.com/ScopeCreep-zip/open-sesame/commit/1d4b4b18ddf71eb72187b8615c56f8de3e118a0c))

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
gh attestation verify open-sesame_*.deb --owner ScopeCreep-zip
```

---

## 1.0.0 (2025-11-28)

### ✨ Features

* add CLI binary with argument parsing ([a336281](https://github.com/ScopeCreep-zip/open-sesame/commit/a336281e058674aa8a9362020f3084dc1e36d13f))
* add example configuration file ([594e1ec](https://github.com/ScopeCreep-zip/open-sesame/commit/594e1ec602139a9bffc3761c2d4d169cb0e752a6))
* add library crate with public API ([3a88754](https://github.com/ScopeCreep-zip/open-sesame/commit/3a887548f47b160f3612814435de93d467655b78))
* **app:** add application module exports ([511ece4](https://github.com/ScopeCreep-zip/open-sesame/commit/511ece4ca2d6ac7a7e899ea95ff5838bf4b79477))
* **app:** add application state machine ([3ea528d](https://github.com/ScopeCreep-zip/open-sesame/commit/3ea528dacd6f2889aa147ab167a9b39bb3b733b6))
* **app:** add frame renderer ([20cf2ec](https://github.com/ScopeCreep-zip/open-sesame/commit/20cf2eca903d8a32fabae3eb81610172a27e5ef2))
* **ci:** implement semantic-release for automated versioning ([b8777cc](https://github.com/ScopeCreep-zip/open-sesame/commit/b8777ccf7c8efc57aa1fc45e025f696ede6cd27a))
* **ci:** prepend install instructions to semantic-release notes ([ffa85db](https://github.com/ScopeCreep-zip/open-sesame/commit/ffa85dbc583e88f79fc1e7362939f7d4b2f60daf))
* **config:** add configuration loading and validation ([aa847a6](https://github.com/ScopeCreep-zip/open-sesame/commit/aa847a65d892d7a99cca8f84f6d5e5c7529260b3))
* **config:** add configuration schema and types ([55ad2c8](https://github.com/ScopeCreep-zip/open-sesame/commit/55ad2c8f87d4990527e1c3db5d68cd0d63e53b30)), closes [#b4a0ffb4](https://github.com/ScopeCreep-zip/open-sesame/issues/b4a0ffb4)
* **core:** add hint matching and filtering ([13a8bb5](https://github.com/ScopeCreep-zip/open-sesame/commit/13a8bb5ee41a1eb42aa9a75fce84676c1f9ec9e7))
* **core:** add hint sequence and assignment logic ([18d9060](https://github.com/ScopeCreep-zip/open-sesame/commit/18d90605ad6139cc604213547923b6e2d77dfaa5))
* **core:** add launch command abstraction ([992f80d](https://github.com/ScopeCreep-zip/open-sesame/commit/992f80d221ff37ee2ac38c551b90df9f307d8a01))
* **core:** add window and app identifier types ([15b0305](https://github.com/ScopeCreep-zip/open-sesame/commit/15b0305db1d4cea45644e6ba6e6f8b2fba24245f))
* **input:** add input buffer for typed characters ([e007486](https://github.com/ScopeCreep-zip/open-sesame/commit/e007486bfdc36a64c346af65b61048a0d8af76c6))
* **input:** add keyboard input processor ([f0b555b](https://github.com/ScopeCreep-zip/open-sesame/commit/f0b555becdc581631c1fad7075ebb41edac86459))
* **platform:** add COSMIC keybinding management ([a0ffd66](https://github.com/ScopeCreep-zip/open-sesame/commit/a0ffd665cd0e038dcc7c76390f33e2089d6d0dc7))
* **platform:** add COSMIC theme integration and font resolution ([fa18bbf](https://github.com/ScopeCreep-zip/open-sesame/commit/fa18bbfd30116e1bc3007cbc8e3c5608275ee8ad))
* **platform:** add Wayland protocol integration ([7b00982](https://github.com/ScopeCreep-zip/open-sesame/commit/7b0098210464330f3e726df7ac2c2676eabe98cf))
* **release:** add comprehensive release body with install instructions ([9235505](https://github.com/ScopeCreep-zip/open-sesame/commit/9235505502bf096c6799fab6627af438b76e7490))
* **render:** add render context and pipeline ([d7ead27](https://github.com/ScopeCreep-zip/open-sesame/commit/d7ead27211018634161c18266827cb2d93d11227))
* **render:** add rendering primitives and color types ([690bb48](https://github.com/ScopeCreep-zip/open-sesame/commit/690bb48c434fc6940afa3c3f57d81be41fdfdca2))
* **render:** add text rendering with fontconfig ([5ae04bd](https://github.com/ScopeCreep-zip/open-sesame/commit/5ae04bdd1dbc07ff7b6c3627e081f149a04e405f))
* **ui:** add overlay window component ([b3d5f0d](https://github.com/ScopeCreep-zip/open-sesame/commit/b3d5f0db0de6cb8cbf9b8a4aa1987fcc74ce3929))
* **ui:** add theme configuration ([15cf44e](https://github.com/ScopeCreep-zip/open-sesame/commit/15cf44e4dbc99af1567a931e78130f6d6e6d6c13))
* **util:** add centralized logging handler ([6ca9619](https://github.com/ScopeCreep-zip/open-sesame/commit/6ca961989f9362642bb0a1f9aeb4605da4edbf43))
* **util:** add environment variable loading ([084ff82](https://github.com/ScopeCreep-zip/open-sesame/commit/084ff8286f88d488cc57082a5b61e5688d685bf1))
* **util:** add error types and result helpers ([efabbd3](https://github.com/ScopeCreep-zip/open-sesame/commit/efabbd300277074d88a023b896f6edbbbaaceac9))
* **util:** add instance lock for single-instance enforcement ([1ca174c](https://github.com/ScopeCreep-zip/open-sesame/commit/1ca174c5c88445582bad4c5dcacd783aa9d83c71))
* **util:** add IPC server and client ([c2f9c81](https://github.com/ScopeCreep-zip/open-sesame/commit/c2f9c818eabdbeb199996720704935e7e0f4ba2a))
* **util:** add MRU state persistence ([4c39ddd](https://github.com/ScopeCreep-zip/open-sesame/commit/4c39ddd3ea996b0f3f4c8f64d290eedd28c9c07b))
* **util:** add path utilities for XDG directories ([b3ce5c8](https://github.com/ScopeCreep-zip/open-sesame/commit/b3ce5c80264ee15b555c6e753133c262dad4339e))
* **util:** add timeout utilities ([9dc5f29](https://github.com/ScopeCreep-zip/open-sesame/commit/9dc5f2948775e1f0b656375a9df94e6dca24ce0a))

### 🐛 Bug Fixes

* **ci:** add bash -x tracing and fix SIGPIPE in apt-repo task ([4b2e5d9](https://github.com/ScopeCreep-zip/open-sesame/commit/4b2e5d9104f85f29044bea8be098045912703f21))
* **ci:** add rustfmt/clippy components and disable auto-install ([fbf4c10](https://github.com/ScopeCreep-zip/open-sesame/commit/fbf4c103e04f2b6ec65149f419098cd254dce5f7))
* **ci:** use install_args to install only required tools ([2a9b22a](https://github.com/ScopeCreep-zip/open-sesame/commit/2a9b22aea7edaf9fac8ba96217392a5e65538d07))
* **ci:** use npm install for semantic-release plugins ([774c79b](https://github.com/ScopeCreep-zip/open-sesame/commit/774c79bf4b43b97b35d3f95611fda589121d3a68))
* **ci:** use relative paths for apt repository filename field ([7d6a181](https://github.com/ScopeCreep-zip/open-sesame/commit/7d6a181121bedbced9f4851ff46b443feb401fec))

### 📚 Documentation

* add mdBook developer guide ([15bd764](https://github.com/ScopeCreep-zip/open-sesame/commit/15bd764f993657079499a67281cf97e8bd1f0308))
* add mdBook user guide ([b842be7](https://github.com/ScopeCreep-zip/open-sesame/commit/b842be7fa2e49e2f16942985ef581cbe33b71901))
* add project README ([839d5b1](https://github.com/ScopeCreep-zip/open-sesame/commit/839d5b148063dfa83e34910d4bea0755a09ff845))
* add security policy ([c9f9324](https://github.com/ScopeCreep-zip/open-sesame/commit/c9f9324b4c93ed9fdc5ae1544c6acb6bb0c00ac7))
* add source code architecture README ([176f535](https://github.com/ScopeCreep-zip/open-sesame/commit/176f53514eb7ffc57e0dbe6788e39669b53e4a9e))
* add versioning strategy documentation ([782a985](https://github.com/ScopeCreep-zip/open-sesame/commit/782a9856c4b885e616df3a7ae412a0ade34e05ef))

### ♻️ Code Refactoring

* **ci:** unify release workflow with semantic-release ([df140c7](https://github.com/ScopeCreep-zip/open-sesame/commit/df140c77cf78f5b47783741553cd11d153f0efbc))

### 📦 Build System

* add Cargo.lock for reproducible builds ([d8de7bc](https://github.com/ScopeCreep-zip/open-sesame/commit/d8de7bc57ff0043ae3a3ca61e3a3e16ce9b1c600))
* add Debian postinst script ([a883f81](https://github.com/ScopeCreep-zip/open-sesame/commit/a883f81f919f14bf2b5b95c3791fc3cfcb0e39c8))
* add mise task runner configuration ([c048c11](https://github.com/ScopeCreep-zip/open-sesame/commit/c048c11f1d39d269632ea7e291b628a64a67b439))
* add xtask for documentation generation ([39c70cd](https://github.com/ScopeCreep-zip/open-sesame/commit/39c70cd3f9b6a7114c33e7c7d1e726a1a09656fd))

### 👷 CI/CD

* add continuous integration workflow ([b8c1200](https://github.com/ScopeCreep-zip/open-sesame/commit/b8c1200f3dce430cc5eacc4c753b65761cc0ed31))
* add GitHub Pages template ([015a0e4](https://github.com/ScopeCreep-zip/open-sesame/commit/015a0e4c38460d51a10ff34d3b486d12d8acd0ce)), closes [#f4f4f4](https://github.com/ScopeCreep-zip/open-sesame/issues/f4f4f4) [#0066cc](https://github.com/ScopeCreep-zip/open-sesame/issues/0066cc) [#0055aa](https://github.com/ScopeCreep-zip/open-sesame/issues/0055aa)
* add release workflow with APT repository ([a2c8570](https://github.com/ScopeCreep-zip/open-sesame/commit/a2c857044d6815bdf6d20810991cae001bd7b0e2))
* migrate workflows to jdx/mise-action@v3 ([1d4b4b1](https://github.com/ScopeCreep-zip/open-sesame/commit/1d4b4b18ddf71eb72187b8615c56f8de3e118a0c))

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
gh attestation verify open-sesame_*.deb --owner ScopeCreep-zip
```

---

## 1.0.0 (2025-11-28)

### ✨ Features

* add CLI binary with argument parsing ([a336281](https://github.com/ScopeCreep-zip/open-sesame/commit/a336281e058674aa8a9362020f3084dc1e36d13f))
* add example configuration file ([594e1ec](https://github.com/ScopeCreep-zip/open-sesame/commit/594e1ec602139a9bffc3761c2d4d169cb0e752a6))
* add library crate with public API ([3a88754](https://github.com/ScopeCreep-zip/open-sesame/commit/3a887548f47b160f3612814435de93d467655b78))
* **app:** add application module exports ([511ece4](https://github.com/ScopeCreep-zip/open-sesame/commit/511ece4ca2d6ac7a7e899ea95ff5838bf4b79477))
* **app:** add application state machine ([3ea528d](https://github.com/ScopeCreep-zip/open-sesame/commit/3ea528dacd6f2889aa147ab167a9b39bb3b733b6))
* **app:** add frame renderer ([20cf2ec](https://github.com/ScopeCreep-zip/open-sesame/commit/20cf2eca903d8a32fabae3eb81610172a27e5ef2))
* **ci:** implement semantic-release for automated versioning ([b8777cc](https://github.com/ScopeCreep-zip/open-sesame/commit/b8777ccf7c8efc57aa1fc45e025f696ede6cd27a))
* **ci:** prepend install instructions to semantic-release notes ([ffa85db](https://github.com/ScopeCreep-zip/open-sesame/commit/ffa85dbc583e88f79fc1e7362939f7d4b2f60daf))
* **config:** add configuration loading and validation ([aa847a6](https://github.com/ScopeCreep-zip/open-sesame/commit/aa847a65d892d7a99cca8f84f6d5e5c7529260b3))
* **config:** add configuration schema and types ([55ad2c8](https://github.com/ScopeCreep-zip/open-sesame/commit/55ad2c8f87d4990527e1c3db5d68cd0d63e53b30)), closes [#b4a0ffb4](https://github.com/ScopeCreep-zip/open-sesame/issues/b4a0ffb4)
* **core:** add hint matching and filtering ([13a8bb5](https://github.com/ScopeCreep-zip/open-sesame/commit/13a8bb5ee41a1eb42aa9a75fce84676c1f9ec9e7))
* **core:** add hint sequence and assignment logic ([18d9060](https://github.com/ScopeCreep-zip/open-sesame/commit/18d90605ad6139cc604213547923b6e2d77dfaa5))
* **core:** add launch command abstraction ([992f80d](https://github.com/ScopeCreep-zip/open-sesame/commit/992f80d221ff37ee2ac38c551b90df9f307d8a01))
* **core:** add window and app identifier types ([15b0305](https://github.com/ScopeCreep-zip/open-sesame/commit/15b0305db1d4cea45644e6ba6e6f8b2fba24245f))
* **input:** add input buffer for typed characters ([e007486](https://github.com/ScopeCreep-zip/open-sesame/commit/e007486bfdc36a64c346af65b61048a0d8af76c6))
* **input:** add keyboard input processor ([f0b555b](https://github.com/ScopeCreep-zip/open-sesame/commit/f0b555becdc581631c1fad7075ebb41edac86459))
* **platform:** add COSMIC keybinding management ([a0ffd66](https://github.com/ScopeCreep-zip/open-sesame/commit/a0ffd665cd0e038dcc7c76390f33e2089d6d0dc7))
* **platform:** add COSMIC theme integration and font resolution ([fa18bbf](https://github.com/ScopeCreep-zip/open-sesame/commit/fa18bbfd30116e1bc3007cbc8e3c5608275ee8ad))
* **platform:** add Wayland protocol integration ([7b00982](https://github.com/ScopeCreep-zip/open-sesame/commit/7b0098210464330f3e726df7ac2c2676eabe98cf))
* **release:** add comprehensive release body with install instructions ([9235505](https://github.com/ScopeCreep-zip/open-sesame/commit/9235505502bf096c6799fab6627af438b76e7490))
* **render:** add render context and pipeline ([d7ead27](https://github.com/ScopeCreep-zip/open-sesame/commit/d7ead27211018634161c18266827cb2d93d11227))
* **render:** add rendering primitives and color types ([690bb48](https://github.com/ScopeCreep-zip/open-sesame/commit/690bb48c434fc6940afa3c3f57d81be41fdfdca2))
* **render:** add text rendering with fontconfig ([5ae04bd](https://github.com/ScopeCreep-zip/open-sesame/commit/5ae04bdd1dbc07ff7b6c3627e081f149a04e405f))
* **ui:** add overlay window component ([b3d5f0d](https://github.com/ScopeCreep-zip/open-sesame/commit/b3d5f0db0de6cb8cbf9b8a4aa1987fcc74ce3929))
* **ui:** add theme configuration ([15cf44e](https://github.com/ScopeCreep-zip/open-sesame/commit/15cf44e4dbc99af1567a931e78130f6d6e6d6c13))
* **util:** add centralized logging handler ([6ca9619](https://github.com/ScopeCreep-zip/open-sesame/commit/6ca961989f9362642bb0a1f9aeb4605da4edbf43))
* **util:** add environment variable loading ([084ff82](https://github.com/ScopeCreep-zip/open-sesame/commit/084ff8286f88d488cc57082a5b61e5688d685bf1))
* **util:** add error types and result helpers ([efabbd3](https://github.com/ScopeCreep-zip/open-sesame/commit/efabbd300277074d88a023b896f6edbbbaaceac9))
* **util:** add instance lock for single-instance enforcement ([1ca174c](https://github.com/ScopeCreep-zip/open-sesame/commit/1ca174c5c88445582bad4c5dcacd783aa9d83c71))
* **util:** add IPC server and client ([c2f9c81](https://github.com/ScopeCreep-zip/open-sesame/commit/c2f9c818eabdbeb199996720704935e7e0f4ba2a))
* **util:** add MRU state persistence ([4c39ddd](https://github.com/ScopeCreep-zip/open-sesame/commit/4c39ddd3ea996b0f3f4c8f64d290eedd28c9c07b))
* **util:** add path utilities for XDG directories ([b3ce5c8](https://github.com/ScopeCreep-zip/open-sesame/commit/b3ce5c80264ee15b555c6e753133c262dad4339e))
* **util:** add timeout utilities ([9dc5f29](https://github.com/ScopeCreep-zip/open-sesame/commit/9dc5f2948775e1f0b656375a9df94e6dca24ce0a))

### 🐛 Bug Fixes

* **ci:** add bash -x tracing and fix SIGPIPE in apt-repo task ([4b2e5d9](https://github.com/ScopeCreep-zip/open-sesame/commit/4b2e5d9104f85f29044bea8be098045912703f21))
* **ci:** add rustfmt/clippy components and disable auto-install ([fbf4c10](https://github.com/ScopeCreep-zip/open-sesame/commit/fbf4c103e04f2b6ec65149f419098cd254dce5f7))
* **ci:** use install_args to install only required tools ([2a9b22a](https://github.com/ScopeCreep-zip/open-sesame/commit/2a9b22aea7edaf9fac8ba96217392a5e65538d07))
* **ci:** use npm install for semantic-release plugins ([774c79b](https://github.com/ScopeCreep-zip/open-sesame/commit/774c79bf4b43b97b35d3f95611fda589121d3a68))
* **ci:** use relative paths for apt repository filename field ([7d6a181](https://github.com/ScopeCreep-zip/open-sesame/commit/7d6a181121bedbced9f4851ff46b443feb401fec))

### 📚 Documentation

* add mdBook developer guide ([15bd764](https://github.com/ScopeCreep-zip/open-sesame/commit/15bd764f993657079499a67281cf97e8bd1f0308))
* add mdBook user guide ([b842be7](https://github.com/ScopeCreep-zip/open-sesame/commit/b842be7fa2e49e2f16942985ef581cbe33b71901))
* add project README ([839d5b1](https://github.com/ScopeCreep-zip/open-sesame/commit/839d5b148063dfa83e34910d4bea0755a09ff845))
* add security policy ([c9f9324](https://github.com/ScopeCreep-zip/open-sesame/commit/c9f9324b4c93ed9fdc5ae1544c6acb6bb0c00ac7))
* add source code architecture README ([176f535](https://github.com/ScopeCreep-zip/open-sesame/commit/176f53514eb7ffc57e0dbe6788e39669b53e4a9e))
* add versioning strategy documentation ([782a985](https://github.com/ScopeCreep-zip/open-sesame/commit/782a9856c4b885e616df3a7ae412a0ade34e05ef))

### 📦 Build System

* add Cargo.lock for reproducible builds ([d8de7bc](https://github.com/ScopeCreep-zip/open-sesame/commit/d8de7bc57ff0043ae3a3ca61e3a3e16ce9b1c600))
* add Debian postinst script ([a883f81](https://github.com/ScopeCreep-zip/open-sesame/commit/a883f81f919f14bf2b5b95c3791fc3cfcb0e39c8))
* add mise task runner configuration ([c048c11](https://github.com/ScopeCreep-zip/open-sesame/commit/c048c11f1d39d269632ea7e291b628a64a67b439))
* add xtask for documentation generation ([39c70cd](https://github.com/ScopeCreep-zip/open-sesame/commit/39c70cd3f9b6a7114c33e7c7d1e726a1a09656fd))

### 👷 CI/CD

* add continuous integration workflow ([b8c1200](https://github.com/ScopeCreep-zip/open-sesame/commit/b8c1200f3dce430cc5eacc4c753b65761cc0ed31))
* add GitHub Pages template ([015a0e4](https://github.com/ScopeCreep-zip/open-sesame/commit/015a0e4c38460d51a10ff34d3b486d12d8acd0ce)), closes [#f4f4f4](https://github.com/ScopeCreep-zip/open-sesame/issues/f4f4f4) [#0066cc](https://github.com/ScopeCreep-zip/open-sesame/issues/0066cc) [#0055aa](https://github.com/ScopeCreep-zip/open-sesame/issues/0055aa)
* add release workflow with APT repository ([a2c8570](https://github.com/ScopeCreep-zip/open-sesame/commit/a2c857044d6815bdf6d20810991cae001bd7b0e2))
* migrate workflows to jdx/mise-action@v3 ([1d4b4b1](https://github.com/ScopeCreep-zip/open-sesame/commit/1d4b4b18ddf71eb72187b8615c56f8de3e118a0c))

## 1.0.0 (2025-11-28)

### ✨ Features

* add CLI binary with argument parsing ([a336281](https://github.com/ScopeCreep-zip/open-sesame/commit/a336281e058674aa8a9362020f3084dc1e36d13f))
* add example configuration file ([594e1ec](https://github.com/ScopeCreep-zip/open-sesame/commit/594e1ec602139a9bffc3761c2d4d169cb0e752a6))
* add library crate with public API ([3a88754](https://github.com/ScopeCreep-zip/open-sesame/commit/3a887548f47b160f3612814435de93d467655b78))
* **app:** add application module exports ([511ece4](https://github.com/ScopeCreep-zip/open-sesame/commit/511ece4ca2d6ac7a7e899ea95ff5838bf4b79477))
* **app:** add application state machine ([3ea528d](https://github.com/ScopeCreep-zip/open-sesame/commit/3ea528dacd6f2889aa147ab167a9b39bb3b733b6))
* **app:** add frame renderer ([20cf2ec](https://github.com/ScopeCreep-zip/open-sesame/commit/20cf2eca903d8a32fabae3eb81610172a27e5ef2))
* **ci:** implement semantic-release for automated versioning ([b8777cc](https://github.com/ScopeCreep-zip/open-sesame/commit/b8777ccf7c8efc57aa1fc45e025f696ede6cd27a))
* **config:** add configuration loading and validation ([aa847a6](https://github.com/ScopeCreep-zip/open-sesame/commit/aa847a65d892d7a99cca8f84f6d5e5c7529260b3))
* **config:** add configuration schema and types ([55ad2c8](https://github.com/ScopeCreep-zip/open-sesame/commit/55ad2c8f87d4990527e1c3db5d68cd0d63e53b30)), closes [#b4a0ffb4](https://github.com/ScopeCreep-zip/open-sesame/issues/b4a0ffb4)
* **core:** add hint matching and filtering ([13a8bb5](https://github.com/ScopeCreep-zip/open-sesame/commit/13a8bb5ee41a1eb42aa9a75fce84676c1f9ec9e7))
* **core:** add hint sequence and assignment logic ([18d9060](https://github.com/ScopeCreep-zip/open-sesame/commit/18d90605ad6139cc604213547923b6e2d77dfaa5))
* **core:** add launch command abstraction ([992f80d](https://github.com/ScopeCreep-zip/open-sesame/commit/992f80d221ff37ee2ac38c551b90df9f307d8a01))
* **core:** add window and app identifier types ([15b0305](https://github.com/ScopeCreep-zip/open-sesame/commit/15b0305db1d4cea45644e6ba6e6f8b2fba24245f))
* **input:** add input buffer for typed characters ([e007486](https://github.com/ScopeCreep-zip/open-sesame/commit/e007486bfdc36a64c346af65b61048a0d8af76c6))
* **input:** add keyboard input processor ([f0b555b](https://github.com/ScopeCreep-zip/open-sesame/commit/f0b555becdc581631c1fad7075ebb41edac86459))
* **platform:** add COSMIC keybinding management ([a0ffd66](https://github.com/ScopeCreep-zip/open-sesame/commit/a0ffd665cd0e038dcc7c76390f33e2089d6d0dc7))
* **platform:** add COSMIC theme integration and font resolution ([fa18bbf](https://github.com/ScopeCreep-zip/open-sesame/commit/fa18bbfd30116e1bc3007cbc8e3c5608275ee8ad))
* **platform:** add Wayland protocol integration ([7b00982](https://github.com/ScopeCreep-zip/open-sesame/commit/7b0098210464330f3e726df7ac2c2676eabe98cf))
* **release:** add comprehensive release body with install instructions ([9235505](https://github.com/ScopeCreep-zip/open-sesame/commit/9235505502bf096c6799fab6627af438b76e7490))
* **render:** add render context and pipeline ([d7ead27](https://github.com/ScopeCreep-zip/open-sesame/commit/d7ead27211018634161c18266827cb2d93d11227))
* **render:** add rendering primitives and color types ([690bb48](https://github.com/ScopeCreep-zip/open-sesame/commit/690bb48c434fc6940afa3c3f57d81be41fdfdca2))
* **render:** add text rendering with fontconfig ([5ae04bd](https://github.com/ScopeCreep-zip/open-sesame/commit/5ae04bdd1dbc07ff7b6c3627e081f149a04e405f))
* **ui:** add overlay window component ([b3d5f0d](https://github.com/ScopeCreep-zip/open-sesame/commit/b3d5f0db0de6cb8cbf9b8a4aa1987fcc74ce3929))
* **ui:** add theme configuration ([15cf44e](https://github.com/ScopeCreep-zip/open-sesame/commit/15cf44e4dbc99af1567a931e78130f6d6e6d6c13))
* **util:** add centralized logging handler ([6ca9619](https://github.com/ScopeCreep-zip/open-sesame/commit/6ca961989f9362642bb0a1f9aeb4605da4edbf43))
* **util:** add environment variable loading ([084ff82](https://github.com/ScopeCreep-zip/open-sesame/commit/084ff8286f88d488cc57082a5b61e5688d685bf1))
* **util:** add error types and result helpers ([efabbd3](https://github.com/ScopeCreep-zip/open-sesame/commit/efabbd300277074d88a023b896f6edbbbaaceac9))
* **util:** add instance lock for single-instance enforcement ([1ca174c](https://github.com/ScopeCreep-zip/open-sesame/commit/1ca174c5c88445582bad4c5dcacd783aa9d83c71))
* **util:** add IPC server and client ([c2f9c81](https://github.com/ScopeCreep-zip/open-sesame/commit/c2f9c818eabdbeb199996720704935e7e0f4ba2a))
* **util:** add MRU state persistence ([4c39ddd](https://github.com/ScopeCreep-zip/open-sesame/commit/4c39ddd3ea996b0f3f4c8f64d290eedd28c9c07b))
* **util:** add path utilities for XDG directories ([b3ce5c8](https://github.com/ScopeCreep-zip/open-sesame/commit/b3ce5c80264ee15b555c6e753133c262dad4339e))
* **util:** add timeout utilities ([9dc5f29](https://github.com/ScopeCreep-zip/open-sesame/commit/9dc5f2948775e1f0b656375a9df94e6dca24ce0a))

### 🐛 Bug Fixes

* **ci:** add bash -x tracing and fix SIGPIPE in apt-repo task ([4b2e5d9](https://github.com/ScopeCreep-zip/open-sesame/commit/4b2e5d9104f85f29044bea8be098045912703f21))
* **ci:** add rustfmt/clippy components and disable auto-install ([fbf4c10](https://github.com/ScopeCreep-zip/open-sesame/commit/fbf4c103e04f2b6ec65149f419098cd254dce5f7))
* **ci:** use install_args to install only required tools ([2a9b22a](https://github.com/ScopeCreep-zip/open-sesame/commit/2a9b22aea7edaf9fac8ba96217392a5e65538d07))
* **ci:** use npm install for semantic-release plugins ([774c79b](https://github.com/ScopeCreep-zip/open-sesame/commit/774c79bf4b43b97b35d3f95611fda589121d3a68))
* **ci:** use relative paths for apt repository filename field ([7d6a181](https://github.com/ScopeCreep-zip/open-sesame/commit/7d6a181121bedbced9f4851ff46b443feb401fec))

### 📚 Documentation

* add mdBook developer guide ([15bd764](https://github.com/ScopeCreep-zip/open-sesame/commit/15bd764f993657079499a67281cf97e8bd1f0308))
* add mdBook user guide ([b842be7](https://github.com/ScopeCreep-zip/open-sesame/commit/b842be7fa2e49e2f16942985ef581cbe33b71901))
* add project README ([839d5b1](https://github.com/ScopeCreep-zip/open-sesame/commit/839d5b148063dfa83e34910d4bea0755a09ff845))
* add security policy ([c9f9324](https://github.com/ScopeCreep-zip/open-sesame/commit/c9f9324b4c93ed9fdc5ae1544c6acb6bb0c00ac7))
* add source code architecture README ([176f535](https://github.com/ScopeCreep-zip/open-sesame/commit/176f53514eb7ffc57e0dbe6788e39669b53e4a9e))
* add versioning strategy documentation ([782a985](https://github.com/ScopeCreep-zip/open-sesame/commit/782a9856c4b885e616df3a7ae412a0ade34e05ef))

### 📦 Build System

* add Cargo.lock for reproducible builds ([d8de7bc](https://github.com/ScopeCreep-zip/open-sesame/commit/d8de7bc57ff0043ae3a3ca61e3a3e16ce9b1c600))
* add Debian postinst script ([a883f81](https://github.com/ScopeCreep-zip/open-sesame/commit/a883f81f919f14bf2b5b95c3791fc3cfcb0e39c8))
* add mise task runner configuration ([c048c11](https://github.com/ScopeCreep-zip/open-sesame/commit/c048c11f1d39d269632ea7e291b628a64a67b439))
* add xtask for documentation generation ([39c70cd](https://github.com/ScopeCreep-zip/open-sesame/commit/39c70cd3f9b6a7114c33e7c7d1e726a1a09656fd))

### 👷 CI/CD

* add continuous integration workflow ([b8c1200](https://github.com/ScopeCreep-zip/open-sesame/commit/b8c1200f3dce430cc5eacc4c753b65761cc0ed31))
* add GitHub Pages template ([015a0e4](https://github.com/ScopeCreep-zip/open-sesame/commit/015a0e4c38460d51a10ff34d3b486d12d8acd0ce)), closes [#f4f4f4](https://github.com/ScopeCreep-zip/open-sesame/issues/f4f4f4) [#0066cc](https://github.com/ScopeCreep-zip/open-sesame/issues/0066cc) [#0055aa](https://github.com/ScopeCreep-zip/open-sesame/issues/0055aa)
* add release workflow with APT repository ([a2c8570](https://github.com/ScopeCreep-zip/open-sesame/commit/a2c857044d6815bdf6d20810991cae001bd7b0e2))
* migrate workflows to jdx/mise-action@v3 ([1d4b4b1](https://github.com/ScopeCreep-zip/open-sesame/commit/1d4b4b18ddf71eb72187b8615c56f8de3e118a0c))
