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
