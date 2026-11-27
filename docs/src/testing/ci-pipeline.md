# CI Pipeline

Open Sesame uses four GitHub Actions workflows for testing, documentation, release, and Nix builds.

## Workflow Overview

| Workflow | File | Triggers | Purpose |
| --- | --- | --- | --- |
| Test | `test.yml` | Push to main/master, PRs | Format check, clippy, tests, and debug build on dual architectures; QA checks; package install in systemd containers; lifecycle under the shipped units; PKGBUILD lint |
| Docs | `docs.yml` | Push to main/master, PRs | Build rustdoc and mdBook |
| Release | `release.yml` | Push to main, manual dispatch | Semantic-release, build, attest, publish |
| Nix | `nix.yml` | Called by release.yml, PRs | Build Nix packages and push to Cachix |

## test.yml

The test workflow runs on every push to `main`/`master` and on pull requests targeting those
branches.

### Dual-Architecture Matrix

```yaml
matrix:
  include:
    - arch: amd64
      runner: ubuntu-24.04
    - arch: arm64
      runner: ubuntu-24.04-arm
```

Both runners use Ubuntu 24.04. ARM builds use GitHub's native `ubuntu-24.04-arm` runner (not
emulation).

### Execution

1. Checks out the repository.
2. Installs the Rust toolchain via `jdx/mise-action@v4` with caching enabled.
3. Raises `RLIMIT_MEMLOCK` to 256 MiB with
   `sudo prlimit --pid $$ --memlock=268435456:268435456`. This is required because `ProtectedAlloc`
   uses `mlock` to pin secret-holding memory pages.
4. Runs `mise run ci:test`: `cargo:fmt:check`, `cargo:clippy`
   (`--all-targets --all-features -D warnings`), `cargo:test`, and `cargo:build:debug`.

The `MISE_AUTO_INSTALL` environment variable is set to `"false"` to prevent automatic tool
installation outside the explicit `mise-action` step.

### QA Job

The `qa` job runs on `ubuntu-24.04`. It installs Nix via `cachix/install-nix-action@v31`, reads
the `scopecreep-zip` Cachix cache, and runs `nix develop --accept-flake-config -c mise run ci:qa`.
`ci:qa` depends on `qa:toml`, `qa:markdown`, `qa:links` (offline), `qa:shell`, and `qa:actions`.
Their tools (taplo, markdownlint-cli2, lychee, shellcheck, shfmt, actionlint) and mise itself come
from the flake devshell, so mise installs nothing.

`MISE_TRUSTED_CONFIG_PATHS` is set to the checkout: mise refuses an untrusted `.mise.toml`, and a
fresh runner has trusted nothing.

### PKGBUILD Lint Job

The `lint-pkgbuild` job runs `scripts/arch/lint-pkgbuild.sh` (namcap) in an
`archlinux:base-devel` container.

### Install Job

The `install` job builds each amd64 package as the release builds it (`ci:build:deb`,
`ci:build:rpm`, `ci:build:arch`) and runs `scripts/docker/verify-install.sh` on it: the
distribution's compose service (`ubuntu-local`, `fedora-local`, `arch-local`; systemd as PID 1, a
lingering user) installs the headless package, and `scripts/docker/post-install.sh` starts
`open-sesame-headless.target` and `sesame-init.service`. The job fails unless every headless daemon
is active under its installed unit, the default vault is unlocked, and no doctor check fails
(`sesame status --doctor --exit-code` exit 1; warnings, exit 2, are reported and accepted). On
failure the container's system and user journals are printed. The release workflow runs only after
this workflow succeeds, so no version is tagged whose packages do not start.

### Nix Job

The `nix` job runs `mise run test:nix` (`nix flake check`) in the flake devshell: the flake is
evaluated, both packages are built, and `checks.x86_64-linux.home-manager-module` checks the Home
Manager module against the units the packages ship (see [Nix Packaging](../packaging/nix.md)).

### Lifecycle Job

The `lifecycle` job runs `tests/protocol_validation.sh` (`mise run test:lifecycle`, in the flake
devshell) on `ubuntu-24.04`: every daemon runs as a transient service of the runner user's service
manager (started by `loginctl enable-linger`) under the `[Service]` sandboxing of its shipped unit,
against a headless sway (`WLR_BACKENDS=headless`), on the runner's own kernel. A daemon that fails
to start under its unit fails the job. The lefthook pre-push hook runs the same task; it needs a
Wayland session and the user's service manager, and exits 2 without them.

## docs.yml

The docs workflow runs on pushes and PRs to `main`/`master`. It runs on `ubuntu-latest` (single
architecture).

1. Checks out the repository.
2. Installs Nix and the `scopecreep-zip` Cachix cache.
3. Runs `mise run ci:docs` in the flake devshell, which provides the toolchain, the system
   libraries, and mdbook.

This workflow validates that documentation builds succeed but does not deploy. Deployment occurs in
the release workflow's `build-docs` and `publish` jobs.

## release.yml

The release workflow is the primary CI/CD pipeline. It triggers on pushes to `main` and supports
manual dispatch with a `dry-run` option.

### Permissions

The workflow declares the following permissions:

- `contents: write` -- GitHub release creation, version commits
- `pages: write` -- GitHub Pages deployment
- `id-token: write` -- OIDC tokens for Pages and attestations
- `attestations: write` -- SLSA build provenance
- `issues: write`, `pull-requests: write` -- semantic-release comments

### Job Dependency Graph

```text
semantic-release ──┬──► build / build-rpm / build-arch ──┬──► attest
                   │                                    ├──► verify-packages ──┐
                   │                                    └──────────────────────┴──► upload-assets
                   ├──► nix-cache
                   ├──► build-docs
                   │
                   └──► [builds + verify-packages + upload-assets + build-docs] ──► publish ──► cleanup
```

All jobs after `semantic-release` are gated on `new_release == 'true'`. `verify-packages` installs
the release's own amd64 `.deb`, `.rpm`, and `.pkg.tar.zst` artifacts with
`scripts/docker/verify-install.sh`, as the Test workflow's `install` job does; `upload-assets` and
`publish` depend on it, so no asset or repository is published for a package that does not start.

### Build Job

The build job uses the same dual-architecture matrix as the test workflow. It installs `rust` and
`cargo:cargo-deb` via mise, raises the memlock limit, and runs architecture-specific mise tasks:

| Architecture | Build Task | Rename Task |
| --- | --- | --- |
| amd64 | `ci:build:deb` | `ci:release:rename-deb` |
| arm64 | `ci:build:deb:arm64` | `ci:release:rename-deb:arm64` |

The rename task adds architecture suffixes to the `.deb` filenames. Artifacts are uploaded with
1-day retention.

### Nix Cache Job

Calls the reusable `nix.yml` workflow, passing the release tag and the
`SCOPE_CREEP_CACHIX_PRIVATE_KEY` secret.

### Build Docs Job

Checks out the release tag, runs `mise run ci:docs:all` and `mise run ci:docs:combine` to produce
a combined rustdoc and mdBook site. The result is uploaded as a `documentation` artifact.

### Publish Job

The publish job:

1. Downloads `.deb` artifacts and documentation.
2. Imports the GPG signing key via `crazy-max/ghaction-import-gpg@v6`.
3. Runs `mise run ci:release:apt-repo` to generate the signed APT repository.
4. Deploys the combined APT repository and documentation to GitHub Pages via
   `actions/deploy-pages@v5`.

This job runs in the `github-pages` environment.

## nix.yml

The Nix workflow serves dual purposes:

- **Reusable workflow**: called by `release.yml` with a tag input to build and push release
  artifacts to Cachix.
- **Standalone PR workflow**: runs on PRs to `main` for cache warming (builds packages but the
  Cachix action only pushes when the auth token is available).

### Matrix

```yaml
matrix:
  include:
    - system: x86_64-linux
      runner: ubuntu-24.04
    - system: aarch64-linux
      runner: ubuntu-24.04-arm
```

### Execution

1. Checks out at the specified tag (or current ref for PRs).
2. Installs Nix via `cachix/install-nix-action@v31`.
3. Configures Cachix via `cachix/cachix-action@v15` with the `scopecreep-zip` cache name.
4. Raises the memlock limit.
5. Builds both `open-sesame` and `open-sesame-desktop` for the matrix system with
   `--accept-flake-config -L`.

## Mise Task Runner

All workflows run tasks through mise. Except for the `qa` job, which takes every tool from the Nix
devshell, they install tools with `jdx/mise-action@v4`. Mise manages:

- Rust toolchain version (from `rust-toolchain.toml` or mise config)
- Node.js (for semantic-release in the release workflow)
- `cargo-deb` (for `.deb` packaging in the build job)

Task names follow the convention `ci:<category>:<action>` (e.g., `ci:test`, `ci:build:deb`,
`ci:docs:all`, `ci:release:apt-repo`).

## Environment Variables

| Variable | Value | Purpose |
| --- | --- | --- |
| `CARGO_TERM_COLOR` | `always` | Colored cargo output in CI logs |
| `MISE_AUTO_INSTALL` | `false` | Prevent implicit tool installation |
| `MISE_TRUSTED_CONFIG_PATHS` | `${{ github.workspace }}` (`qa` job) | Trust the repository's `.mise.toml` |
