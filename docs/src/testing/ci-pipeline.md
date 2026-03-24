# CI Pipeline

Open Sesame uses four GitHub Actions workflows for testing, documentation, release, and Nix builds.

## Workflow Overview

| Workflow | File | Triggers | Purpose |
|----------|------|----------|---------|
| Test | `test.yml` | Push to main/master, PRs | Run `cargo test` on dual architectures |
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
4. Runs `mise run ci:test`.

The `MISE_AUTO_INSTALL` environment variable is set to `"false"` to prevent automatic tool
installation outside the explicit `mise-action` step.

## docs.yml

The docs workflow runs on pushes and PRs to `main`/`master`. It runs on `ubuntu-latest` (single
architecture).

1. Checks out the repository.
2. Installs Rust via mise with caching.
3. Runs `mise run ci:docs` to build documentation.

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
semantic-release ──┬──► build (amd64)  ──┬──► attest
                   ├──► build (arm64)  ──┤
                   │                     └──► upload-assets
                   ├──► nix-cache
                   ├──► build-docs
                   │
                   └──► [build + upload-assets + build-docs] ──► publish ──► cleanup
```

All jobs after `semantic-release` are gated on `new_release == 'true'`.

### Build Job

The build job uses the same dual-architecture matrix as the test workflow. It installs `rust` and
`cargo:cargo-deb` via mise, raises the memlock limit, and runs architecture-specific mise tasks:

| Architecture | Build Task | Rename Task |
|-------------|-----------|-------------|
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

All workflows use `jdx/mise-action@v4` to install tools and run tasks. Mise manages:

- Rust toolchain version (from `rust-toolchain.toml` or mise config)
- Node.js (for semantic-release in the release workflow)
- `cargo-deb` (for `.deb` packaging in the build job)

Task names follow the convention `ci:<category>:<action>` (e.g., `ci:test`, `ci:build:deb`,
`ci:docs:all`, `ci:release:apt-repo`).

## Environment Variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `CARGO_TERM_COLOR` | `always` | Colored cargo output in CI logs |
| `MISE_AUTO_INSTALL` | `false` | Prevent implicit tool installation |
