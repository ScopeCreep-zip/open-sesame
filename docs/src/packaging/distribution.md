# Distribution

Open Sesame uses semantic-release for automated versioning, GitHub Actions for building, SLSA
attestations for supply chain security, and GitHub Pages for hosting APT and DNF repositories
alongside documentation.

## Semantic Release

Version management is configured in `release.config.mjs`. Semantic-release runs on pushes to `main`
and analyzes conventional commits to determine version bumps.

### Release Rules

| Commit type | Release |
|-------------|---------|
| `feat` | minor |
| `fix` | patch |
| `perf` | patch |
| `revert` | patch |
| `docs` (scope: README) | patch |
| `refactor`, `style`, `chore`, `test`, `build`, `ci` | no release |
| Any scope `no-release` | no release |

### Plugin Pipeline

The semantic-release plugin chain executes in order:

1. **`@semantic-release/commit-analyzer`** -- Analyzes commits using the `conventionalcommits`
   preset to determine the version bump type.
2. **`@semantic-release/exec`** -- Generates a release header from
   `.github/templates/RELEASE_HEADER.md`.
3. **`@semantic-release/release-notes-generator`** -- Generates release notes from commits,
   categorized by type.
4. **`@semantic-release/changelog`** -- Updates `CHANGELOG.md`.
5. **`@semantic-release/exec`** -- Updates the `[workspace.package]` version in `Cargo.toml` using
   `sed`, then runs `cargo generate-lockfile` to update `Cargo.lock`.
6. **`@semantic-release/git`** -- Commits `CHANGELOG.md`, `Cargo.toml`, and `Cargo.lock` with
   message `chore(release): <version> [skip ci]`.
7. **`@semantic-release/github`** -- Creates the GitHub release.

## Release Pipeline DAG

The release workflow (`release.yml`) runs on pushes to `main` and defines the following job
dependency graph:

```text
semantic-release
├── build (amd64)        ─┐
├── build (arm64)        ─┤
├── build-rpm (amd64)    ─┼──► attest
├── build-rpm (arm64)    ─┤
├── build-arch (amd64)   ─┤
├── build-arch (arm64)   ─┤
│                         └──► upload-assets ──► aur-publish
├── nix-cache
├── build-docs
│
└── [all above] ─────────────► publish ──► cleanup
```

All downstream jobs gate on `needs.semantic-release.outputs.new_release == 'true'`. If
semantic-release determines no version bump is needed, the pipeline stops after the first job.

### Job Details

**semantic-release**: Checks out with `fetch-depth: 0`, installs Node.js via mise, runs
`npx semantic-release`. Outputs `new_release`, `version`, and `tag`.

**build**: Runs on a dual-architecture matrix (`ubuntu-24.04` for amd64, `ubuntu-24.04-arm` for
arm64). Installs Rust and `cargo-deb` via mise. Raises `RLIMIT_MEMLOCK` to 256 MiB with `prlimit`
before building (required by `ProtectedAlloc`). Builds `.deb` packages via mise tasks
(`ci:build:deb` / `ci:build:deb:arm64`), renames them with architecture suffixes, and uploads as
artifacts.

**nix-cache**: Calls the reusable `nix.yml` workflow with the release tag. Builds both `open-sesame`
and `open-sesame-desktop` for each architecture and pushes to Cachix.

**build-docs**: Builds rustdoc and mdBook documentation via `mise run ci:docs:all` and
`mise run ci:docs:combine`, then uploads as an artifact.

**build-rpm**: Runs on the same dual-architecture matrix as the deb build. Installs Rust and
`cargo-generate-rpm` via mise. Builds `.rpm` packages via mise tasks (`ci:build:rpm` /
`ci:build:rpm:arm64`), renames them with architecture suffixes, and uploads as artifacts.

**build-arch**: Runs on the same dual-architecture matrix. Installs `makepkg` and
`pacman-package-manager` from Ubuntu universe. Builds release tarballs via
`scripts/arch/build-tarball.sh`, then `.pkg.tar.zst` packages via `scripts/arch/build-pkg.sh`
using Ubuntu's native `makepkg` with `CARCH` and `PKGEXT` environment overrides.

**attest**: Downloads `SHA256SUMS.txt` from the GitHub Release (produced by `upload-assets`)
and generates SLSA build provenance attestations via `actions/attest@v4` with
`subject-checksums`. Covers all artifact formats in a single attestation.

**upload-assets**: Downloads `.deb`, `.rpm`, `.tar.gz`, and `.pkg.tar.zst` artifacts, generates
`SHA256SUMS.txt` covering all packages, renders install instructions from a template with
per-architecture checksums for all formats, and uploads everything to the GitHub release.

**publish**: Downloads all artifacts and documentation, imports the GPG signing key,
generates the APT repository via `mise run ci:release:apt-repo`, the DNF repository via
`mise run ci:release:rpm-repo`, and the pacman repository via `mise run ci:release:arch-repo`.
Merges all repository trees with documentation into a single
`gh-pages/` directory, and deploys to GitHub Pages. Includes post-deploy verification polling
for both APT `Release` and RPM `repomd.xml` endpoints. The publish job has a 30-minute timeout
and runs within a `pages-deploy` concurrency group with `cancel-in-progress: false` to prevent
mid-deploy corruption.

**cleanup**: Deletes old releases, keeping the 10 most recent. Uses
`dev-drprasad/delete-older-releases@v0.3.4`. Tags are preserved.

## APT Repository

The APT repository is hosted on GitHub Pages and generated by the `ci:release:apt-repo` mise task
during the publish job. See [Debian Packaging](deb.md) for details.

## DNF Repository

The DNF repository is hosted on GitHub Pages alongside the APT repository, generated by the
`ci:release:rpm-repo` mise task during the publish job. The process:

1. Installs `createrepo-c` from Ubuntu's universe repository.
2. Copies `.rpm` packages into `rpm-site/repo/`.
3. Signs packages using `rpmsign` inside a Fedora container when `GPG_PRIVATE_KEY` is set.
4. Runs `createrepo_c` to generate `repodata/` metadata.
5. Generates `manifest.txt` and HTML index via `scripts/rpm/generate-repo-index.sh`.
6. Merges `rpm-site/` into the `gh-pages/` tree alongside APT and documentation.

See [RPM Packaging](rpm.md) for client configuration, scriptlet semantics, and verification.

## Repository Hosting

Both APT and DNF repositories share a single GitHub Pages site. The process:

1. Downloads all `.deb` artifacts into a `packages/` directory.
2. Imports the GPG private key (`GPG_PRIVATE_KEY` secret) using
   `crazy-max/ghaction-import-gpg@v6`.
3. Generates the `Packages` index and signs the repository with GPG.
4. Combines the APT repository with the documentation site into a single `gh-pages/` directory.
5. Deploys to GitHub Pages using `actions/deploy-pages@v5`.

The publish job runs in the `github-pages` environment and requires `pages: write` and
`id-token: write` permissions.

## SLSA Build Provenance

Every `.deb` and `.rpm` artifact receives a SLSA build provenance attestation generated by
`actions/attest@v4`. This runs in the `attest` job after both deb and rpm builds
complete. The workflow declares `attestations: write` permission at the top level.

Attestations provide a cryptographic link between each package file and its GitHub Actions build,
allowing consumers to verify that artifacts were produced by the CI pipeline and not tampered with.

## Checksum Verification

The `upload-assets` job generates `SHA256SUMS.txt` containing SHA-256 hashes for all `.deb` and
`.rpm` files:

```bash
sha256sum ./*.deb ./*.rpm > SHA256SUMS.txt
```

The checksums file is uploaded alongside the packages to the GitHub release. Per-architecture
checksums for both formats are interpolated into the release body template for inline verification
instructions.

## Workflow Permissions

The release workflow requests the following permissions:

| Permission | Purpose |
|-----------|---------|
| `contents: write` | Create GitHub releases, push version commits |
| `pages: write` | Deploy APT + DNF repos and docs to GitHub Pages |
| `id-token: write` | OIDC token for Pages deployment and attestations |
| `attestations: write` | SLSA build provenance |
| `issues: write` | Semantic-release issue comments |
| `pull-requests: write` | Semantic-release PR comments |
