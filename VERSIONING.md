# Versioning Strategy

This document describes the consolidated versioning strategy for the open-sesame project, designed to minimize
manual version management and support semantic-release automation.

## Philosophy

**Single Source of Truth:** The version is managed in ONE place only - `Cargo.toml` `[package] version = "X.Y.Z"`.

All other version references are either:

- **Derived automatically** from Cargo.toml
- **Version-neutral** (documentation that doesn't mention specific versions)

## Version Sources

### Primary (Single Source of Truth)

| File | Field | Managed By |
| --- | --- | --- |
| `Cargo.toml` | `[package] version` | semantic-release |

This is the ONLY file that semantic-release needs to update.

### Derived (Automatic)

These automatically derive their version from `Cargo.toml`:

| Component | Source | How |
| --- | --- | --- |
| CLI binary (`sesame --version`) | Cargo.toml | Cargo's `CARGO_PKG_VERSION` env var at compile time |
| Man pages | Cargo.toml | xtask renders `open_sesame::cli::Cli`, whose `version` is `CARGO_PKG_VERSION` |
| Shell completions | Cargo.toml | xtask renders `open_sesame::cli::Cli`, whose `version` is `CARGO_PKG_VERSION` |
| Debian packages (.deb) | Cargo.toml | cargo-deb reads from `[package] version` |

### Version-Neutral (No Specific Version)

Documentation has been updated to be version-neutral:

| File | Change |
| --- | --- |
| `README.md` | Version badge uses GitHub releases API (auto-updates) |
| `README.md` | Download URLs use `/latest/` pattern (no version in filename) |
| `docs/src/**/*.md` | All version badges use GitHub API or removed |
| `docs/src/**/*.md` | All examples show `X.Y.Z` instead of specific versions |

### Reference Only

| File | Field | Purpose |
| --- | --- | --- |
| `.mise.toml` | `vars.ver` | Reference only - NOT used in any tasks |

## Semantic Release Configuration

### Files to Update

semantic-release should ONLY update:

```json
{
  "plugins": [
    [
      "@semantic-release/exec",
      {
        "prepareCmd": "sed -i 's/^version = \".*\"/version = \"${nextRelease.version}\"/' Cargo.toml"
      }
    ]
  ]
}
```

### Why Only Cargo.toml?

1. **CLI binary version** - Automatically uses `CARGO_PKG_VERSION` from Cargo.toml
2. **Man pages** - Rendered by xtask from the CLI definition, carrying `CARGO_PKG_VERSION`
3. **Shell completions** - Rendered by xtask from the CLI definition, carrying `CARGO_PKG_VERSION`
4. **Debian packages** - Built by cargo-deb which reads Cargo.toml
5. **Documentation** - Version-neutral or uses dynamic badges

## Release Workflow

### Automated Release Process

1. **Commit changes** to main branch
2. **semantic-release analyzes** commits for version bump type (major/minor/patch)
3. **semantic-release updates** `Cargo.toml` version field
4. **CI builds** documentation (man pages, completions) with new version
5. **CI builds** release binary and .deb packages
6. **CI creates** GitHub release with version from Cargo.toml

### Manual Verification

After semantic-release updates the version:

```bash
# Verify version is consistent everywhere
grep "version.*1\.0\.0" Cargo.toml
mise run docs:man && head -3 target/man/sesame.1
cargo build --release && ./target/release/sesame --version
```

All should show the same version from Cargo.toml.

## Implementation Details

### Man Page and Completion Version

xtask is a workspace member that depends on the `open-sesame` library and
renders `open_sesame::cli::Cli::command()`, the same definition the `sesame`
binary parses with. `#[command(version)]` expands to the workspace
`CARGO_PKG_VERSION` at compile time, so the man page, the completions, and
`sesame --version` carry one version and document one command tree.

### GitHub Release Asset Naming

Release assets should use version-neutral names for `/latest/` downloads:

**Correct:**

```text
open-sesame_amd64.deb
open-sesame_arm64.deb
```

**Incorrect (requires version-specific URLs):**

```text
open-sesame_1.0.0_amd64.deb
open-sesame_1.0.0_arm64.deb
```

## Validation Checklist

After a version bump, verify:

- [ ] `Cargo.toml` shows new version
- [ ] `sesame --version` shows new version
- [ ] Man page header shows new version (`man sesame` or `target/man/sesame.1`)
- [ ] GitHub release has correct version tag
- [ ] .deb package filename contains version
- [ ] Documentation builds without errors

## Troubleshooting

### Version Mismatch

If you see different versions:

1. **Check Cargo.toml** - This is the source of truth
2. **Regenerate docs** - `mise run docs:man`
3. **Rebuild binary** - `cargo build --release`
4. **Check build cache** - Clear if needed: `cargo clean`

### semantic-release Not Updating

Verify:

- Commit messages follow conventional commits format
- `Cargo.toml` is in the repository root
- sed command has correct path: `Cargo.toml` (not `./Cargo.toml`)

## Future Considerations

### Additional Automation Opportunities

- **Changelog generation** - Could auto-generate from commits
- **Release notes** - Could extract from CHANGELOG.md
- **Version badges** - Already using GitHub API (auto-updates)

### DO NOT Add Version To

- Configuration files (config.toml)
- Shell scripts
- GitHub workflows (use `${{ github.ref_name }}` instead)
- Documentation content (use X.Y.Z placeholders or dynamic badges)

## Summary

**One version to rule them all:** `Cargo.toml`

Everything else derives from it or is version-neutral.

semantic-release updates exactly ONE line in ONE file, and the entire project stays consistent.
