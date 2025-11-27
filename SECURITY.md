# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Package Verification

### GPG Signature Verification

All APT repository indices are signed with our GPG key:

```bash
# Import our public key
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key | gpg --import -

# Verify Release signature
curl -fsSL https://scopecreep-zip.github.io/open-sesame/dists/noble/Release.gpg -o Release.gpg
curl -fsSL https://scopecreep-zip.github.io/open-sesame/dists/noble/Release -o Release
gpg --verify Release.gpg Release
```

### Build Provenance Attestations

All release packages include SLSA Level 2 provenance attestations generated via GitHub Actions:

```bash
# Verify attestation (requires gh CLI)
gh attestation verify open-sesame_*.deb --owner ScopeCreep-zip
```

### Supply Chain Security

- All builds run on GitHub-hosted runners
- Build environment is ephemeral and isolated
- No third-party actions with write permissions
- GPG signing key stored in GitHub Secrets (not in repository)
- Native ARM64 builds (no cross-compilation)

## Reporting a Vulnerability

Please report security vulnerabilities via GitHub Security Advisories:

1. Go to the [Security tab](https://github.com/ScopeCreep-zip/open-sesame/security) of this repository
2. Click "Report a vulnerability"
3. Provide details about the vulnerability

We aim to respond within 48 hours and will coordinate disclosure timelines with you.

## Security Best Practices for Users

1. Always verify package signatures before installation
2. Use the APT repository for automatic signature verification
3. Keep packages updated: `sudo apt update && sudo apt upgrade`
4. Review attestations for critical deployments
