# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Security Architecture

Open Sesame implements defense-in-depth across four layers:

### Memory Protection

All secret-carrying types (`SecureBytes`, `SecureVec`, `SensitiveBytes`) are backed by `ProtectedAlloc` from the `core-memory` crate:

- **Guard pages** (PROT_NONE) on both sides of every allocation -- buffer overflows and underflows trigger SIGSEGV
- **16-byte random canary** verified in constant time on drop -- detects heap corruption, aborts process on mismatch
- **User data right-aligned** within data pages so overflows immediately hit the trailing guard page
- **Volatile zeroize** of entire data region before munmap via the `zeroize` crate with compiler fence
- **`memfd_secret(2)`** on Linux 5.14+ with `CONFIG_SECRETMEM=y` -- secret pages are removed from the kernel direct map and invisible to `/proc/pid/mem`, kernel modules, DMA, and ptrace even as root
- **Fallback** to `mmap(MAP_ANONYMOUS)` with `mlock(2)` + `MADV_DONTDUMP` on older kernels, logged at ERROR with compliance impact statement
- **Zero-copy secret lifecycle** -- derived keys go directly from stack arrays into ProtectedAlloc; SecureBytes transfers to SensitiveBytes without heap intermediaries; custom serde Visitor deserializes directly from postcard input buffers into ProtectedAlloc

### Process Isolation

Each daemon runs in its own systemd user service with tailored restrictions:

- **Landlock filesystem sandboxing** -- per-daemon path-based access control, partially enforced Landlock is a fatal error
- **seccomp-bpf syscall filtering** -- per-daemon allowlists, unallowed syscalls kill the offending thread (`SECCOMP_RET_KILL_THREAD`) with SIGSYS handler for visibility
- **systemd hardening** -- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateNetwork` (secrets daemon), `LimitCORE=0`, `LimitMEMLOCK=64M`, memory limits, empty capability bounding set

### Cryptographic Design

- **Noise IK encrypted IPC** -- all inter-daemon communication authenticated and encrypted (X25519 + ChaChaPoly + BLAKE2s) with peer identity bound via kernel UCred in the Noise prologue
- **SQLCipher encrypted vaults** -- AES-256-CBC with HMAC-SHA512 per page, Argon2id key derivation (19 MiB memory, 2 iterations)
- **Multi-factor vault unlock** -- password (Argon2id KEK), SSH agent (deterministic signature KEK), or both with configurable auth policies (any, all, threshold)
- **BLAKE3 hash-chained audit log** -- tamper evidence for all vault operations, detects modifications, deletions, and reorderings
- **Rate-limited unlock attempts** via governor token bucket

### Input Validation

- **Environment injection denylist** -- blocks `LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `JAVA_TOOL_OPTIONS`, and 30+ other vectors
- **Trust profile isolation** -- secrets, clipboard, frecency, snippets, audit all scoped to trust profiles with no cross-profile access without explicit configuration

## Kernel Requirements for Full Security Posture

| Requirement | Purpose | Check |
|-------------|---------|-------|
| Linux 5.14+ | `memfd_secret(2)` syscall | `uname -r` |
| `CONFIG_SECRETMEM=y` | Kernel direct-map removal | `grep SECRETMEM /boot/config-$(uname -r)` |
| systemd 255+ | User service management | `systemctl --version` |

Systems without `memfd_secret` fall back to `mmap` with `mlock` -- functional, but secrets remain on the kernel direct map. Daemon startup logs explicitly state the active security posture.

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

All release packages include SLSA build provenance attestations generated via GitHub Actions:

```bash
# Verify attestation (requires gh CLI)
gh attestation verify open-sesame-linux-$(uname -m).deb --owner ScopeCreep-zip
gh attestation verify open-sesame-desktop-linux-$(uname -m).deb --owner ScopeCreep-zip
```

### Nix Binary Cache

Pre-built Nix packages are served from [scopecreep-zip.cachix.org](https://app.cachix.org/cache/scopecreep-zip) with Ed25519 signing:

```
Public key: scopecreep-zip.cachix.org-1:LPiVDsYXJvgljVfZPN43zBWB7ZCGFr2jZ/lBinnPGvU=
```

### Supply Chain Security

- All builds run on GitHub-hosted runners (ephemeral, isolated)
- No third-party actions with write permissions
- GPG signing key stored in GitHub Secrets (not in repository)
- Native ARM64 builds (no cross-compilation or QEMU emulation)
- Nix builds pushed to Cachix with signed NARs on every release

## Reporting a Vulnerability

Please report security vulnerabilities via GitHub Security Advisories:

1. Go to the [Security tab](https://github.com/ScopeCreep-zip/open-sesame/security) of this repository
2. Click "Report a vulnerability"
3. Provide details about the vulnerability

We aim to respond within 48 hours and will coordinate disclosure timelines with you.

## Known Residual Risks

Tracked as individual GitHub issues:

- [#7](https://github.com/ScopeCreep-zip/open-sesame/issues/7) -- SSH agent library heap buffer not zeroized after signature (upstream)
- [#8](https://github.com/ScopeCreep-zip/open-sesame/issues/8) -- `SecureBytes::new(Vec)` retains brief heap exposure for external API returns
- [#9](https://github.com/ScopeCreep-zip/open-sesame/issues/9) -- Serde `visit_byte_buf` fallback creates heap copy for non-postcard deserializers
- [#10](https://github.com/ScopeCreep-zip/open-sesame/issues/10) -- `memfd_secret` unavailable fallback degrades to mmap with direct-map exposure
- [#11](https://github.com/ScopeCreep-zip/open-sesame/issues/11) -- SIGKILL/OOM kill bypasses volatile zeroing in Drop
- [#14](https://github.com/ScopeCreep-zip/open-sesame/issues/14) -- Argon2id 19 MiB working memory on unprotected heap (upstream)
