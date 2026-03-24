# Edge and Embedded

> **Design Intent.** This page describes deploying Open Sesame on IoT, embedded, and
> resource-constrained environments. The headless daemon architecture and ARM64 build targets
> exist today. Embedded-specific optimizations (reduced memory profiles, static linking,
> busybox integration) are architectural targets.

## Minimal Footprint

Edge deployments use the headless package only. The four headless daemons (`daemon-profile`,
`daemon-secrets`, `daemon-launcher`, `daemon-snippets`) provide secret management without
GUI dependencies.

For the most constrained environments, only `daemon-profile` and `daemon-secrets` are
required. The launcher and snippets daemons are optional if application launching and snippet
management are not needed.

### Resource Profile

| Resource | Desktop Default | Edge Target |
|----------|----------------|-------------|
| `LimitMEMLOCK` | 64M | 8M--16M (configurable) |
| `MemoryMax` (profile) | 128M | 32M |
| `MemoryMax` (secrets) | 256M | 64M |
| IPC channel capacity | 1024 | 64--128 |
| Daemons | 7 | 2--4 |
| Vault count | Multiple profiles | Single profile typical |

The `LimitMEMLOCK` value in each daemon's systemd unit controls the maximum `memfd_secret`
and `mlock` allocation. Edge devices with limited RAM should reduce this to match available
memory, trading maximum concurrent secret capacity for lower memory pressure.

The IPC channel capacity is configurable via `global.ipc.channel_capacity` in `config.toml`
(`IpcConfig` in `core-config/src/schema.rs`). Reducing it from the default 1024 lowers
per-subscriber memory usage.

## ARM64 Native Builds

Open Sesame builds natively for `aarch64-linux`. The CI pipeline produces ARM64 `.deb`
packages and Nix derivations without cross-compilation or QEMU emulation, avoiding the
performance and correctness risks of emulated builds.

### Supported Targets

| Target | Status | Use Case |
|--------|--------|----------|
| `x86_64-linux` | Supported | Desktop, server, cloud |
| `aarch64-linux` | Supported | Edge, embedded, ARM servers, Raspberry Pi |

### Building for ARM64

```bash
# Native build on an ARM64 host
cargo build --release --workspace

# Or install from the APT repository (ARM64 packages available)
sudo apt install open-sesame
```

## Embedded Linux Considerations

### systemd Environments

On embedded Linux systems running systemd, Open Sesame's service files work without
modification. Adjust resource limits in the service unit overrides:

```bash
systemctl --user edit open-sesame-secrets.service
```

```ini
[Service]
LimitMEMLOCK=16M
MemoryMax=64M
```

### Non-systemd Environments (Design Intent)

Embedded systems using busybox init, OpenRC, or runit do not have systemd user services. For
these environments, Open Sesame daemons can be started as supervised processes:

```bash
# Direct daemon startup (no systemd)
daemon-profile &
daemon-secrets &
```

The daemons use `sd_notify` for systemd integration but do not require it. On non-systemd
systems, the watchdog and notify protocols are inactive; the daemons start and run without
them.

### Static Linking (Design Intent)

For minimal embedded root filesystems without a full glibc, static linking with musl is an
architectural target:

```bash
# Target: static musl binary
cargo build --release --target aarch64-unknown-linux-musl
```

Static binaries eliminate shared library dependencies, simplifying deployment to embedded
images. The primary obstacle is SQLCipher's C dependency, which requires careful static
linking configuration.

## Secure Boot Chain

Edge devices in high-security deployments benefit from a layered protection model that roots
trust in hardware.

### TPM Integration (Design Intent)

The `MachineBindingType::TpmBound` variant (`core-types/src/security.rs`) represents
TPM-sealed key material:

```text
MachineBinding {
    binding_hash: BLAKE3(tpm_sealed_key || installation_id),
    binding_type: TpmBound,
}
```

TPM-bound installations tie the vault master key to a specific device's TPM PCR state. If
the device's boot chain is modified (firmware update, rootkit), the PCR values change and
the TPM refuses to unseal the key, preventing vault unlock on a compromised device.

### Self-Encrypting Drives (SED)

On devices with SED-capable storage, the layered protection model is:

```text
Layer 1: SED hardware encryption (transparent, always-on)
Layer 2: SQLCipher vault encryption (application-level, per-profile keys)
Layer 3: memfd_secret(2) (runtime memory protection, kernel direct-map removal)
```

Each layer is independent. SED protects data at rest at the storage level. SQLCipher
protects vault files even if the drive is mounted on another system. `memfd_secret`
protects decrypted secrets in memory even if the OS kernel is partially compromised.

### memfd_secret on Edge Kernels

Many embedded Linux distributions use custom or vendor kernels that may not include
`CONFIG_SECRETMEM=y`. Before deploying Open Sesame to edge devices, verify kernel support:

```bash
grep CONFIG_SECRETMEM /boot/config-$(uname -r)
# or, if /boot/config is not available:
zcat /proc/config.gz 2>/dev/null | grep SECRETMEM
```

For Yocto/Buildroot-based images, add `CONFIG_SECRETMEM=y` to the kernel defconfig. For
vendor kernels where this is not possible, Open Sesame operates in fallback mode with
`mlock(2)`, logged at ERROR level.

## Edge-Specific Configuration

```toml
# config.toml for edge deployment
[global]
default_profile = "device"

[global.ipc]
channel_capacity = 64
slow_subscriber_timeout_ms = 2000

[global.logging]
level = "warn"       # Reduce log volume on constrained storage
json = true          # Structured output for remote collection
journald = false     # May not have journald on embedded systems
```

## Connectivity Patterns

Edge devices are often intermittently connected. Open Sesame's offline-first design means
all core operations (vault unlock, secret access, profile switching) work without network
connectivity. Network-dependent operations are limited to:

- SSH agent forwarding for remote unlock (requires SSH connection).
- Extension fetching from OCI registries (can be pre-staged).
- Log shipping to central aggregator (buffered locally, forwarded when connected).
- Audit chain export (manual transfer via removable media if never connected).

For permanently air-gapped edge devices, see the [Air-Gapped Environments](air-gapped.md)
documentation.
