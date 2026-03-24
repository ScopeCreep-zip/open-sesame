# Headless Server

Open Sesame operates without a display server, making it suitable for servers, CI/CD runners,
containers, and virtual machines. The headless deployment uses the `open-sesame` package only,
with no GUI dependencies.

## Package

Only the `open-sesame` package is required. It contains:

- `sesame` CLI
- `daemon-profile` (IPC bus host, key management, audit)
- `daemon-secrets` (SQLCipher vaults, ACL, rate limiting)
- `daemon-launcher` (application launching, frecency scoring)
- `daemon-snippets` (snippet management)

The `open-sesame-desktop` package is not installed. The three desktop daemons (`daemon-wm`,
`daemon-clipboard`, `daemon-input`) are absent and no Wayland or COSMIC libraries are linked.

## Use Cases

### CI/CD Secret Injection

Open Sesame injects secrets into build processes as environment variables, scoped by trust
profile:

```bash
sesame env -p ci-production -- make deploy
```

The `sesame env` command activates the named profile, decrypts the vault, and launches the
child process with secrets projected into its environment. The child process inherits only
the secrets defined in the `ci-production` profile's vault. On process exit, the secrets are
not persisted anywhere on disk outside the encrypted vault.

### Server Credential Management

Long-running services can read secrets at startup or on demand:

```bash
# One-shot: print a secret value
sesame secret get -p work database-url

# Launch a service with its secret environment
sesame env -p production -- ./my-service
```

### Container Secret Injection

In container environments, Open Sesame can run as a sidecar or init container that projects
secrets into shared volumes or environment:

```bash
# In an init container or entrypoint script
sesame init --non-interactive
sesame env -p container -- exec "$@"
```

## systemd Target

The headless target starts on `default.target`, requiring no graphical session:

```ini
# contrib/systemd/open-sesame-headless.target
[Unit]
Description=Open Sesame Headless Suite
# No display server required. Suitable for servers, containers, VMs.

[Install]
WantedBy=default.target
```

The four headless daemons are `PartOf=open-sesame-headless.target`. The profile daemon starts
first; secrets, launcher, and snippets declare ordering dependencies on profile.

### Starting and Stopping

```bash
# Start the headless suite
systemctl --user start open-sesame-headless.target

# Stop all headless daemons
systemctl --user stop open-sesame-headless.target

# Enable on boot
systemctl --user enable open-sesame-headless.target
```

## SSH Agent Forwarding for Remote Vault Unlock

When Open Sesame is installed on a remote server, vault unlock can use an SSH agent key from
the operator's local machine. This avoids storing passwords on the server.

### Setup

1. On the remote server, enroll an SSH agent factor during `sesame init`:

   ```bash
   sesame init --auth-factor ssh-agent
   ```

2. When connecting, forward the SSH agent:

   ```bash
   ssh -A user@server
   ```

3. On the remote server, unlock the vault using the forwarded agent:

   ```bash
   sesame unlock -p work --factor ssh-agent
   ```

The SSH agent backend (`AuthFactorId::SshAgent` in `core-types/src/auth.rs`) produces a
deterministic signature over a challenge, which is processed through
`BLAKE3 derive_key("pds v2 ssh-vault-kek {profile}")` to produce a KEK. The KEK unwraps the
master key from the `EnrollmentBlob` stored on disk. The SSH private key never leaves the
local machine.

### Multi-Factor on Headless

The `AuthCombineMode` (`core-types/src/auth.rs`) supports three modes for headless
environments:

| Mode | Behavior |
|------|----------|
| `Any` | Any single enrolled factor unlocks. SSH agent alone suffices. |
| `All` | All enrolled factors required. Both password and SSH agent must be provided. |
| `Policy` | Configurable: e.g., SSH agent always required, plus one additional factor. |

For headless servers where interactive password entry is impractical, enrolling SSH agent as
the sole factor with `Any` mode provides passwordless unlock gated on SSH key possession.

## Configuration

Headless configuration is identical to desktop, minus the window manager, clipboard, and input
sections. The relevant top-level configuration file is `~/.config/pds/config.toml` with the
schema defined in `core-config/src/schema.rs`.

Key headless-specific settings:

```toml
[global]
default_profile = "production"

[global.ipc]
# Custom socket path for containerized deployments
# socket_path = "/run/pds/bus.sock"
channel_capacity = 1024

[global.logging]
level = "info"
json = true        # Structured output for log aggregation
journald = true    # journald integration on systemd hosts
```

## File Locations

| Path | Purpose |
|------|---------|
| `~/.config/pds/config.toml` | User configuration |
| `~/.config/pds/installation.toml` | Installation identity |
| `~/.config/pds/vaults/{profile}.db` | Encrypted vaults |
| `$XDG_RUNTIME_DIR/pds/bus.sock` | IPC socket |
| `~/.config/pds/audit/` | Audit log |

## Security Notes

The secrets daemon runs with `PrivateNetwork=yes`, which is particularly relevant on servers
where network-facing services coexist. Even if an adjacent service is compromised, it cannot
reach the secrets daemon over the network. All access is via the authenticated Noise IK IPC
bus over a Unix domain socket.

On headless systems without `memfd_secret(2)` support (e.g., older kernels or containers
without `CONFIG_SECRETMEM=y`), the daemons fall back to `mmap(MAP_ANONYMOUS)` with `mlock(2)`
and `MADV_DONTDUMP`. This fallback is logged at ERROR level with an explicit compliance impact
statement naming the frameworks affected (IL5/IL6, STIG, PCI-DSS) and the remediation command
to enable `CONFIG_SECRETMEM`.

## Headless-First Design

Every `sesame` CLI command works from explicit primitives without interactive prompts. The CLI
does not assume a terminal is attached. Exit codes, structured JSON output, and non-interactive
flags support automation:

```bash
# Non-interactive unlock with SSH agent
sesame unlock -p work --factor ssh-agent --non-interactive

# JSON output for scripting
sesame secret list -p work --json | jq '.[].key'

# Exit code indicates vault lock state
sesame status -p work --quiet; echo $?
```
