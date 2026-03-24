# Secret Injection

Secrets flow from per-profile SQLCipher vaults into launched processes as environment variables.
Two mechanisms exist: the `sesame env` CLI command for interactive use, and the daemon-launcher
IPC path for overlay-driven launches.

## Vault to Environment Pipeline

### daemon-launcher Path

When daemon-launcher processes a `LaunchExecute` request with tags, the pipeline is:

1. **Tag resolution**: each tag is resolved to a `LaunchProfile` from the hot-reloaded
   configuration. Cross-profile tags (`work:corp`) route to different trust profiles.
2. **Secret collection**: secret names from all resolved launch profiles are accumulated with
   their owning trust profile name. Duplicates (same name, same profile) are deduplicated.
3. **IPC fetch**: for each `(secret_name, trust_profile_name)` pair, daemon-launcher sends a
   `SecretGet` request over the Noise IK bus to daemon-secrets. The request specifies the trust
   profile that owns the vault.
4. **Name conversion**: the secret name is converted to an environment variable name (see below).
5. **Environment injection**: the secret value is inserted into the composed environment map,
   then passed to the child process via `Command::env()`.
6. **Zeroization**: after the child process is spawned and the environment has been copied to
   the OS process, all secret values in the composed environment map are zeroized via
   `zeroize::Zeroize`.

### Batched Denial Collection

Daemon-launcher does not abort on the first secret fetch failure. Instead, it collects all
denials and returns them in a single response so the window manager can prompt for all required
vault unlocks at once:

- **Locked vaults**: `SecretDenialReason::Locked` or `ProfileNotActive` denials are collected
  into a `locked_profiles` list.
- **Missing secrets**: `SecretDenialReason::NotFound` denials increment a `missing_count`.
- **Rate limiting**: `SecretDenialReason::RateLimited` causes an immediate abort with
  `LaunchDenial::RateLimited`.

After iterating all secrets, locked vaults take priority: if any vaults are locked,
`LaunchDenial::VaultsLocked` is returned with the full list. Otherwise, if secrets are missing,
`LaunchDenial::SecretNotFound` is returned.

## sesame env

The `sesame env` command spawns a child process with vault secrets injected as environment
variables:

```bash
sesame env -p work -- my-command --flag
```

It connects to the IPC bus, fetches all secrets for the specified profile(s), converts each
secret name to an env var, injects them into the child process, waits for the child to exit,
zeroizes all secret copies, and exits with the child's exit code.

The child also receives a `SESAME_PROFILES` environment variable containing a comma-separated
list of the profile specs that were used.

## sesame export

The `sesame export` command outputs secrets in shell, dotenv, or JSON format without spawning
a child:

```bash
sesame export -p work --format shell
sesame export -p work --format dotenv
sesame export -p work --format json
```

Output is written to stdout. Secret values are zeroized after printing.

## Secret Name to Env Var Conversion

Two conversion implementations exist, with slightly different rules:

### daemon-launcher (launch.rs)

Applies to secrets injected via launch profile tags:

- Uppercase the entire name.
- Replace hyphens with underscores.

Examples: `github-token` becomes `GITHUB_TOKEN`. `anthropic-api-key` becomes
`ANTHROPIC_API_KEY`.

### sesame env / sesame export (env.rs)

Applies to secrets injected via the CLI:

- Uppercase the entire name.
- Replace hyphens, dots, and non-alphanumeric characters (except underscores) with underscores.

Examples: `api-key` becomes `API_KEY`. `db.host-name` becomes `DB_HOST_NAME`.

## Prefix System

The `--prefix` flag (available on `sesame env` and `sesame export`) prepends a string to every
generated environment variable name, separated by an underscore:

```bash
sesame env --prefix MYAPP -p work -- my-command
```

With prefix `MYAPP`, the secret `api-key` becomes `MYAPP_API_KEY`.

The prefix is also configurable per-workspace via `.sesame.toml`:

```toml
secret_prefix = "MYAPP"
```

The prefix is applied after the name-to-env-var conversion, so the full transformation is:
`secret_name` -> uppercase + substitute -> prepend prefix.

## Denied Environment Variables

The `sesame env` and `sesame export` commands maintain a deny list of environment variable names
that must never be overwritten by secret injection. This prevents secrets with adversarial names
from hijacking the dynamic linker, shell execution, or privilege escalation vectors. The deny
list includes:

- Dynamic linker variables: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, and
  others.
- Core execution: `PATH`, `HOME`, `SHELL`, `USER`.
- Shell injection vectors: `BASH_ENV`, `IFS`, `PROMPT_COMMAND`, and others.
- Language runtime injection: `PYTHONPATH`, `NODE_OPTIONS`, `RUBYOPT`, and others.
- Open Sesame's own namespace: `SESAME_PROFILE`.

Matching is case-insensitive. The `BASH_FUNC_` prefix is matched as a prefix pattern to block
Bash function export injection.

## Implicit Environment Variables

Every launched process receives these environment variables regardless of tag configuration:

| Variable | Value |
|---|---|
| `SESAME_PROFILE` | The trust profile name used for the launch. |
| `SESAME_APP_ID` | The desktop entry ID of the launched application. |
| `SESAME_SOCKET` | Path to the IPC bus Unix socket. |

These are injected after the composed environment, so they cannot be overridden by launch profile
`env` entries.
