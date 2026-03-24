# Launch Profiles

Launch profiles define composable environment bundles that attach to application launches. Each
profile specifies environment variables, secret references, an optional Nix devshell, and an
optional working directory. Profiles are scoped to trust profiles and composed at launch time
via tags.

## Profile Structure

A launch profile is defined by the `LaunchProfile` struct in `core-config/src/schema_wm.rs`:

```toml
[profiles.work.launch_profiles.dev-rust]
env = { RUST_LOG = "debug", CARGO_HOME = "/workspace/.cargo" }
secrets = ["github-token", "crates-io-token"]
devshell = "/workspace/myproject#rust"
cwd = "/workspace/usrbinkat/github.com/org/repo"
```

Each field is optional and defaults to empty:

| Field | Type | Description |
|---|---|---|
| `env` | `BTreeMap<String, String>` | Static environment variables injected into the child process. |
| `secrets` | `Vec<String>` | Secret names fetched from the vault and converted to env vars. |
| `devshell` | `Option<String>` | Nix flake devshell reference. Wraps the command in `nix develop`. |
| `cwd` | `Option<String>` | Absolute path used as the working directory for the spawned process. |

## Tag System

Key bindings in the window manager configuration reference launch profiles through the `tags`
field on `WmKeyBinding`:

```toml
[profiles.default.wm.key_bindings.g]
apps = ["ghostty", "com.mitchellh.ghostty"]
launch = "ghostty"
tags = ["dev-rust", "ai-tools"]
launch_args = ["--working-directory=/workspace/user/github.com/org/repo"]
```

When a key binding triggers a launch, daemon-launcher resolves each tag against the configuration
to compose the final environment. Tags are processed in order; the composition rules are
described below.

## Cross-Profile Tag References

Tags support qualified cross-profile references using the `profile:name` syntax. An unqualified
tag resolves against the default (or explicitly specified) trust profile. A qualified tag
resolves against a different trust profile.

| Tag | Resolution |
|---|---|
| `dev-rust` | Resolves `dev-rust` in the current trust profile. |
| `work:corp` | Resolves `corp` in the `work` trust profile. |

The parsing logic in `daemon-launcher/src/launch.rs` (`parse_tag`) splits on the first colon.
If no colon is present, the tag is unqualified and uses the default profile.

Cross-profile references allow a single key binding to compose environments from multiple trust
boundaries. For example, a terminal binding might combine a personal development environment
with corporate secrets:

```toml
tags = ["dev-rust", "work:corp-secrets"]
```

## Tag Composition Rules

When multiple tags are specified, they are processed sequentially. The composition semantics are:

- **Environment variables**: merged into a single `BTreeMap`. When the same key appears in
  multiple tags, the later tag wins.
- **Secrets**: accumulated. Duplicate secret names (same name, same trust profile) are
  deduplicated; secrets from different trust profiles are kept independently.
- **Devshell**: last tag with a non-`None` devshell wins.
- **Working directory**: last tag with a non-`None` `cwd` wins.

This is implemented in `daemon-launcher/src/launch.rs` in the `launch_entry` function. The
composed environment is applied to the child process after secret fetching completes.

## Configuration Schema

Launch profiles live under each trust profile's configuration section:

```toml
[profiles.personal]
# ... other profile settings ...

[profiles.personal.launch_profiles.dev-rust]
env = { RUST_LOG = "debug" }
secrets = ["github-token"]
devshell = "/workspace/project#rust"
cwd = "/workspace/usrbinkat/github.com/org/repo"

[profiles.personal.launch_profiles.ai-tools]
env = { ANTHROPIC_MODEL = "claude-sonnet-4-20250514" }
secrets = ["anthropic-api-key"]
```

The full path in the config tree is
`profiles.<trust_profile_name>.launch_profiles.<launch_profile_name>`. Daemon-launcher reads
these from the hot-reloaded configuration state (`ConfigWatcher`) at launch time, so changes
take effect without daemon restart.

## Denial Handling

If a tag references a trust profile or launch profile that does not exist, daemon-launcher
returns a structured `LaunchDenial` to the window manager:

- `LaunchDenial::ProfileNotFound` -- the trust profile name in a qualified tag does not exist.
- `LaunchDenial::LaunchProfileNotFound` -- the launch profile name does not exist within the
  resolved trust profile.

The window manager can use these denials to display user-facing error messages.
