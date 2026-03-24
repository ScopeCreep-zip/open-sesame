# Workspace Conventions

Open Sesame enforces a deterministic directory layout for source code
repositories. Git remote URLs are parsed into canonical filesystem paths
following the convention `{root}/{user}/{server}/{org}/{repo}`.

## Canonical Path Convention

Every repository maps to a unique filesystem path:

```text
/workspace/{user}/{server}/{org}/{repo}
```

For example:

| Remote URL | Canonical path |
|---|---|
| `https://github.com/scopecreep-zip/open-sesame` | `/workspace/usrbinkat/github.com/scopecreep-zip/open-sesame` |
| `git@github.com:braincraftio/k9.git` | `/workspace/usrbinkat/github.com/braincraftio/k9` |
| `git@git.braincraft.io:braincraft/k9.git` | `/workspace/usrbinkat/git.braincraft.io/braincraft/k9` |

The default root is `/workspace`, configurable via the
`SESAME_WORKSPACE_ROOT` environment variable or `settings.root` in
`workspaces.toml`.

## URL Parsing

The `parse_url` function in `sesame-workspace/src/convention.rs` accepts
two URL formats:

### HTTPS

```text
https://github.com/org/repo[.git]
```

Splits on `/` after stripping the scheme. Requires at least three path
components: `server/org/repo`.

### SSH

```text
git@github.com:org/repo.git
```

Splits on `@` to isolate the user portion, then on `:` to separate the
server from the org/repo path. The path after the colon is split on `/`
to extract org and repo.

### workspace.git Format

URLs where the repo component is `workspace` (or `workspace.git`) are
treated as org-level workspace repositories. These represent a monorepo
pattern where the org directory itself is a git repository containing
sibling project repos. The canonical path stops at the org level:

```text
https://github.com/braincraftio/workspace.git
  -> /workspace/usrbinkat/github.com/braincraftio/
```

The `CloneTarget` enum distinguishes `Regular(PathBuf)` from
`WorkspaceGit(PathBuf)`. Cloning a workspace.git into an existing org
directory that already contains sibling repos triggers a special
initialization flow: `git init`, `git remote add origin`,
`git fetch origin`, then `git checkout -f origin/HEAD -B main`.

### Normalization and Validation

- Server names are lowercased (`GITHUB.COM` becomes `github.com`).
- `.git` suffixes are stripped from repo names.
- Insecure `http://` URLs log a tracing warning about cleartext
  credential transmission but are not rejected.

Component validation (`validate_component`) rejects:

| Condition | Rejection reason |
|---|---|
| Empty component | `"{label} component is empty"` |
| Leading `.` | Prevents collision with `.git`, `.ssh`, `.config` directories. |
| Contains `..` | Path traversal attack. |
| Contains `/` or `\` | Path separator embedded in component. |
| Contains null byte | Null byte injection. |
| Exceeds 255 bytes | Filesystem component length limit (ext4, btrfs). |
| Leading/trailing whitespace | Filesystem ambiguity. |

## Git-Aware Discovery

### is_git_repo

The `git::is_git_repo` function in `sesame-workspace/src/git.rs` checks
for the existence of a `.git` entry (directory or file) at the given
path. It does not shell out to git.

### Remote URL Extraction

`git::remote_url` runs
`git -C {path} remote get-url origin` via `std::process::Command` with
explicit `.arg()` calls. Returns `Ok(None)` if the path lacks a `.git`
entry or has no origin remote. Returns `Ok(Some(url))` on success.

### Additional Git Operations

The `git` module provides:

- `current_branch(path)`: runs `git rev-parse --abbrev-ref HEAD`.
- `is_clean(path)`: runs `git status --porcelain` and checks for empty
  output.
- `clone_repo(url, target, depth)`: clones with optional `--depth` and
  `--` separator before URL/path arguments.

All commands use explicit `.arg()` calls. The module-level documentation
states: "NEVER use `format!()` to build command strings. NEVER use
shell interpolation."

### Workspace Discovery

`discover::discover_workspaces` in
`sesame-workspace/src/discover.rs` walks the directory tree at
`{root}/{user}/` to find all git repositories. The walk follows the
convention depth structure:

1. **Server level**: enumerate directories under `{root}/{user}/`.
2. **Org level**: enumerate directories under each server. If an org
   directory contains a `.git` entry, it is recorded as a `workspace.git`
   discovery.
3. **Repo level**: enumerate directories under each org. Directories
   with `.git` entries are recorded as regular repositories.

Security properties of the walk:

- **Symlinks skipped**: `entry.file_type()?.is_symlink()` causes the
  entry to be skipped at every level. This prevents symlink loops and
  TOCTOU traversal attacks.
- **Permission denied**: silently skipped
  (`ErrorKind::PermissionDenied` returns `Ok(())`).
- **`.git` directories**: explicitly skipped as traversal targets (they
  are detected but not descended into).

Results are sorted by path. Each `DiscoveredWorkspace` includes:

- `path`: filesystem path to the repository root.
- `convention`: parsed `WorkspaceConvention` components (server, org,
  repo).
- `remote_url`: from `git remote get-url origin`, if available.
- `linked_profile`: resolved from workspace config links, if configured.
- `is_workspace_git`: true for org-level workspace.git repositories.

## Workspace Configuration

### workspaces.toml

The user-level workspace configuration is stored at
`~/.config/pds/workspaces.toml`. The schema is defined by
`WorkspaceConfig` in `core-config/src/schema_workspace.rs`:

```toml
[settings]
root = "/workspace"
user = "usrbinkat"
default_ssh = true

[links]
"/workspace/usrbinkat/github.com/org" = "personal"
"/workspace/usrbinkat/github.com/org/k9" = "work"
```

**Settings fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `root` | `PathBuf` | `$SESAME_WORKSPACE_ROOT` or `/workspace` | Root directory for all workspaces. |
| `user` | `String` | `$USER` or `"user"` | Username for path construction. |
| `default_ssh` | `bool` | `true` | Prefer SSH URLs when cloning. |

**Links section:** a `BTreeMap<String, String>` mapping canonical paths
to profile names. More specific paths override less specific ones
(longest prefix wins).

### Profile Link Resolution

`resolve_workspace_profile` in `sesame-workspace/src/config.rs` resolves
a filesystem path to a profile name using two strategies:

1. **Exact match**: the path matches a link key exactly.
2. **Longest prefix match**: the longest link key that is a prefix of
   the path wins. Path boundary enforcement prevents `/org` from
   matching `/organic` -- the link path must match exactly or be
   followed by `/`.

### .sesame.toml (Local Config)

Workspace-level and repo-level configuration files (`.sesame.toml`)
provide per-directory overrides. The schema is `LocalSesameConfig` in
`core-config/src/schema_workspace.rs`:

```toml
# /workspace/usrbinkat/github.com/org/.sesame.toml
profile = "work"
secret_prefix = "MYAPP"
tags = ["dev-rust"]

[env]
RUST_LOG = "debug"
```

| Field | Type | Description |
|---|---|---|
| `profile` | `Option<String>` | Default trust profile for this context. |
| `env` | `BTreeMap<String, String>` | Non-secret environment variables to inject. |
| `tags` | `Vec<String>` | Launch profile tags to apply by default. |
| `secret_prefix` | `Option<String>` | Env var prefix for secret injection (e.g., `"MYAPP"` causes `api-key` to become `MYAPP_API_KEY`). |

### Multi-Layer Config Precedence

`resolve_effective_config` in `sesame-workspace/src/config.rs` merges
configuration from all layers. Precedence (highest to lowest):

1. **Repo `.sesame.toml`** (`{path}/.sesame.toml`)
2. **Workspace `.sesame.toml`**
   (`{root}/{user}/{server}/{org}/.sesame.toml`)
3. **User config links** (`workspaces.toml` `[links]` section)

Merge semantics per field:

- **`profile`**: highest-priority layer wins outright.
- **`env`**: all layers are merged into a single `BTreeMap`.
  Higher-priority keys override lower-priority ones; keys unique to
  lower layers are preserved.
- **`tags`**: all layers' tags are concatenated (workspace tags first,
  then repo tags).
- **`secret_prefix`**: highest-priority layer wins outright.

The `ConfigProvenance` struct tracks which layer determined each value
(`"user config link"`, `"workspace .sesame.toml"`, or
`"repo .sesame.toml"`).

## Platform-Specific Root Resolution

The workspace root is resolved in `sesame-workspace/src/config.rs`
(`resolve_root`) with this priority:

1. `SESAME_WORKSPACE_ROOT` environment variable.
2. `config.settings.root` from `workspaces.toml`.
3. Default: `/workspace`.

The default `WorkspaceSettings` reads `SESAME_WORKSPACE_ROOT` at
construction time, so the env var takes effect even without an explicit
`workspaces.toml`. The username defaults to the `USER` environment
variable, falling back to the string `"user"`.

## Shell Injection Prevention

All git operations in `sesame-workspace/src/git.rs` use
`std::process::Command` with explicit `.arg()` calls. The `--` separator
is used before URL and path arguments in `git clone` to prevent argument
injection (a URL starting with `-` would otherwise be interpreted as a
flag). No temporary files are created. No secret material is written to
disk.
