# Workspace Conventions

Open Sesame enforces a deterministic directory layout for source code
repositories. Git remote URLs are parsed into canonical filesystem paths
following the convention `{root}/{user}/{server}/{namespace...}/{repo}`.

## Canonical Path Convention

Every repository maps to a unique filesystem path:

```text
/workspace/{user}/{server}/{namespace...}/{repo}
```

For example:

| Remote URL | Canonical path |
| --- | --- |
| `https://github.com/scopecreep-zip/open-sesame` | `/workspace/alice/github.com/scopecreep-zip/open-sesame` |
| `git@github.com:braincraftio/k9.git` | `/workspace/alice/github.com/braincraftio/k9` |
| `https://gitlab.com/Group/SubGroup/Project` | `/workspace/alice/gitlab.com/group/subgroup/project` |

The root is `$SESAME_WORKSPACE_ROOT` when set, otherwise `settings.root`
in `workspaces.toml` (default `/workspace`). `WorkspaceLayout` in
`sesame-workspace/src/config.rs` is the single owner of root and user
resolution: an existing root is canonicalized, so a symlinked root and
its target produce the same paths and the same link keys.

## URL Parsing

`convention::parse_url` and `convention::parse_clone_input` in
`sesame-workspace/src/convention.rs` accept:

| Form | Example |
| --- | --- |
| HTTPS | `https://github.com/org/repo[.git]`, `https://host:8443/group/sub/repo` |
| SCP-style SSH | `git@github.com:org/repo.git` |
| `ssh://` | `ssh://git@host:2222/org/repo.git`, `ssh://git@[::1]/org/repo` |
| Shorthand (clone only) | `org/repo` (default server), `server.tld/org/repo` |

Parsing is strict:

- A port must be a valid `u16`; a bad port, or anything other than
  `:port` after a bracketed IPv6 address, is an `InvalidUrl` error.
- Query strings, fragments, and null bytes are rejected.
- An HTTPS URL that carries credentials (`https://user:token@host/...`)
  is rejected; credentials come from a git credential helper. Every URL
  printed in an error has its userinfo replaced by `***`
  (`net::redact_credentials`).
- `http://` URLs log a warning about cleartext transport.

### Clone Targets

`parse_clone_input` returns a `CloneInput` with a `RemoteTarget` and a
`WorkspaceCoordinate`:

- `RemoteTarget::Repository(RemoteEndpoint)`: a cloneable repository,
  in the transport, port, user, and spelling supplied.
- `RemoteTarget::Organization { host, namespace }`: a URL with no
  repository component (`https://github.com/ScopeCreep-zip`); only
  `--project` clones it, through the forge API.

The coordinate's `WorkspaceKind` is:

- `Repository(RepoDir)`: a regular or member repository.
- `WorkspaceRepository`: a repository whose placement equals the
  placement of `settings.workspace_repo` (default `workspace`); it is
  placed at the namespace directory itself, which then holds its member
  repositories as siblings inside its working tree.
- `Organization`: the namespace directory of an organization URL.

Cloning a workspace repository into an existing namespace directory
initializes the repository around the existing content. With or without
`--force`, it refuses when the workspace repository tracks paths inside
an existing member repository directory, and lists them. Without
`--force` it also refuses to overwrite existing files.

### Remote Spelling and Placement

Identity types form two vocabularies with a one-way mapping:

| Vocabulary | Types | Case |
| --- | --- | --- |
| Remote (forge-facing) | `GitHost`, `NamespacePath`, `RepositoryName`, `RemoteIdentity`, `RemoteEndpoint` | Preserved as given |
| Placement (filesystem-facing) | `WorkspaceUser`, `NamespaceDir`, `RepoDir`, `WorkspaceCoordinate` | Lowercase by construction |

- Clone URLs render the remote spelling. Explicit URLs are never
  rewritten; case-sensitive servers (`git daemon`, `git-http-backend`,
  bare repositories over SSH) receive exactly the path supplied.
- Placement is derived from remote identity through
  `WorkspaceCoordinate::from_remote_*`. Every spelling of one remote
  (`NixOS/NixPkgs`, `nixos/nixpkgs`) resolves to one directory
  (`github.com/nixos/nixpkgs`) on every filesystem. No mapping from
  placement back to remote exists.
- Server names are lowercased (`GITHUB.COM` becomes `github.com`).
- One `.git` URL suffix, in any case, is stripped from repository names.

Because placement is lowercase, remotes that differ only in case share
a directory. `sesame workspace clone` adopts an existing repository only
when its `origin` is exactly the requested remote identity (host,
namespace, and repository spelling; transport and port do not matter).
A different `origin` at the same placement is a `PlacementConflict`
error naming both remotes, and an existing directory that is not a
repository root is refused before git runs.

Directory names read from disk are parsed strictly: a name that is not
canonical (`NixOS`, `GitHub.com`) is a `NonCanonical` error, never a
silent normalization. Before any clone or workspace setup,
`WorkspaceLayout::checked_path` rejects a canonical path when a sibling
differing only in case already exists (`CaseConflict`).

Component validation rejects:

| Condition | Rejection reason |
| --- | --- |
| Empty component | Empty directory name. |
| Leading `.` (user, namespace segment) | Hidden directories are never forge user or namespace identifiers. |
| Exactly `.` or `..` | Path traversal attack. |
| Contains `/` or `\` | Path separator embedded in component. |
| Contains null byte | Null byte injection. |
| Non-ASCII characters | Lowercase placement must be length-preserving and collision-free. |
| Exceeds 255 bytes | Filesystem component length limit (ext4, btrfs). |
| Leading/trailing whitespace | Filesystem ambiguity. |

Repository names permit a leading `.` because forges host repositories
such as `.github` and `.dotfiles`; `github.com/org/.github` maps to
`/workspace/{user}/github.com/org/.github`. A repository name whose
placement is `.git` (`.git`, `.GIT`, `.git.git`) is rejected as
reserved: it would resolve to the namespace directory's own git
metadata, which is the workspace repository.

## Layout Discovery

### Repository Detection

`git::git_marker` in `sesame-workspace/src/git/marker.rs` is the only
repository detector. It classifies a directory by its `.git` entry
through `gix::discover::is_git`:

| `.git` entry | Marker | Role in the layout |
| --- | --- | --- |
| Absent | `Absent` | Namespace directory, if it leads to a repository |
| Repository git directory | `Repository` | Repository root |
| Gitfile to `<main>/.git/worktrees/<id>` | `LinkedWorktree` | Repository root, placed like a clone |
| Gitfile into an ancestor's `.git/modules/...` | `Submodule` | Content of the superproject, never layout |

A symlinked `.git` is rejected, and an invalid one is an error.

### The Layout Walk

`layout::walk` in `sesame-workspace/src/layout.rs` is the single
traversal that discovery and normalization both consume. It visits each
directory under `{root}/{user}` once:

- A directory outside any repository is a namespace directory only when
  some directory below it is a repository root. Trees that lead to no
  repository (`Notes/Meeting Docs`, `Archive/`) are not layout at any
  depth and are never reported or renamed.
- A repository root whose direct children include member repositories
  (repository roots or linked worktrees, not submodules) is a workspace
  root. Inside its working tree only directories that are, or lead to,
  member repositories are layout; everything else is the workspace
  repository's own content.
- Any other repository root is a leaf; its contents are not walked.
- Nested workspace roots are treated identically by discovery and
  normalization.
- Symlinks are never followed. A symlink at layout level, and an
  unreadable directory inside workspace content, is recorded as skipped
  (path and reason) instead of failing the walk; symlinks inside
  workspace content are that repository's content and are not recorded.
  An unreadable layout directory is an issue.
- Directory names are held as `OsString`; a non-UTF-8 layout name is
  reported with its real path.

`discover::discover_workspaces` parses every layout directory name
strictly into a `DiscoveredWorkspace { path, coordinate, linked_profile }`.
Entries it cannot place are `DiscoveryIssue { path, error }`:
non-canonical names, case variants of the user directory, undecodable
server directories, repositories with no namespace, and non-UTF-8
names. Skipped entries are listed separately.

### sesame workspace list

`sesame workspace list` prints the placed entries grouped by server and
namespace. Workspace repositories are rows of their own namespace group,
and the group header is tagged `(workspace)`. Issues go to stderr as
`! <path>: [<kind>] <error>`, followed by the number of skipped entries.
Only `NonCanonical` and `CaseConflict` issues suggest
`sesame workspace normalize`; every other issue names its own cause.

`--format json` prints one document:

```json
{
  "workspaces": [
    { "path": "...", "server": "github.com", "namespace": "org", "repo": "repo", "kind": "repository" }
  ],
  "issues": [
    { "path": "...", "kind": "case-conflict", "message": "...", "normalizable": true }
  ],
  "skipped": [
    { "path": "...", "reason": "symlink not followed" }
  ]
}
```

`kind` is `repository` or `workspace`. Discovery never places an
organization, since an organization has no directory of its own to
discover.

`--stale` takes the units the `LAST` column prints: `m` (minutes), `h`,
`d`, `w`, `mo` (30 days), `y` (365 days).

Exit status: 0 when every layout entry was placed; 1 when any entry
could not be placed (the listing is still printed) or on any other
error.

## Normalization

`sesame workspace normalize` (dry run) and
`sesame workspace normalize --apply` bring existing directories to their
canonical names, using the same layout walk:

- The user directory is the first step: a case variant (`Alice`) is
  renamed to the canonical user (`alice`).
- Server, namespace, repository, and member-path directories follow, top
  down. Repository contents, submodule checkouts, and trees that lead to
  no repository are never renamed.
- A directory whose canonical name is held by a different directory, or
  claimed by an earlier rename in the same pass, is a collision and is
  never resolved automatically.
- Names that cannot be made canonical (non-UTF-8, non-ASCII, undecodable
  server directories) are unfixable and reported; they do not stop the
  pass.
- Every rename is atomic and never replaces an existing directory
  (`renameat2(RENAME_NOREPLACE)` on Linux and Android,
  `renameatx_np(RENAME_EXCL)` on Apple platforms; no fallback to a
  replacing rename). A case-only rename on a case-insensitive filesystem
  goes through a unique temporary name and is restored if the second
  step fails.

Stored paths are rewritten through the renames actually performed:

- linked-worktree link files: `<admin>/gitdir`, an absolute
  `<admin>/commondir` (libgit2 writes it absolute, git writes `../..`),
  and the worktree's `.git` file;
- profile links in `workspaces.toml` and `workspaces.d/*.toml`, each in
  the file that defines it;
- launch-profile `cwd` and `devshell` values in `config.toml`,
  `config.d/*.toml`, and every `profiles/*/config.toml`. Values in the
  read-only system policy are reported, never written.

Exit status: 0 when the layout is (or after `--apply` would be) fully
canonical; 1 when collisions, unfixable names, read-only policy values,
or failures remain.

## Workspace Configuration

### workspaces.toml

The user-level workspace configuration is stored at
`~/.config/pds/workspaces.toml`, with `workspaces.d/*.toml` fragments
loaded after it. The schema is `WorkspaceConfig` in
`core-config/src/schema_workspace.rs`:

```toml
[settings]
root = "/workspace"
user = "alice"
transport = "https"
default_server = "github.com"
workspace_repo = "workspace"
workspace_auto = "auto"

[links]
"/workspace/alice/github.com/org" = "personal"
"/workspace/alice/github.com/org/k9" = "work"
```

**Settings fields:**

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `root` | path | `/workspace` | Root directory for all workspaces; `$SESAME_WORKSPACE_ROOT` overrides it. |
| `user` | `WorkspaceUser` | `user` | The `{user}` directory; validated and stored lowercase. |
| `transport` | `https` or `ssh` | `https` | Transport for shorthand clone input; explicit URLs are never rewritten. |
| `default_server` | `GitHost` | `github.com` | Server for `org/repo` shorthand. |
| `workspace_repo` | `RepositoryName` | `workspace` | Repository name placed at the namespace directory as its workspace repository. |
| `workspace_auto` | `auto`, `always`, `never` | `auto` | Org workspace repository setup on clone (below). |

`sesame workspace init` writes `root` and `user` through
`core_config::edit`, which edits only the file that defines each key and
keeps comments and ordering.

**Links section:** a map from physical paths to profile names. Keys are
written for the path's physical form (symlinks resolved, trailing
separators dropped), so `/a/b` and `/a/b/` cannot both be keys.

### Org Workspace Setup

A member clone, and `--project`, set up the namespace's workspace
repository through one decision:

| Namespace directory | `auto` | `always` (or `--workspace-init`/`--workspace-update`) |
| --- | --- | --- |
| Absent | Clone it when the forge hosts one | Clone it when the forge hosts one |
| Workspace repository | Report when it is behind upstream | Fast-forward it |
| Other existing directory | Print a tip | Initialize around it with `--force`; without it, report the command |

`never` and `--no-workspace` skip setup. Cloning the workspace
repository itself skips it, so the requested endpoint, transport, and
port are used. A setup failure is printed and does not fail the clone
that triggered it.

`--project` prints the number of repositories the forge listed and the
number processed (the workspace repository is excluded), and exits 1
when any repository failed to clone. On GitHub, an owner is tried as an
organization first; only a 404 falls back to the user endpoint, and
rate limits and other failures are returned.

### Profile Link Resolution

`resolve_workspace_profile` in `sesame-workspace/src/config.rs` resolves
the physical form of a path to a profile name:

1. **Exact match**: the path matches a link key exactly.
2. **Longest component-wise prefix match**: the link key with the most
   path components that is a prefix of the path wins. Matching is per
   component, so `/org` never matches `/organic`.

### .sesame.toml (Local Config)

Workspace-level and repo-level configuration files (`.sesame.toml`)
provide per-directory overrides. The schema is `LocalSesameConfig` in
`core-config/src/schema_workspace.rs`:

```toml
# /workspace/alice/github.com/org/.sesame.toml
profile = "work"
secret_prefix = "MYAPP"
tags = ["dev-rust"]

[env]
RUST_LOG = "debug"
```

| Field | Type | Description |
| --- | --- | --- |
| `profile` | `Option<String>` | Default trust profile for this context. |
| `env` | `BTreeMap<String, String>` | Non-secret environment variables to inject. |
| `tags` | `Vec<String>` | Launch profile tags to apply by default. |
| `secret_prefix` | `Option<String>` | Env var prefix for secret injection (e.g., `"MYAPP"` causes `api-key` to become `MYAPP_API_KEY`). |

### Multi-Layer Config Precedence

`resolve_effective_config` in `sesame-workspace/src/config.rs` merges
configuration from all layers. Precedence (highest to lowest):

1. **Repo `.sesame.toml`** (`{path}/.sesame.toml`)
2. **Workspace `.sesame.toml`**
   (`{root}/{user}/{server}/{namespace}/.sesame.toml`)
3. **User config links** (`workspaces.toml` `[links]` section)

A path outside the layout skips the workspace layer; a path inside the
layout with a non-canonical directory is an error.

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

## Git Without a git Binary

Git operations use `gix` for cloning, discovery, and inspection, and
`libgit2` (`git2`; bundled in Cargo builds, nixpkgs' `libgit2` in the Nix
packages) for initializing a repository around existing content and
fast-forward pulls. No git CLI is executed and nothing is interpolated
into a shell:

- **HTTPS** remotes are served by gix in-process.
- **SSH** remotes run the system `ssh` client, which runs `git-upload-pack`
  on the server, as git does.
- **Local** remotes (`file://` or a path) are opened in-process by the
  remote probe and the upstream-drift check, because gix's local transport
  would run `git upload-pack`. A relative local `origin` is taken relative
  to its repository. Clones and workspace remotes are built from
  `RemoteEndpoint`, which is HTTPS or SSH only.

Clone failures are classified from gix's
typed handshake and transport errors: missing, empty, or rejected
credentials (an HTTP 401 included) are reported as authentication
failures with a credential-helper hint.
