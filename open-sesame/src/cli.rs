//! The `sesame` command-line interface: the one definition the binary
//! parses with and xtask renders the man page and shell completions from.

use anyhow::Context;
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use core_types::{ClipboardEntryId, TrustProfileName};

/// Open Sesame — Platform Orchestration CLI.
#[derive(Parser)]
#[command(
    name = "sesame",
    about = "Open Sesame — platform orchestration CLI",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// One profile of a profile spec: `vault` or `org:vault`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSpec {
    /// Organizational namespace, carried through to `$SESAME_PROFILES`.
    pub org: Option<String>,
    /// The vault (trust profile) the spec names.
    pub vault: TrustProfileName,
}

impl std::fmt::Display for ProfileSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.org {
            Some(org) => write!(f, "{org}:{}", self.vault),
            None => write!(f, "{}", self.vault),
        }
    }
}

/// A non-empty, comma-separated list of profile specs, as `--profile` and
/// `$SESAME_PROFILES` carry it. `Display` writes the same form back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSpecs(Vec<ProfileSpec>);

impl ProfileSpecs {
    /// Parse `vault,org:vault,...`. Empty entries are skipped; each vault
    /// must be a valid trust profile name.
    ///
    /// # Errors
    ///
    /// When no entry remains, or a vault is not a valid profile name.
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let specs = input
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                let (org, vault) = match entry.rsplit_once(':') {
                    Some((org, vault)) => (Some(org.to_owned()), vault),
                    None => (None, entry),
                };
                let vault = TrustProfileName::try_from(vault)
                    .with_context(|| format!("invalid profile '{entry}'"))?;
                Ok(ProfileSpec { org, vault })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        anyhow::ensure!(!specs.is_empty(), "no profile given in '{input}'");
        Ok(Self(specs))
    }

    /// The specs, in precedence order (first wins).
    pub fn iter(&self) -> std::slice::Iter<'_, ProfileSpec> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a ProfileSpecs {
    type Item = &'a ProfileSpec;
    type IntoIter = std::slice::Iter<'a, ProfileSpec>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl std::fmt::Display for ProfileSpecs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, spec) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{spec}")?;
        }
        Ok(())
    }
}

/// A trust profile name argument, validated at parse time.
fn profile_name(value: &str) -> Result<TrustProfileName, core_types::Error> {
    TrustProfileName::try_from(value)
}

/// A launcher key combination argument, validated at parse time.
#[cfg(all(target_os = "linux", feature = "desktop"))]
fn launcher_key(value: &str) -> Result<core_types::KeyCombo, core_types::Error> {
    value.parse()
}

/// A clipboard entry ID argument: `clip-<uuid>` as `sesame clipboard
/// history` prints it.
fn clipboard_entry_id(value: &str) -> Result<ClipboardEntryId, String> {
    let uuid = value
        .strip_prefix("clip-")
        .ok_or_else(|| format!("'{value}' is not a clipboard entry ID (clip-<uuid>)"))?;
    uuid.parse()
        .map(ClipboardEntryId::from_uuid)
        .map_err(|e| format!("'{value}' is not a clipboard entry ID: {e}"))
}

/// The unlock policy of a new multi-factor vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthPolicyArg {
    /// Any one enrolled factor unlocks the vault.
    Any,
    /// Every enrolled factor is required.
    All,
}

impl From<AuthPolicyArg> for core_types::AuthCombineMode {
    fn from(policy: AuthPolicyArg) -> Self {
        match policy {
            AuthPolicyArg::Any => Self::Any,
            AuthPolicyArg::All => Self::All,
        }
    }
}

/// A `sesame status --doctor` check category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DoctorCategory {
    /// Every category below.
    All,
    /// Daemon units: running state, memory, restarts, uptime.
    Daemon,
    /// Accepted source revision, watcher health, and acknowledged consumer application.
    Config,
    /// Secret memory: `memfd_secret`, core dumps, swap.
    Memory,
    /// The environment proxy policy of git and forge transports.
    Network,
    /// Seccomp and `no_new_privs` of every daemon.
    Sandbox,
    /// Kernel, ptrace scope, session type, input group.
    Platform,
}

/// Output format of `sesame status --doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DoctorFormat {
    /// Grouped, colored lines.
    Text,
    /// One JSON document.
    Json,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize Open Sesame: create config, start daemons, set master password.
    Init {
        /// Skip keybinding setup.
        #[arg(long)]
        no_keybinding: bool,

        /// Destroy ALL Open Sesame data and reset to clean state. Requires typing "destroy all data" to confirm.
        #[arg(long, conflicts_with_all = ["no_keybinding", "org", "ssh_key", "password", "auth_policy"])]
        wipe_reset_destroy_all_data: bool,

        /// Organization domain for namespace scoping (e.g., "example.invalid").
        #[arg(long)]
        org: Option<String>,

        /// Enroll an SSH key for vault unlock.
        /// Accepts a fingerprint (`SHA256:...`), a public key file path (`~/.ssh/id_ed25519.pub`),
        /// or no value to interactively select from the SSH agent.
        /// Without --password, creates an SSH-key-only vault.
        /// With --password, creates a dual-factor vault.
        // Option<Option<_>>: clap's form for a flag with an optional value
        // (absent, bare, or valued).
        #[arg(long, num_args = 0..=1)]
        ssh_key: Option<Option<String>>,

        /// Enroll a password for vault unlock. Required with --ssh-key for dual-factor init.
        /// Without --ssh-key, this is the default behavior.
        #[arg(long)]
        password: bool,

        /// Unlock policy of a dual-factor vault; a single-factor vault
        /// ignores it.
        #[arg(long, value_enum, default_value_t = AuthPolicyArg::Any)]
        auth_policy: AuthPolicyArg,
    },

    /// Show daemon status, active profiles, and lock state.
    Status {
        /// Run diagnostic checks. Takes a comma-separated list of
        /// categories; without a value, every category.
        #[arg(
            long,
            value_name = "CATEGORIES",
            value_enum,
            value_delimiter = ',',
            num_args = 0..=1,
            default_missing_value = "all"
        )]
        doctor: Option<Vec<DoctorCategory>>,

        /// Output format for --doctor results.
        #[arg(long, value_enum, default_value_t = DoctorFormat::Text, requires = "doctor")]
        output: DoctorFormat,

        /// Exit with code 0 if all checks pass, 1 if any fail, 2 if any warn.
        /// Useful for systemd health checks and CI.
        #[arg(long, requires = "doctor")]
        exit_code: bool,

        /// Suppress output, only set exit code. Implies --exit-code.
        #[arg(long, requires = "doctor")]
        quiet: bool,

        /// Trigger immediate Noise IK key rotation across all daemons.
        /// Phase 2 (finalize registry, remove old keys) runs automatically
        /// after the 30-second grace period.
        #[arg(long, conflicts_with = "doctor")]
        rotate_keys: bool,
    },

    /// Clone a repository to its canonical workspace path.
    ///
    /// Automatically discovers and sets up the org-level workspace.git if one
    /// exists on the server. Equivalent to `sesame workspace clone` with sane
    /// defaults.
    ///
    /// Usage: sesame clone <https://github.com/org/repo>
    #[command(alias = "cl")]
    Clone {
        /// Git remote URL (HTTPS or SSH).
        url: String,

        /// Shallow clone depth.
        #[arg(long)]
        depth: Option<u32>,

        /// Link to a profile after cloning.
        #[arg(short, long, value_parser = profile_name)]
        profile: Option<TrustProfileName>,

        /// Skip workspace.git auto-discovery for this clone.
        #[arg(long)]
        no_workspace: bool,

        /// Clone all repositories in the org from the forge API.
        /// URL identifies the server and org (repo component is ignored).
        #[arg(long)]
        project: bool,

        /// Include forked repositories when using --project.
        #[arg(long, requires = "project")]
        include_forks: bool,

        /// Include archived repositories when using --project.
        #[arg(long, requires = "project")]
        include_archived: bool,
    },

    /// Unlock vaults with their enrolled factors.
    Unlock {
        /// Target profiles (CSV: "default,work" or "org:vault,org:vault").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,
    },

    /// Lock a vault (zeroize cached key material).
    Lock {
        /// Target profile. Omit to lock all vaults.
        #[arg(short, long, value_parser = profile_name)]
        profile: Option<TrustProfileName>,
    },

    /// Profile management.
    #[command(subcommand)]
    Profile(ProfileCmd),

    /// SSH agent key management for passwordless vault unlock.
    #[command(subcommand)]
    Ssh(SshCmd),

    /// Platform keyring (Secret Service) factor for passwordless vault unlock.
    #[command(subcommand)]
    Keyring(KeyringCmd),

    /// Secret management (profile-scoped).
    #[command(subcommand)]
    Secret(SecretCmd),

    /// Audit log operations.
    #[command(subcommand)]
    Audit(AuditCmd),

    /// Application launcher.
    #[command(subcommand)]
    Launch(LaunchCmd),

    /// Window manager operations.
    #[command(subcommand)]
    Wm(WmCmd),

    /// Clipboard operations.
    #[command(subcommand)]
    Clipboard(ClipboardCmd),

    /// Input daemon status and layers.
    #[command(subcommand)]
    Input(InputCmd),

    /// Snippet operations.
    #[command(subcommand)]
    Snippet(SnippetCmd),

    /// Bind the window switcher and launcher overlay shortcuts.
    ///
    /// Alt+Tab switches, Alt+Shift+Tab switches backward, and the launcher
    /// key (with Shift: backward) opens the launcher. Bound through the
    /// desktop's `GlobalShortcuts` portal when it implements it (daemon-launcher
    /// requests them), otherwise in COSMIC's shortcut configuration.
    ///
    /// Usage: `sesame setup-keybinding [KEY_COMBO]`
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    SetupKeybinding {
        /// Launcher key combo (default: `[global] launcher_key`, "alt+space").
        /// Examples: "super+space", "alt+space".
        #[arg(value_parser = launcher_key)]
        launcher_key: Option<core_types::KeyCombo>,
    },

    /// Remove the overlay shortcuts from the session's keybinding backend.
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    RemoveKeybinding,

    /// Show the keybinding backend and the overlay shortcuts it holds.
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    KeybindingStatus,

    /// Run a command with profile-scoped secrets as environment variables.
    ///
    /// Each secret key is transformed to an env var: uppercase, hyphens become
    /// underscores. Example: secret `api-key` becomes env var `API_KEY`.
    /// The command's exit status is sesame's exit status.
    ///
    /// Usage: sesame env -p work -- aws s3 ls
    Env {
        /// Profiles to source secrets from (CSV: "default,work" or "org:vault").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,

        /// Prefix for env var names (e.g., --prefix MYAPP: `api-key` becomes `MYAPP_API_KEY`).
        #[arg(long)]
        prefix: Option<String>,

        /// Command and arguments to execute.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Print profile secrets as shell/dotenv/json for eval or piping.
    ///
    /// Formats:
    ///   shell  (default) — export KEY='value'  (eval in bash/zsh/direnv)
    ///   dotenv           — KEY="value"         (Docker, docker-compose, node)
    ///   json             — {"KEY":"value",...}  (jq, CI/CD, programmatic)
    ///
    /// Usage:
    ///   eval "$(sesame export -p work)"
    ///   sesame export -p work --format dotenv > .env.secrets
    ///   sesame export -p work --format json | jq .
    Export {
        /// Profiles to source secrets from (CSV: "default,work" or "org:vault").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,

        /// Output format.
        #[arg(short, long, value_enum, default_value_t = ExportFormat::Shell)]
        format: ExportFormat,

        /// Prefix for env var names (e.g., --prefix MYAPP: `api-key` becomes `MYAPP_API_KEY`).
        #[arg(long)]
        prefix: Option<String>,
    },

    /// Workspace management (directory-scoped project environments).
    #[command(subcommand, alias = "ws")]
    Workspace(WorkspaceCmd),
}

#[derive(Subcommand)]
pub enum WorkspaceCmd {
    /// Create the workspace root and user directory.
    Init {
        /// Workspace root directory.
        ///
        /// Default: `$SESAME_WORKSPACE_ROOT`, else `settings.root` from
        /// `workspaces.toml` (default `/workspace`).
        #[arg(long)]
        root: Option<std::path::PathBuf>,

        /// Workspace user (default: $USER).
        #[arg(long)]
        user: Option<String>,
    },

    /// Clone a repository to its canonical workspace path.
    ///
    /// An existing repository at the path is adopted only when its
    /// `origin` is exactly the requested remote (host, namespace and
    /// repository spelling); a different remote at the same lowercase
    /// placement is a placement conflict.
    ///
    /// Exit status: 0 on success; 1 on any error, and with --project
    /// when any repository failed to clone.
    Clone {
        /// Git remote URL (HTTPS or SSH).
        url: String,

        /// Shallow clone depth.
        #[arg(long)]
        depth: Option<u32>,

        /// Link to a profile after cloning.
        #[arg(short, long, value_parser = profile_name)]
        profile: Option<TrustProfileName>,

        /// Adopt a pre-existing repository whose origin is exactly the
        /// requested remote. Enabled by default; `--adopt false` refuses
        /// an existing repository instead.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        adopt: bool,

        /// Initialize the org-level workspace.git even if the org directory
        /// already exists. Overrides the `workspace_auto` config setting.
        /// If the org directory has existing files that would be overwritten,
        /// requires `--force` to proceed.
        #[arg(long)]
        workspace_init: bool,

        /// Pull workspace.git updates if behind remote.
        /// Overrides the `workspace_auto` config setting.
        #[arg(long)]
        workspace_update: bool,

        /// Skip all workspace.git auto-discovery for this clone.
        /// Overrides the `workspace_auto` config setting.
        #[arg(long)]
        no_workspace: bool,

        /// Allow destructive workspace operations: overwrite existing files
        /// during `--workspace-init`, recover from broken partial init.
        /// Without this flag, operations that would modify existing content
        /// will print what would happen and refuse.
        #[arg(long)]
        force: bool,

        /// Clone all repositories in the org from the forge API.
        /// URL identifies the server and org (repo component is ignored).
        #[arg(long)]
        project: bool,

        /// Include forked repositories when using --project.
        #[arg(long, requires = "project")]
        include_forks: bool,

        /// Include archived repositories when using --project.
        #[arg(long, requires = "project")]
        include_archived: bool,
    },

    /// List all discovered workspaces.
    ///
    /// Layout entries that cannot be placed (non-canonical names, case
    /// variants, unreadable layout directories) are reported on stderr,
    /// and in the `issues` array of JSON output.
    ///
    /// Exit status: 0 when every layout entry was placed; 1 when any
    /// entry could not be placed (the listing is still printed) or on
    /// any other error.
    List {
        /// Filter by git server hostname.
        #[arg(long)]
        server: Option<String>,

        /// Filter by organization/user.
        #[arg(long)]
        org: Option<String>,

        /// Filter by linked profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: Option<TrustProfileName>,

        /// Filter by repository name (substring match).
        #[arg(long)]
        repo: Option<String>,

        /// Show only dirty (uncommitted changes) repositories.
        #[arg(long)]
        dirty: bool,

        /// Show only repos with local HEAD older than duration.
        /// Units match the LAST column: Nm (minutes), Nh (hours), Nd (days),
        /// Nw (weeks), Nmo (months, 30d), Ny (years, 365d).
        /// Example: --stale 30d
        #[arg(long)]
        stale: Option<String>,

        /// Columns to display (comma-separated).
        ///
        /// Default: `name,branch,commit,profile`
        ///
        /// Available: `name`, `branch`, `commit`, `status`, `size`, `git_size`,
        /// `files`, `last_commit`, `upstream_date`, `profile`, `server`, `org`,
        /// `remote`
        #[arg(short = 'o', long)]
        columns: Option<String>,

        /// Output format.
        #[arg(short, long, value_enum, default_value_t = WorkspaceListFormat::Table)]
        format: WorkspaceListFormat,
    },

    /// Show workspace status and metadata.
    Status {
        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,

        /// Show detailed convention breakdown and disk usage.
        #[arg(short, long)]
        verbose: bool,
    },

    /// Associate a workspace directory with a sesame profile.
    Link {
        /// Profile to link.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,

        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,
    },

    /// Remove a workspace-to-profile association.
    Unlink {
        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,
    },

    /// Open an interactive shell with vault secrets injected.
    ///
    /// Profiles: --profile, else the workspace's linked profile, else
    /// `$SESAME_PROFILES`, else `default`.
    ///
    /// Secrets are injected as environment variables and are visible in
    /// `/proc/<pid>/environ` to processes running as the same user. All
    /// child processes inherit the secret environment. The command's exit
    /// status is sesame's exit status.
    Shell {
        /// Override the linked profile (CSV: "default,work" or "org:vault").
        #[arg(short, long, value_parser = ProfileSpecs::parse)]
        profile: Option<ProfileSpecs>,

        /// The profiles of an enclosing sesame session, below the linked
        /// profile in precedence.
        #[arg(long, env = "SESAME_PROFILES", hide = true, value_parser = ProfileSpecs::parse)]
        inherited_profiles: Option<ProfileSpecs>,

        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,

        /// Shell binary (default: $SHELL).
        #[arg(long)]
        shell: Option<std::path::PathBuf>,

        /// Prefix for env var names (e.g., --prefix MYAPP).
        #[arg(long)]
        prefix: Option<String>,

        /// Command to run instead of interactive shell.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Show or inspect workspace configuration.
    #[command(subcommand)]
    Config(WorkspaceConfigCmd),

    /// Rename workspace directories to their canonical lowercase names.
    ///
    /// Without --apply, prints the renames, collisions, and stored-path
    /// rewrites (profile links, launch-profile cwd/devshell, linked
    /// worktree link files) that --apply would perform, and changes
    /// nothing. A collision (a non-canonical directory whose canonical
    /// name is held by another directory) is never resolved
    /// automatically; merge or remove one of the pair, then rerun.
    ///
    /// Exit status: 0 when the layout is (or would be) fully canonical;
    /// 1 when collisions, unfixable names, read-only policy values, or
    /// failures remain.
    Normalize {
        /// Perform the renames and rewrite stored paths.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
pub enum WorkspaceConfigCmd {
    /// Show resolved configuration with provenance for the current workspace.
    Show {
        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum WorkspaceListFormat {
    /// Formatted table output.
    Table,
    /// JSON output.
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    /// export KEY='value' — for eval in bash/zsh/direnv
    Shell,
    /// KEY="value" — for Docker, docker-compose, node, python-dotenv
    Dotenv,
    /// {"KEY":"value",...} — for jq, CI/CD, programmatic consumers
    Json,
}

#[derive(Subcommand)]
pub enum ProfileCmd {
    /// List configured profiles.
    List,

    /// Activate a profile scope (open vault, register namespace).
    Activate {
        /// Profile name.
        #[arg(value_parser = profile_name)]
        name: TrustProfileName,
    },

    /// Deactivate a profile scope (flush cache, close vault).
    Deactivate {
        /// Profile name.
        #[arg(value_parser = profile_name)]
        name: TrustProfileName,
    },

    /// Set the default profile.
    Default {
        /// Profile name.
        #[arg(value_parser = profile_name)]
        name: TrustProfileName,
    },

    /// Show configuration for a named profile.
    Show {
        /// Profile name.
        #[arg(value_parser = profile_name)]
        name: TrustProfileName,
    },
}

#[derive(Subcommand)]
pub enum SshCmd {
    /// Enroll an SSH key for passwordless vault unlock.
    ///
    /// Requires the vault to be unlockable with a password (the master key
    /// is derived via Argon2id, then wrapped under an SSH-derived KEK).
    /// Only Ed25519 and RSA (PKCS#1 v1.5) keys are supported — their
    /// signatures are deterministic, which is required for KEK derivation.
    Enroll {
        /// Target profiles (CSV: "default,work").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,

        /// SSH key to enroll. Accepts a fingerprint (`SHA256:...`),
        /// a public key file path (`~/.ssh/id_ed25519.pub`), or omit
        /// to interactively select from the SSH agent.
        #[arg(short = 'k', long = "ssh-key")]
        ssh_key: Option<String>,
    },

    /// List SSH key enrollments for profiles.
    List {
        /// Target profiles (CSV: "default,work").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,
    },

    /// Revoke SSH key enrollment for a profile.
    Revoke {
        /// Target profiles (CSV: "default,work").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,
    },
}

#[derive(Subcommand)]
pub enum KeyringCmd {
    /// Enroll the platform keyring for passwordless vault unlock.
    ///
    /// Stores a random 256-bit key-encrypting key in the operating system's
    /// credential store (the Secret Service on Linux) as
    /// `open-sesame`/`vault-kek:<profile>`, wraps the vault's master key
    /// under it, and proves the enrollment by unlocking with it before
    /// recording the factor. Requires the vault password.
    Enroll {
        /// Target profiles (CSV: "default,work").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,
    },

    /// Show each vault's platform keyring factor: its enrollment file,
    /// its metadata record, and its key in the credential store (reading
    /// the key may raise the keyring's unlock prompt).
    Status {
        /// Target profiles (CSV: "default,work").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,

        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Revoke the platform keyring factor: the enrollment file, the
    /// metadata record, and the key in the credential store.
    Revoke {
        /// Target profiles (CSV: "default,work").
        #[arg(short, long, env = "SESAME_PROFILES", default_value = core_types::DEFAULT_PROFILE_NAME, value_parser = ProfileSpecs::parse)]
        profile: ProfileSpecs,
    },
}

#[derive(Subcommand)]
pub enum SecretCmd {
    /// Store a secret (prompts for value; reads it from stdin when piped).
    Set {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,

        /// Secret key name.
        key: String,
    },

    /// Retrieve a secret value.
    Get {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,

        /// Secret key name.
        key: String,
    },

    /// Delete a secret.
    Delete {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,

        /// Secret key name.
        key: String,

        /// Skip confirmation prompt (for non-interactive/scripted use).
        #[arg(long)]
        yes: bool,
    },

    /// List secret keys (never values).
    List {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,
    },
}

#[derive(Subcommand)]
pub enum AuditCmd {
    /// Verify audit log hash chain integrity.
    Verify,

    /// Show recent audit log entries.
    Tail {
        /// Number of entries to show.
        #[arg(short = 'n', long, default_value = "20")]
        count: usize,

        /// Follow (stream) new entries as they are appended.
        #[arg(short = 'f', long)]
        follow: bool,
    },
}

#[derive(Subcommand)]
pub enum WmCmd {
    /// List windows known to daemon-wm.
    List,

    /// Switch to next/previous window in MRU order.
    Switch {
        /// Switch backward (previous) instead of forward.
        #[arg(long)]
        backward: bool,
    },

    /// Activate a specific window by ID or app ID.
    Focus {
        /// Window ID or app ID string.
        window_id: String,
    },

    /// Activate the window switcher overlay.
    ///
    /// Shows a visual overlay with hint keys for quick window selection.
    /// Use --launcher to skip the border-only phase and show the full
    /// overlay immediately.
    Overlay {
        /// Start in launcher mode (full overlay immediately, no border-only phase).
        #[arg(long)]
        launcher: bool,

        /// Start with backward direction (previous window in MRU order).
        #[arg(long)]
        backward: bool,
    },

    /// Run as resident fast-path process for overlay activation.
    ///
    /// Holds an active IPC connection and listens on a Unix datagram socket
    /// so subsequent overlay invocations can skip the Noise IK handshake.
    /// Not intended for direct user invocation.
    #[command(hide = true)]
    OverlayResident,
}

#[derive(Subcommand)]
pub enum LaunchCmd {
    /// Search for applications by name (fuzzy match with frecency ranking).
    Search {
        /// Search query.
        query: String,

        /// Maximum results to return.
        #[arg(short = 'n', long, default_value = "10")]
        max_results: u32,

        /// Profile context for scoped frecency ranking.
        #[arg(short, long, value_parser = profile_name)]
        profile: Option<TrustProfileName>,
    },

    /// Launch an application by its desktop entry ID.
    ///
    /// Use `sesame launch search <query>` to find entry IDs.
    Run {
        /// Desktop entry ID (e.g., "org.mozilla.firefox").
        entry_id: String,

        /// Profile context for secrets and frecency.
        #[arg(short, long, value_parser = profile_name)]
        profile: Option<TrustProfileName>,
    },
}

#[derive(Subcommand)]
pub enum ClipboardCmd {
    /// Show clipboard history for a profile.
    History {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,

        /// Maximum entries to show.
        #[arg(short = 'n', long, default_value = "20")]
        limit: u32,
    },

    /// Clear clipboard history for a profile.
    Clear {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,
    },

    /// Get a specific clipboard entry by ID.
    Get {
        /// Clipboard entry ID (`clip-<uuid>`, as `history` prints it).
        #[arg(value_parser = clipboard_entry_id)]
        entry_id: ClipboardEntryId,
    },
}

#[derive(Subcommand)]
pub enum InputCmd {
    /// List configured input layers.
    Layers,

    /// Show input daemon status (active layer, grabbed devices).
    Status,
}

#[derive(Subcommand)]
pub enum SnippetCmd {
    /// List snippets for a profile.
    List {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,
    },

    /// Expand a snippet trigger.
    Expand {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,

        /// Trigger string.
        trigger: String,
    },

    /// Add a new snippet.
    Add {
        /// Profile name.
        #[arg(short, long, value_parser = profile_name)]
        profile: TrustProfileName,

        /// Trigger string.
        trigger: String,

        /// Template body.
        template: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(name: &str) -> TrustProfileName {
        TrustProfileName::try_from(name).unwrap()
    }

    #[test]
    fn bare_vaults() {
        let specs = ProfileSpecs::parse("a,b,c").unwrap();
        let vaults: Vec<&str> = specs.iter().map(|s| s.vault.as_ref()).collect();
        assert_eq!(vaults, ["a", "b", "c"]);
        assert!(specs.iter().all(|s| s.org.is_none()));
    }

    #[test]
    fn org_scoped_vaults() {
        let specs = ProfileSpecs::parse("acme:operations,default:dev").unwrap();
        assert_eq!(
            specs.iter().cloned().collect::<Vec<_>>(),
            [
                ProfileSpec {
                    org: Some("acme".into()),
                    vault: vault("operations"),
                },
                ProfileSpec {
                    org: Some("default".into()),
                    vault: vault("dev"),
                },
            ]
        );
    }

    #[test]
    fn display_writes_the_parsed_form_back() {
        let input = "default,acme:ops";
        assert_eq!(ProfileSpecs::parse(input).unwrap().to_string(), input);
    }

    #[test]
    fn empty_entries_and_whitespace_are_ignored() {
        assert_eq!(ProfileSpecs::parse(" a ,, b ").unwrap().to_string(), "a,b");
    }

    #[test]
    fn no_profile_is_an_error() {
        assert!(ProfileSpecs::parse("").is_err());
        assert!(ProfileSpecs::parse(" , ").is_err());
    }

    #[test]
    fn invalid_vault_names_are_errors() {
        assert!(ProfileSpecs::parse("org:").is_err());
        assert!(ProfileSpecs::parse("a,../etc").is_err());
    }

    /// clap's own consistency checks (conflicting short flags, dangling
    /// `requires`/`conflicts_with` names) over the whole tree xtask renders.
    #[test]
    fn the_command_tree_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn clipboard_entry_ids_round_trip_their_display_form() {
        let id = ClipboardEntryId::from_uuid(uuid::Uuid::from_u128(5));
        assert_eq!(clipboard_entry_id(&id.to_string()).unwrap(), id);
        assert!(clipboard_entry_id("00000000-0000-0000-0000-000000000005").is_err());
        assert!(clipboard_entry_id("clip-nope").is_err());
    }

    #[test]
    fn doctor_without_a_value_selects_every_category() {
        let cli = Cli::try_parse_from(["sesame", "status", "--doctor"]).unwrap();
        let Command::Status { doctor, .. } = cli.command else {
            panic!("status");
        };
        assert_eq!(doctor, Some(vec![DoctorCategory::All]));
        let cli = Cli::try_parse_from(["sesame", "status", "--doctor", "memory,network"]).unwrap();
        let Command::Status { doctor, .. } = cli.command else {
            panic!("status");
        };
        assert_eq!(
            doctor,
            Some(vec![DoctorCategory::Memory, DoctorCategory::Network])
        );
        assert!(Cli::try_parse_from(["sesame", "status", "--doctor", "vault"]).is_err());
    }

    #[test]
    fn init_ssh_key_distinguishes_absent_bare_and_valued() {
        let parse = |args: &[&str]| {
            let cli = Cli::try_parse_from(args).unwrap();
            let Command::Init { ssh_key, .. } = cli.command else {
                panic!("init");
            };
            ssh_key
        };
        assert_eq!(parse(&["sesame", "init"]), None);
        assert_eq!(parse(&["sesame", "init", "--ssh-key"]), Some(None));
        assert_eq!(
            parse(&["sesame", "init", "--ssh-key", "SHA256:abc"]),
            Some(Some("SHA256:abc".into()))
        );
    }

    #[test]
    fn exclusive_modes_refuse_other_flags() {
        for args in [
            &[
                "sesame",
                "init",
                "--wipe-reset-destroy-all-data",
                "--password",
            ][..],
            &[
                "sesame",
                "init",
                "--wipe-reset-destroy-all-data",
                "--org",
                "example.invalid",
            ],
            &["sesame", "status", "--rotate-keys", "--doctor"],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
        assert!(Cli::try_parse_from(["sesame", "init", "--wipe-reset-destroy-all-data"]).is_ok());
        assert!(Cli::try_parse_from(["sesame", "status", "--rotate-keys"]).is_ok());
    }

    #[test]
    fn invalid_profile_names_are_rejected_at_parse_time() {
        assert!(Cli::try_parse_from(["sesame", "secret", "list", "-p", "../etc"]).is_err());
        assert!(Cli::try_parse_from(["sesame", "secret", "list", "-p", "work"]).is_ok());
    }
}
