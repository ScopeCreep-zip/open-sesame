use anyhow::Context;
use clap::ValueEnum;
use clap::{Parser, Subcommand};

/// Open Sesame — Platform Orchestration CLI.
#[derive(Parser)]
#[command(
    name = "sesame",
    about = "Open Sesame — platform orchestration CLI",
    version
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Initialize Open Sesame: create config, start daemons, set master password.
    Init {
        /// Skip keybinding setup.
        #[arg(long)]
        no_keybinding: bool,

        /// Destroy ALL Open Sesame data and reset to clean state. Requires typing "destroy all data" to confirm.
        #[arg(long)]
        wipe_reset_destroy_all_data: bool,

        /// Organization domain for namespace scoping (e.g., "braincraft.io").
        #[arg(long)]
        org: Option<String>,

        /// Enroll an SSH key for vault unlock.
        /// Accepts a fingerprint (SHA256:...), a public key file path (~/.ssh/id_ed25519.pub),
        /// or no value to interactively select from the SSH agent.
        /// Without --password, creates an SSH-key-only vault.
        /// With --password, creates a dual-factor vault.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        ssh_key: Option<String>,

        /// Enroll a password for vault unlock. Required with --ssh-key for dual-factor init.
        /// Without --ssh-key, this is the default behavior.
        #[arg(long)]
        password: bool,

        /// Auth policy for multi-factor vaults: "any" (either factor unlocks),
        /// "all" (every factor required), or policy expression.
        /// Default: "any" for dual-factor, ignored for single-factor.
        #[arg(long, default_value = "any")]
        auth_policy: String,
    },

    /// Show daemon status, active profiles, and lock state.
    Status,

    /// Clone a repository to its canonical workspace path.
    ///
    /// Automatically discovers and sets up the org-level workspace.git if one
    /// exists on the server. Equivalent to `sesame workspace clone` with sane
    /// defaults.
    ///
    /// Usage: sesame clone https://github.com/org/repo
    #[command(alias = "cl")]
    Clone {
        /// Git remote URL (HTTPS or SSH).
        url: String,

        /// Shallow clone depth.
        #[arg(long)]
        depth: Option<u32>,

        /// Link to a profile after cloning.
        #[arg(short, long)]
        profile: Option<String>,

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

    /// Unlock a vault with its password.
    Unlock {
        /// Target profiles (CSV: "default,work" or "org:vault,org:vault").
        /// Falls back to SESAME_PROFILES env var, then "default".
        #[arg(short, long)]
        profile: Option<String>,
    },

    /// Lock a vault (zeroize cached key material).
    Lock {
        /// Target profile. Omit to lock all vaults.
        #[arg(short, long)]
        profile: Option<String>,
    },

    /// Profile management.
    #[command(subcommand)]
    Profile(ProfileCmd),

    /// SSH agent key management for passwordless vault unlock.
    #[command(subcommand)]
    Ssh(SshCmd),

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

    /// Input remapper operations.
    #[command(subcommand)]
    Input(InputCmd),

    /// Snippet operations.
    #[command(subcommand)]
    Snippet(SnippetCmd),

    /// Setup COSMIC keybindings for window switcher and launcher overlay.
    ///
    /// Configures Alt+Tab (switch), Alt+Shift+Tab (switch backward),
    /// and a launcher key (default: alt+space) in COSMIC's shortcuts.ron.
    ///
    /// Usage: `sesame setup-keybinding [KEY_COMBO]`
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    SetupKeybinding {
        /// Launcher key combo (default: "alt+space"). Examples: "super+space", "alt+space".
        #[arg(default_value = "alt+space")]
        launcher_key: String,
    },

    /// Remove sesame keybindings from COSMIC configuration.
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    RemoveKeybinding,

    /// Show current sesame keybinding status in COSMIC.
    #[cfg(all(target_os = "linux", feature = "desktop"))]
    KeybindingStatus,

    /// Run a command with profile-scoped secrets as environment variables.
    ///
    /// Each secret key is transformed to an env var: uppercase, hyphens become
    /// underscores. Example: secret "api-key" becomes env var "API_KEY".
    ///
    /// Usage: sesame env -p work -- aws s3 ls
    Env {
        /// Profiles to source secrets from (CSV: "default,work" or "org:vault").
        /// Falls back to SESAME_PROFILES env var, then "default".
        #[arg(short, long)]
        profile: Option<String>,

        /// Prefix for env var names (e.g., --prefix MYAPP: "api-key" becomes "MYAPP_API_KEY").
        #[arg(long)]
        prefix: Option<String>,

        /// Command and arguments to execute.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Print profile secrets as shell/dotenv/json for eval or piping.
    ///
    /// Formats:
    ///   shell  (default) — export KEY="value"  (eval in bash/zsh/direnv)
    ///   dotenv           — KEY=value           (Docker, docker-compose, node)
    ///   json             — {"KEY":"value",...}  (jq, CI/CD, programmatic)
    ///
    /// Usage:
    ///   eval "$(sesame export -p work)"
    ///   sesame export -p work --format dotenv > .env.secrets
    ///   sesame export -p work --format json | jq .
    Export {
        /// Profiles to source secrets from (CSV: "default,work" or "org:vault").
        /// Falls back to SESAME_PROFILES env var, then "default".
        #[arg(short, long)]
        profile: Option<String>,

        /// Output format: shell, dotenv, json.
        #[arg(short, long, default_value = "shell")]
        format: ExportFormat,

        /// Prefix for env var names (e.g., --prefix MYAPP: "api-key" becomes "MYAPP_API_KEY").
        #[arg(long)]
        prefix: Option<String>,
    },

    /// Workspace management (directory-scoped project environments).
    #[command(subcommand, alias = "ws")]
    Workspace(WorkspaceCmd),
}

/// Resolve the workspace root from `SESAME_WORKSPACE_ROOT` or fall back to `/workspace`.
pub(crate) fn default_workspace_root() -> std::path::PathBuf {
    std::env::var("SESAME_WORKSPACE_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/workspace"))
}

/// Resolve the workspace path argument, defaulting to the current directory.
///
/// Fails explicitly if the current directory cannot be determined — a security
/// tool must never silently fall back to `"."`.
pub(crate) fn resolve_workspace_path(
    path: Option<std::path::PathBuf>,
) -> anyhow::Result<std::path::PathBuf> {
    match path {
        Some(p) => Ok(p),
        None => std::env::current_dir().context("failed to determine current directory"),
    }
}

#[derive(Subcommand)]
pub(crate) enum WorkspaceCmd {
    /// Create the workspace root and user directory.
    Init {
        /// Override the workspace root directory (default: $SESAME_WORKSPACE_ROOT or /workspace).
        #[arg(long, default_value_os_t = default_workspace_root())]
        root: std::path::PathBuf,

        /// Override username detection.
        #[arg(long)]
        user: Option<String>,
    },

    /// Clone a repository to its canonical workspace path.
    Clone {
        /// Git remote URL (HTTPS or SSH).
        url: String,

        /// Shallow clone depth.
        #[arg(long)]
        depth: Option<u32>,

        /// Link to a profile after cloning.
        #[arg(short, long)]
        profile: Option<String>,

        /// Adopt a pre-existing directory if it has the correct remote.
        /// Enabled by default; use --no-adopt to require a fresh clone.
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
    List {
        /// Filter by git server hostname.
        #[arg(long)]
        server: Option<String>,

        /// Filter by organization/user.
        #[arg(long)]
        org: Option<String>,

        /// Filter by linked profile name.
        #[arg(short, long)]
        profile: Option<String>,

        /// Output format.
        #[arg(short, long, default_value = "table")]
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
        #[arg(short, long)]
        profile: String,

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
    /// Secrets are injected as environment variables and are visible in
    /// `/proc/<pid>/environ` to processes running as the same user. All
    /// child processes inherit the secret environment.
    Shell {
        /// Override the linked profile.
        #[arg(short, long)]
        profile: Option<String>,

        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,

        /// Shell binary (default: $SHELL).
        #[arg(long)]
        shell: Option<String>,

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
}

#[derive(Subcommand)]
pub(crate) enum WorkspaceConfigCmd {
    /// Show resolved configuration with provenance for the current workspace.
    Show {
        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,
    },
}

#[derive(Clone, ValueEnum)]
pub(crate) enum WorkspaceListFormat {
    /// Formatted table output.
    Table,
    /// JSON output.
    Json,
}

#[derive(Clone, ValueEnum)]
pub(crate) enum ExportFormat {
    /// export KEY="value" — for eval in bash/zsh/direnv
    Shell,
    /// KEY=value — for Docker, docker-compose, node, python-dotenv
    Dotenv,
    /// {"KEY":"value",...} — for jq, CI/CD, programmatic consumers
    Json,
}

#[derive(Subcommand)]
pub(crate) enum ProfileCmd {
    /// List configured profiles.
    List,

    /// Activate a profile scope (open vault, register namespace).
    Activate {
        /// Profile name.
        name: String,
    },

    /// Deactivate a profile scope (flush cache, close vault).
    Deactivate {
        /// Profile name.
        name: String,
    },

    /// Set the default profile.
    Default {
        /// Profile name.
        name: String,
    },

    /// Show configuration for a named profile.
    Show {
        /// Profile name.
        name: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum SshCmd {
    /// Enroll an SSH key for passwordless vault unlock.
    ///
    /// Requires the vault to be unlockable with a password (the master key
    /// is derived via Argon2id, then wrapped under an SSH-derived KEK).
    /// Only Ed25519 and RSA (PKCS#1 v1.5) keys are supported — their
    /// signatures are deterministic, which is required for KEK derivation.
    Enroll {
        /// Target profiles (CSV: "default,work").
        /// Falls back to SESAME_PROFILES env var, then "default".
        #[arg(short, long)]
        profile: Option<String>,

        /// SSH key to enroll. Accepts a fingerprint (SHA256:...),
        /// a public key file path (~/.ssh/id_ed25519.pub), or omit
        /// to interactively select from the SSH agent.
        #[arg(short = 'k', long = "ssh-key")]
        ssh_key: Option<String>,
    },

    /// List SSH key enrollments for profiles.
    List {
        /// Target profiles (CSV: "default,work").
        /// Falls back to SESAME_PROFILES env var, then "default".
        #[arg(short, long)]
        profile: Option<String>,
    },

    /// Revoke SSH key enrollment for a profile.
    Revoke {
        /// Target profiles (CSV: "default,work").
        /// Falls back to SESAME_PROFILES env var, then "default".
        #[arg(short, long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum SecretCmd {
    /// Store a secret (prompts for value).
    Set {
        /// Profile name.
        #[arg(short, long)]
        profile: String,

        /// Secret key name.
        key: String,
    },

    /// Retrieve a secret value.
    Get {
        /// Profile name.
        #[arg(short, long)]
        profile: String,

        /// Secret key name.
        key: String,
    },

    /// Delete a secret.
    Delete {
        /// Profile name.
        #[arg(short, long)]
        profile: String,

        /// Secret key name.
        key: String,

        /// Skip confirmation prompt (for non-interactive/scripted use).
        #[arg(long)]
        yes: bool,
    },

    /// List secret keys (never values).
    List {
        /// Profile name.
        #[arg(short, long)]
        profile: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuditCmd {
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
pub(crate) enum WmCmd {
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
pub(crate) enum LaunchCmd {
    /// Search for applications by name (fuzzy match with frecency ranking).
    Search {
        /// Search query.
        query: String,

        /// Maximum results to return.
        #[arg(short = 'n', long, default_value = "10")]
        max_results: u32,

        /// Profile context for scoped frecency ranking.
        #[arg(short, long)]
        profile: Option<String>,
    },

    /// Launch an application by its desktop entry ID.
    ///
    /// Use `sesame launch search <query>` to find entry IDs.
    Run {
        /// Desktop entry ID (e.g., "org.mozilla.firefox").
        entry_id: String,

        /// Profile context for secrets and frecency.
        #[arg(short, long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ClipboardCmd {
    /// Show clipboard history for a profile.
    History {
        /// Profile name.
        #[arg(short, long)]
        profile: String,

        /// Maximum entries to show.
        #[arg(short = 'n', long, default_value = "20")]
        limit: u32,
    },

    /// Clear clipboard history for a profile.
    Clear {
        /// Profile name.
        #[arg(short, long)]
        profile: String,
    },

    /// Get a specific clipboard entry by ID.
    Get {
        /// Clipboard entry ID.
        entry_id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum InputCmd {
    /// List configured input layers.
    Layers,

    /// Show input daemon status (active layer, grabbed devices).
    Status,
}

#[derive(Subcommand)]
pub(crate) enum SnippetCmd {
    /// List snippets for a profile.
    List {
        /// Profile name.
        #[arg(short, long)]
        profile: String,
    },

    /// Expand a snippet trigger.
    Expand {
        /// Profile name.
        #[arg(short, long)]
        profile: String,

        /// Trigger string.
        trigger: String,
    },

    /// Add a new snippet.
    Add {
        /// Profile name.
        #[arg(short, long)]
        profile: String,

        /// Trigger string.
        trigger: String,

        /// Template body.
        template: String,
    },
}
