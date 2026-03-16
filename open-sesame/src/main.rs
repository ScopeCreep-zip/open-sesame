//! Open Sesame CLI — platform orchestration for multi-agent desktop control.
//!
//! All subcommands connect to the IPC bus, send a request, wait for a
//! correlated response, format the output, and exit.
//!
//! Exit codes:
//!   0 — success (or child process exit code for `sesame env`)
//!   1 — error (daemon unreachable, request failed, etc.)
//!   2 — timeout waiting for response

mod init;

use anyhow::Context;
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use comfy_table::{Table, presets::UTF8_FULL};
use core_ipc::BusClient;
use core_types::{DaemonId, EventKind, ProfileId, SecurityLevel, SensitiveBytes, TrustProfileName};
use owo_colors::OwoColorize;
use std::time::Duration;
use zeroize::Zeroize;

/// Default RPC timeout.
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Open Sesame — Platform Orchestration CLI.
#[derive(Parser)]
#[command(
    name = "sesame",
    about = "Open Sesame — platform orchestration CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    },

    /// Show daemon status, active profiles, and lock state.
    Status,

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
    /// Usage: sesame setup-keybinding [KEY_COMBO]
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
fn default_workspace_root() -> std::path::PathBuf {
    std::env::var("SESAME_WORKSPACE_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/workspace"))
}

/// Resolve the workspace path argument, defaulting to the current directory.
///
/// Fails explicitly if the current directory cannot be determined — a security
/// tool must never silently fall back to `"."`.
fn resolve_workspace_path(path: Option<std::path::PathBuf>) -> anyhow::Result<std::path::PathBuf> {
    match path {
        Some(p) => Ok(p),
        None => std::env::current_dir().context("failed to determine current directory"),
    }
}

#[derive(Subcommand)]
enum WorkspaceCmd {
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
enum WorkspaceConfigCmd {
    /// Show resolved configuration with provenance for the current workspace.
    Show {
        /// Workspace path (default: current directory).
        path: Option<std::path::PathBuf>,
    },
}

#[derive(Clone, ValueEnum)]
enum WorkspaceListFormat {
    /// Formatted table output.
    Table,
    /// JSON output.
    Json,
}

#[derive(Clone, ValueEnum)]
enum ExportFormat {
    /// export KEY="value" — for eval in bash/zsh/direnv
    Shell,
    /// KEY=value — for Docker, docker-compose, node, python-dotenv
    Dotenv,
    /// {"KEY":"value",...} — for jq, CI/CD, programmatic consumers
    Json,
}

#[derive(Subcommand)]
enum ProfileCmd {
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
enum SshCmd {
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
enum SecretCmd {
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
enum AuditCmd {
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
enum WmCmd {
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
enum LaunchCmd {
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
enum ClipboardCmd {
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
enum InputCmd {
    /// List configured input layers.
    Layers,

    /// Show input daemon status (active layer, grabbed devices).
    Status,
}

#[derive(Subcommand)]
enum SnippetCmd {
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("{}: {e:#}", "error".red().bold());
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Init {
            no_keybinding,
            wipe_reset_destroy_all_data,
            org,
        } => {
            if wipe_reset_destroy_all_data {
                init::cmd_wipe()
            } else {
                init::cmd_init(no_keybinding, org).await
            }
        }
        Command::Status => cmd_status().await,
        Command::Unlock { profile } => cmd_unlock(profile).await,
        Command::Lock { profile } => cmd_lock(profile).await,
        Command::Profile(sub) => match sub {
            ProfileCmd::List => cmd_profile_list().await,
            ProfileCmd::Activate { name } => cmd_profile_activate(&name).await,
            ProfileCmd::Deactivate { name } => cmd_profile_deactivate(&name).await,
            ProfileCmd::Default { name } => cmd_profile_default(&name).await,
            ProfileCmd::Show { name } => cmd_profile_show(&name),
        },
        Command::Ssh(sub) => match sub {
            SshCmd::Enroll { profile } => cmd_ssh_enroll(profile).await,
            SshCmd::List { profile } => cmd_ssh_list(profile).await,
            SshCmd::Revoke { profile } => cmd_ssh_revoke(profile).await,
        },
        Command::Secret(sub) => match sub {
            SecretCmd::Set { profile, key } => cmd_secret_set(&profile, &key).await,
            SecretCmd::Get { profile, key } => cmd_secret_get(&profile, &key).await,
            SecretCmd::Delete { profile, key, yes } => cmd_secret_delete(&profile, &key, yes).await,
            SecretCmd::List { profile } => cmd_secret_list(&profile).await,
        },
        Command::Audit(sub) => match sub {
            AuditCmd::Verify => cmd_audit_verify(),
            AuditCmd::Tail { count, follow } => cmd_audit_tail(count, follow).await,
        },
        Command::Wm(sub) => match sub {
            WmCmd::List => cmd_wm_list().await,
            WmCmd::Switch { backward } => cmd_wm_switch(backward).await,
            WmCmd::Focus { window_id } => cmd_wm_focus(&window_id).await,
            WmCmd::Overlay { launcher, backward } => cmd_wm_overlay(launcher, backward).await,
            WmCmd::OverlayResident => cmd_wm_overlay_resident().await,
        },
        Command::Launch(sub) => match sub {
            LaunchCmd::Search {
                query,
                max_results,
                profile,
            } => cmd_launch_search(&query, max_results, profile.as_deref()).await,
            LaunchCmd::Run { entry_id, profile } => {
                cmd_launch_run(&entry_id, profile.as_deref()).await
            }
        },
        Command::Clipboard(sub) => match sub {
            ClipboardCmd::History { profile, limit } => {
                cmd_clipboard_history(&profile, limit).await
            }
            ClipboardCmd::Clear { profile } => cmd_clipboard_clear(&profile).await,
            ClipboardCmd::Get { entry_id } => cmd_clipboard_get(&entry_id).await,
        },
        Command::Input(sub) => match sub {
            InputCmd::Layers => cmd_input_layers().await,
            InputCmd::Status => cmd_input_status().await,
        },
        Command::Snippet(sub) => match sub {
            SnippetCmd::List { profile } => cmd_snippet_list(&profile).await,
            SnippetCmd::Expand { profile, trigger } => cmd_snippet_expand(&profile, &trigger).await,
            SnippetCmd::Add {
                profile,
                trigger,
                template,
            } => cmd_snippet_add(&profile, &trigger, &template).await,
        },
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::SetupKeybinding { launcher_key } => {
            platform_linux::cosmic_keys::setup_keybinding(&launcher_key)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::RemoveKeybinding => {
            platform_linux::cosmic_keys::remove_keybinding().map_err(|e| anyhow::anyhow!("{e}"))
        }
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::KeybindingStatus => {
            platform_linux::cosmic_keys::keybinding_status().map_err(|e| anyhow::anyhow!("{e}"))
        }
        Command::Env {
            profile,
            prefix,
            command,
        } => cmd_env(profile.as_deref(), prefix.as_deref(), &command).await,
        Command::Export {
            profile,
            format,
            prefix,
        } => cmd_export(profile.as_deref(), &format, prefix.as_deref()).await,
        Command::Workspace(sub) => cmd_workspace(sub).await,
    }
}

// ============================================================================
// IPC connection helper
// ============================================================================

pub(crate) async fn connect() -> anyhow::Result<BusClient> {
    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;

    let server_pub = core_ipc::noise::read_bus_public_key()
        .await
        .context("daemon-profile is not running (no bus public key found)")?;

    let daemon_id = DaemonId::new();

    // CLI uses ephemeral keypair — server assigns Open clearance for unknown keys.
    let client_keypair =
        core_ipc::generate_keypair().context("failed to generate ephemeral keypair")?;

    let mut client = BusClient::connect_encrypted(
        daemon_id,
        &socket_path,
        &server_pub,
        client_keypair.as_inner(),
    )
    .await
    .context("failed to connect to IPC bus — is daemon-profile running?")?;

    // Populate origin_installation on outbound messages if installation.toml exists.
    if let Ok(install_config) = core_config::load_installation() {
        let install_id = core_types::InstallationId {
            id: install_config.id,
            org_ns: install_config
                .org
                .map(|o| core_types::OrganizationNamespace {
                    domain: o.domain,
                    namespace: o.namespace,
                }),
            namespace: install_config.namespace,
            machine_binding: None,
        };
        client.set_installation(install_id);
    }

    Ok(client)
}

/// Send an RPC request and wait for the correlated response.
pub(crate) async fn rpc(
    client: &BusClient,
    event: EventKind,
    security_level: SecurityLevel,
) -> anyhow::Result<EventKind> {
    let response = client
        .request(event, security_level, RPC_TIMEOUT)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("timed out") {
                eprintln!(
                    "{}: no response within {}s",
                    "timeout".yellow().bold(),
                    RPC_TIMEOUT.as_secs()
                );
                std::process::exit(2);
            }
            anyhow::anyhow!("{e}")
        })?;
    if let EventKind::AccessDenied { reason } = &response.payload {
        anyhow::bail!("access denied: {reason}");
    }
    Ok(response.payload)
}

// ============================================================================
// Command implementations
// ============================================================================

async fn cmd_status() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::StatusRequest, SecurityLevel::Internal).await? {
        EventKind::StatusResponse {
            active_profiles,
            default_profile,
            locked,
            lock_state,
            ..
        } => {
            // Per-profile lock state display.
            if lock_state.is_empty() {
                // Fallback: daemon didn't return per-profile state, use global locked flag.
                let lock_status = if locked {
                    "locked".red().bold().to_string()
                } else {
                    "unlocked".green().bold().to_string()
                };
                println!("Secrets daemon: {lock_status}");
            } else {
                println!("Vaults:");
                let max_name_len = lock_state
                    .keys()
                    .map(|k| k.as_ref().len())
                    .max()
                    .unwrap_or(0);
                for (profile, is_locked) in &lock_state {
                    let status = if *is_locked {
                        "locked".red().bold().to_string()
                    } else {
                        "unlocked".green().bold().to_string()
                    };
                    println!(
                        "  {:width$}  {status}",
                        profile.as_ref(),
                        width = max_name_len
                    );
                }
            }

            println!("Default profile: {}", default_profile.as_ref().bold());

            if active_profiles.is_empty() {
                println!("Active profiles: {}", "none".dimmed());
            } else {
                println!("Active profiles:");
                for p in &active_profiles {
                    let marker = if p == &default_profile {
                        " (default)"
                    } else {
                        ""
                    };
                    println!("  - {p}{marker}");
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

/// A parsed profile spec from CSV input like "org:vault" or bare "vault".
#[derive(Debug, Clone)]
struct ProfileSpec {
    /// Organizational namespace (optional). Currently informational.
    org: Option<String>,
    /// The vault/profile name used for IPC.
    vault: String,
}

/// Parse a CSV profile spec string.
///
/// Format: `vault,org:vault,org:vault`
/// - `default` → ProfileSpec { org: None, vault: "default" }
/// - `braincraft:operations` → ProfileSpec { org: Some("braincraft"), vault: "operations" }
///
/// Designed for future extension to `docker.io/project/org:vault@sha256`.
fn parse_profile_specs(input: &str) -> Vec<ProfileSpec> {
    input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|entry| {
            if let Some((org, vault)) = entry.rsplit_once(':') {
                ProfileSpec {
                    org: Some(org.to_string()),
                    vault: vault.to_string(),
                }
            } else {
                ProfileSpec {
                    org: None,
                    vault: entry.to_string(),
                }
            }
        })
        .collect()
}

/// Resolve profile specs from a CLI flag or SESAME_PROFILES env var.
fn resolve_profile_specs(cli_arg: Option<&str>) -> Vec<ProfileSpec> {
    let input = match cli_arg {
        Some(p) => p.to_string(),
        None => std::env::var("SESAME_PROFILES").unwrap_or_else(|_| "default".into()),
    };
    parse_profile_specs(&input)
}

/// Fetch secrets from multiple profiles, merging with left-wins collision resolution.
async fn fetch_multi_profile_secrets(
    client: &BusClient,
    specs: &[ProfileSpec],
    prefix: Option<&str>,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut seen_keys = std::collections::HashSet::new();
    let mut merged = Vec::new();

    for spec in specs {
        let profile = TrustProfileName::try_from(spec.vault.as_str())
            .map_err(|e| anyhow::anyhow!("invalid profile/vault '{}': {e}", spec.vault))?;
        let secrets = fetch_profile_secrets(client, &profile, prefix).await?;
        for (key, value) in secrets {
            if seen_keys.insert(key.clone()) {
                merged.push((key, value));
            }
        }
    }

    Ok(merged)
}

async fn cmd_unlock(profile_arg: Option<String>) -> anyhow::Result<()> {
    let client = connect().await?;

    let specs = resolve_profile_specs(profile_arg.as_deref());
    let config_dir = core_config::config_dir();

    for spec in &specs {
        let profile_name = &spec.vault;
        let target_profile = TrustProfileName::try_from(profile_name.as_str())
            .map_err(|e| anyhow::anyhow!("invalid profile name '{profile_name}': {e}"))?;

        // Try SSH-agent auto-unlock first
        let salt_path = config_dir
            .join("vaults")
            .join(format!("{target_profile}.salt"));
        if let Ok(salt) = std::fs::read(&salt_path) {
            let dispatcher = core_auth::AuthDispatcher::new();
            if let Some(backend) = dispatcher
                .find_auto_backend(&target_profile, &config_dir)
                .await
            {
                match backend.unlock(&target_profile, &config_dir, &salt).await {
                    Ok(outcome) => {
                        let fp = outcome
                            .audit_metadata
                            .get("ssh_fingerprint")
                            .cloned()
                            .unwrap_or_default();
                        // Transfer master key bytes without creating an
                        // unprotected intermediate copy. into_vec() moves
                        // the backing allocation directly into SensitiveBytes.
                        let event = EventKind::SshUnlockRequest {
                            master_key: SensitiveBytes::new(outcome.master_key.into_vec()),
                            profile: target_profile.clone(),
                            ssh_fingerprint: fp,
                        };
                        match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
                            EventKind::UnlockResponse {
                                success: true,
                                profile,
                            } => {
                                println!(
                                    "{}",
                                    format!("Vault '{profile}' unlocked via SSH agent.").green()
                                );
                                continue;
                            }
                            EventKind::UnlockRejected {
                                reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
                                profile,
                            } => {
                                println!(
                                    "{}",
                                    format!(
                                        "Vault '{}' already unlocked.",
                                        profile.as_ref().map_or("unknown", |p| p.as_ref())
                                    )
                                    .yellow()
                                );
                                continue;
                            }
                            EventKind::UnlockResponse { success: false, .. } => {
                                tracing::debug!(
                                    "SSH unlock rejected by daemon-secrets, falling back to password"
                                );
                            }
                            _ => {
                                tracing::debug!(
                                    "unexpected SSH unlock response, falling back to password"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "SSH auto-unlock failed, falling back to password");
                    }
                }
            }
        }

        // Fall through to password prompt
        let mut password = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            dialoguer::Password::new()
                .with_prompt(format!("Password for vault '{profile_name}'"))
                .interact()
                .context("failed to read password")?
        } else {
            let mut buf = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buf)
                .context("failed to read password from stdin")?;
            if buf.ends_with('\n') {
                buf.pop();
                if buf.ends_with('\r') {
                    buf.pop();
                }
            }
            if buf.is_empty() {
                anyhow::bail!(
                    "empty password from stdin for vault '{profile_name}' — refusing to unlock with no password"
                );
            }
            buf
        };

        let mut password_bytes = password.as_bytes().to_vec();
        password.zeroize();

        let event = EventKind::UnlockRequest {
            password: SensitiveBytes::new(std::mem::take(&mut password_bytes)),
            profile: Some(target_profile),
        };
        password_bytes.zeroize();

        match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
            EventKind::UnlockResponse {
                success: true,
                profile,
            } => {
                println!("{}", format!("Vault '{}' unlocked.", profile).green());
            }
            EventKind::UnlockResponse {
                success: false,
                profile,
            } => {
                anyhow::bail!(
                    "unlock failed for vault '{}' — wrong password or keyring error",
                    profile
                );
            }
            EventKind::UnlockRejected {
                reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
                profile,
            } => {
                println!(
                    "{}",
                    format!(
                        "Vault '{}' already unlocked.",
                        profile.as_ref().map_or("unknown", |p| p.as_ref())
                    )
                    .yellow()
                );
            }
            other => anyhow::bail!("unexpected response: {other:?}"),
        }
    }

    Ok(())
}

async fn cmd_ssh_enroll(profile_arg: Option<String>) -> anyhow::Result<()> {
    let specs = resolve_profile_specs(profile_arg.as_deref());
    let config_dir = core_config::config_dir();

    for spec in &specs {
        let profile_name = &spec.vault;
        let target = TrustProfileName::try_from(profile_name.as_str())
            .map_err(|e| anyhow::anyhow!("invalid profile name '{profile_name}': {e}"))?;

        // Vault must have a salt (must be initialized)
        let salt_path = config_dir.join("vaults").join(format!("{target}.salt"));
        let salt = std::fs::read(&salt_path)
            .context("failed to read vault salt — is the vault created?")?;

        // Need password to derive master key for wrapping
        println!("SSH enrollment requires your vault password to derive the master key.");
        let password = dialoguer::Password::new()
            .with_prompt(format!("Password for vault '{profile_name}'"))
            .interact()
            .context("failed to read password")?;

        let salt_array: [u8; 16] = salt
            .as_slice()
            .try_into()
            .context("vault salt must be exactly 16 bytes")?;
        let master_key = core_crypto::derive_key_argon2(password.as_bytes(), &salt_array)
            .context("failed to derive master key from password")?;

        // List SSH agent keys for user selection
        let sock_path = std::env::var("SSH_AUTH_SOCK")
            .context("SSH_AUTH_SOCK not set — is ssh-agent running?")?;
        let mut agent = ssh_agent_client_rs::Client::connect(std::path::Path::new(&sock_path))
            .context("failed to connect to SSH agent")?;
        let identities = agent
            .list_all_identities()
            .context("failed to list SSH agent keys")?;

        let eligible: Vec<_> = identities
            .into_iter()
            .filter(|id| {
                let algo = match id {
                    ssh_agent_client_rs::Identity::PublicKey(cow) => cow.algorithm(),
                    ssh_agent_client_rs::Identity::Certificate(cow) => cow.algorithm(),
                };
                core_auth::SshKeyType::from_algorithm(&algo).is_ok()
            })
            .collect();

        if eligible.is_empty() {
            anyhow::bail!(
                "no eligible SSH keys found in agent.\n\
                 Only Ed25519 and RSA keys are supported (ECDSA uses non-deterministic signatures).\n\
                 Add a key with: ssh-add ~/.ssh/id_ed25519"
            );
        }

        let key_labels: Vec<String> = eligible
            .iter()
            .map(|id| match id {
                ssh_agent_client_rs::Identity::PublicKey(cow) => {
                    let fp = cow.fingerprint(ssh_key::HashAlg::Sha256);
                    let algo = cow.algorithm();
                    format!("{fp} ({algo:?})")
                }
                ssh_agent_client_rs::Identity::Certificate(cow) => {
                    let algo = cow.algorithm();
                    format!("<certificate> ({algo:?})")
                }
            })
            .collect();

        let selection = if key_labels.len() == 1 {
            println!("Using key: {}", key_labels[0]);
            0
        } else {
            dialoguer::Select::new()
                .with_prompt("Select SSH key for enrollment")
                .items(&key_labels)
                .default(0)
                .interact()?
        };

        let backend = core_auth::SshAgentBackend::new();
        core_auth::VaultAuthBackend::enroll(
            &backend,
            &target,
            &master_key,
            &config_dir,
            &salt,
            Some(selection),
        )
        .await?;

        println!(
            "{}",
            format!("SSH enrollment created for vault '{profile_name}'.").green()
        );
        println!("Future unlocks will use your SSH key automatically when the agent is loaded.");
    }

    Ok(())
}

async fn cmd_ssh_list(profile_arg: Option<String>) -> anyhow::Result<()> {
    let specs = resolve_profile_specs(profile_arg.as_deref());
    let config_dir = core_config::config_dir();

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "Profile",
        "SSH Enrolled",
        "Key Fingerprint",
        "Key Type",
        "Agent Available",
    ]);

    for spec in &specs {
        let profile_name = &spec.vault;
        let target = TrustProfileName::try_from(profile_name.as_str())
            .map_err(|e| anyhow::anyhow!("invalid profile name '{profile_name}': {e}"))?;

        let backend = core_auth::SshAgentBackend::new();
        let enrolled = core_auth::VaultAuthBackend::is_enrolled(&backend, &target, &config_dir);

        if enrolled {
            let blob_path = config_dir
                .join("vaults")
                .join(format!("{target}.ssh-enrollment"));
            let (fp, kt) = std::fs::read(&blob_path)
                .ok()
                .and_then(|data| core_auth::EnrollmentBlob::deserialize(&data).ok())
                .map(|blob| (blob.key_fingerprint, blob.key_type.wire_name().to_string()))
                .unwrap_or_else(|| ("<unreadable>".into(), "<unknown>".into()));

            let available =
                core_auth::VaultAuthBackend::can_unlock(&backend, &target, &config_dir).await;

            table.add_row(vec![
                profile_name.clone(),
                "yes".into(),
                fp,
                kt,
                if available { "yes" } else { "no" }.into(),
            ]);
        } else {
            table.add_row(vec![
                profile_name.clone(),
                "no".into(),
                "-".into(),
                "-".into(),
                "-".into(),
            ]);
        }
    }

    println!("{table}");
    Ok(())
}

async fn cmd_ssh_revoke(profile_arg: Option<String>) -> anyhow::Result<()> {
    let specs = resolve_profile_specs(profile_arg.as_deref());
    let config_dir = core_config::config_dir();

    for spec in &specs {
        let profile_name = &spec.vault;
        let target = TrustProfileName::try_from(profile_name.as_str())
            .map_err(|e| anyhow::anyhow!("invalid profile name '{profile_name}': {e}"))?;

        let backend = core_auth::SshAgentBackend::new();
        if !core_auth::VaultAuthBackend::is_enrolled(&backend, &target, &config_dir) {
            println!(
                "{}",
                format!("No SSH enrollment found for vault '{profile_name}'.").yellow()
            );
            continue;
        }

        core_auth::VaultAuthBackend::revoke(&backend, &target, &config_dir).await?;
        println!(
            "{}",
            format!("SSH enrollment revoked for vault '{profile_name}'.").green()
        );
    }

    Ok(())
}

async fn cmd_lock(profile_arg: Option<String>) -> anyhow::Result<()> {
    let client = connect().await?;

    let target_profile = profile_arg
        .map(|p| TrustProfileName::try_from(p.as_str()))
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid profile name: {e}"))?;

    let event = EventKind::LockRequest {
        profile: target_profile,
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::LockResponse {
            success: true,
            profiles_locked,
        } => {
            if profiles_locked.is_empty() {
                println!("{}", "All vaults locked. Key material zeroized.".green());
            } else {
                for p in &profiles_locked {
                    println!(
                        "{}",
                        format!("Vault '{}' locked. Key material zeroized.", p).green()
                    );
                }
            }
        }
        EventKind::LockResponse { success: false, .. } => {
            anyhow::bail!("lock failed");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_profile_list() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::ProfileList, SecurityLevel::Internal).await? {
        EventKind::ProfileListResponse { profiles } => {
            if profiles.is_empty() {
                println!("{}", "No profiles configured.".dimmed());
                return Ok(());
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Name", "Active", "Default"]);

            for p in &profiles {
                let active = if p.is_active {
                    "yes".green().to_string()
                } else {
                    "no".dimmed().to_string()
                };
                let default = if p.is_default {
                    "yes".green().to_string()
                } else {
                    "".to_string()
                };
                let name_str = p.name.to_string();
                table.add_row(vec![&name_str, &active, &default]);
            }

            println!("{table}");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_profile_activate(name: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile_name = TrustProfileName::try_from(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::ProfileActivate {
        target: ProfileId::new(),
        profile_name,
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileActivateResponse { success: true } => {
            println!("Profile '{}' activated.", name.green());
        }
        EventKind::ProfileActivateResponse { success: false } => {
            anyhow::bail!("failed to activate profile '{name}'");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_profile_deactivate(name: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile_name = TrustProfileName::try_from(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::ProfileDeactivate {
        target: ProfileId::new(),
        profile_name,
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileDeactivateResponse { success: true } => {
            println!("Profile '{}' deactivated.", name.green());
        }
        EventKind::ProfileDeactivateResponse { success: false } => {
            anyhow::bail!("failed to deactivate profile '{name}' — not active?");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_profile_default(name: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile_name = TrustProfileName::try_from(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SetDefaultProfile { profile_name };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SetDefaultProfileResponse { success: true } => {
            println!("Default profile set to '{}'.", name.green());
        }
        EventKind::SetDefaultProfileResponse { success: false } => {
            anyhow::bail!("failed to set default profile to '{name}'");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

fn cmd_profile_show(name: &str) -> anyhow::Result<()> {
    let config = core_config::load_config(None).context("failed to load config")?;

    let profile = config
        .profiles
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("profile '{name}' not found in config"))?;

    let toml_str = toml::to_string_pretty(profile).context("failed to serialize profile config")?;

    println!("Profile: {}", name.bold());
    if name == config.global.default_profile.as_ref() {
        println!("(default profile)");
    }
    println!();
    println!("{toml_str}");

    Ok(())
}

async fn cmd_secret_set(profile: &str, key: &str) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut value = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        dialoguer::Password::new()
            .with_prompt(format!("Value for '{key}'"))
            .interact()
            .context("failed to read secret value")?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("failed to read secret value from stdin")?;
        // Trim trailing newline from piped input.
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    };

    let mut value_bytes = value.as_bytes().to_vec();
    value.zeroize();

    let event = EventKind::SecretSet {
        profile: profile.clone(),
        key: key.to_owned(),
        value: SensitiveBytes::new(std::mem::take(&mut value_bytes)),
    };
    value_bytes.zeroize();

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretSetResponse { success: true, .. } => {
            println!("Secret '{key}' stored in profile '{profile}'.");
        }
        EventKind::SecretSetResponse {
            success: false,
            denial,
        } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, key, &profile));
            }
            anyhow::bail!("failed to store secret");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_secret_get(profile: &str, key: &str) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SecretGet {
        profile: profile.clone(),
        key: key.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretGetResponse {
            key: k,
            value,
            denial,
        } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, &k, &profile));
            }
            if value.is_empty() {
                anyhow::bail!("secret '{k}' not found in profile '{profile}'");
            }
            // With default config (ipc-field-encryption off), value is
            // plaintext over Noise-encrypted transport. Print as UTF-8
            // if valid, hex otherwise. Zeroize all copies after printing.
            match String::from_utf8(value.as_bytes().to_vec()) {
                Ok(mut s) => {
                    println!("{s}");
                    s.zeroize();
                }
                Err(_) => {
                    let mut hex: String = value
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    println!("{hex}");
                    hex.zeroize();
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_secret_delete(profile: &str, key: &str, skip_confirm: bool) -> anyhow::Result<()> {
    validate_secret_key(key)?;
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Confirm deletion with TTY and non-TTY support.
    if !skip_confirm {
        let confirmed = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            dialoguer::Confirm::new()
                .with_prompt(format!("Delete secret '{key}' from profile '{profile}'?"))
                .default(false)
                .interact()
                .context("failed to read confirmation")?
        } else {
            // Non-TTY: read a line from stdin and check for "y" or "yes".
            eprintln!("Delete secret '{key}' from profile '{profile}'? [y/N]");
            let mut buf = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(std::io::stdin()), &mut buf)
                .context("failed to read confirmation from stdin")?;
            let answer = buf.trim().to_lowercase();
            answer == "y" || answer == "yes"
        };

        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let event = EventKind::SecretDelete {
        profile: profile.clone(),
        key: key.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretDeleteResponse { success: true, .. } => {
            println!("Secret '{key}' deleted from profile '{profile}'.");
        }
        EventKind::SecretDeleteResponse {
            success: false,
            denial,
        } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, key, &profile));
            }
            anyhow::bail!("failed to delete secret");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_secret_list(profile: &str) -> anyhow::Result<()> {
    validate_profile_in_config(profile)?;
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SecretList {
        profile: profile.clone(),
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretListResponse { keys, denial } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, "", &profile));
            }
            if keys.is_empty() {
                println!("{}", "No secrets in this profile.".dimmed());
            } else {
                println!("Secrets in profile '{}':", profile.as_ref().bold());
                for k in &keys {
                    println!("  - {k}");
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

fn cmd_audit_verify() -> anyhow::Result<()> {
    let audit_path = core_config::config_dir().join("audit.jsonl");

    if !audit_path.exists() {
        println!("{}", "No audit log found.".dimmed());
        return Ok(());
    }

    let contents = std::fs::read_to_string(&audit_path).context("failed to read audit log")?;

    match core_profile::verify_chain(&contents, &core_types::AuditHash::Blake3) {
        Ok(count) => {
            println!("{} {} entries verified.", "OK:".green().bold(), count);
        }
        Err(e) => {
            eprintln!(
                "{} audit chain integrity check failed: {e}",
                "FAIL:".red().bold()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn cmd_audit_tail(count: usize, follow: bool) -> anyhow::Result<()> {
    let audit_path = core_config::config_dir().join("audit.jsonl");

    if !audit_path.exists() {
        println!("{}", "No audit log found.".dimmed());
        return Ok(());
    }

    let contents = std::fs::read_to_string(&audit_path).context("failed to read audit log")?;

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(count);

    for line in &lines[start..] {
        print_audit_entry(line);
    }

    if !follow {
        return Ok(());
    }

    // --follow: watch for new appends using notify.
    let mut last_len = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);

    let watch_path = audit_path.clone();
    let _watcher = {
        use notify::{EventKind as NotifyEvent, RecommendedWatcher, RecursiveMode, Watcher};

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res
                    && matches!(event.kind, NotifyEvent::Modify(_))
                {
                    let _ = tx.blocking_send(());
                }
            },
            notify::Config::default(),
        )
        .context("failed to start file watcher")?;

        watcher
            .watch(
                watch_path.parent().unwrap_or(watch_path.as_ref()),
                RecursiveMode::NonRecursive,
            )
            .context("failed to watch audit log directory")?;

        watcher
    };

    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                let new_len = std::fs::metadata(&audit_path)
                    .map(|m| m.len())
                    .unwrap_or(0);

                if new_len > last_len {
                    // Read only the new bytes.
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = std::fs::File::open(&audit_path)?;
                    f.seek(SeekFrom::Start(last_len))?;
                    let mut buf = String::new();
                    f.read_to_string(&mut buf)?;
                    last_len = new_len;

                    for line in buf.lines() {
                        if !line.trim().is_empty() {
                            print_audit_entry(line);
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(())
}

fn print_audit_entry(line: &str) {
    if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line)
        && let Ok(pretty) = serde_json::to_string_pretty(&entry)
    {
        println!("{pretty}");
        println!("---");
        return;
    }
    println!("{line}");
}

// ============================================================================
// WM commands
// ============================================================================

async fn cmd_wm_list() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::WmListWindows, SecurityLevel::Internal).await? {
        EventKind::WmListWindowsResponse { windows } => {
            if windows.is_empty() {
                println!("{}", "No windows tracked.".dimmed());
                return Ok(());
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["ID", "App", "Title", "Focused"]);

            for w in &windows {
                let focused = if w.is_focused {
                    "yes".green().to_string()
                } else {
                    "".to_string()
                };
                table.add_row(vec![
                    &w.id.to_string(),
                    &w.app_id.to_string(),
                    &w.title,
                    &focused,
                ]);
            }

            println!("{table}");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_wm_switch(backward: bool) -> anyhow::Result<()> {
    let client = connect().await?;

    // List windows, pick next/previous in MRU order.
    let windows = match rpc(&client, EventKind::WmListWindows, SecurityLevel::Internal).await? {
        EventKind::WmListWindowsResponse { windows } => windows,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    if windows.is_empty() {
        println!("{}", "No windows to switch to.".dimmed());
        return Ok(());
    }

    // Find currently focused window index.
    let focused_idx = windows.iter().position(|w| w.is_focused).unwrap_or(0);
    let target_idx = if backward {
        if focused_idx == 0 {
            windows.len() - 1
        } else {
            focused_idx - 1
        }
    } else {
        (focused_idx + 1) % windows.len()
    };

    let target_id = windows[target_idx].id.to_string();

    match rpc(
        &client,
        EventKind::WmActivateWindow {
            window_id: target_id.clone(),
        },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::WmActivateWindowResponse { success: true } => {
            println!(
                "Switched to: {} ({})",
                windows[target_idx].title.green(),
                windows[target_idx].app_id,
            );
        }
        EventKind::WmActivateWindowResponse { success: false } => {
            anyhow::bail!("failed to activate window '{target_id}'");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_wm_focus(window_id: &str) -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(
        &client,
        EventKind::WmActivateWindow {
            window_id: window_id.to_owned(),
        },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::WmActivateWindowResponse { success: true } => {
            println!("Focused window: {}", window_id.green());
        }
        EventKind::WmActivateWindowResponse { success: false } => {
            anyhow::bail!("window '{window_id}' not found");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_wm_overlay(launcher: bool, backward: bool) -> anyhow::Result<()> {
    let variant = if launcher {
        "overlay-launcher"
    } else if backward {
        "overlay-backward"
    } else {
        "overlay"
    };

    // Fast path: send datagram to resident process (~2ms).
    if try_send_fast_path(variant) {
        return Ok(());
    }

    // Slow path: full Noise IK connect + publish.
    let client = connect().await?;
    let event = match variant {
        "overlay-launcher" => EventKind::WmActivateOverlayLauncher,
        "overlay-backward" => EventKind::WmActivateOverlayBackward,
        _ => EventKind::WmActivateOverlay,
    };
    client
        .publish(event, SecurityLevel::Internal)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Spawn resident in background for next invocation.
    spawn_resident();

    client.shutdown().await;
    Ok(())
}

/// Send an overlay command to the resident fast-path process via Unix datagram.
///
/// Returns `true` if the datagram was sent (resident is alive).
fn try_send_fast_path(variant: &str) -> bool {
    let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") else {
        return false;
    };
    let pid_path = format!("{runtime_dir}/pds/wm-fast.pid");
    let sock_path = format!("{runtime_dir}/pds/wm-fast.sock");

    // Check PID file for liveness.
    let Ok(pid_content) = std::fs::read_to_string(&pid_path) else {
        return false;
    };
    let Ok(pid) = pid_content.trim().parse::<i32>() else {
        return false;
    };

    // Verify process is alive via kill(pid, 0).
    if unsafe { libc::kill(pid, 0) } != 0 {
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&sock_path);
        return false;
    }

    // Send datagram (blocking — this is a ~0.1ms operation).
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return false;
    };
    sock.send_to(variant.as_bytes(), &sock_path).is_ok()
}

/// Fork a resident fast-path process in the background.
fn spawn_resident() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = std::process::Command::new(exe)
        .args(["wm", "overlay-resident"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Resident fast-path daemon: holds an IPC connection, listens for datagrams.
///
/// Exits on IPC disconnect, datagram error, or 5-minute idle timeout.
async fn cmd_wm_overlay_resident() -> anyhow::Result<()> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR not set")?;
    let pds_dir = format!("{runtime_dir}/pds");
    let pid_path = format!("{pds_dir}/wm-fast.pid");
    let sock_path = format!("{pds_dir}/wm-fast.sock");

    // Check if another resident is already running.
    if let Ok(existing_pid) = std::fs::read_to_string(&pid_path)
        && let Ok(pid) = existing_pid.trim().parse::<i32>()
        && unsafe { libc::kill(pid, 0) } == 0
    {
        return Ok(());
    }

    // Write PID file.
    std::fs::write(&pid_path, std::process::id().to_string())?;

    // Bind datagram socket with 0600 permissions.
    let _ = std::fs::remove_file(&sock_path);
    let dgram = tokio::net::UnixDatagram::bind(&sock_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Establish IPC connection (full Noise IK handshake — done once).
    let client = connect().await?;

    // Event loop: receive datagrams, publish to IPC bus.
    let idle_timeout = Duration::from_secs(300);
    let mut buf = [0u8; 64];

    loop {
        match tokio::time::timeout(idle_timeout, dgram.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let variant = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let event = match variant {
                    "overlay" => EventKind::WmActivateOverlay,
                    "overlay-backward" => EventKind::WmActivateOverlayBackward,
                    "overlay-launcher" => EventKind::WmActivateOverlayLauncher,
                    _ => continue,
                };
                if client
                    .publish(event, SecurityLevel::Internal)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break, // Idle timeout.
        }
    }

    // Cleanup.
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
    client.shutdown().await;
    Ok(())
}

// ============================================================================
// Launch commands
// ============================================================================

async fn cmd_launch_search(
    query: &str,
    max_results: u32,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = profile
        .map(|s| TrustProfileName::try_from(s).map_err(|e| anyhow::anyhow!("{e}")))
        .transpose()?;

    let event = EventKind::LaunchQuery {
        query: query.to_owned(),
        max_results,
        profile,
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::LaunchQueryResponse { results } => {
            if results.is_empty() {
                println!("{}", "No results.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Name", "ID", "Score"]);

                for r in &results {
                    table.add_row(vec![&r.name, &r.entry_id, &format!("{:.2}", r.score)]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_launch_run(entry_id: &str, profile: Option<&str>) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = profile
        .map(|s| TrustProfileName::try_from(s).map_err(|e| anyhow::anyhow!("{e}")))
        .transpose()?;

    let event = EventKind::LaunchExecute {
        entry_id: entry_id.to_owned(),
        profile,
        tags: Vec::new(),
        launch_args: Vec::new(),
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::LaunchExecuteResponse { pid, error, .. } => {
            if pid == 0 {
                let detail = error.as_deref().unwrap_or("unknown error");
                anyhow::bail!("launch failed: {detail}");
            }
            println!("Launched {} (PID {})", entry_id.green(), pid);
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

// ============================================================================
// Clipboard commands
// ============================================================================

async fn cmd_clipboard_history(profile: &str, limit: u32) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::ClipboardHistory { profile, limit };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ClipboardHistoryResponse { entries } => {
            if entries.is_empty() {
                println!("{}", "No clipboard history.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["ID", "Type", "Sensitivity", "Preview"]);

                for e in &entries {
                    table.add_row(vec![
                        &e.entry_id.to_string(),
                        &e.content_type,
                        &format!("{:?}", e.sensitivity),
                        &e.preview,
                    ]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_clipboard_clear(profile: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    match rpc(
        &client,
        EventKind::ClipboardClear { profile },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::ClipboardClearResponse { success: true } => {
            println!("{}", "Clipboard history cleared.".green());
        }
        EventKind::ClipboardClearResponse { success: false } => {
            anyhow::bail!("failed to clear clipboard history");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_clipboard_get(entry_id: &str) -> anyhow::Result<()> {
    let client = connect().await?;

    let uuid = entry_id.strip_prefix("clip-").unwrap_or(entry_id);
    let uuid: uuid::Uuid = uuid
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid clipboard entry ID: {entry_id}"))?;
    let entry_id_parsed = core_types::ClipboardEntryId::from_uuid(uuid);

    match rpc(
        &client,
        EventKind::ClipboardGet {
            entry_id: entry_id_parsed,
        },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::ClipboardGetResponse {
            content: Some(c),
            content_type,
        } => {
            if let Some(ct) = content_type {
                eprintln!("Content-Type: {ct}");
            }
            println!("{c}");
        }
        EventKind::ClipboardGetResponse { content: None, .. } => {
            anyhow::bail!("clipboard entry not found or expired");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

// ============================================================================
// Input commands
// ============================================================================

async fn cmd_input_layers() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::InputLayersList, SecurityLevel::Internal).await? {
        EventKind::InputLayersListResponse { layers } => {
            if layers.is_empty() {
                println!("{}", "No input layers configured.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Layer", "Active", "Remaps"]);

                for l in &layers {
                    let active = if l.is_active {
                        "yes".green().to_string()
                    } else {
                        "no".dimmed().to_string()
                    };
                    table.add_row(vec![&l.name, &active, &l.remap_count.to_string()]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_input_status() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::InputStatus, SecurityLevel::Internal).await? {
        EventKind::InputStatusResponse {
            active_layer,
            grabbed_devices,
            remapping_active,
        } => {
            let status = if remapping_active {
                "active".green().to_string()
            } else {
                "inactive".yellow().to_string()
            };

            println!("Remapping: {status}");
            println!("Active layer: {}", active_layer.bold());
            if grabbed_devices.is_empty() {
                println!("Grabbed devices: {}", "none".dimmed());
            } else {
                println!("Grabbed devices:");
                for d in &grabbed_devices {
                    println!("  - {d}");
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

// ============================================================================
// Snippet commands
// ============================================================================

async fn cmd_snippet_list(profile: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    match rpc(
        &client,
        EventKind::SnippetList { profile },
        SecurityLevel::Internal,
    )
    .await?
    {
        EventKind::SnippetListResponse { snippets } => {
            if snippets.is_empty() {
                println!("{}", "No snippets configured.".dimmed());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Trigger", "Template Preview"]);

                for s in &snippets {
                    table.add_row(vec![&s.trigger, &s.template_preview]);
                }

                println!("{table}");
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_snippet_expand(profile: &str, trigger: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SnippetExpand {
        profile,
        trigger: trigger.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SnippetExpandResponse {
            expanded: Some(text),
        } => {
            println!("{text}");
        }
        EventKind::SnippetExpandResponse { expanded: None } => {
            anyhow::bail!("snippet trigger '{trigger}' not found");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_snippet_add(profile: &str, trigger: &str, template: &str) -> anyhow::Result<()> {
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SnippetAdd {
        profile,
        trigger: trigger.to_owned(),
        template: template.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SnippetAddResponse { success: true } => {
            println!("Snippet '{}' added.", trigger.green());
        }
        EventKind::SnippetAddResponse { success: false } => {
            anyhow::bail!("failed to add snippet");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

// ============================================================================
// Secret denial reason formatting
// ============================================================================

/// Validate a secret key name at the CLI trust boundary.
/// Delegates to the canonical implementation in core-types.
fn validate_secret_key(key: &str) -> anyhow::Result<()> {
    core_types::validate_secret_key(key).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Validate that a profile exists in config before sending an RPC.
/// Fails fast at the CLI boundary with a clear error message.
fn validate_profile_in_config(profile: &str) -> anyhow::Result<()> {
    let config = core_config::load_config(None).map_err(|e| anyhow::anyhow!("{e}"))?;
    if !config.profiles.contains_key(profile) {
        anyhow::bail!("profile '{}' not found in config", profile);
    }
    Ok(())
}

fn format_denial_reason(
    reason: &core_types::SecretDenialReason,
    key: &str,
    profile: &TrustProfileName,
) -> String {
    use core_types::SecretDenialReason;
    match reason {
        SecretDenialReason::Locked => "vault locked -- run `sesame unlock`".into(),
        SecretDenialReason::ProfileNotActive => format!(
            "profile '{}' is not active -- run `sesame profile activate {}`",
            profile, profile
        ),
        SecretDenialReason::AccessDenied => format!("access denied for secret '{}'", key),
        SecretDenialReason::RateLimited => "rate limited -- try again later".into(),
        SecretDenialReason::NotFound => {
            format!("secret '{}' not found in profile '{}'", key, profile)
        }
        SecretDenialReason::VaultError(e) => format!("vault error: {}", e),
        _ => format!("secret access denied for '{}': {:?}", key, reason),
    }
}

// ============================================================================
// Shared secret fetch — used by env, export, and workspace shell
// ============================================================================

/// Fetch all secrets for a profile from the vault via IPC.
///
/// Returns sanitized env var name/value pairs. Secrets that map to denied
/// env var names are skipped with a warning on stderr.
async fn fetch_profile_secrets(
    client: &BusClient,
    profile: &TrustProfileName,
    prefix: Option<&str>,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    // 1. List all secret keys in this profile.
    let keys = match rpc(
        client,
        EventKind::SecretList {
            profile: profile.clone(),
        },
        SecurityLevel::SecretsOnly,
    )
    .await?
    {
        EventKind::SecretListResponse { keys, denial } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, "", profile));
            }
            keys
        }
        other => anyhow::bail!("unexpected response to SecretList: {other:?}"),
    };

    if keys.is_empty() {
        eprintln!(
            "{}: profile '{}' has no secrets",
            "warning".yellow().bold(),
            profile,
        );
        return Ok(Vec::new());
    }

    // 2. Fetch each secret value, apply env var mapping and denylist.
    let mut env_vars: Vec<(String, Vec<u8>)> = Vec::with_capacity(keys.len());

    for key in &keys {
        let event = EventKind::SecretGet {
            profile: profile.clone(),
            key: key.clone(),
        };

        match rpc(client, event, SecurityLevel::SecretsOnly).await? {
            EventKind::SecretGetResponse { value, denial, .. }
                if denial.is_none() && !value.is_empty() =>
            {
                let env_name = secret_key_to_env_var(key, prefix);
                if is_denied_env_var(&env_name) {
                    eprintln!(
                        "{}: secret '{}' maps to denied env var '{}', skipping (security policy)",
                        "error".red().bold(),
                        key,
                        env_name,
                    );
                    continue;
                }
                env_vars.push((env_name, value.as_bytes().to_vec()));
            }
            EventKind::SecretGetResponse {
                denial: Some(reason),
                key: k,
                ..
            } => {
                eprintln!(
                    "{}: {}",
                    "warning".yellow().bold(),
                    format_denial_reason(&reason, &k, profile),
                );
            }
            _ => {
                eprintln!(
                    "{}: failed to resolve secret '{}', skipping",
                    "warning".yellow().bold(),
                    key,
                );
            }
        }
    }

    Ok(env_vars)
}

// ============================================================================
// Env command — run a command with secrets as environment variables
// ============================================================================

/// Transform a secret key name into an environment variable name.
///
/// Rules: uppercase, hyphens and dots become underscores, strip non-alphanumeric
/// except underscores. With prefix "MYAPP": "api-key" -> "MYAPP_API_KEY".
fn secret_key_to_env_var(key: &str, prefix: Option<&str>) -> String {
    let var: String = key
        .chars()
        .map(|c| match c {
            '-' | '.' => '_',
            c if c.is_ascii_alphanumeric() || c == '_' => c.to_ascii_uppercase(),
            _ => '_',
        })
        .collect();

    match prefix {
        Some(p) => format!("{p}_{var}"),
        None => var,
    }
}

async fn cmd_env(
    profile: Option<&str>,
    prefix: Option<&str>,
    command: &[String],
) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    if command.first().is_some_and(|c| c.starts_with('-')) {
        eprintln!("hint: use '--' to separate sesame options from the command, e.g.:");
        eprintln!("  sesame env -p default -- {}", command.join(" "));
    }

    let specs = resolve_profile_specs(profile);
    let client = connect().await?;
    let env_vars = fetch_multi_profile_secrets(&client, &specs, prefix).await?;

    // Spawn child process with secrets as env vars.
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Inject SESAME_PROFILES so the child knows its context.
    let profiles_csv: String = specs
        .iter()
        .map(|s| match &s.org {
            Some(org) => format!("{org}:{}", s.vault),
            None => s.vault.clone(),
        })
        .collect::<Vec<_>>()
        .join(",");
    cmd.env("SESAME_PROFILES", &profiles_csv);

    // Inject each secret as an env var.
    for (env_name, value) in &env_vars {
        let val_str = String::from_utf8_lossy(value);
        cmd.env(env_name, val_str.as_ref());
    }

    let mut child = cmd.spawn().context("failed to spawn command")?;

    let status = child.wait().context("failed to wait for child process")?;

    for (_, mut value) in env_vars {
        value.zeroize();
    }

    std::process::exit(status.code().unwrap_or(1));
}

// ============================================================================
// Export command — print secrets as shell/dotenv/json
// ============================================================================

/// Env var names that must never be overwritten by secret export.
/// Covers dynamic linker, shell execution, path hijack, and privilege escalation vectors.
const DENIED_ENV_VARS: &[&str] = &[
    // Dynamic linker — arbitrary code execution
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_PROFILE",
    "LD_SHOW_AUXV",
    "LD_BIND_NOW",
    "LD_BIND_NOT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Core execution environment
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LOGNAME",
    "LANG",
    "TERM",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    // Shell injection vectors
    "BASH_ENV",
    "ENV",
    "BASH_FUNC_",
    "CDPATH",
    "GLOBIGNORE",
    "SHELLOPTS",
    "BASHOPTS",
    "PROMPT_COMMAND",
    "PS1",
    "PS2",
    "PS4",
    "MAIL",
    "MAILPATH",
    "MAILCHECK",
    "IFS",
    // Language runtime code execution
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYLIB",
    "RUBYOPT",
    "GOPATH",
    "GOROOT",
    "GOFLAGS",
    "JAVA_HOME",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    // Security / auth
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "KRB5_CONFIG",
    "KRB5CCNAME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "NIX_SSL_CERT_FILE",
    // Nix
    "NIX_PATH",
    "NIX_CONF_DIR",
    // Sudo / privilege
    "SUDO_ASKPASS",
    "SUDO_EDITOR",
    "VISUAL",
    "EDITOR",
    // Systemd
    "SYSTEMD_UNIT_PATH",
    "DBUS_SESSION_BUS_ADDRESS",
    // Open Sesame's own namespace
    "SESAME_PROFILE",
];

/// Returns true if `name` is a denied env var (case-insensitive prefix match for BASH_FUNC_).
fn is_denied_env_var(name: &str) -> bool {
    if name.starts_with("BASH_FUNC_") {
        return true;
    }
    DENIED_ENV_VARS
        .iter()
        .any(|&d| d.eq_ignore_ascii_case(name))
}

/// Shell-escape a value for safe embedding in `export K="V"`.
/// Strips null bytes (C string truncation), escapes shell metacharacters.
fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\0' => {} // strip null bytes — C string truncation risk
            '"' | '\\' | '$' | '`' | '!' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

/// JSON-escape a string value.
fn json_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\0' => String::new(),
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if c.is_control() => format!("\\u{:04x}", c as u32),
            c => c.to_string(),
        })
        .collect()
}

async fn cmd_export(
    profile: Option<&str>,
    format: &ExportFormat,
    prefix: Option<&str>,
) -> anyhow::Result<()> {
    let specs = resolve_profile_specs(profile);
    let client = connect().await?;
    let raw_secrets = fetch_multi_profile_secrets(&client, &specs, prefix).await?;
    if raw_secrets.is_empty() {
        return Ok(());
    }

    // Convert byte values to strings for text output formats.
    let entries: Vec<(String, String)> = raw_secrets
        .into_iter()
        .map(|(k, v)| {
            let val_str = String::from_utf8_lossy(&v).into_owned();
            (k, val_str)
        })
        .collect();

    // Output in requested format.
    match format {
        ExportFormat::Shell => {
            for (k, v) in &entries {
                println!("export {}=\"{}\"", k, shell_escape(v));
            }
        }
        ExportFormat::Dotenv => {
            for (k, v) in &entries {
                println!("{}=\"{}\"", k, shell_escape(v));
            }
        }
        ExportFormat::Json => {
            print!("{{");
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    print!(",");
                }
                print!("\"{}\":\"{}\"", json_escape(k), json_escape(v));
            }
            println!("}}");
        }
    }

    // 4. Zeroize secret copies.
    for (_, mut v) in entries {
        unsafe {
            v.as_bytes_mut().zeroize();
        }
    }

    Ok(())
}

// ============================================================================
// Workspace command
// ============================================================================

/// Check if creating a path requires privilege escalation.
///
/// Walks up the directory tree to find the first existing ancestor and
/// checks if it is owned by the current user.
#[cfg(target_os = "linux")]
fn needs_privilege(path: &std::path::Path) -> bool {
    let uid = unsafe { libc::getuid() };
    let mut check = path.to_path_buf();
    loop {
        if check.exists() {
            return std::fs::metadata(&check)
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    m.uid() != uid
                })
                .unwrap_or(true);
        }
        if !check.pop() {
            return true;
        }
    }
}

/// Compare two git remote URLs, normalizing `.git` suffix and trailing slashes.
fn urls_match(a: &str, b: &str) -> bool {
    fn normalize(url: &str) -> String {
        url.trim_end_matches('/')
            .trim_end_matches(".git")
            .to_lowercase()
    }
    normalize(a) == normalize(b)
}

async fn cmd_workspace(cmd: WorkspaceCmd) -> anyhow::Result<()> {
    match cmd {
        WorkspaceCmd::Init { root, user } => {
            let user =
                user.unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "user".into()));

            #[cfg(target_os = "linux")]
            {
                // Confirm before privilege escalation.
                if !root.exists() && needs_privilege(&root) {
                    eprintln!(
                        "Workspace root '{}' does not exist and requires elevated privileges to create.",
                        root.display()
                    );
                    eprint!("Continue? [y/N] ");
                    use std::io::Write;
                    std::io::stderr().flush()?;
                    let mut answer = String::new();
                    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)
                        .context("failed to read confirmation")?;
                    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                use sesame_workspace::platform::WorkspacePlatform;
                let platform = sesame_workspace::platform::linux::LinuxPlatform;
                platform
                    .ensure_root(&root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }

            #[cfg(not(target_os = "linux"))]
            {
                std::fs::create_dir_all(&root).context("failed to create workspace root")?;
            }

            let user_dir = root.join(&user);
            std::fs::create_dir_all(&user_dir).context("failed to create user directory")?;

            let mut config = core_config::load_workspace_config().unwrap_or_default();
            config.settings.root = root.clone();
            config.settings.user = user.clone();
            core_config::save_workspace_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("Workspace initialized: {}", user_dir.display());
            println!(
                "Config written: {}",
                core_config::config_dir().join("workspaces.toml").display()
            );
            Ok(())
        }

        WorkspaceCmd::Clone {
            url,
            depth,
            profile,
            adopt,
        } => {
            let config = core_config::load_workspace_config().unwrap_or_default();
            let root = sesame_workspace::config::resolve_root(&config);
            let user = sesame_workspace::config::resolve_user(&config);

            let conv = sesame_workspace::convention::parse_url(&url)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let target = sesame_workspace::convention::canonical_path(&root, &user, &conv);

            // Check if the target directory already exists and can be adopted.
            let target_path = match &target {
                sesame_workspace::CloneTarget::Regular(p) => p.clone(),
                sesame_workspace::CloneTarget::WorkspaceGit(p) => p.clone(),
            };

            let adopted = if target_path.exists()
                && sesame_workspace::git::is_git_repo(&target_path)
                && adopt
            {
                // Verify the remote matches the requested URL.
                let existing_remote = sesame_workspace::git::remote_url(&target_path)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                match existing_remote {
                    Some(ref remote) if urls_match(remote, &url) => true,
                    Some(ref remote) => {
                        anyhow::bail!(
                            "directory exists with different remote:\n  existing: {remote}\n  requested: {url}\nRemove the directory or fix the remote manually."
                        );
                    }
                    None => {
                        anyhow::bail!(
                            "directory exists as a git repo but has no 'origin' remote: {}",
                            target_path.display()
                        );
                    }
                }
            } else {
                false
            };

            let result_path = if adopted {
                println!(
                    "\x1b[32mAdopted\x1b[0m existing repository: {}",
                    target_path.display()
                );
                target_path
            } else {
                let rp = sesame_workspace::git::clone_repo(&url, &target, depth)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                // Contextual output based on clone target type.
                match &target {
                    sesame_workspace::CloneTarget::WorkspaceGit(_) => {
                        println!("Cloned workspace.git to org directory: {}", rp.display());
                        println!("  Peer repos will be cloned as siblings inside this directory.");
                    }
                    sesame_workspace::CloneTarget::Regular(_) => {
                        println!("Cloned to: {}", rp.display());
                    }
                }
                rp
            };

            // Link to profile if requested.
            if let Some(ref profile_name) = profile {
                let _validated = TrustProfileName::try_from(profile_name.as_str())
                    .map_err(|e| anyhow::anyhow!("invalid profile name: {e}"))?;
                let mut ws_config = core_config::load_workspace_config().unwrap_or_default();
                sesame_workspace::config::add_link(
                    &mut ws_config,
                    &result_path.display().to_string(),
                    profile_name,
                );
                core_config::save_workspace_config(&ws_config)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("Linked -> profile \"{}\"", profile_name);
            }

            Ok(())
        }

        WorkspaceCmd::List {
            server,
            org,
            profile,
            format,
        } => {
            let config = core_config::load_workspace_config().unwrap_or_default();
            let mut workspaces = sesame_workspace::discover::discover_workspaces(&config)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            if let Some(ref s) = server {
                workspaces.retain(|w| w.convention.server == *s);
            }
            if let Some(ref o) = org {
                workspaces.retain(|w| w.convention.org == *o);
            }
            if let Some(ref p) = profile {
                workspaces.retain(|w| w.linked_profile.as_deref() == Some(p.as_str()));
            }

            match format {
                WorkspaceListFormat::Table => {
                    if workspaces.is_empty() {
                        println!("No workspaces found.");
                        return Ok(());
                    }
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL);
                    table.set_header(vec!["SERVER", "ORG", "REPO", "PROFILE", "PATH"]);
                    for ws in &workspaces {
                        let repo = ws.convention.repo.as_deref().unwrap_or("(workspace)");
                        let ws_profile = ws.linked_profile.as_deref().unwrap_or("-");
                        table.add_row(vec![
                            &ws.convention.server,
                            &ws.convention.org,
                            repo,
                            ws_profile,
                            &ws.path.display().to_string(),
                        ]);
                    }
                    println!("{table}");
                }
                WorkspaceListFormat::Json => {
                    let json: Vec<serde_json::Value> = workspaces
                        .iter()
                        .map(|ws| {
                            serde_json::json!({
                                "server": ws.convention.server,
                                "org": ws.convention.org,
                                "repo": ws.convention.repo,
                                "profile": ws.linked_profile,
                                "path": ws.path.display().to_string(),
                                "is_workspace_git": ws.is_workspace_git,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
            }
            Ok(())
        }

        WorkspaceCmd::Status { path, verbose } => {
            let path = resolve_workspace_path(path)?;
            let config = core_config::load_workspace_config().unwrap_or_default();
            let root = sesame_workspace::config::resolve_root(&config);

            let conv = sesame_workspace::convention::parse_path(&root, &path)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let remote = sesame_workspace::git::remote_url(&path)
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown".into());
            let branch =
                sesame_workspace::git::current_branch(&path).unwrap_or_else(|_| "unknown".into());
            let clean = sesame_workspace::git::is_clean(&path).unwrap_or(false);

            // Use effective config for profile resolution.
            let effective =
                sesame_workspace::config::resolve_effective_config(&config, &path, &root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            let in_ws_git = sesame_workspace::convention::is_inside_workspace_git(&path);

            println!("Workspace:  {}", path.display());
            println!("Remote:     {remote}");
            println!("Branch:     {branch}");

            // Color-coded status.
            let status_str = if clean {
                "clean".green().to_string()
            } else {
                "dirty".yellow().to_string()
            };
            println!("Status:     {status_str}");
            println!(
                "Profile:    {}",
                effective.profile.as_deref().unwrap_or("(none)")
            );
            println!(
                "Namespace:  {} ({})",
                conv.org,
                if in_ws_git {
                    "workspace.git"
                } else {
                    "no workspace.git"
                }
            );

            if verbose {
                println!(
                    "Convention: {} / {} / {} / {} / {}",
                    root.display(),
                    config.settings.user,
                    conv.server,
                    conv.org,
                    conv.repo.as_deref().unwrap_or("(workspace.git)")
                );

                // Disk usage.
                if let Ok(output) = std::process::Command::new("du")
                    .arg("-sh")
                    .arg("--")
                    .arg(&path)
                    .output()
                    && let Ok(s) = String::from_utf8(output.stdout)
                    && let Some(size) = s.split_whitespace().next()
                {
                    println!("Disk:       {size}");
                }
            }
            Ok(())
        }

        WorkspaceCmd::Link { profile, path } => {
            let _validated = TrustProfileName::try_from(profile.as_str())
                .map_err(|e| anyhow::anyhow!("invalid profile name: {e}"))?;

            let path = resolve_workspace_path(path)?;

            let mut config = core_config::load_workspace_config().unwrap_or_default();
            sesame_workspace::config::add_link(&mut config, &path.display().to_string(), &profile);
            core_config::save_workspace_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Linked {} -> profile \"{}\"", path.display(), profile);
            Ok(())
        }

        WorkspaceCmd::Unlink { path } => {
            let path = resolve_workspace_path(path)?;
            let mut config = core_config::load_workspace_config().unwrap_or_default();
            let path_str = path.display().to_string();
            if sesame_workspace::config::remove_link(&mut config, &path_str) {
                core_config::save_workspace_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("Unlinked {}", path.display());
            } else {
                println!("No link found for {}", path.display());
            }
            Ok(())
        }

        WorkspaceCmd::Shell {
            profile,
            path,
            shell,
            prefix,
            command,
        } => {
            let path = resolve_workspace_path(path)?;
            let config = core_config::load_workspace_config().unwrap_or_default();
            let root = sesame_workspace::config::resolve_root(&config);

            // Use effective config for profile resolution.
            let effective =
                sesame_workspace::config::resolve_effective_config(&config, &path, &root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Profile resolution: CLI flag > effective config > SESAME_PROFILES env > "default"
            let profile_csv = profile
                .or(effective.profile)
                .or_else(|| std::env::var("SESAME_PROFILES").ok())
                .unwrap_or_else(|| "default".into());

            let specs = parse_profile_specs(&profile_csv);
            let secret_prefix = prefix.or(effective.secret_prefix);

            // Connect to IPC and fetch secrets from all profiles.
            let client = connect().await?;
            let env_vars =
                fetch_multi_profile_secrets(&client, &specs, secret_prefix.as_deref()).await?;

            // Determine what to spawn.
            let (bin, args, is_interactive) = if !command.is_empty() {
                (command[0].clone(), command[1..].to_vec(), false)
            } else {
                let shell_bin = shell
                    .or_else(|| std::env::var("SHELL").ok())
                    .unwrap_or_else(|| "/bin/sh".into());
                (shell_bin, Vec::new(), true)
            };

            let mut cmd = std::process::Command::new(&bin);
            cmd.args(&args);
            cmd.current_dir(&path);
            cmd.env("SESAME_PROFILES", &profile_csv);
            cmd.env("SESAME_WORKSPACE", path.display().to_string());

            // Inject effective env vars from .sesame.toml layers.
            for (k, v) in &effective.env {
                cmd.env(k, v);
            }

            // Inject secrets.
            for (k, v) in &env_vars {
                let val_str = String::from_utf8_lossy(v);
                cmd.env(k, val_str.as_ref());
            }

            if is_interactive {
                println!(
                    "Entering workspace shell (profiles: {profile_csv}, {} secrets injected)",
                    env_vars.len()
                );
            }
            let status = cmd.status().context("failed to spawn command")?;

            // Zeroize secrets.
            for (_, mut v) in env_vars {
                v.zeroize();
            }

            std::process::exit(status.code().unwrap_or(1));
        }

        WorkspaceCmd::Config(sub) => match sub {
            WorkspaceConfigCmd::Show { path } => {
                let path = resolve_workspace_path(path)?;
                let config = core_config::load_workspace_config().unwrap_or_default();
                let root = sesame_workspace::config::resolve_root(&config);

                let effective =
                    sesame_workspace::config::resolve_effective_config(&config, &path, &root)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;

                println!("Workspace:      {}", path.display());
                println!(
                    "Profile:        {} (source: {})",
                    effective.profile.as_deref().unwrap_or("(none)"),
                    if effective.provenance.profile_source.is_empty() {
                        "default"
                    } else {
                        effective.provenance.profile_source
                    }
                );
                if let Some(ref prefix) = effective.secret_prefix {
                    println!(
                        "Secret prefix:  {prefix} (source: {})",
                        effective.provenance.secret_prefix_source
                    );
                }
                if !effective.env.is_empty() {
                    println!("Environment:");
                    for (k, v) in &effective.env {
                        println!("  {k}={v}");
                    }
                }
                if !effective.tags.is_empty() {
                    println!("Tags:           {}", effective.tags.join(", "));
                }
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_specs_bare_vaults() {
        let specs = parse_profile_specs("a,b,c");
        assert_eq!(specs.len(), 3);
        assert!(specs[0].org.is_none());
        assert_eq!(specs[0].vault, "a");
        assert_eq!(specs[1].vault, "b");
        assert_eq!(specs[2].vault, "c");
    }

    #[test]
    fn parse_specs_org_vault() {
        let specs = parse_profile_specs("braincraft:operations,braincraft:frontend,default:dev");
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].org.as_deref(), Some("braincraft"));
        assert_eq!(specs[0].vault, "operations");
        assert_eq!(specs[1].org.as_deref(), Some("braincraft"));
        assert_eq!(specs[1].vault, "frontend");
        assert_eq!(specs[2].org.as_deref(), Some("default"));
        assert_eq!(specs[2].vault, "dev");
    }

    #[test]
    fn parse_specs_mixed() {
        let specs = parse_profile_specs("default,braincraft:ops");
        assert_eq!(specs.len(), 2);
        assert!(specs[0].org.is_none());
        assert_eq!(specs[0].vault, "default");
        assert_eq!(specs[1].org.as_deref(), Some("braincraft"));
        assert_eq!(specs[1].vault, "ops");
    }

    #[test]
    fn parse_specs_single() {
        let specs = parse_profile_specs("default");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].vault, "default");
    }

    #[test]
    fn parse_specs_empty_segments_filtered() {
        let specs = parse_profile_specs("a,,b");
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn parse_specs_whitespace_trimmed() {
        let specs = parse_profile_specs(" a , b ");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].vault, "a");
        assert_eq!(specs[1].vault, "b");
    }

    #[test]
    fn parse_specs_empty_string() {
        assert!(parse_profile_specs("").is_empty());
    }

    #[test]
    fn parse_specs_org_with_no_vault() {
        let specs = parse_profile_specs("org:");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].org.as_deref(), Some("org"));
        assert_eq!(specs[0].vault, "");
    }

    #[test]
    fn shell_escape_plain() {
        assert_eq!(shell_escape("hello"), "hello");
    }

    #[test]
    fn shell_escape_special_chars() {
        assert_eq!(shell_escape(r#"a"b$c`d\e!f"#), r#"a\"b\$c\`d\\e\!f"#);
    }

    #[test]
    fn shell_escape_newlines() {
        assert_eq!(shell_escape("line1\nline2\r"), "line1\\nline2\\r");
    }

    #[test]
    fn secret_name_to_env_var_basic() {
        assert_eq!(secret_key_to_env_var("api-key", None), "API_KEY");
    }

    #[test]
    fn secret_name_to_env_var_with_prefix() {
        assert_eq!(
            secret_key_to_env_var("api-key", Some("MYAPP")),
            "MYAPP_API_KEY"
        );
    }

    #[test]
    fn secret_name_to_env_var_dots_and_mixed() {
        assert_eq!(secret_key_to_env_var("db.host-name", None), "DB_HOST_NAME");
    }

    #[test]
    fn shell_escape_strips_null_bytes() {
        assert_eq!(shell_escape("before\0after"), "beforeafter");
    }

    #[test]
    fn denied_env_var_ld_preload() {
        assert!(is_denied_env_var("LD_PRELOAD"));
    }

    #[test]
    fn denied_env_var_path() {
        assert!(is_denied_env_var("PATH"));
    }

    #[test]
    fn denied_env_var_case_insensitive() {
        assert!(is_denied_env_var("ld_preload"));
        assert!(is_denied_env_var("Path"));
    }

    #[test]
    fn denied_env_var_bash_func_prefix() {
        assert!(is_denied_env_var("BASH_FUNC_evil%%"));
    }

    #[test]
    fn denied_env_var_allows_normal_names() {
        assert!(!is_denied_env_var("GITHUB_TOKEN"));
        assert!(!is_denied_env_var("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_denied_env_var("CORP_API_KEY"));
    }

    #[test]
    fn denied_env_var_sesame_profile() {
        assert!(is_denied_env_var("SESAME_PROFILE"));
    }

    #[test]
    fn json_escape_special_chars() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn json_escape_strips_null() {
        assert_eq!(json_escape("ab\0cd"), "abcd");
    }

    #[test]
    fn json_escape_control_chars() {
        assert_eq!(json_escape("\x01\x1f"), "\\u0001\\u001f");
    }
}
