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
use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL, Table};
use core_ipc::BusClient;
use core_types::{DaemonId, EventKind, ProfileId, SecurityLevel, SensitiveBytes, TrustProfileName};
use owo_colors::OwoColorize;
use std::time::Duration;
use zeroize::Zeroize;

/// Default RPC timeout.
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Open Sesame — Platform Orchestration CLI.
#[derive(Parser)]
#[command(name = "sesame", about = "Open Sesame — platform orchestration CLI", version)]
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

        /// Destroy ALL Open Sesame data and reset to clean state.
        #[arg(long)]
        wipe_reset_destroy_all_data: bool,
    },

    /// Show daemon status, active profiles, and lock state.
    Status,

    /// Unlock the secrets daemon with master password.
    Unlock,

    /// Lock the secrets daemon (zeroize cached master key).
    Lock,

    /// Profile management.
    #[command(subcommand)]
    Profile(ProfileCmd),

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
    #[cfg(target_os = "linux")]
    SetupKeybinding {
        /// Launcher key combo (default: "alt+space"). Examples: "super+space", "alt+space".
        #[arg(default_value = "alt+space")]
        launcher_key: String,
    },

    /// Remove sesame keybindings from COSMIC configuration.
    #[cfg(target_os = "linux")]
    RemoveKeybinding,

    /// Show current sesame keybinding status in COSMIC.
    #[cfg(target_os = "linux")]
    KeybindingStatus,

    /// Run a command with profile-scoped secrets as environment variables.
    ///
    /// Each secret key is transformed to an env var: uppercase, hyphens become
    /// underscores. Example: secret "api-key" becomes env var "API_KEY".
    ///
    /// Usage: sesame env -p work -- aws s3 ls
    Env {
        /// Profile to source secrets from.
        #[arg(short, long)]
        profile: String,

        /// Prefix for env var names (e.g., --prefix MYAPP: "api-key" becomes "MYAPP_API_KEY").
        #[arg(long)]
        prefix: Option<String>,

        /// Command and arguments to execute.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
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
        Command::Init { no_keybinding, wipe_reset_destroy_all_data } => {
            if wipe_reset_destroy_all_data {
                init::cmd_wipe()
            } else {
                init::cmd_init(no_keybinding).await
            }
        }
        Command::Status => cmd_status().await,
        Command::Unlock => cmd_unlock().await,
        Command::Lock => cmd_lock().await,
        Command::Profile(sub) => match sub {
            ProfileCmd::List => cmd_profile_list().await,
            ProfileCmd::Activate { name } => cmd_profile_activate(&name).await,
            ProfileCmd::Deactivate { name } => cmd_profile_deactivate(&name).await,
            ProfileCmd::Default { name } => cmd_profile_default(&name).await,
            ProfileCmd::Show { name } => cmd_profile_show(&name),
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
        },
        Command::Launch(sub) => match sub {
            LaunchCmd::Search { query, max_results, profile } => {
                cmd_launch_search(&query, max_results, profile.as_deref()).await
            }
            LaunchCmd::Run { entry_id, profile } => {
                cmd_launch_run(&entry_id, profile.as_deref()).await
            }
        },
        Command::Clipboard(sub) => match sub {
            ClipboardCmd::History { profile, limit } => cmd_clipboard_history(&profile, limit).await,
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
            SnippetCmd::Add { profile, trigger, template } => {
                cmd_snippet_add(&profile, &trigger, &template).await
            }
        },
        #[cfg(target_os = "linux")]
        Command::SetupKeybinding { launcher_key } => {
            platform_linux::cosmic_keys::setup_keybinding(&launcher_key)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        #[cfg(target_os = "linux")]
        Command::RemoveKeybinding => {
            platform_linux::cosmic_keys::remove_keybinding()
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        #[cfg(target_os = "linux")]
        Command::KeybindingStatus => {
            platform_linux::cosmic_keys::keybinding_status()
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        Command::Env { profile, prefix, command } => {
            cmd_env(&profile, prefix.as_deref(), &command).await
        }
    }
}

// ============================================================================
// IPC connection helper
// ============================================================================

pub(crate) async fn connect() -> anyhow::Result<BusClient> {
    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;

    let server_pub = core_ipc::noise::read_bus_public_key().await
        .context("daemon-profile is not running (no bus public key found)")?;

    let daemon_id = DaemonId::new();

    // CLI uses ephemeral keypair — server assigns Open clearance for unknown keys.
    let client_keypair = core_ipc::generate_keypair()
        .context("failed to generate ephemeral keypair")?;

    BusClient::connect_encrypted(daemon_id, &socket_path, &server_pub, client_keypair.as_inner())
        .await
        .context("failed to connect to IPC bus — is daemon-profile running?")
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
                eprintln!("{}: no response within {}s", "timeout".yellow().bold(), RPC_TIMEOUT.as_secs());
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
            ..
        } => {
            let lock_status = if locked {
                "locked".red().bold().to_string()
            } else {
                "unlocked".green().bold().to_string()
            };

            println!("Secrets daemon: {lock_status}");
            println!("Default profile: {}", default_profile.as_ref().bold());

            if active_profiles.is_empty() {
                println!("Active profiles: {}", "none".dimmed());
            } else {
                println!("Active profiles:");
                for p in &active_profiles {
                    let marker = if p == &default_profile { " (default)" } else { "" };
                    println!("  - {p}{marker}");
                }
            }
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_unlock() -> anyhow::Result<()> {
    let client = connect().await?;

    // Check if already unlocked.
    if let EventKind::StatusResponse { locked: false, .. } =
        rpc(&client, EventKind::StatusRequest, SecurityLevel::Internal).await?
    {
        println!("Already unlocked.");
        return Ok(());
    }

    let mut password = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        dialoguer::Password::new()
            .with_prompt("Master password")
            .interact()
            .context("failed to read password")?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("failed to read password from stdin")?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    };

    let mut password_bytes = password.as_bytes().to_vec();
    password.zeroize();

    let event = EventKind::UnlockRequest {
        password: SensitiveBytes::new(std::mem::take(&mut password_bytes)),
    };
    password_bytes.zeroize();

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::UnlockResponse { success: true } => {
            println!("{}", "Secrets unlocked.".green());
        }
        EventKind::UnlockResponse { success: false } => {
            anyhow::bail!("unlock failed — wrong password or keyring error");
        }
        EventKind::UnlockRejected { reason: core_types::UnlockRejectedReason::AlreadyUnlocked } => {
            println!("{}", "Already unlocked.".yellow());
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

async fn cmd_lock() -> anyhow::Result<()> {
    let client = connect().await?;

    match rpc(&client, EventKind::LockRequest, SecurityLevel::SecretsOnly).await? {
        EventKind::LockResponse { success: true } => {
            println!("{}", "Secrets locked. Master key zeroized.".green());
        }
        EventKind::LockResponse { success: false } => {
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
                let active = if p.is_active { "yes".green().to_string() } else { "no".dimmed().to_string() };
                let default = if p.is_default { "yes".green().to_string() } else { "".to_string() };
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
    let profile_name = TrustProfileName::try_from(name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
    let profile_name = TrustProfileName::try_from(name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
    let profile_name = TrustProfileName::try_from(name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
    let config = core_config::load_config(None)
        .context("failed to load config")?;

    let profile = config
        .profiles
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("profile '{name}' not found in config"))?;

    let toml_str = toml::to_string_pretty(profile)
        .context("failed to serialize profile config")?;

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
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
        EventKind::SecretSetResponse { success: false, denial } => {
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
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SecretGet {
        profile: profile.clone(),
        key: key.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
        EventKind::SecretGetResponse { key: k, value, denial } => {
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
                    let mut hex: String = value.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
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
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
        EventKind::SecretDeleteResponse { success: false, denial } => {
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
    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SecretList { profile: profile.clone() };

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

    let contents = std::fs::read_to_string(&audit_path)
        .context("failed to read audit log")?;

    match core_profile::verify_chain(&contents) {
        Ok(count) => {
            println!(
                "{} {} entries verified.",
                "OK:".green().bold(),
                count
            );
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

    let contents = std::fs::read_to_string(&audit_path)
        .context("failed to read audit log")?;

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(count);

    for line in &lines[start..] {
        print_audit_entry(line);
    }

    if !follow {
        return Ok(());
    }

    // --follow: watch for new appends using notify.
    let mut last_len = std::fs::metadata(&audit_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);

    let watch_path = audit_path.clone();
    let _watcher = {
        use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind as NotifyEvent};

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res
                    && matches!(event.kind, NotifyEvent::Modify(_))
                {
                    let _ = tx.blocking_send(());
                }
            },
            notify::Config::default(),
        ).context("failed to start file watcher")?;

        watcher
            .watch(watch_path.parent().unwrap_or(watch_path.as_ref()), RecursiveMode::NonRecursive)
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
        if focused_idx == 0 { windows.len() - 1 } else { focused_idx - 1 }
    } else {
        (focused_idx + 1) % windows.len()
    };

    let target_id = windows[target_idx].id.to_string();

    match rpc(
        &client,
        EventKind::WmActivateWindow { window_id: target_id.clone() },
        SecurityLevel::Internal,
    ).await? {
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
        EventKind::WmActivateWindow { window_id: window_id.to_owned() },
        SecurityLevel::Internal,
    ).await? {
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

// ============================================================================
// Launch commands
// ============================================================================

async fn cmd_launch_search(query: &str, max_results: u32, profile: Option<&str>) -> anyhow::Result<()> {
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
                    table.add_row(vec![
                        &r.name,
                        &r.entry_id,
                        &format!("{:.2}", r.score),
                    ]);
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
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::LaunchExecuteResponse { pid } => {
            if pid == 0 {
                anyhow::bail!("launch failed — desktop entry not found or spawn error");
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
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    match rpc(&client, EventKind::ClipboardClear { profile }, SecurityLevel::Internal).await? {
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
    let uuid: uuid::Uuid = uuid.parse()
        .map_err(|_| anyhow::anyhow!("invalid clipboard entry ID: {entry_id}"))?;
    let entry_id_parsed = core_types::ClipboardEntryId::from_uuid(uuid);

    match rpc(
        &client,
        EventKind::ClipboardGet { entry_id: entry_id_parsed },
        SecurityLevel::Internal,
    ).await? {
        EventKind::ClipboardGetResponse { content: Some(c), content_type } => {
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
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    match rpc(&client, EventKind::SnippetList { profile }, SecurityLevel::Internal).await? {
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
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let event = EventKind::SnippetExpand {
        profile,
        trigger: trigger.to_owned(),
    };

    match rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::SnippetExpandResponse { expanded: Some(text) } => {
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
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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

fn format_denial_reason(reason: &core_types::SecretDenialReason, key: &str, profile: &TrustProfileName) -> String {
    use core_types::SecretDenialReason;
    match reason {
        SecretDenialReason::Locked => "vault locked -- run `sesame unlock`".into(),
        SecretDenialReason::ProfileNotActive => format!("profile '{}' is not active -- run `sesame profile activate {}`", profile, profile),
        SecretDenialReason::AccessDenied => format!("access denied for secret '{}'", key),
        SecretDenialReason::RateLimited => "rate limited -- try again later".into(),
        SecretDenialReason::NotFound => format!("secret '{}' not found in profile '{}'", key, profile),
        SecretDenialReason::VaultError(e) => format!("vault error: {}", e),
    }
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

async fn cmd_env(profile: &str, prefix: Option<&str>, command: &[String]) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    let client = connect().await?;
    let profile = TrustProfileName::try_from(profile)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // 1. List all secret keys in this profile.
    let keys = match rpc(
        &client,
        EventKind::SecretList { profile: profile.clone() },
        SecurityLevel::SecretsOnly,
    ).await? {
        EventKind::SecretListResponse { keys, denial } => {
            if let Some(reason) = denial {
                anyhow::bail!("{}", format_denial_reason(&reason, "", &profile));
            }
            keys
        }
        other => anyhow::bail!("unexpected response to SecretList: {other:?}"),
    };

    if keys.is_empty() {
        eprintln!(
            "{}: profile '{}' has no secrets — running command without secret injection",
            "warning".yellow().bold(),
            profile,
        );
    }

    // 2. Fetch each secret value.
    let mut env_vars: Vec<(String, Vec<u8>)> = Vec::with_capacity(keys.len());

    for key in &keys {
        let event = EventKind::SecretGet {
            profile: profile.clone(),
            key: key.clone(),
        };

        match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
            EventKind::SecretGetResponse { value, denial, .. } if denial.is_none() && !value.is_empty() => {
                let env_name = secret_key_to_env_var(key, prefix);
                env_vars.push((env_name, value.as_bytes().to_vec()));
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

    // 3. Spawn child process with secrets as env vars.
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Inject SESAME_PROFILE so the child knows its context.
    cmd.env("SESAME_PROFILE", profile.as_ref());

    // Inject each secret as an env var.
    for (env_name, value) in &env_vars {
        // Best-effort UTF-8. OsStr::from_bytes would work for arbitrary bytes
        // on Unix but env vars are conventionally UTF-8.
        let val_str = String::from_utf8_lossy(value);
        cmd.env(env_name, val_str.as_ref());
    }

    let mut child = cmd.spawn()
        .context("failed to spawn command")?;

    let status = child.wait()
        .context("failed to wait for child process")?;

    // 4. Zeroize all secret copies in our process.
    for (_, mut value) in env_vars {
        value.zeroize();
    }

    // Forward the child's exit code.
    std::process::exit(status.code().unwrap_or(1));
}
