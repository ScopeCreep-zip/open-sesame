//! `sesame init` — first-run setup and factory reset.

use anyhow::Context;
use core_types::{EventKind, ProfileId, SecurityLevel, SensitiveBytes, TrustProfileName};
use owo_colors::OwoColorize;
use zeroize::Zeroize;

/// Whether the COSMIC keybinding step applies.
fn keybinding_applicable(no_keybinding: bool) -> bool {
    if no_keybinding {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CURRENT_DESKTOP")
            .map(|d| d.contains("COSMIC"))
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn step_header(step: u32, total: u32, label: &str) {
    println!(
        "\n  {} {}",
        format!("[{step}/{total}]").bold(),
        label.bold(),
    );
}

fn step_done(msg: &str) {
    println!("        {msg} ... {}", "done".green());
}

fn step_skip(msg: &str) {
    println!("        {msg} ... {}", "(already done)".dimmed());
}

// ============================================================================
// sesame init
// ============================================================================

pub async fn cmd_init(no_keybinding: bool, org: Option<String>) -> anyhow::Result<()> {
    let do_keybinding = keybinding_applicable(no_keybinding);
    let total_steps: u32 = if do_keybinding { 5 } else { 4 };

    println!("\n  {}", "Open Sesame — First-Time Setup".bold());

    // Step 1: Configuration
    step_header(1, total_steps, "Configuration");
    init_config()?;

    // Step 2: Installation Identity
    step_header(2, total_steps, "Installation Identity");
    init_installation(org.as_deref())?;

    // Step 3: Services
    step_header(3, total_steps, "Services");
    init_services().await?;

    // Step 4: Master password
    step_header(4, total_steps, "Master Password");
    init_unlock().await?;

    // Step 5: Keybinding (conditional)
    if do_keybinding {
        step_header(5, total_steps, "Keybinding (COSMIC desktop detected)");
        init_keybinding()?;
    }

    println!("\n  {}", "Setup complete.".green().bold());
    println!("  Try:");
    println!("    {}        — check system state", "sesame status".bold());
    println!("    {}       — list open windows", "sesame wm list".bold());
    println!(
        "    {}  — store a secret",
        "sesame secret set -p default my-api-key".bold()
    );
    println!();

    Ok(())
}

// ── Step 1: Config ──────────────────────────────────────────────────────────

fn init_config() -> anyhow::Result<()> {
    let config_dir = core_config::config_dir();
    let config_path = config_dir.join("config.toml");

    if config_path.exists() {
        step_skip("Config exists");
        return Ok(());
    }

    std::fs::create_dir_all(&config_dir)
        .context("failed to create config directory")?;

    let mut config = core_config::Config::default();
    config.profiles.insert(
        "default".into(),
        core_config::ProfileConfig::default(),
    );

    let toml_str = toml::to_string_pretty(&config)
        .context("failed to serialize default config")?;
    core_config::atomic_write(&config_path, toml_str.as_bytes())
        .context("failed to write config")?;

    step_done(&format!("Creating {}", config_path.display()));
    println!("        Default profile: {}", "\"default\"".green());

    Ok(())
}

// ── Step 2: Installation Identity ──────────────────────────────────────────

fn init_installation(org: Option<&str>) -> anyhow::Result<()> {
    let installation_path = core_config::installation_path();

    if installation_path.exists() {
        step_skip("Installation identity exists");
        return Ok(());
    }

    let id = uuid::Uuid::new_v4();

    // Deterministic namespace for profile IDs — matches daemon-profile.
    let profile_ns = uuid::Uuid::from_bytes([
        0x4c, 0x45, 0xa6, 0x4f, 0xab, 0xcd, 0x59, 0x77,
        0xbc, 0x73, 0x99, 0xd4, 0xc9, 0x3d, 0x66, 0x8b,
    ]);

    let (install_ns, org_config) = if let Some(domain) = org {
        let org_ns = uuid::Uuid::new_v5(&profile_ns, format!("org:{domain}").as_bytes());
        let ns = uuid::Uuid::new_v5(&org_ns, format!("install:{id}").as_bytes());
        let org_cfg = core_config::OrgConfig {
            domain: domain.to_string(),
            namespace: org_ns,
        };
        (ns, Some(org_cfg))
    } else {
        let ns = uuid::Uuid::new_v5(&profile_ns, format!("install:{id}").as_bytes());
        (ns, None)
    };

    // Machine binding: read /etc/machine-id
    let machine_binding = std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|mid| {
            let mid = mid.trim();
            let mut hasher = blake3::Hasher::new();
            hasher.update(mid.as_bytes());
            hasher.update(id.as_bytes());
            let hash = hasher.finalize();
            core_config::MachineBindingConfig {
                binding_hash: hash.to_hex().to_string(),
                binding_type: "machine-id".to_string(),
            }
        });

    let install_config = core_config::InstallationConfig {
        id,
        namespace: install_ns,
        org: org_config,
        machine_binding: machine_binding.clone(),
    };

    core_config::write_installation(&install_config)
        .context("failed to write installation.toml")?;

    // Write InstallationCreated audit event directly (bus not running yet)
    {
        let audit_path = core_config::config_dir().join("audit.jsonl");
        let audit_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)
            .context("failed to open audit log for installation event")?;
        let audit_writer = std::io::BufWriter::new(audit_file);

        let (last_hash, sequence) = if audit_path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
            let contents = std::fs::read_to_string(&audit_path).unwrap_or_default();
            if let Some(last_line) = contents.lines().rev().find(|l| !l.trim().is_empty()) {
                if let Ok(entry) = serde_json::from_str::<core_profile::AuditEntry>(last_line) {
                    let hash = blake3::hash(last_line.as_bytes());
                    (hash.to_hex().to_string(), entry.sequence)
                } else {
                    (String::new(), 0)
                }
            } else {
                (String::new(), 0)
            }
        } else {
            (String::new(), 0)
        };

        let mut audit = core_profile::AuditLogger::new(
            audit_writer, last_hash, sequence, core_types::AuditHash::Blake3, None,
        );
        audit.append(core_profile::AuditAction::InstallationCreated {
            id: core_types::InstallationId {
                id,
                org_ns: None,
                namespace: install_ns,
                machine_binding: None,
            },
            org: org.map(|s| s.to_string()),
            machine_binding_present: machine_binding.is_some(),
        }).map_err(|e| anyhow::anyhow!("failed to write audit event: {e}"))?;
    }

    step_done(&format!("Created {}", installation_path.display()));
    println!("        Installation ID: {}", id);
    println!("        Namespace:       {}", install_ns);
    if let Some(domain) = org {
        println!("        Organization:    {}", domain);
    }
    println!("        Machine binding: {}", if machine_binding.is_some() { "present" } else { "absent" });

    Ok(())
}

// ── Step 3: Services ────────────────────────────────────────────────────────

async fn init_services() -> anyhow::Result<()> {
    // Check if already running.
    let is_active = std::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "open-sesame.target"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if is_active {
        // Daemons running — verify bus is reachable.
        if core_ipc::noise::read_bus_public_key().await.is_ok() {
            step_skip("Daemons running");
            return Ok(());
        }
    }

    // daemon-reload to pick up any new/changed unit files.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    // Reset any failed units from prior crash-loops (e.g. daemon-profile
    // crashed before config dir existed). Without this, `start` is a no-op
    // on failed units and the daemon never retries.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "reset-failed", "open-sesame.target"])
        .status();
    for unit in [
        "open-sesame-profile", "open-sesame-secrets", "open-sesame-wm",
        "open-sesame-launcher", "open-sesame-clipboard", "open-sesame-input",
        "open-sesame-snippets",
    ] {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "reset-failed", unit])
            .status();
    }

    // Start the target (idempotent if already running).
    let start = std::process::Command::new("systemctl")
        .args(["--user", "start", "open-sesame.target"])
        .output()
        .context("failed to run systemctl")?;

    if !start.status.success() {
        let stderr = String::from_utf8_lossy(&start.stderr);
        anyhow::bail!(
            "failed to start daemons: {stderr}\n\
             Check: journalctl --user -u open-sesame-profile"
        );
    }

    step_done("Starting daemons");

    // Poll for bus.pub (up to 10s).
    print!("        Waiting for IPC bus ... ");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if core_ipc::noise::read_bus_public_key().await.is_ok() {
            println!("{}", "ready".green());
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            println!("{}", "timeout".red());
            anyhow::bail!(
                "IPC bus not available after 10s.\n\
                 Check: journalctl --user -u open-sesame-profile"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

// ── Step 3: Unlock + activate ───────────────────────────────────────────────

async fn init_unlock() -> anyhow::Result<()> {
    let client = crate::connect().await?;

    // Check current state.
    let already_unlocked = matches!(
        crate::rpc(&client, EventKind::StatusRequest, SecurityLevel::Internal).await?,
        EventKind::StatusResponse { locked: false, .. }
    );

    if already_unlocked {
        step_skip("Secrets already unlocked");
    } else {
        println!("        This password encrypts your secrets vault.");
        println!("        Choose something strong — you'll need it to unlock after reboot.");
        println!();

        let mut password = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            dialoguer::Password::new()
                .with_prompt("        Master password")
                .with_confirmation("        Confirm", "        Passwords don't match, try again")
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
                anyhow::bail!("empty password from stdin — refusing to create vault with no password");
            }
            buf
        };

        let mut password_bytes = password.as_bytes().to_vec();
        password.zeroize();

        let event = EventKind::UnlockRequest {
            password: SensitiveBytes::new(std::mem::take(&mut password_bytes)),
            profile: None,
        };
        password_bytes.zeroize();

        match crate::rpc(&client, event, SecurityLevel::SecretsOnly).await? {
            EventKind::UnlockResponse { success: true, .. } => {
                step_done("Secrets vault unlocked");
            }
            EventKind::UnlockResponse { success: false, .. } => {
                anyhow::bail!("unlock failed — wrong password or keyring error");
            }
            EventKind::UnlockRejected { reason: core_types::UnlockRejectedReason::AlreadyUnlocked, .. } => {
                // Benign: another client unlocked between our StatusRequest and UnlockRequest.
                step_skip("Secrets already unlocked");
            }
            other => anyhow::bail!("unexpected response: {other:?}"),
        }
    }

    // Activate default profile.
    let profile_name = TrustProfileName::try_from("default")
        .expect("hardcoded valid name");
    let event = EventKind::ProfileActivate {
        target: ProfileId::new(),
        profile_name,
    };

    match crate::rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileActivateResponse { success: true } => {
            step_done("Default profile activated");
        }
        EventKind::ProfileActivateResponse { success: false } => {
            // May already be active — not fatal.
            println!("        Default profile: {}", "(already active)".dimmed());
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

// ── Step 4: Keybinding ─────────────────────────────────────────────────────

#[cfg(all(target_os = "linux", feature = "desktop"))]
fn init_keybinding() -> anyhow::Result<()> {
    platform_linux::cosmic_keys::setup_keybinding("alt+space")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    step_done("Alt+Tab window switching configured");
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "desktop")))]
fn init_keybinding() -> anyhow::Result<()> {
    Ok(())
}

// ============================================================================
// sesame init --wipe-reset-destroy-all-data
// ============================================================================

pub fn cmd_wipe() -> anyhow::Result<()> {
    let config_dir = core_config::config_dir();
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(|d| std::path::PathBuf::from(d).join("pds"))
        .ok();

    println!();
    println!(
        "  {}: This will permanently destroy ALL Open Sesame data:",
        "WARNING".red().bold()
    );
    println!("    - Configuration:  {}/", config_dir.display());
    println!("    - Secrets vaults: {}/vaults/", config_dir.display());
    println!("    - Secrets salt:   {}/secrets.salt", config_dir.display());
    println!("    - Audit logs:     {}/audit.jsonl", config_dir.display());
    if let Some(ref rt) = runtime_dir {
        println!("    - Runtime state:  {}/", rt.display());
    }
    println!();

    let confirmation: String = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        dialoguer::Input::new()
            .with_prompt("  Type \"destroy all data\" to confirm")
            .interact_text()
            .context("failed to read confirmation")?
    } else {
        let mut buf = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buf)
            .context("failed to read confirmation from stdin")?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    };

    if confirmation.trim() != "destroy all data" {
        println!("  Cancelled.");
        return Ok(());
    }

    println!();

    // Stop daemons.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "open-sesame.target"])
        .status();
    println!("  Stopping daemons ... {}", "done".green());

    // Remove config directory.
    if config_dir.exists() {
        std::fs::remove_dir_all(&config_dir)
            .context("failed to remove config directory")?;
        println!("  Removing {} ... {}", config_dir.display(), "done".green());
    }

    // Remove runtime directory.
    if let Some(ref rt) = runtime_dir
        && rt.exists()
    {
        std::fs::remove_dir_all(rt)
            .context("failed to remove runtime directory")?;
        println!("  Removing {} ... {}", rt.display(), "done".green());
    }

    println!();
    println!("  {}", "All data destroyed.".green().bold());
    println!("  Run `sesame init` to start fresh.");
    println!();

    Ok(())
}
