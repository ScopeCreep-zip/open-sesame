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

fn parse_auth_policy(s: &str) -> anyhow::Result<core_types::AuthCombineMode> {
    match s.to_lowercase().as_str() {
        "any" => Ok(core_types::AuthCombineMode::Any),
        "all" => Ok(core_types::AuthCombineMode::All),
        _ => anyhow::bail!(
            "unknown auth policy '{s}'. Valid values: \"any\" (either factor unlocks), \
             \"all\" (every enrolled factor required)"
        ),
    }
}

/// Resolve an `--ssh-key` CLI value into a SHA256 fingerprint.
///
/// Accepts three forms:
///   - Empty string (`--ssh-key` with no value): list keys from agent, interactive select.
///   - File path (`--ssh-key ~/.ssh/id_ed25519.pub`): read public key, compute fingerprint.
///   - Fingerprint (`--ssh-key SHA256:...`): use directly.
pub(crate) async fn resolve_ssh_key(raw: &str) -> anyhow::Result<String> {
    // Empty: interactive selection from SSH agent.
    if raw.is_empty() {
        return select_ssh_key_interactive().await;
    }

    // Looks like a fingerprint (starts with SHA256: or is base64-ish hash).
    if raw.starts_with("SHA256:") {
        return Ok(raw.to_string());
    }

    // Try as a file path (expand ~ to home dir).
    let expanded = if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            let candidate = home.join(rest);
            // Canonicalize to resolve ../ traversals, then verify the result
            // is still within the user's home directory.
            let canonical = candidate.canonicalize().unwrap_or(candidate.clone());
            if !canonical.starts_with(&home) {
                anyhow::bail!(
                    "SSH key path '{}' resolves to '{}' which is outside your home directory.\n\
                     Only paths within $HOME are accepted for security.",
                    raw,
                    canonical.display()
                );
            }
            canonical
        } else {
            std::path::PathBuf::from(raw)
        }
    } else {
        std::path::PathBuf::from(raw)
    };

    if expanded.exists() {
        // Guard against accidentally reading huge files — SSH public keys are
        // never larger than a few KB.
        let meta = std::fs::metadata(&expanded).with_context(|| {
            format!("failed to stat SSH public key file: {}", expanded.display())
        })?;
        if meta.len() > 64 * 1024 {
            anyhow::bail!(
                "SSH public key file is too large ({} bytes). \
                 Public keys should be under 64 KB.",
                meta.len()
            );
        }
        let contents = std::fs::read_to_string(&expanded).with_context(|| {
            format!("failed to read SSH public key file: {}", expanded.display())
        })?;
        let pubkey = ssh_key::PublicKey::from_openssh(contents.trim()).with_context(|| {
            format!(
                "failed to parse SSH public key from: {}",
                expanded.display()
            )
        })?;
        let fingerprint = pubkey.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        tracing::info!(
            fingerprint = %fingerprint,
            path = %expanded.display(),
            "resolved SSH key from file"
        );
        step_done(&format!(
            "Resolved SSH key ({})",
            expanded
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
        ));
        return Ok(fingerprint);
    }

    // Not a file, not a fingerprint — error with guidance.
    anyhow::bail!(
        "'{raw}' is not a valid SSH key fingerprint (SHA256:...) or public key file path.\n\
         Usage:\n  \
         --ssh-key                           (interactive selection from agent)\n  \
         --ssh-key SHA256:abc123...          (fingerprint from `ssh-add -l`)\n  \
         --ssh-key ~/.ssh/id_ed25519.pub    (public key file)"
    );
}

/// Interactively select an SSH key from the running SSH agent.
async fn select_ssh_key_interactive() -> anyhow::Result<String> {
    let sock_path =
        std::env::var("SSH_AUTH_SOCK").context("SSH_AUTH_SOCK not set — is ssh-agent running?")?;
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
        .map(|id| {
            let (fp, comment) = match id {
                ssh_agent_client_rs::Identity::PublicKey(cow) => (
                    cow.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                    cow.comment().to_string(),
                ),
                ssh_agent_client_rs::Identity::Certificate(cow) => (
                    cow.public_key()
                        .fingerprint(ssh_key::HashAlg::Sha256)
                        .to_string(),
                    cow.comment().to_string(),
                ),
            };
            if comment.is_empty() {
                fp
            } else {
                format!("{fp} ({comment})")
            }
        })
        .collect();

    let selection = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        dialoguer::Select::new()
            .with_prompt("        Select SSH key for enrollment")
            .items(&key_labels)
            .default(0)
            .interact()
            .context("SSH key selection cancelled")?
    } else {
        anyhow::bail!(
            "non-interactive mode requires an explicit SSH key.\n\
             Usage:\n  \
             --ssh-key SHA256:abc123...          (fingerprint from `ssh-add -l`)\n  \
             --ssh-key ~/.ssh/id_ed25519.pub    (public key file)"
        );
    };

    let fingerprint = match &eligible[selection] {
        ssh_agent_client_rs::Identity::PublicKey(cow) => {
            cow.fingerprint(ssh_key::HashAlg::Sha256).to_string()
        }
        ssh_agent_client_rs::Identity::Certificate(cow) => cow
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
    };

    Ok(fingerprint)
}

// ============================================================================
// sesame init
// ============================================================================

pub async fn cmd_init(
    no_keybinding: bool,
    org: Option<String>,
    ssh_key: Option<String>,
    password: bool,
    auth_policy: String,
) -> anyhow::Result<()> {
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

    // Resolve --ssh-key into a fingerprint before vault init.
    let ssh_fingerprint = match ssh_key {
        Some(val) => Some(resolve_ssh_key(&val).await?),
        None => None,
    };

    // Step 4: Vault initialization
    let combine_mode = parse_auth_policy(&auth_policy)?;
    step_header(4, total_steps, "Vault");
    init_vault(ssh_fingerprint.as_deref(), password, combine_mode).await?;

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

    std::fs::create_dir_all(&config_dir).context("failed to create config directory")?;

    let mut config = core_config::Config::default();
    config.profiles.insert(
        core_types::DEFAULT_PROFILE_NAME.into(),
        core_config::ProfileConfig::default(),
    );

    let toml_str = toml::to_string_pretty(&config).context("failed to serialize default config")?;
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
    let profile_ns = core_types::PROFILE_NAMESPACE;

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
    let machine_binding = std::fs::read_to_string("/etc/machine-id").ok().map(|mid| {
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o600))
                .context("failed to set audit file permissions")?;
        }
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
            audit_writer,
            last_hash,
            sequence,
            core_types::AuditHash::Blake3,
            None,
        );
        let audit_org_ns = org.map(|domain| core_types::OrganizationNamespace {
            domain: domain.to_string(),
            namespace: uuid::Uuid::new_v5(&profile_ns, format!("org:{domain}").as_bytes()),
        });
        let audit_machine_binding = machine_binding.as_ref().and_then(|mb| {
            let hash = blake3::Hash::from_hex(&mb.binding_hash).ok()?;
            Some(core_types::MachineBinding {
                binding_hash: *hash.as_bytes(),
                binding_type: core_types::MachineBindingType::MachineId,
            })
        });
        audit
            .append(core_profile::AuditAction::InstallationCreated {
                id: core_types::InstallationId {
                    id,
                    org_ns: audit_org_ns,
                    namespace: install_ns,
                    machine_binding: audit_machine_binding,
                },
                org: org.map(|s| s.to_string()),
                machine_binding_present: machine_binding.is_some(),
            })
            .map_err(|e| anyhow::anyhow!("failed to write audit event: {e}"))?;
    }

    step_done(&format!("Created {}", installation_path.display()));
    println!("        Installation ID: {}", id);
    println!("        Namespace:       {}", install_ns);
    if let Some(domain) = org {
        println!("        Organization:    {}", domain);
    }
    println!(
        "        Machine binding: {}",
        if machine_binding.is_some() {
            "present"
        } else {
            "absent"
        }
    );

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

    // Ensure runtime directory exists before starting services.
    core_config::bootstrap_dirs();

    // Also run tmpfiles to create any other dirs we declared.
    let _ = std::process::Command::new("systemd-tmpfiles")
        .args(["--user", "--create"])
        .status();

    // daemon-reload to pick up any new/changed unit files.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    // Reset any failed units from prior crash-loops.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "reset-failed", "open-sesame.target"])
        .status();
    for unit in [
        "open-sesame-profile",
        "open-sesame-secrets",
        "open-sesame-wm",
        "open-sesame-launcher",
        "open-sesame-clipboard",
        "open-sesame-input",
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

// ── Step 4: Vault initialization (unified) ──────────────────────────────────

async fn init_vault(
    ssh_fingerprint: Option<&str>,
    use_password: bool,
    combine_mode: core_types::AuthCombineMode,
) -> anyhow::Result<()> {
    let config_dir = core_config::config_dir();
    let profile =
        TrustProfileName::try_from(core_types::DEFAULT_PROFILE_NAME).expect("hardcoded valid name");
    let client = crate::connect().await?;

    // Determine which factors to enroll.
    // Default: password-only if no --key provided.
    let has_password = use_password || ssh_fingerprint.is_none();
    let has_ssh = ssh_fingerprint.is_some();

    // Check current state.
    let already_unlocked = matches!(
        crate::rpc(&client, EventKind::StatusRequest, SecurityLevel::Internal).await?,
        EventKind::StatusResponse { locked: false, .. }
    );

    if already_unlocked {
        step_skip("Secrets already unlocked");
    } else {
        // Generate random master key.
        let mut master_key_bytes = [0u8; 32];
        getrandom::getrandom(&mut master_key_bytes)
            .map_err(|e| anyhow::anyhow!("failed to generate random master key: {e}"))?;
        let master_key = core_crypto::SecureBytes::new(master_key_bytes.to_vec());
        master_key_bytes.zeroize();

        // Generate salt.
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| anyhow::anyhow!("failed to generate salt: {e}"))?;
        let salt_path = config_dir.join("vaults").join(format!("{profile}.salt"));
        let vaults_dir = config_dir.join("vaults");
        std::fs::create_dir_all(&vaults_dir).context("failed to create vaults dir")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&vaults_dir, std::fs::Permissions::from_mode(0o700))
                .context("failed to set vaults directory permissions")?;
        }
        core_config::atomic_write(&salt_path, &salt).context("failed to write salt")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o600))
                .context("failed to set salt file permissions")?;
        }

        // Track enrolled factors for metadata.
        let mut enrolled_factors = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Enroll password factor.
        if has_password {
            if has_ssh {
                println!("        Password is one of the enrolled factors.");
            } else {
                println!("        This password encrypts your secrets vault.");
                println!(
                    "        Choose something strong — you'll need it to unlock after reboot."
                );
            }
            println!();

            let mut password_str = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                dialoguer::Password::new()
                    .with_prompt("        Master password")
                    .with_confirmation(
                        "        Confirm",
                        "        Passwords don't match, try again",
                    )
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
                        "empty password from stdin — refusing to create vault with no password"
                    );
                }
                buf
            };

            let mut password_sv = core_crypto::SecureVec::new();
            for ch in password_str.chars() {
                password_sv.push_char(ch);
            }
            password_str.zeroize();

            let pw_backend = core_auth::PasswordBackend::new().with_password(password_sv);
            core_auth::VaultAuthBackend::enroll(
                &pw_backend,
                &profile,
                &master_key,
                &config_dir,
                &salt,
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("password enrollment failed: {e}"))?;

            enrolled_factors.push(core_auth::EnrolledFactor {
                factor_id: core_types::AuthFactorId::Password,
                label: "master password".into(),
                enrolled_at: now,
            });
            step_done("Password factor enrolled");
        }

        // Enroll SSH factor.
        if let Some(fingerprint) = ssh_fingerprint {
            let key_index = crate::find_ssh_key_index(fingerprint).await?;
            let ssh_backend = core_auth::SshAgentBackend::new();
            core_auth::VaultAuthBackend::enroll(
                &ssh_backend,
                &profile,
                &master_key,
                &config_dir,
                &salt,
                Some(key_index),
            )
            .await
            .map_err(|e| anyhow::anyhow!("SSH enrollment failed: {e}"))?;

            enrolled_factors.push(core_auth::EnrolledFactor {
                factor_id: core_types::AuthFactorId::SshAgent,
                label: fingerprint.to_string(),
                enrolled_at: now,
            });
            step_done(&format!("SSH factor enrolled ({})", fingerprint));
        }

        // Write vault metadata.
        let meta =
            core_auth::VaultMetadata::new_multi_factor(enrolled_factors, combine_mode.clone());
        meta.save(&config_dir, &profile)
            .map_err(|e| anyhow::anyhow!("failed to write vault metadata: {e}"))?;

        let policy_label = match &combine_mode {
            core_types::AuthCombineMode::Any => "any",
            core_types::AuthCombineMode::All => "all",
            core_types::AuthCombineMode::Policy(_) => "policy",
        };
        step_done(&format!(
            "Vault metadata written (auth policy: {policy_label})"
        ));

        // Compute the unlock key that daemon-secrets will use for this vault.
        // In All mode, daemon-secrets combines factor pieces via BLAKE3 derive_key,
        // so we must create the vault with that same derived key.
        let unlock_key = if matches!(combine_mode, core_types::AuthCombineMode::All) {
            // Replicate daemon-secrets All-mode combination:
            // sort factor pieces by AuthFactorId, concatenate, BLAKE3 derive_key.
            let mut pieces: Vec<(core_types::AuthFactorId, &[u8])> = Vec::new();
            if has_password {
                pieces.push((core_types::AuthFactorId::Password, master_key.as_bytes()));
            }
            if ssh_fingerprint.is_some() {
                pieces.push((core_types::AuthFactorId::SshAgent, master_key.as_bytes()));
            }
            pieces.sort_by_key(|(id, _)| *id);
            let mut combined = Vec::new();
            for (_id, piece) in &pieces {
                combined.extend_from_slice(piece);
            }
            let ctx_str = format!("pds v2 combined-master-key {profile}");
            let derived: [u8; 32] = blake3::derive_key(&ctx_str, &combined);
            combined.zeroize();
            drop(master_key);
            core_crypto::SecureBytes::new(derived.to_vec())
        } else if has_ssh {
            // Any mode with SSH: unlock via SSH to verify the enrollment round-trips.
            // Drop raw master_key early — SSH unlock recovers it from the enrolled blob.
            drop(master_key);
            let unlock_backend = core_auth::SshAgentBackend::new();
            let outcome =
                core_auth::VaultAuthBackend::unlock(&unlock_backend, &profile, &config_dir, &salt)
                    .await
                    .map_err(|e| anyhow::anyhow!("SSH unlock failed: {e}"))?;
            step_done("SSH enrollment verified");
            outcome.master_key
        } else {
            // Password-only or Any mode without SSH: use raw master key.
            master_key
        };

        // Send unlock key to daemon-secrets to create/open the vault.
        let event = EventKind::SshUnlockRequest {
            master_key: SensitiveBytes::new(unlock_key.into_vec()),
            profile: profile.clone(),
            ssh_fingerprint: "direct-init".to_string(),
        };
        match crate::rpc(&client, event, SecurityLevel::SecretsOnly).await? {
            EventKind::UnlockResponse { success: true, .. } => {
                step_done("Secrets vault unlocked");
            }
            EventKind::UnlockResponse { success: false, .. } => {
                anyhow::bail!("unlock failed — key rejected by daemon-secrets");
            }
            EventKind::UnlockRejected {
                reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
                ..
            } => {
                step_skip("Secrets already unlocked");
            }
            other => anyhow::bail!("unexpected response: {other:?}"),
        }
    }

    // Activate default profile.
    let event = EventKind::ProfileActivate {
        target: ProfileId::new(),
        profile_name: profile,
    };
    match crate::rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileActivateResponse { success: true } => {
            step_done("Default profile activated");
        }
        EventKind::ProfileActivateResponse { success: false } => {
            println!("        Default profile: {}", "(already active)".dimmed());
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

// ── Step 5: Keybinding ─────────────────────────────────────────────────────

#[cfg(all(target_os = "linux", feature = "desktop"))]
fn init_keybinding() -> anyhow::Result<()> {
    platform_linux::cosmic_keys::setup_keybinding("alt+space")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    step_done("Alt+Space launcher keybinding configured");
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
    println!(
        "    - Secrets salt:   {}/secrets.salt",
        config_dir.display()
    );
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

    // Overwrite sensitive files with zeros before unlinking.
    // This ensures key material and vault data don't linger on disk.
    if config_dir.exists() {
        let vaults_dir = config_dir.join("vaults");
        if vaults_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&vaults_dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Ok(meta) = path.metadata()
                {
                    let len = meta.len() as usize;
                    if len > 0 {
                        let zeros = vec![0u8; len];
                        let _ = std::fs::write(&path, &zeros);
                    }
                }
            }
        }
        // Also zeroize salt and audit files at the top level.
        for name in ["secrets.salt", "audit.jsonl"] {
            let path = config_dir.join(name);
            if path.is_file()
                && let Ok(meta) = path.metadata()
            {
                let len = meta.len() as usize;
                if len > 0 {
                    let zeros = vec![0u8; len];
                    let _ = std::fs::write(&path, &zeros);
                }
            }
        }
        println!("  Zeroizing sensitive files ... {}", "done".green());

        std::fs::remove_dir_all(&config_dir).context("failed to remove config directory")?;
        println!("  Removing {} ... {}", config_dir.display(), "done".green());
    }

    // Remove runtime directory.
    if let Some(ref rt) = runtime_dir
        && rt.exists()
    {
        std::fs::remove_dir_all(rt).context("failed to remove runtime directory")?;
        println!("  Removing {} ... {}", rt.display(), "done".green());
    }

    println!();
    println!("  {}", "All data destroyed.".green().bold());
    println!("  Run `sesame init` to start fresh.");
    println!();

    Ok(())
}
