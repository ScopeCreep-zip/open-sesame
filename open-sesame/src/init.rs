//! `sesame init` — first-run setup and factory reset.

use anyhow::Context;
use core_auth::VaultAuthBackend as _;
use core_layout::Layout;
use core_types::{
    AuthCombineMode, AuthFactorId, EventKind, ProfileId, SecurityLevel, TrustProfileName,
};
use owo_colors::OwoColorize;

use crate::helpers::unexpected;
use core_auth::FactorProgress;
use open_sesame::cli::AuthPolicyArg;

/// Whether the keybinding step applies: not skipped, and a desktop build
/// (the step reports a session without a keybinding backend).
fn keybinding_applicable(no_keybinding: bool) -> bool {
    cfg!(all(target_os = "linux", feature = "desktop")) && !no_keybinding
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

fn step_warn(msg: &str) {
    println!("        {msg} ... {}", "warning".yellow());
}

/// Run `program args`, returning its output. Failing to spawn is an error;
/// the exit status is the caller's to judge.
fn run_output(program: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program} {}", args.join(" ")))
}

/// Run a command whose failure must stop `sesame init`.
fn run_required(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = run_output(program, args)?;
    anyhow::ensure!(
        out.status.success(),
        "{program} {} failed ({}): {}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

/// Run a command whose failure does not stop `sesame init` (cleanup steps
/// whose effect the next required step verifies). A non-zero exit is
/// printed with its stderr, never discarded.
fn run_reported(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = run_output(program, args)?;
    if !out.status.success() {
        step_warn(&format!(
            "{program} {} exited {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// The vault factors `sesame init` enrolls.
struct VaultFactors {
    /// The new vault password, entered twice.
    password: Option<core_crypto::SecureVec>,
    /// The agent key's fingerprint.
    ssh_fingerprint: Option<String>,
    /// The policy of a two-factor vault.
    policy: AuthCombineMode,
}

// ============================================================================
// sesame init
// ============================================================================

pub(crate) async fn cmd_init(
    layout: &Layout,
    no_keybinding: bool,
    org: Option<&str>,
    ssh_key: Option<crate::ssh::KeySource<'_>>,
    password: bool,
    auth_policy: AuthPolicyArg,
) -> anyhow::Result<()> {
    let do_keybinding = keybinding_applicable(no_keybinding);
    let total_steps: u32 = if do_keybinding { 5 } else { 4 };

    println!("\n  {}", "Open Sesame — First-Time Setup".bold());

    step_header(1, total_steps, "Configuration");
    layout.bootstrap()?;
    init_config(layout)?;
    let crypto = core_config::load_config(layout)?
        .crypto()
        .context("invalid [crypto] configuration")?;

    step_header(2, total_steps, "Installation Identity");
    init_installation(layout, org, &crypto)?;

    step_header(3, total_steps, "Services");
    init_services(layout).await?;

    step_header(4, total_steps, "Vault");
    let ssh_fingerprint = match ssh_key {
        Some(source) => Some(crate::ssh::resolve_ssh_key(layout, source).await?),
        None => None,
    };
    init_vault(layout, ssh_fingerprint, password, auth_policy, &crypto).await?;

    if do_keybinding {
        step_header(5, total_steps, "Keybinding");
        init_keybinding(layout).await?;
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

fn init_config(layout: &Layout) -> anyhow::Result<()> {
    let config_path = layout.config_file()?;
    if config_path
        .try_exists()
        .with_context(|| format!("failed to check {}", config_path.display()))?
    {
        step_skip("Config exists");
        return Ok(());
    }

    let mut config = core_config::Config::default();
    config.profiles.insert(
        core_types::DEFAULT_PROFILE_NAME.into(),
        core_config::ProfileConfig::default(),
    );
    let toml_str = toml::to_string_pretty(&config).context("failed to serialize default config")?;
    core_layout::file::write(
        &config_path,
        toml_str.as_bytes(),
        core_layout::file::Mode::OwnerOnly,
    )?;

    step_done(&format!("Creating {}", config_path.display()));
    println!("        Default profile: {}", "\"default\"".green());
    Ok(())
}

// ── Step 2: Installation Identity ──────────────────────────────────────────

fn init_installation(
    layout: &Layout,
    org: Option<&str>,
    crypto: &core_types::CryptoConfig,
) -> anyhow::Result<()> {
    if core_config::load_installation(layout)?.is_some() {
        step_skip("Installation identity exists");
        return Ok(());
    }

    let machine_id = core_config::read_machine_id(layout)?;
    let install =
        core_config::InstallationConfig::new(uuid::Uuid::new_v4(), org, machine_id.as_deref());
    let identity = install.identity()?;
    core_config::write_installation(layout, &install)?;

    // The bus is not running yet: the creation event goes straight into the
    // audit chain, under the algorithm the daemons continue it with.
    let mut audit = core_profile::open_audit_log(&layout.audit_log()?, crypto.audit_hash, None)
        .context("failed to open audit log for installation event")?;
    audit.append(core_profile::AuditAction::InstallationCreated {
        id: identity.clone(),
        org: org.map(str::to_owned),
        machine_binding_present: identity.machine_binding.is_some(),
    })?;

    step_done(&format!(
        "Created {}",
        layout.installation_file()?.display()
    ));
    println!("        Installation ID: {}", identity.id);
    println!("        Namespace:       {}", identity.namespace);
    if let Some(domain) = org {
        println!("        Organization:    {domain}");
    }
    println!(
        "        Machine binding: {}",
        if identity.machine_binding.is_some() {
            "present"
        } else {
            "absent (no machine ID)"
        }
    );
    Ok(())
}

// ── Step 3: Services ────────────────────────────────────────────────────────

/// Whether daemon-profile has published the bus endpoint.
fn bus_ready(layout: &Layout) -> anyhow::Result<bool> {
    let path = layout.bus_endpoint_file()?;
    Ok(core_layout::file::exists(&path)?)
}

async fn init_services(layout: &Layout) -> anyhow::Result<()> {
    // `is-active` exits non-zero for an inactive unit.
    let is_active = run_output(
        "systemctl",
        &[
            "--user",
            "is-active",
            "--quiet",
            "open-sesame-headless.target",
        ],
    )?
    .status
    .success();
    if is_active && bus_ready(layout)? {
        step_skip("Daemons running");
        return Ok(());
    }

    // daemon-reload to pick up any new/changed unit files.
    run_required("systemctl", &["--user", "daemon-reload"])?;

    // Whether desktop units are installed decides what is reset and started.
    let listing = run_output(
        "systemctl",
        &[
            "--user",
            "list-unit-files",
            "open-sesame-desktop.target",
            "--no-pager",
            "--no-legend",
        ],
    )?;
    let desktop_installed = !listing.stdout.is_empty();

    // Reset any failed units from prior crash-loops. The start below
    // verifies the outcome, so a reset failure is reported, not fatal.
    let mut reset_units = vec![
        "open-sesame-headless.target",
        "open-sesame-profile",
        "open-sesame-secrets",
        "open-sesame-launcher",
        "open-sesame-snippets",
    ];
    if desktop_installed {
        reset_units.extend([
            "open-sesame-desktop.target",
            "open-sesame-wm",
            "open-sesame-clipboard",
            "open-sesame-input",
        ]);
    }
    for unit in reset_units {
        run_reported("systemctl", &["--user", "reset-failed", unit])?;
    }

    run_required(
        "systemctl",
        &["--user", "start", "open-sesame-headless.target"],
    )
    .context("failed to start headless daemons\nCheck: journalctl --user -u open-sesame-profile")?;
    step_done("Starting headless daemons");

    if desktop_installed {
        run_required(
            "systemctl",
            &["--user", "start", "open-sesame-desktop.target"],
        )
        .context("failed to start desktop daemons\nCheck: journalctl --user -u open-sesame-wm")?;
        step_done("Starting desktop daemons");
    }

    print!("        Waiting for IPC bus ... ");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if bus_ready(layout)? {
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

// ── Step 4: Vault ───────────────────────────────────────────────────────────

/// The factors to enroll: a password unless only an SSH key was asked
/// for, and the policy only when two factors are enrolled.
fn vault_factors(
    ssh_fingerprint: Option<String>,
    password: bool,
    auth_policy: AuthPolicyArg,
) -> anyhow::Result<VaultFactors> {
    let with_password = password || ssh_fingerprint.is_none();
    if with_password {
        if ssh_fingerprint.is_some() {
            println!("        Password is one of the enrolled factors.");
        } else {
            println!("        This password encrypts your secrets vault.");
            println!("        Choose something strong — you'll need it to unlock after reboot.");
        }
        println!();
    }
    let two_factor = with_password && ssh_fingerprint.is_some();
    Ok(VaultFactors {
        password: with_password
            .then(|| crate::prompt::new_password("        Master password"))
            .transpose()?,
        ssh_fingerprint,
        policy: if two_factor {
            auth_policy.into()
        } else {
            AuthCombineMode::Any
        },
    })
}

/// Create the default profile's vault: its metadata (the enrolled factors
/// and the `crypto` algorithms its keys derive under), a random master key
/// wrapped under every enrolled factor, and the factors submitted to
/// daemon-secrets, which creates the vault database under the key.
async fn create_vault(
    client: &core_ipc::BusClient,
    layout: &Layout,
    profile: &TrustProfileName,
    factors: VaultFactors,
    crypto: &core_types::CryptoConfig,
) -> anyhow::Result<()> {
    let mut enrolled = Vec::new();
    if factors.password.is_some() {
        enrolled.push((AuthFactorId::Password, "master password".to_owned()));
    }
    if let Some(fingerprint) = &factors.ssh_fingerprint {
        enrolled.push((AuthFactorId::SshAgent, fingerprint.clone()));
    }
    let policy_label = match &factors.policy {
        AuthCombineMode::Any => "any",
        AuthCombineMode::All => "all",
        AuthCombineMode::Policy(_) => "policy",
    };
    let meta = core_auth::VaultMetadata::new(enrolled, factors.policy, crypto)?;
    let keying = meta.keying(core_auth::salt::create(layout, profile)?);

    let key_bytes = zeroize::Zeroizing::new(
        core_crypto::random_bytes::<32>().context("failed to generate a random master key")?,
    );
    let master_key = core_crypto::SecureBytes::from_slice(&*key_bytes);
    drop(key_bytes);

    let password_backend = match factors.password {
        Some(password) => {
            let backend = core_auth::PasswordBackend::new().with_password(password);
            backend
                .enroll(profile, &master_key, layout, &keying, None)
                .await
                .context("password enrollment failed")?;
            step_done("Password factor enrolled");
            Some(backend)
        }
        None => None,
    };
    if let Some(fingerprint) = &factors.ssh_fingerprint {
        core_auth::SshAgentBackend::new()
            .enroll(profile, &master_key, layout, &keying, Some(fingerprint))
            .await
            .context("SSH enrollment failed")?;
        step_done(&format!("SSH factor enrolled ({fingerprint})"));
    }
    drop(master_key);

    meta.save(layout, profile)?;
    step_done(&format!(
        "Vault metadata written (auth policy: {policy_label})"
    ));

    // Each factor unwraps its enrollment and is submitted exactly as an
    // unlock submits it: the enrollment round-trip is verified, and an
    // "all" vault is created under the combined key unlocks will derive.
    let mut progress = FactorProgress::MoreRequired;
    if let Some(backend) = password_backend {
        let outcome = backend.unlock(profile, layout, &keying).await?;
        progress = crate::unlock::submit_factor(client, outcome, profile).await?;
    }
    if progress == FactorProgress::MoreRequired && factors.ssh_fingerprint.is_some() {
        let outcome = core_auth::SshAgentBackend::new()
            .unlock(profile, layout, &keying)
            .await?;
        progress = crate::unlock::submit_factor(client, outcome, profile).await?;
    }
    anyhow::ensure!(
        progress.is_unlocked(),
        "daemon-secrets did not unlock the new vault with its enrolled factors"
    );
    Ok(())
}

async fn init_vault(
    layout: &Layout,
    ssh_fingerprint: Option<String>,
    password: bool,
    auth_policy: AuthPolicyArg,
    crypto: &core_types::CryptoConfig,
) -> anyhow::Result<()> {
    let profile = TrustProfileName::try_from(core_types::DEFAULT_PROFILE_NAME)?;
    let client = crate::ipc::connect(layout).await?;

    let response =
        crate::ipc::rpc(&client, EventKind::StatusRequest, SecurityLevel::Internal).await?;
    let EventKind::StatusResponse { lock_state, .. } = response else {
        return Err(unexpected(&response));
    };
    if lock_state.as_ref().and_then(|state| state.get(&profile)) == Some(&false) {
        step_skip("Vault already unlocked");
    } else if core_auth::salt::load(layout, &profile)?.is_some() {
        // An initialized vault keeps its key: it is unlocked, never
        // re-created.
        step_skip("Vault exists");
        crate::unlock::unlock_profile(&client, layout, &profile).await?;
        step_done("Secrets vault unlocked");
    } else {
        let factors = vault_factors(ssh_fingerprint, password, auth_policy)?;
        create_vault(&client, layout, &profile, factors, crypto).await?;
        step_done("Secrets vault created and unlocked");
    }

    let event = EventKind::ProfileActivate {
        target: ProfileId::new(),
        profile_name: profile.clone(),
    };
    match crate::ipc::rpc(&client, event, SecurityLevel::Internal).await? {
        EventKind::ProfileActivateResponse { success: true } => {
            step_done("Default profile activated");
            Ok(())
        }
        EventKind::ProfileActivateResponse { success: false } => anyhow::bail!(
            "daemon-profile could not activate profile '{profile}'\n\
             Check: journalctl --user -u open-sesame-profile -u open-sesame-secrets"
        ),
        other => Err(unexpected(&other)),
    }
}

// ── Step 5: Keybinding ─────────────────────────────────────────────────────

#[cfg(all(target_os = "linux", feature = "desktop"))]
async fn init_keybinding(layout: &Layout) -> anyhow::Result<()> {
    step_done(&crate::keybinding::init_step(layout).await?);
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "desktop")))]
async fn init_keybinding(_layout: &Layout) -> anyhow::Result<()> {
    anyhow::bail!("keybinding setup needs a Linux desktop build")
}

// ============================================================================
// sesame init --wipe-reset-destroy-all-data
// ============================================================================

/// Every regular file directly in `dir`; an absent directory has none.
fn files_in(dir: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("failed to list {}", dir.display())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to list {}", dir.display()))?;
        if entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?
            .is_file()
        {
            files.push(entry.path());
        }
    }
    Ok(files)
}

pub(crate) fn cmd_wipe(layout: &Layout) -> anyhow::Result<()> {
    let config_dir = layout.config_dir()?;
    let audit_path = layout.audit_log()?;
    let vaults_dir = layout.vaults_dir()?;
    // No session runtime directory means no runtime state to wipe.
    let runtime_dir = layout.runtime_dir();

    println!();
    println!(
        "  {}: This will permanently destroy ALL Open Sesame data:",
        "WARNING".red().bold()
    );
    println!("    - Configuration:  {}/", config_dir.display());
    println!("    - Secrets vaults: {}/", vaults_dir.display());
    println!("    - Audit log:      {}", audit_path.display());
    match &runtime_dir {
        Ok(rt) => println!("    - Runtime state:  {}/", rt.display()),
        Err(e) => println!("    - Runtime state:  none ({e})"),
    }
    println!();

    if crate::prompt::text("  Type \"destroy all data\" to confirm")?.trim() != "destroy all data" {
        println!("  Cancelled.");
        return Ok(());
    }
    println!();

    // Stop daemons — desktop first, then headless. Stopping an absent
    // target exits non-zero; that is reported, and the wipe proceeds.
    run_reported(
        "systemctl",
        &["--user", "stop", "open-sesame-desktop.target"],
    )?;
    run_reported(
        "systemctl",
        &["--user", "stop", "open-sesame-headless.target"],
    )?;
    println!("  Stopping daemons ... {}", "done".green());

    // Overwrite vault files and the audit log with zeros before unlinking,
    // so key material and vault data don't linger on disk. Every file is
    // attempted; any failure aborts before removal so the wipe can be
    // retried.
    let mut targets = files_in(&vaults_dir)?;
    if audit_path
        .try_exists()
        .with_context(|| format!("failed to check {}", audit_path.display()))?
    {
        targets.push(audit_path);
    }
    let failures: Vec<String> = targets
        .iter()
        .filter_map(|path| {
            core_layout::file::zero_fill(path)
                .err()
                .map(|e| e.to_string())
        })
        .collect();
    anyhow::ensure!(
        failures.is_empty(),
        "zeroization failed; nothing was removed:\n  {}",
        failures.join("\n  ")
    );
    println!("  Zeroizing sensitive files ... {}", "done".green());

    for dir in std::iter::once(config_dir).chain(runtime_dir) {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => println!("  Removing {} ... {}", dir.display(), "done".green()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("failed to remove {}", dir.display())),
        }
    }

    println!();
    println!("  {}", "All data destroyed.".green().bold());
    println!("  Run `sesame init` to start fresh.");
    println!();
    Ok(())
}
