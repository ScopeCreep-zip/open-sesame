use anyhow::Context;
use comfy_table::{Table, presets::UTF8_FULL};
use core_types::TrustProfileName;
use owo_colors::OwoColorize;
use zeroize::Zeroize;

use crate::ipc::resolve_profile_specs;

pub(crate) async fn cmd_ssh_enroll(
    profile_arg: Option<String>,
    ssh_key: Option<String>,
) -> anyhow::Result<()> {
    // Resolve --ssh-key into a fingerprint (interactive select, file path, or direct fingerprint).
    let key_fingerprint: Option<String> = match ssh_key {
        Some(ref val) => Some(crate::init::resolve_ssh_key(val).await?),
        None => None,
    };
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
                    "empty password from stdin for vault '{profile_name}' — refusing to enroll with no password"
                );
            }
            buf
        };

        // Unwrap the real master key from the PasswordWrapBlob.
        // In Any/Policy mode, the master key is a random value wrapped under
        // the Argon2id-derived KEK. Each factor independently wraps this same
        // master key, so factors can be added/revoked independently.
        let mut password_sv = core_crypto::SecureVec::new();
        for ch in password.chars() {
            password_sv.push_char(ch);
        }
        password.zeroize();
        let pw_backend = core_auth::PasswordBackend::new().with_password(password_sv);
        let outcome = core_auth::VaultAuthBackend::unlock(&pw_backend, &target, &config_dir, &salt)
            .await
            .map_err(|e| anyhow::anyhow!("failed to derive master key from password: {e}"))?;
        let master_key = outcome.master_key;

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

        let selection = if let Some(ref fp) = key_fingerprint {
            // Explicit key selection by fingerprint (headless-safe).
            let fp_normalized = fp.strip_prefix("SHA256:").unwrap_or(fp);
            eligible
                .iter()
                .position(|id| {
                    let id_fp = match id {
                        ssh_agent_client_rs::Identity::PublicKey(cow) => {
                            cow.fingerprint(ssh_key::HashAlg::Sha256).to_string()
                        }
                        ssh_agent_client_rs::Identity::Certificate(cow) => cow
                            .public_key()
                            .fingerprint(ssh_key::HashAlg::Sha256)
                            .to_string(),
                    };
                    // Match with or without "SHA256:" prefix.
                    let id_fp_bare = id_fp.strip_prefix("SHA256:").unwrap_or(&id_fp);
                    id_fp_bare == fp_normalized
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "SSH key with fingerprint '{fp}' not found in agent.\n\
                         Available keys:\n{}\n\
                         Use `ssh-add -l` to list loaded keys.",
                        key_labels.join("\n")
                    )
                })?
        } else if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            // Interactive: always require explicit selection.
            dialoguer::Select::new()
                .with_prompt("Select SSH key for enrollment")
                .items(&key_labels)
                .default(0)
                .interact()?
        } else {
            anyhow::bail!(
                "no --ssh-key specified (required for non-interactive use).\n\
                 Available keys:\n{}\n\
                 Use --ssh-key <SHA256:fingerprint> or --ssh-key ~/.ssh/id_ed25519.pub",
                key_labels.join("\n")
            );
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

        // Update vault metadata to record the new SSH factor.
        let fingerprint = match &eligible[selection] {
            ssh_agent_client_rs::Identity::PublicKey(cow) => {
                cow.fingerprint(ssh_key::HashAlg::Sha256).to_string()
            }
            ssh_agent_client_rs::Identity::Certificate(cow) => cow
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
        };
        let mut meta = core_auth::VaultMetadata::load(&config_dir, &target).unwrap_or_else(|_| {
            core_auth::VaultMetadata::new_password(core_types::AuthCombineMode::Any)
        });
        meta.add_factor(core_types::AuthFactorId::SshAgent, fingerprint);
        meta.save(&config_dir, &target)
            .context("failed to update vault metadata")?;

        println!(
            "{}",
            format!("SSH enrollment created for vault '{profile_name}'.").green()
        );
        println!("Future unlocks will use your SSH key automatically when the agent is loaded.");
    }

    Ok(())
}

pub(crate) async fn cmd_ssh_list(profile_arg: Option<String>) -> anyhow::Result<()> {
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

pub(crate) async fn cmd_ssh_revoke(profile_arg: Option<String>) -> anyhow::Result<()> {
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
