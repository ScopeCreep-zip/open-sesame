//! `sesame ssh`: SSH agent factor enrollment, listing, and revocation, and
//! the SSH key resolution `sesame init` shares.

use anyhow::Context;
use core_auth::VaultAuthBackend as _;
use core_layout::Layout;
use owo_colors::OwoColorize;

use crate::helpers::table;
use open_sesame::cli::ProfileSpecs;

/// Largest public key file read: SSH public keys are a few KB.
const MAX_PUBLIC_KEY_FILE: u64 = 64 * 1024;

/// Where the SSH key to enroll comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySource<'a> {
    /// One of the agent's enrollable keys, selected interactively.
    Agent,
    /// A fingerprint (`SHA256:...`) or a public key file.
    Named(&'a str),
}

impl<'a> From<Option<&'a str>> for KeySource<'a> {
    fn from(value: Option<&'a str>) -> Self {
        value.map_or(Self::Agent, Self::Named)
    }
}

/// The SHA-256 fingerprint of the SSH key `source` names:
/// - `Agent`: select one of the agent's enrollable keys interactively;
/// - `SHA256:...`: that fingerprint;
/// - otherwise a public key file, `~/` resolved against the home directory
///   and required to stay inside it.
///
/// # Errors
///
/// When the agent cannot be listed or offers no enrollable key, stdin is
/// not a terminal for an interactive choice, or the file cannot be read or
/// parsed.
pub(crate) async fn resolve_ssh_key(
    layout: &Layout,
    source: KeySource<'_>,
) -> anyhow::Result<String> {
    let KeySource::Named(raw) = source else {
        return select_agent_key(layout).await;
    };
    if raw.starts_with("SHA256:") {
        return Ok(raw.to_owned());
    }
    let path = match raw.strip_prefix("~/") {
        Some(rest) => {
            let home = layout.home()?;
            let candidate = home.join(rest);
            let resolved = match candidate.canonicalize() {
                Ok(canonical) => canonical,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => candidate,
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("failed to resolve {}", candidate.display()));
                }
            };
            anyhow::ensure!(
                resolved.starts_with(home),
                "SSH key path '{raw}' resolves to '{}', outside the home directory",
                resolved.display()
            );
            resolved
        }
        None => std::path::PathBuf::from(raw),
    };
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
            "'{raw}' is neither an SSH key fingerprint (SHA256:...) nor a public key file.\n\
             Usage:\n  \
             --ssh-key                           (interactive selection from the agent)\n  \
             --ssh-key SHA256:abc123...          (fingerprint from `ssh-add -l`)\n  \
             --ssh-key ~/.ssh/id_ed25519.pub     (public key file)"
        ),
        Err(e) => return Err(e).with_context(|| format!("failed to stat {}", path.display())),
    };
    anyhow::ensure!(
        meta.len() <= MAX_PUBLIC_KEY_FILE,
        "{} is {} bytes; an SSH public key is under {MAX_PUBLIC_KEY_FILE} bytes",
        path.display(),
        meta.len()
    );
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let key = ssh_key::PublicKey::from_openssh(contents.trim())
        .with_context(|| format!("{} is not an OpenSSH public key", path.display()))?;
    Ok(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

/// Select one of the agent's enrollable keys on the terminal.
async fn select_agent_key(layout: &Layout) -> anyhow::Result<String> {
    let keys = core_auth::eligible_agent_keys(layout).await?;
    anyhow::ensure!(
        !keys.is_empty(),
        "the SSH agent holds no enrollable key: only Ed25519 and RSA keys are supported \
         (ECDSA signatures are not deterministic).\nAdd one with: ssh-add ~/.ssh/id_ed25519"
    );
    let labels: Vec<String> = keys.iter().map(core_auth::AgentKey::label).collect();
    let index = crate::prompt::select(
        "Select SSH key for enrollment",
        &labels,
        &format!(
            "selecting an SSH key needs a terminal; pass --ssh-key with one of:\n{}",
            labels.join("\n")
        ),
    )?;
    Ok(keys[index].fingerprint.clone())
}

pub(crate) async fn cmd_ssh_enroll(
    layout: &Layout,
    specs: &ProfileSpecs,
    ssh_key: Option<&str>,
) -> anyhow::Result<()> {
    let fingerprint = resolve_ssh_key(layout, ssh_key.into()).await?;
    let backend = core_auth::SshAgentBackend::new();
    for spec in specs {
        let profile = &spec.vault;
        crate::enrollment::enroll(
            layout,
            profile,
            &backend,
            Some(&fingerprint),
            fingerprint.clone(),
        )
        .await?;
        println!(
            "{}",
            format!("SSH enrollment created and verified for vault '{profile}'.").green()
        );
    }
    println!("Future unlocks will use your SSH key automatically when the agent is loaded.");
    Ok(())
}

pub(crate) async fn cmd_ssh_list(layout: &Layout, specs: &ProfileSpecs) -> anyhow::Result<()> {
    let backend = core_auth::SshAgentBackend::new();
    let mut table = table(&[
        "Profile",
        "SSH Enrolled",
        "Key Fingerprint",
        "Key Type",
        "Agent Available",
    ]);
    for spec in specs {
        let profile = &spec.vault;
        let row = match core_auth::SshAgentBackend::read_enrollment(layout, profile)
            .with_context(|| format!("SSH enrollment of '{profile}'"))?
        {
            Some(blob) => {
                let available = backend.can_unlock(profile, layout).await?;
                vec![
                    profile.to_string(),
                    "yes".into(),
                    blob.key_fingerprint,
                    blob.key_type.wire_name().into(),
                    if available { "yes" } else { "no" }.into(),
                ]
            }
            None => vec![
                profile.to_string(),
                "no".into(),
                "-".into(),
                "-".into(),
                "-".into(),
            ],
        };
        table.add_row(row);
    }
    println!("{table}");
    Ok(())
}

pub(crate) async fn cmd_ssh_revoke(layout: &Layout, specs: &ProfileSpecs) -> anyhow::Result<()> {
    let backend = core_auth::SshAgentBackend::new();
    for spec in specs {
        let profile = &spec.vault;
        if crate::enrollment::revoke(layout, profile, &backend).await? {
            println!(
                "{}",
                format!("SSH enrollment revoked for vault '{profile}'.").green()
            );
        } else {
            println!(
                "{}",
                format!("No SSH enrollment found for vault '{profile}'.").yellow()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fingerprints_are_taken_as_given() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        assert_eq!(
            resolve_ssh_key(&layout, KeySource::Named("SHA256:abc"))
                .await
                .unwrap(),
            "SHA256:abc"
        );
    }

    #[tokio::test]
    async fn home_relative_paths_must_stay_in_home() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        std::fs::create_dir_all(layout.home().unwrap()).unwrap();
        std::fs::write(root.path().join("outside.pub"), "x").unwrap();
        let err = resolve_ssh_key(&layout, KeySource::Named("~/../outside.pub"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside the home directory"), "{err}");
    }

    #[tokio::test]
    async fn public_key_files_resolve_to_their_fingerprint() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let home = layout.home().unwrap().to_path_buf();
        std::fs::create_dir_all(&home).unwrap();
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.invalid";
        std::fs::write(home.join("id.pub"), line).unwrap();
        let expected = ssh_key::PublicKey::from_openssh(line)
            .unwrap()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        assert_eq!(
            resolve_ssh_key(&layout, KeySource::Named("~/id.pub"))
                .await
                .unwrap(),
            expected
        );
        assert!(
            resolve_ssh_key(&layout, KeySource::Named("~/absent.pub"))
                .await
                .is_err()
        );
    }
}
