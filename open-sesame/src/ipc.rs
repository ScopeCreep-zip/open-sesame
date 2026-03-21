use anyhow::Context;
use core_ipc::BusClient;
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use owo_colors::OwoColorize;
use std::time::Duration;

use crate::env::{is_denied_env_var, secret_key_to_env_var};
use crate::helpers::format_denial_reason;

/// Default RPC timeout.
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Find the index of an SSH key by fingerprint in the agent's eligible key list.
pub(crate) async fn find_ssh_key_index(fingerprint: &str) -> anyhow::Result<usize> {
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

    let fp_normalized = fingerprint.strip_prefix("SHA256:").unwrap_or(fingerprint);

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
            let id_fp_bare = id_fp.strip_prefix("SHA256:").unwrap_or(&id_fp);
            id_fp_bare == fp_normalized
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "SSH key with fingerprint '{fingerprint}' not found in agent.\n\
                 Use `ssh-add -l` to list loaded keys."
            )
        })
}

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

/// A parsed profile spec from CSV input like "org:vault" or bare "vault".
#[derive(Debug, Clone)]
pub(crate) struct ProfileSpec {
    /// Organizational namespace (optional). Currently informational.
    pub org: Option<String>,
    /// The vault/profile name used for IPC.
    pub vault: String,
}

/// Parse a CSV profile spec string.
///
/// Format: `vault,org:vault,org:vault`
/// - `default` → ProfileSpec { org: None, vault: "default" }
/// - `braincraft:operations` → ProfileSpec { org: Some("braincraft"), vault: "operations" }
///
/// Designed for future extension to `docker.io/project/org:vault@sha256`.
pub(crate) fn parse_profile_specs(input: &str) -> Vec<ProfileSpec> {
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
pub(crate) fn resolve_profile_specs(cli_arg: Option<&str>) -> Vec<ProfileSpec> {
    let input = match cli_arg {
        Some(p) => p.to_string(),
        None => std::env::var("SESAME_PROFILES")
            .unwrap_or_else(|_| core_types::DEFAULT_PROFILE_NAME.into()),
    };
    parse_profile_specs(&input)
}

/// Fetch secrets from multiple profiles, merging with left-wins collision resolution.
pub(crate) async fn fetch_multi_profile_secrets(
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
}
