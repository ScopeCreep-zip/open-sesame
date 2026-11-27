//! The CLI's bus connection, request/response exchange, and multi-profile
//! secret retrieval.

use anyhow::Context;
use core_ipc::BusClient;
use core_layout::Layout;
use core_types::secret_env::{env_var_name, is_protected_env_var};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use open_sesame::cli::ProfileSpecs;
use owo_colors::OwoColorize;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::helpers::format_denial_reason;

/// How long a request waits for its response.
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect to the bus with an ephemeral keypair (the server assigns
/// `SecretsOnly` clearance to unregistered keys), stamping outbound
/// messages with the installation identity once `sesame init` has created
/// it.
///
/// # Errors
///
/// When the bus socket cannot be placed, the endpoint cannot be read
/// (daemon-profile is not running), the handshake fails, or the
/// installation file exists but cannot be read.
pub(crate) async fn connect(layout: &Layout) -> anyhow::Result<BusClient> {
    let socket_path = layout.bus_socket()?;
    let endpoint = core_ipc::noise::read_bus_endpoint(layout)
        .await
        .context("cannot read the bus endpoint; is daemon-profile running?")?;
    let client_keypair =
        core_ipc::noise::generate_keypair().context("failed to generate ephemeral keypair")?;
    let mut client = BusClient::connect_encrypted(
        DaemonId::new(),
        &socket_path,
        &endpoint,
        client_keypair.as_inner(),
    )
    .await
    .context("failed to connect to the IPC bus; is daemon-profile running?")?;
    if let Some(installation) = core_config::load_installation(layout)? {
        client.set_installation(installation.identity()?);
    }
    Ok(client)
}

/// Send `event` and wait for its correlated response.
///
/// # Errors
///
/// `core_types::Error::Timeout` (exit status 2) when no response arrives
/// within [`RPC_TIMEOUT`], the transport errors, and the bus's
/// `AccessDenied`.
pub(crate) async fn rpc(
    client: &BusClient,
    event: EventKind,
    security_level: SecurityLevel,
) -> anyhow::Result<EventKind> {
    let response = client.request(event, security_level, RPC_TIMEOUT).await?;
    if let EventKind::AccessDenied { reason } = &response.payload {
        anyhow::bail!("access denied: {reason}");
    }
    Ok(response.payload)
}

/// Environment variables built from secrets: name and value bytes, the
/// values zeroized on drop.
pub(crate) type SecretEnv = Vec<(String, Zeroizing<Vec<u8>>)>;

/// The secrets of every profile in `specs` as environment variables. A
/// name produced by more than one profile takes the first profile's value.
///
/// # Errors
///
/// The `rpc` errors, a denied secret listing, and an unexpected response.
pub(crate) async fn fetch_multi_profile_secrets(
    client: &BusClient,
    specs: &ProfileSpecs,
    prefix: Option<&str>,
) -> anyhow::Result<SecretEnv> {
    let mut merged = SecretEnv::new();
    for spec in specs {
        for (name, value) in fetch_profile_secrets(client, &spec.vault, prefix).await? {
            if merged.iter().all(|(seen, _)| *seen != name) {
                merged.push((name, value));
            }
        }
    }
    Ok(merged)
}

/// The secrets of `profile` as environment variables.
///
/// A key whose variable name is protected
/// (`core_types::secret_env::is_protected_env_var`) is skipped without
/// being fetched; a key the vault denies is reported and skipped. Both are
/// printed on stderr.
async fn fetch_profile_secrets(
    client: &BusClient,
    profile: &TrustProfileName,
    prefix: Option<&str>,
) -> anyhow::Result<SecretEnv> {
    let keys = match rpc(
        client,
        EventKind::SecretList {
            profile: profile.clone(),
        },
        SecurityLevel::SecretsOnly,
    )
    .await?
    {
        EventKind::SecretListResponse {
            denial: Some(reason),
            ..
        } => anyhow::bail!("{}", format_denial_reason(&reason, "", profile)),
        EventKind::SecretListResponse { keys, denial: None } => keys,
        other => anyhow::bail!("unexpected response to SecretList: {other:?}"),
    };
    if keys.is_empty() {
        eprintln!(
            "{}: profile '{profile}' has no secrets",
            "warning".yellow().bold()
        );
    }

    let mut env = SecretEnv::with_capacity(keys.len());
    for key in keys {
        let name = env_var_name(&key, prefix);
        if is_protected_env_var(&name) {
            eprintln!(
                "{}: secret '{key}' maps to protected variable '{name}', skipped",
                "warning".yellow().bold()
            );
            continue;
        }
        let event = EventKind::SecretGet {
            profile: profile.clone(),
            key,
        };
        match rpc(client, event, SecurityLevel::SecretsOnly).await? {
            EventKind::SecretGetResponse {
                value,
                denial: None,
                ..
            } => env.push((name, Zeroizing::new(value.as_bytes().to_vec()))),
            EventKind::SecretGetResponse {
                key,
                denial: Some(reason),
                ..
            } => eprintln!(
                "{}: {}, skipped",
                "warning".yellow().bold(),
                format_denial_reason(&reason, &key, profile)
            ),
            other => anyhow::bail!("unexpected response to SecretGet: {other:?}"),
        }
    }
    Ok(env)
}
