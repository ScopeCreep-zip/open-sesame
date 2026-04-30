//! IPC bus integration for daemon-network.
//!
//! Connects to daemon-profile's `BusServer` as a `BusClient` (Noise IK over Unix
//! socket). Requests the network identity X25519 keypair from daemon-secrets
//! via `NetworkIdentityRequest`. Emits `FederationSessionEstablished` and
//! `FederationSessionTerminated` events when network sessions are created
//! or destroyed.

use core_ipc::{BusClient, RetryConfig, noise};
use core_types::DaemonId;
use std::path::PathBuf;

/// Connect to the IPC bus as daemon-network.
///
/// Reads the bus keypair from disk (daemon-profile generates it at startup),
/// reads the bus server's public key, and connects with transparent key
/// rotation support.
///
/// # Errors
///
/// Returns an error if the bus keypair cannot be read, the bus server's
/// public key is missing, or the Noise IK handshake fails.
pub async fn connect_to_bus() -> core_types::Result<BusClient> {
    let daemon_id = DaemonId::new();

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map_or_else(|_| PathBuf::from("/run/user/1000"), PathBuf::from);
    let socket_path = runtime_dir.join("pds").join("bus.sock");

    let server_pub = noise::read_bus_public_key().await?;

    let client = BusClient::connect_daemon_with_keypair_retry(
        "daemon-network",
        daemon_id,
        &socket_path,
        &server_pub,
        vec!["network".into(), "transport".into(), "federation".into()],
        env!("CARGO_PKG_VERSION"),
        RetryConfig {
            max_attempts: 10,
            backoff: std::time::Duration::from_millis(500),
        },
    )
    .await?;

    tracing::info!("connected to IPC bus as daemon-network");
    Ok(client)
}

/// Request the network identity keypair from daemon-secrets.
///
/// Sends `NetworkIdentityRequest` on the bus and waits for
/// `NetworkIdentityResponse` with the X25519 private + public key.
///
/// Returns `None` if daemon-secrets has not yet implemented the handler
/// (the stub returns nothing / times out).
pub async fn request_network_identity(client: &mut BusClient) -> Option<(Vec<u8>, [u8; 32])> {
    use core_types::EventKind;

    let response = match client
        .request(
            EventKind::NetworkIdentityRequest,
            core_types::SecurityLevel::SecretsOnly,
            std::time::Duration::from_secs(5),
        )
        .await
    {
        Ok(msg) => msg,
        Err(e) => {
            tracing::warn!(error = %e, "NetworkIdentityRequest failed — daemon-secrets may not support it yet");
            return None;
        }
    };

    match response.payload {
        EventKind::NetworkIdentityResponse {
            private_key,
            public_key,
        } => {
            let mut pub_array = [0u8; 32];
            if public_key.len() == 32 {
                pub_array.copy_from_slice(&public_key);
                Some((private_key.as_bytes().to_vec(), pub_array))
            } else {
                tracing::error!(
                    len = public_key.len(),
                    "NetworkIdentityResponse public key wrong size"
                );
                None
            }
        }
        other => {
            tracing::warn!(event = ?other, "unexpected response to NetworkIdentityRequest");
            None
        }
    }
}

/// Request a secret from daemon-secrets via `SecretGet`.
///
/// Used to retrieve the signing seed (`_signing-seed`) stored during
/// `sesame init`. Returns the raw secret bytes, or None if the vault
/// is locked or the key does not exist.
///
/// # Panics
///
/// Panics if the hardcoded default profile name is invalid (cannot happen
/// in practice — the constant is compile-time validated).
pub async fn request_secret(client: &mut BusClient, key: &str) -> Option<Vec<u8>> {
    use core_types::{EventKind, TrustProfileName};

    let profile = TrustProfileName::try_from(core_types::DEFAULT_PROFILE_NAME)
        .expect("hardcoded valid profile name");

    let response = match client
        .request(
            EventKind::SecretGet {
                profile,
                key: key.to_string(),
            },
            core_types::SecurityLevel::SecretsOnly,
            std::time::Duration::from_secs(5),
        )
        .await
    {
        Ok(msg) => msg,
        Err(e) => {
            tracing::debug!(key = key, error = %e, "SecretGet request failed");
            return None;
        }
    };

    match response.payload {
        EventKind::SecretGetResponse {
            value,
            denial: None,
            ..
        } => Some(value.as_bytes().to_vec()),
        EventKind::SecretGetResponse {
            denial: Some(reason),
            ..
        } => {
            tracing::debug!(key = key, ?reason, "secret access denied");
            None
        }
        _ => None,
    }
}
