//! Bus connection and lifecycle announcements.

use std::time::Duration;

use anyhow::Context;
use core_ipc::{BusClient, Message, RetryConfig};
use core_layout::Layout;
use core_types::{Daemon, EventKind, SecurityLevel};

/// Send `response` correlated to `request`, at the request's security
/// level. A failed send is logged: the requester's RPC then times out.
pub async fn reply(client: &BusClient, request: &Message<EventKind>, response: EventKind) {
    let response = Message::new(
        &core_ipc::MessageContext::new(client.daemon_id()),
        response,
        request.security_level,
        client.epoch(),
    )
    .with_correlation(request.msg_id);
    if let Err(e) = client.send(&response).await {
        tracing::warn!(error = %e, request = %request.msg_id, "failed to send response");
    }
}

/// A daemon on the bus: which daemon (its name is its keypair name), its
/// version, and its capabilities.
#[derive(Debug, Clone, Copy)]
pub struct DaemonIdentity {
    pub daemon: Daemon,
    pub version: &'static str,
    pub capabilities: &'static [&'static str],
}

/// Connect to the bus as `identity`, with transparent key rotation.
///
/// # Errors
///
/// When the bus endpoint cannot be read (daemon-profile is not running)
/// or every connection attempt fails.
pub async fn connect_bus(layout: &Layout, identity: &DaemonIdentity) -> anyhow::Result<BusClient> {
    let endpoint = core_ipc::noise::read_bus_endpoint(layout)
        .await
        .context("daemon-profile is not running (no bus endpoint found)")?;
    BusClient::connect_daemon_with_keypair_retry(
        layout,
        identity.daemon.name(),
        core_types::DaemonId::new(),
        &endpoint,
        capabilities(identity),
        identity.version,
        RetryConfig {
            max_attempts: 5,
            backoff: Duration::from_millis(500),
        },
    )
    .await
    .context("failed to connect to IPC bus")
}

fn capabilities(identity: &DaemonIdentity) -> Vec<String> {
    identity
        .capabilities
        .iter()
        .map(|&c| c.to_owned())
        .collect()
}

/// Announce that `identity` started.
pub async fn announce_started(client: &BusClient, identity: &DaemonIdentity) {
    client
        .publish_or_log(
            "DaemonStarted",
            EventKind::DaemonStarted {
                daemon_id: client.daemon_id(),
                version: identity.version.into(),
                capabilities: capabilities(identity),
            },
            SecurityLevel::Internal,
        )
        .await;
}

/// Announce that the daemon is stopping.
pub async fn announce_stopped(client: &BusClient) {
    client
        .publish_or_log(
            "DaemonStopped",
            EventKind::DaemonStopped {
                daemon_id: client.daemon_id(),
                reason: "shutdown".into(),
            },
            SecurityLevel::Internal,
        )
        .await;
}
