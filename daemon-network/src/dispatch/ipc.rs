//! IPC message dispatch: routes bus messages from daemon-profile.

use crate::handshake::{self, HandshakeContext};
use crate::send;
use crate::state::DaemonState;
use std::sync::Arc;

/// Handle an inbound IPC bus message.
#[allow(clippy::too_many_lines)]
pub async fn handle_ipc_message(
    msg: core_ipc::Message<core_types::EventKind>,
    state: &DaemonState,
) {
    use core_types::EventKind;

    let response = match &msg.payload {
        EventKind::NetworkStatusRequest => {
            let tofu_count = state.tofu_store.lock()
                .ok()
                .and_then(|s| s.list_peers().ok())
                .map_or(0, |p| p.len());

            if !state.peer_table.is_empty() {
                for sid in state.peer_table.session_ids() {
                    if let Some(peer) = state.peer_table.get(&sid) {
                        tracing::debug!(
                            session = %sid,
                            addr = %peer.remote_addr,
                            key = %&peer.remote_key_hex()[..16],
                            initiator = peer.is_initiator(),
                            age = peer.age_secs(),
                            idle = peer.idle_secs(),
                            "session status"
                        );
                    }
                }
            }

            let event_count = state.tofu_store.lock()
                .ok()
                .and_then(|s| s.event_count().ok())
                .unwrap_or(0);

            Some(EventKind::NetworkStatusResponse {
                active_sessions: state.peer_table.len(),
                #[allow(clippy::cast_possible_truncation)]
                tofu_peers: tofu_count as u32,
                #[allow(clippy::cast_possible_truncation)]
                tofu_events: event_count as u32,
                #[allow(clippy::cast_possible_truncation)]
                dial_queue_depth: state.discovery.queue_depth() as u32,
                listen_port: state.listen_port,
                enabled: true,
            })
        }
        EventKind::NetworkDialRequest { addr } => {
            match addr.parse::<std::net::SocketAddr>() {
                Ok(target) => {
                    let ctx = HandshakeContext::from_state(state);
                    let result = handshake::dial_peer(target, &ctx).await;
                    match result {
                        handshake::HandshakeOutcome::Established { session_id, remote_key_hex, .. } => {
                            tracing::info!(key = %&remote_key_hex[..16.min(remote_key_hex.len())], "dial established");
                            Some(EventKind::NetworkDialResponse {
                                success: true,
                                session_id: Some(format!("{session_id}")),
                                error: None,
                            })
                        }
                        handshake::HandshakeOutcome::Rejected { reason } => {
                            Some(EventKind::NetworkDialResponse {
                                success: false,
                                session_id: None,
                                error: Some(reason),
                            })
                        }
                    }
                }
                Err(e) => Some(EventKind::NetworkDialResponse {
                    success: false,
                    session_id: None,
                    error: Some(format!("invalid address: {e}")),
                }),
            }
        }
        EventKind::NetworkDiscoverRequest => {
            Some(EventKind::NetworkDiscoverResponse {
                mdns_peers: state.discovery.mdns_peer_count(),
                bep44_published: state.bep44_enabled && state.signing_seed.is_some(),
                dns_srv_domains: state.dns_srv_domains.clone(),
                #[allow(clippy::cast_possible_truncation)]
                dial_queue_depth: state.discovery.queue_depth() as u32,
                swim_members: 0,
            })
        }
        EventKind::VaultReplicationPullResponse { entries_json, .. } => {
            let payload = entries_json.as_bytes();
            let sids = state.peer_table.session_ids();
            for sid in &sids {
                let table = Arc::clone(&state.peer_table);
                let socket = Arc::clone(&state.udp_socket);
                let metrics = Arc::clone(&state.metrics);
                let sid = *sid;
                let data = payload.to_vec();
                tokio::spawn(async move {
                    let mut framed = vec![0x01, 0x00];
                    framed.extend_from_slice(&data);
                    let _ = send::send_data(&sid, &framed, &table, &socket, &metrics).await;
                });
            }
            None
        }
        EventKind::NetworkUnpinRequest { public_key_hex } => {
            let result = state.tofu_store.lock()
                .map_err(|e| format!("TOFU lock: {e}"))
                .and_then(|store| {
                    store.unpin(public_key_hex)
                        .map_err(|e| format!("unpin failed: {e}"))
                });
            match result {
                Ok(()) => {
                    state.audit.append("peer_unpinned", public_key_hex);
                    Some(EventKind::NetworkUnpinResponse {
                        success: true,
                        error: None,
                    })
                }
                Err(e) => Some(EventKind::NetworkUnpinResponse {
                    success: false,
                    error: Some(e),
                }),
            }
        }
        _ => None,
    };

    if let Some(event) = response {
        let client = state.bus_client.lock().await;
        if let Err(e) = client.publish(event, core_types::SecurityLevel::Internal).await {
            tracing::warn!(error = %e, "IPC response failed");
        }
    }
}
