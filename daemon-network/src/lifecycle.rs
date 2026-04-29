//! Session lifecycle management: maintenance sweeps, keepalives, dial queue.

use crate::handshake::{self, HandshakeContext};
use crate::send;
use crate::state::DaemonState;
use std::sync::Arc;

/// Periodic maintenance: cookie rotation, `PoW` tier activation, idle session
/// cleanup, rekey sweep.
pub fn run_maintenance(state: &DaemonState) {
    if let Ok(mut c) = state.cookie.lock() {
        c.maybe_rotate();
    }

    if let Ok(mut pow) = state.pow.lock() {
        let max = state.peer_table.max_sessions();
        let current = state.peer_table.len();
        if current > max * 3 / 4 {
            pow.activate();
        } else {
            pow.deactivate();
        }
    }

    state.metrics.sessions_active.store(
        u64::from(state.peer_table.len()),
        std::sync::atomic::Ordering::Relaxed,
    );

    // TOFU pin expiry: expire stale Tofu pins whose TTL has passed.
    if let Ok(store) = state.tofu_store.lock() {
        match store.expire_stale_pins() {
            Ok(0) => {}
            Ok(n) => tracing::info!(expired = n, "expired stale TOFU pins"),
            Err(e) => tracing::warn!(error = %e, "TOFU pin expiry failed"),
        }
    }

    // Idle session cleanup: encrypt→remove→send (unconditional removal).
    let idle = state.peer_table.idle_sessions(state.idle_timeout_secs);
    for sid in &idle {
        tracing::info!(session = %sid, "closing idle session");
        send::close_session(sid, &state.peer_table, &state.udp_socket, &state.metrics);
        state.audit.append("session_idle_closed", &format!("{sid}"));
    }

    // Rekey sweep: notify peer, session stays active until replaced.
    let rekey = state.peer_table.sessions_needing_rekey(state.rekey_interval_secs);
    for sid in &rekey {
        tracing::info!(session = %sid, "sending RehandshakeRequest");
        let sid_copy = *sid;
        let table = Arc::clone(&state.peer_table);
        let socket = Arc::clone(&state.udp_socket);
        let metrics = Arc::clone(&state.metrics);
        tokio::spawn(async move {
            let _ = send::send_rehandshake_request(&sid_copy, &table, &socket, &metrics).await;
        });
        state.audit.append("rehandshake_sent", &format!("{sid}"));
    }
}

/// Send keepalive probes to sessions idle longer than half the idle timeout.
pub fn run_keepalives(state: &DaemonState) {
    let half_idle = state.idle_timeout_secs / 2;
    let candidates = state.peer_table.idle_sessions(half_idle);
    for sid in &candidates {
        let sid_copy = *sid;
        let table = Arc::clone(&state.peer_table);
        let socket = Arc::clone(&state.udp_socket);
        let metrics = Arc::clone(&state.metrics);
        tokio::spawn(async move {
            if let Err(e) = send::send_keepalive(&sid_copy, &table, &socket, &metrics).await {
                tracing::trace!(session = %sid_copy, error = %e, "keepalive failed");
            }
        });
    }
}

/// Pull vault replication entries from daemon-secrets for each active peer.
///
/// Sends a `VaultReplicationPullRequest` per active session with the
/// default profile name and the peer's last-known watermark. The response
/// (`VaultReplicationPullResponse`) is handled by the IPC dispatch handler
/// which re-encrypts and forwards to the peer.
pub async fn run_replication_pull(state: &DaemonState, default_profile: &str) {
    let sids = state.peer_table.session_ids();
    if sids.is_empty() {
        return;
    }

    for sid in &sids {
        let Some(peer) = state.peer_table.get(sid) else { continue };
        let peer_key = peer.remote_key_hex();
        drop(peer);

        // Look up the peer's installation ID from the TOFU store for
        // watermark scoping (which peer's progress are we tracking).
        let install_id = state.tofu_store.lock().ok()
            .and_then(|store| {
                store.lookup_key(&peer_key).ok()
                    .flatten()
                    .and_then(|p| p.installation_id)
            });
        let Some(peer_install_id) = install_id else {
            continue;
        };

        // Read cached watermark for this peer (if any).
        let watermark = state.replication_watermarks.lock().ok()
            .and_then(|wm| wm.get(&peer_install_id).cloned());

        let event = core_types::EventKind::VaultReplicationPullRequest {
            profile_name: default_profile.to_string(),
            peer_id: peer_install_id.clone(),
            since_watermark_json: watermark,
            max_entries: 100,
        };
        let client = state.bus_client.lock().await;
        if let Err(e) = client.publish(event, core_types::SecurityLevel::Internal).await {
            tracing::debug!(error = %e, session = %sid, "replication pull request failed");
        }
    }
}

/// Consume ready entries from the discovery dial queue and initiate handshakes.
pub fn run_dial_queue(state: &DaemonState) {
    while let Some(entry) = state.discovery.queue.pop_ready() {
        let ctx = HandshakeContext::from_state(state);
        let discovery = Arc::clone(&state.discovery);
        tokio::spawn(async move {
            let result = handshake::dial_peer(entry.addr, &ctx).await;
            match result {
                handshake::HandshakeOutcome::Established { session_id, remote_key_hex, trust_level } => {
                    tracing::info!(addr = %entry.addr, session = %session_id, key = %&remote_key_hex[..16.min(remote_key_hex.len())], ?trust_level, "dial succeeded");
                }
                handshake::HandshakeOutcome::Rejected { reason } => {
                    tracing::debug!(addr = %entry.addr, %reason, "dial failed");
                    discovery.queue.requeue_failed(entry);
                }
            }
        });
    }
}
