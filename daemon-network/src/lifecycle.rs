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
