//! Discovery event dispatch: immediate dial on `PeerDiscovered`, session
//! teardown on `PeerRemoved`.

use crate::handshake::{self, HandshakeContext};
use crate::state::DaemonState;
use std::sync::Arc;

/// Handle a discovery event from the `DiscoveryManager` event channel.
pub fn handle_discovery_event(
    event: daemon_discovery::manager::DiscoveryEvent,
    state: &DaemonState,
) {
    match event {
        daemon_discovery::manager::DiscoveryEvent::PeerDiscovered {
            addr,
            source,
            advisory_pubkey_hex,
        } => {
            if state.peer_table.lookup_addr(&addr).is_some() {
                tracing::trace!(%addr, ?source, "discovery: already connected, skipping");
                return;
            }
            tracing::info!(%addr, ?source, key = ?advisory_pubkey_hex.as_deref().map(|k| &k[..16.min(k.len())]), "discovery: immediate dial");
            state.audit.append("discovery_peer_found", &format!("{addr} {source:?}"));

            // Two-tier dial pattern: this spawns an immediate dial attempt.
            // On failure, the entry is requeued into the `DialQueue` with 30s
            // backoff and `consecutive_failures=1`. The main event loop's
            // `run_dial_queue` (5s tick) picks up requeued entries for retry,
            // so the immediate path handles the fast case and the queue
            // handles persistence + exponential backoff.
            let ctx = HandshakeContext::from_state(state);
            let discovery = Arc::clone(&state.discovery);
            tokio::spawn(async move {
                let result = handshake::dial_peer(addr, &ctx).await;
                match result {
                    handshake::HandshakeOutcome::Established { session_id, remote_key_hex, trust_level } => {
                        tracing::info!(%addr, session = %session_id, key = %&remote_key_hex[..16.min(remote_key_hex.len())], ?trust_level, "discovery dial succeeded");
                    }
                    handshake::HandshakeOutcome::Rejected { reason } => {
                        tracing::debug!(%addr, %reason, "discovery dial failed — requeueing");
                        let entry = daemon_discovery::queue::DialEntry {
                            addr,
                            source,
                            advisory_pubkey_hex,
                            next_dial_at: std::time::Instant::now() + std::time::Duration::from_secs(30),
                            consecutive_failures: 1,
                        };
                        discovery.queue.push(entry);
                    }
                }
            });
        }
        daemon_discovery::manager::DiscoveryEvent::PeerRemoved { addr, source } => {
            state.audit.append("discovery_peer_removed", &format!("{addr} {source:?}"));

            // Remove from the dial queue only — do NOT tear down active
            // sessions. All discovery backends are unauthenticated (mDNS
            // multicast, SWIM raw UDP, DNS SRV). An attacker on the network
            // can forge a PeerRemoved event by sending a spoofed mDNS goodbye
            // or SWIM MemberDown. Tearing down an authenticated Noise session
            // based on unauthenticated discovery input would allow a one-packet
            // session kill from any LAN device.
            //
            // Active sessions are terminated only through:
            // - Authenticated Close frame (AEAD-verified)
            // - Idle timeout (maintenance sweep)
            // - Rekey sweep (RehandshakeRequest)
            // - Operator action (sesame network peers --unpin)
            state.discovery.queue.remove(&addr);
            tracing::info!(%addr, ?source, "discovery: peer removed from dial queue");
        }
    }
}
