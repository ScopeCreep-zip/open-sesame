//! TCP event dispatch: handshake spawning and post-handshake frame routing.

use crate::handshake::{self, HandshakeContext};
use crate::metrics::Metrics;
use crate::state::DaemonState;
use crate::transport;
use crate::transport::frame::WireSessionId;

/// Maximum size of a replication frame payload before UTF-8 conversion.
const MAX_REPLICATION_FRAME: usize = 256 * 1024;

/// Handle a TCP inbound event.
///
/// `NewConnection`: spawn the Noise XX responder handshake task.
/// `Frame`: forward to the appropriate session (post-handshake TCP transport).
#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
pub fn handle_tcp_event(event: transport::tcp::TcpInbound, state: &DaemonState) {
    match event {
        transport::tcp::TcpInbound::NewConnection { stream, peer_addr } => {
            if !state.global_hs_limiter.check() {
                Metrics::inc(&state.metrics.rate_limited_total);
                tracing::debug!(%peer_addr, "TCP handshake rate limited");
                drop(stream);
                return;
            }
            state.audit.append("tcp_connection", &peer_addr.to_string());

            let ctx = HandshakeContext::from_state(state);
            tokio::spawn(async move {
                let timeout = tokio::time::Duration::from_secs(10);
                let result = tokio::time::timeout(
                    timeout,
                    handshake::handle_inbound_handshake(stream, peer_addr, &ctx),
                )
                .await;

                match result {
                    Ok(handshake::HandshakeOutcome::Established {
                        session_id,
                        remote_key_hex,
                        ..
                    }) => {
                        tracing::info!(session = %session_id, %peer_addr, key = %&remote_key_hex[..16.min(remote_key_hex.len())], "handshake complete");
                    }
                    Ok(handshake::HandshakeOutcome::Rejected { reason }) => {
                        tracing::warn!(%peer_addr, %reason, "handshake rejected");
                    }
                    Err(_) => {
                        Metrics::inc(&ctx.metrics.handshake_failures_total);
                        let timeout_err = crate::noise::state::NoiseError::Timeout;
                        ctx.audit
                            .append("handshake_timeout", &peer_addr.to_string());
                        tracing::warn!(%peer_addr, error = %timeout_err, "handshake timed out");
                    }
                }
            });
        }
        transport::tcp::TcpInbound::Frame { frame, peer_addr } => {
            Metrics::inc(&state.metrics.frames_received_total);
            let sid = WireSessionId(frame.session_id.0);
            if let Some(mut peer) = state.peer_table.get_mut(&sid) {
                if let Ok(plaintext) = peer.transport.decrypt(&frame.body) {
                    #[allow(clippy::cast_possible_truncation)]
                    peer.record_productive_recv(plaintext.len() as u64);

                    let remote_key = peer.remote_key_hex();
                    drop(peer);

                    // Route VaultReplication messages to daemon-secrets.
                    if plaintext.len() > 2
                        && plaintext[0] == 0x01
                        && plaintext[1] == 0x00
                        && plaintext.len() <= MAX_REPLICATION_FRAME
                    {
                        // M-08: reject non-UTF-8 instead of silent lossy replacement.
                        let envelope = if let Ok(s) = std::str::from_utf8(&plaintext[2..]) {
                            s.to_string()
                        } else {
                            tracing::warn!(session = %sid, %peer_addr, "replication frame not valid UTF-8, dropping");
                            return;
                        };
                        let install_id = state
                            .tofu_store
                            .lock()
                            .ok()
                            .and_then(|store| store.lookup_key(&remote_key).ok().flatten())
                            .and_then(|peer| {
                                // M-07: only forward from pinned peers.
                                if peer.trust_level == core_types::TofuTrustLevel::Unpinned
                                    || peer.trust_level == core_types::TofuTrustLevel::Revoked
                                {
                                    return None;
                                }
                                peer.installation_id
                            });
                        if let Some(iid) = install_id {
                            let allowed = {
                                let mut limiters = state
                                    .replication_rate_limiter
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let limiter = limiters.entry(iid.clone()).or_insert_with(|| {
                                    governor::RateLimiter::direct(
                                        governor::Quota::per_second(
                                            std::num::NonZeroU32::new(10).unwrap(),
                                        )
                                        .allow_burst(std::num::NonZeroU32::new(50).unwrap()),
                                    )
                                });
                                limiter.check().is_ok()
                            };
                            if allowed {
                                if state
                                    .replication_inbound_tx
                                    .try_send((iid, envelope))
                                    .is_err()
                                {
                                    Metrics::inc(&state.metrics.frames_dropped_total);
                                    tracing::warn!(session = %sid, %peer_addr, "replication inbound channel full, entry dropped");
                                }
                            } else {
                                Metrics::inc(&state.metrics.rate_limited_total);
                            }
                        }
                    }

                    tracing::trace!(session = %sid, %peer_addr, len = plaintext.len(), "TCP data frame");
                } else {
                    peer.record_aead_failure();
                    Metrics::inc(&state.metrics.aead_failures_total);
                    tracing::warn!(session = %sid, %peer_addr, "TCP AEAD failure");
                }
            }
        }
    }
}
