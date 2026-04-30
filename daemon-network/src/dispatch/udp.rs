//! UDP frame dispatch: routes inbound UDP datagrams by frame type.

use crate::flood;
use crate::metrics::Metrics;
use crate::session::replay::ReplayCheck;
use crate::state::DaemonState;
use crate::transport;
use crate::transport::frame::WireSessionId;
use crate::transport::udp::UdpInbound;
use core_types::FrameType;
use std::sync::Arc;

/// Maximum size of a replication frame payload before UTF-8 conversion.
const MAX_REPLICATION_FRAME: usize = 256 * 1024;

/// Dispatch an inbound UDP frame to the appropriate handler.
#[allow(clippy::too_many_lines, clippy::missing_panics_doc)]
pub fn handle_udp_frame(inbound: &UdpInbound, state: &DaemonState) {
    let frame = &inbound.frame;
    let src = inbound.src_addr;

    Metrics::inc(&state.metrics.frames_received_total);

    let Some(ft) = frame.known_frame_type() else {
        Metrics::inc(&state.metrics.frames_dropped_total);
        return;
    };

    match ft {
        FrameType::HandshakeInit => {
            handle_handshake_init(frame, src, state);
        }

        FrameType::Data | FrameType::KeepAlive => {
            let sid = WireSessionId(frame.session_id.0);
            let resolved_sid = if state.peer_table.get(&sid).is_some() {
                sid
            } else if let Some(addr_sid) = state.peer_table.lookup_addr(&src) {
                addr_sid
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            };
            if let Some(mut peer) = state.peer_table.get_mut(&resolved_sid) {
                // Step 1: Tentative replay check (read-only — no state mutation).
                match peer.replay_window.check(frame.sequence) {
                    ReplayCheck::Accept => {}
                    ReplayCheck::Duplicate | ReplayCheck::TooOld => {
                        Metrics::inc(&state.metrics.replay_detected_total);
                        return;
                    }
                }

                // Step 2: AEAD verification. This is the authentication gate —
                // no session state is mutated until the frame body is proven
                // authentic. An attacker who can observe the plaintext header
                // (session ID, sequence number) cannot forge a frame that
                // passes this check without the session's symmetric key.
                if ft == FrameType::Data {
                    match peer.transport.decrypt(&frame.body) {
                        Ok(plaintext) => {
                            // Step 3: Commit replay window (AEAD proved authenticity).
                            peer.replay_window.accept(frame.sequence);
                            #[allow(clippy::cast_possible_truncation)]
                            peer.record_productive_recv(plaintext.len() as u64);

                            // Step 4: Path migration (only after AEAD success).
                            if peer.remote_addr == src {
                                drop(peer);
                            } else {
                                tracing::info!(session = %sid, old = %peer.remote_addr, new = %src, "path migration");
                                let old_addr = peer.remote_addr;
                                drop(peer);
                                state.peer_table.update_addr(&sid, &old_addr, src);
                                state
                                    .audit
                                    .append("path_migration", &format!("{sid} {src}"));
                            }

                            // Step 5: Route application-layer messages.
                            // VaultReplication: [0x01, 0x00] prefix → forward to daemon-secrets.
                            if plaintext.len() > 2
                                && plaintext[0] == 0x01
                                && plaintext[1] == 0x00
                                && plaintext.len() <= MAX_REPLICATION_FRAME
                            {
                                // M-08: reject non-UTF-8 instead of silent lossy replacement.
                                let envelope = if let Ok(s) = std::str::from_utf8(&plaintext[2..]) {
                                    s.to_string()
                                } else {
                                    tracing::warn!(session = %sid, "replication frame not valid UTF-8, dropping");
                                    return;
                                };
                                // Look up peer for rate limiting (E-02) and pin check (M-07).
                                let remote_key = state
                                    .peer_table
                                    .get(&resolved_sid)
                                    .map(|p| p.remote_key_hex());
                                let install_id = remote_key.and_then(|key_hex| {
                                    state
                                        .tofu_store
                                        .lock()
                                        .ok()
                                        .and_then(|store| store.lookup_key(&key_hex).ok().flatten())
                                        .and_then(|peer| {
                                            // M-07: only forward from pinned peers.
                                            if peer.trust_level
                                                == core_types::TofuTrustLevel::Unpinned
                                                || peer.trust_level
                                                    == core_types::TofuTrustLevel::Revoked
                                            {
                                                return None;
                                            }
                                            peer.installation_id
                                        })
                                });
                                if let Some(iid) = install_id {
                                    // Per-installation rate limit check.
                                    let allowed = {
                                        let mut limiters = state
                                            .replication_rate_limiter
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                                        let limiter =
                                            limiters.entry(iid.clone()).or_insert_with(|| {
                                                governor::RateLimiter::direct(
                                                    governor::Quota::per_second(
                                                        std::num::NonZeroU32::new(10).unwrap(),
                                                    )
                                                    .allow_burst(
                                                        std::num::NonZeroU32::new(50).unwrap(),
                                                    ),
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
                                            tracing::warn!(session = %sid, "replication inbound channel full, entry dropped");
                                        }
                                    } else {
                                        Metrics::inc(&state.metrics.rate_limited_total);
                                        tracing::debug!(session = %sid, "replication entry rate-limited");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // AEAD failed — do NOT commit replay window or
                            // update address. The frame is unauthenticated.
                            peer.record_aead_failure();
                            Metrics::inc(&state.metrics.aead_failures_total);
                            tracing::warn!(session = %sid, %src, error = %e, "AEAD failure");
                            state.audit.append("aead_failure", &format!("{sid} {src}"));
                        }
                    }
                } else {
                    // KeepAlive: empty body, still AEAD-sealed.
                    match peer.transport.decrypt(&frame.body) {
                        Ok(_) => {
                            peer.replay_window.accept(frame.sequence);
                            peer.record_recv(0);
                            if peer.remote_addr != src {
                                tracing::info!(session = %sid, old = %peer.remote_addr, new = %src, "path migration");
                                let old_addr = peer.remote_addr;
                                drop(peer);
                                state.peer_table.update_addr(&sid, &old_addr, src);
                                state
                                    .audit
                                    .append("path_migration", &format!("{sid} {src}"));
                            }
                        }
                        Err(e) => {
                            peer.record_aead_failure();
                            Metrics::inc(&state.metrics.aead_failures_total);
                            tracing::warn!(session = %sid, %src, error = %e, "KeepAlive AEAD failure");
                        }
                    }
                }
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
            }
        }

        // Close and RehandshakeRequest must also be AEAD-verified before
        // acting on them. Without AEAD, an attacker who observes the
        // 12-byte session ID in the plaintext header can forge a Close
        // frame and tear down any session.
        FrameType::Close => {
            let sid = WireSessionId(frame.session_id.0);
            if let Some(mut peer) = state.peer_table.get_mut(&sid) {
                match peer.transport.decrypt(&frame.body) {
                    Ok(_) => {
                        drop(peer);
                        state.peer_table.remove(&sid);
                        Metrics::inc(&state.metrics.sessions_closed_total);
                        tracing::info!(session = %sid, %src, "session closed by peer (AEAD verified)");
                        state
                            .audit
                            .append("session_closed", &format!("{sid} {src}"));
                    }
                    Err(e) => {
                        peer.record_aead_failure();
                        Metrics::inc(&state.metrics.aead_failures_total);
                        tracing::warn!(session = %sid, %src, error = %e, "spoofed Close frame rejected");
                        state
                            .audit
                            .append("spoofed_close_rejected", &format!("{sid} {src}"));
                    }
                }
            }
        }

        FrameType::RehandshakeRequest => {
            let sid = WireSessionId(frame.session_id.0);
            if let Some(mut peer) = state.peer_table.get_mut(&sid) {
                match peer.transport.decrypt(&frame.body) {
                    Ok(_) => {
                        drop(peer);
                        state.peer_table.remove(&sid);
                        tracing::info!(session = %sid, "rehandshake requested (AEAD verified)");
                        state
                            .audit
                            .append("rehandshake_requested", &format!("{sid}"));
                    }
                    Err(e) => {
                        peer.record_aead_failure();
                        Metrics::inc(&state.metrics.aead_failures_total);
                        tracing::warn!(session = %sid, %src, error = %e, "spoofed RehandshakeRequest rejected");
                    }
                }
            }
        }

        FrameType::CookieResponse => {
            handle_cookie_response(frame, src, state);
        }

        _ => {
            Metrics::inc(&state.metrics.frames_dropped_total);
        }
    }
}

/// Handle a `HandshakeInit` knock: respond with cookie or `PoW` challenge.
fn handle_handshake_init(
    frame: &transport::frame::Frame,
    src: std::net::SocketAddr,
    state: &DaemonState,
) {
    let pow_active = state.pow.lock().ok().is_some_and(|p| p.is_active());

    if pow_active {
        let cookie_secret = state.cookie.lock().ok().and_then(|c| c.generate(&src));
        let Some(cookie_secret) = cookie_secret else {
            Metrics::inc(&state.metrics.frames_dropped_total);
            return;
        };
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seed =
            flood::pow::PowChallenger::generate_seed(&cookie_secret, epoch, &src.to_string());
        let mut body = vec![0x01u8];
        body.extend_from_slice(&epoch.to_be_bytes());
        body.extend_from_slice(&seed);
        let resp =
            transport::frame::Frame::new(FrameType::CookieRequest as u8, frame.session_id, 0, body);
        let socket = Arc::clone(&state.udp_socket);
        tokio::spawn(async move {
            let _ = transport::udp::udp_send(&socket, &resp, &src).await;
        });
        Metrics::inc(&state.metrics.cookie_challenges_total);
        state.audit.append("pow_challenge_sent", &src.to_string());
    } else if let Ok(challenger) = state.cookie.lock() {
        let Some(cookie) = challenger.generate(&src) else {
            Metrics::inc(&state.metrics.frames_dropped_total);
            return;
        };
        let mut body = vec![0x00u8];
        body.extend_from_slice(&cookie);
        let resp =
            transport::frame::Frame::new(FrameType::CookieRequest as u8, frame.session_id, 0, body);
        let socket = Arc::clone(&state.udp_socket);
        tokio::spawn(async move {
            let _ = transport::udp::udp_send(&socket, &resp, &src).await;
        });
        Metrics::inc(&state.metrics.cookie_challenges_total);
    }
    tracing::debug!(%src, pow = pow_active, "HandshakeInit knock — challenge sent");
    state.audit.append("handshake_init_udp", &src.to_string());
}

/// Validate a `CookieResponse` frame body.
///
/// # Panics
///
/// Panics if a 24-byte `PoW` payload has an epoch slice that fails `try_into`
/// for `[u8; 8]` — this cannot happen because the length is checked first.
pub fn handle_cookie_response(
    frame: &transport::frame::Frame,
    src: std::net::SocketAddr,
    state: &DaemonState,
) {
    if frame.body.is_empty() {
        Metrics::inc(&state.metrics.frames_dropped_total);
        return;
    }

    let type_byte = frame.body[0];
    let payload = &frame.body[1..];

    match type_byte {
        0x00 => {
            if payload.len() != 32 {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            }
            let mut cookie = [0u8; 32];
            cookie.copy_from_slice(payload);
            let Ok(challenger) = state.cookie.lock() else {
                return;
            };
            if challenger.verify(&src, &cookie) {
                Metrics::inc(&state.metrics.cookie_challenges_total);
                state.audit.append("cookie_validated", &src.to_string());
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
            }
        }
        0x01 => {
            if payload.len() != 24 {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            }
            let epoch = u64::from_be_bytes(payload[..8].try_into().unwrap());
            let solution_bytes = &payload[8..24];
            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if epoch > now_epoch || now_epoch.saturating_sub(epoch) > 300 {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            }
            let cookie_secret = state.cookie.lock().ok().and_then(|c| c.generate(&src));
            let Some(cookie_secret) = cookie_secret else {
                Metrics::inc(&state.metrics.frames_dropped_total);
                return;
            };
            let seed =
                flood::pow::PowChallenger::generate_seed(&cookie_secret, epoch, &src.to_string());
            let solution: equix::SolutionByteArray = solution_bytes.try_into().unwrap_or([0u8; 16]);
            if flood::pow::PowChallenger::verify_solution(&seed, &solution) {
                Metrics::inc(&state.metrics.cookie_challenges_total);
                state.audit.append("pow_validated", &src.to_string());
                tracing::debug!(%src, "PoW solution verified");
            } else {
                Metrics::inc(&state.metrics.frames_dropped_total);
                state.audit.append("pow_invalid", &src.to_string());
            }
        }
        _ => {
            Metrics::inc(&state.metrics.frames_dropped_total);
        }
    }
}
