//! Handshake orchestration: composes Noise XX/`IKpsk2`, TOFU verification,
//! `HandshakeAck` exchange, PSK derivation, session creation, and audit logging.

use crate::audit::AuditLog;
use crate::handshake_ack;

/// TOFU pin TTL for first-contact peers (24 hours).
const TOFU_PIN_TTL_SECS: u64 = 86_400;
use crate::metrics::Metrics;
use crate::noise::state::{self, NoiseTransport, derive_psk_from_handshake};
use crate::session::state::PeerState;
use crate::session::table::PeerTable;
use crate::tofu::store::TofuStore;
use crate::transport::frame::WireSessionId;
use core_types::TofuTrustLevel;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

/// Result of a completed handshake.
pub enum HandshakeOutcome {
    Established {
        session_id: WireSessionId,
        remote_key_hex: String,
        trust_level: TofuTrustLevel,
    },
    Rejected {
        reason: String,
    },
}

/// Owned handshake context. `Send + 'static` — safe to pass to `tokio::spawn`.
///
/// Constructed via [`HandshakeContext::from_state`] which clones the `Arc`s
/// and copies the scalar fields. All handshake functions borrow from this.
pub struct HandshakeContext {
    pub local_keypair: Arc<snow::Keypair>,
    pub tofu_store: Arc<std::sync::Mutex<TofuStore>>,
    pub peer_table: Arc<PeerTable>,
    pub bus_client: Arc<tokio::sync::Mutex<core_ipc::BusClient>>,
    pub metrics: Arc<Metrics>,
    pub audit: Arc<AuditLog>,
    pub signing_seed: Option<[u8; 32]>,
    pub installation_id: String,
    pub network_pubkey: [u8; 32],
    pub signing_pubkey: Option<[u8; 32]>,
    pub udp_socket: Arc<tokio::net::UdpSocket>,
    pub tcp_tx: tokio::sync::mpsc::Sender<crate::transport::tcp::TcpInbound>,
    /// If true, reject first-contact TOFU pins from unknown peers.
    pub require_known_peers: bool,
}

impl HandshakeContext {
    /// Build from `DaemonState`. Clones `Arc`s (cheap atomic increment),
    /// copies scalars, clones the installation ID string.
    #[must_use]
    pub fn from_state(state: &crate::state::DaemonState) -> Self {
        Self {
            local_keypair: Arc::clone(&state.local_keypair),
            tofu_store: Arc::clone(&state.tofu_store),
            peer_table: Arc::clone(&state.peer_table),
            bus_client: Arc::clone(&state.bus_client),
            metrics: Arc::clone(&state.metrics),
            audit: Arc::clone(&state.audit),
            signing_seed: state.signing_seed.as_deref().copied(),
            installation_id: state.identity.id.clone(),
            network_pubkey: state.identity.network_pubkey,
            signing_pubkey: state.identity.signing_pubkey,
            udp_socket: Arc::clone(&state.udp_socket),
            tcp_tx: state.tcp_tx.clone(),
            require_known_peers: state.require_known_peers,
        }
    }
}

/// Run the responder-side handshake on an inbound TCP connection.
#[allow(clippy::too_many_lines)]
pub async fn handle_inbound_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    ctx: &HandshakeContext,
) -> HandshakeOutcome {
    use tokio::io::AsyncReadExt;
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Step 1: Read pattern discriminant byte.
    // 0x01 = Noise XX (first contact), 0x02 = Noise IKpsk2 (reconnection).
    let mut pattern_byte = [0u8; 1];
    if reader.read_exact(&mut pattern_byte).await.is_err() {
        Metrics::inc(&ctx.metrics.handshake_failures_total);
        return HandshakeOutcome::Rejected {
            reason: "failed to read pattern discriminant".into(),
        };
    }

    let mut transport = match pattern_byte[0] {
        0x02 => {
            // IKpsk2 responder: peer is reconnecting with cached PSK.
            let psk = ctx
                .tofu_store
                .lock()
                .ok()
                .and_then(|store| {
                    // We don't know the peer's key yet — look up by address.
                    let peer = store.lookup_addr(&peer_addr.to_string()).ok()??;
                    store.get_psk(&peer.public_key_hex).ok()?
                })
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());

            if let Some(psk) = psk {
                match state::ikpsk2_responder(&mut reader, &mut writer, &ctx.local_keypair, &psk)
                    .await
                {
                    Ok(t) => {
                        ctx.audit
                            .append("ikpsk2_responder_ok", &peer_addr.to_string());
                        t
                    }
                    Err(e) => {
                        Metrics::inc(&ctx.metrics.handshake_failures_total);
                        ctx.audit
                            .append("ikpsk2_responder_failed", &format!("{peer_addr} {e}"));
                        return HandshakeOutcome::Rejected {
                            reason: format!("IKpsk2 responder failed: {e}"),
                        };
                    }
                }
            } else {
                Metrics::inc(&ctx.metrics.handshake_failures_total);
                return HandshakeOutcome::Rejected {
                    reason: "IKpsk2 requested but no cached PSK for this peer".into(),
                };
            }
        }
        _ => {
            // 0x01 or any other byte: XX handshake (default).
            match state::xx_responder(&mut reader, &mut writer, &ctx.local_keypair).await {
                Ok(t) => t,
                Err(e) => {
                    Metrics::inc(&ctx.metrics.handshake_failures_total);
                    ctx.audit
                        .append("handshake_failed", &format!("{peer_addr} {e}"));
                    return HandshakeOutcome::Rejected {
                        reason: format!("Noise XX failed: {e}"),
                    };
                }
            }
        }
    };

    // Step 2: TOFU check.
    let Some(remote_static) = transport.remote_static() else {
        Metrics::inc(&ctx.metrics.handshake_failures_total);
        ctx.audit
            .append("handshake_failed", &format!("{peer_addr} no remote static"));
        return HandshakeOutcome::Rejected {
            reason: "no remote static key after handshake".into(),
        };
    };

    let remote_key_hex = hex::encode(remote_static);
    let trust_level = match run_tofu_check(
        &remote_key_hex,
        &peer_addr.to_string(),
        &ctx.tofu_store,
        &ctx.metrics,
        &ctx.audit,
        ctx.require_known_peers,
    ) {
        Ok(level) => level,
        Err(reason) => return HandshakeOutcome::Rejected { reason },
    };

    // Step 3: HandshakeAck exchange over the TCP stream (5s timeout).
    // Returns (installation_id, signing_pubkey_hex) on success.
    let peer_ack_info = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        exchange_handshake_ack(
            &mut transport,
            &mut reader,
            &mut writer,
            &remote_static,
            ctx,
            false,
        ),
    )
    .await
    .unwrap_or_else(|_| {
        tracing::warn!(%peer_addr, "HandshakeAck exchange timed out");
        None
    });

    // Step 4: PSK derivation, caching, and installation identity write-back.
    let psk = derive_psk_from_handshake(&transport.handshake_hash());
    let (peer_install_id, peer_signing_pubkey) = match &peer_ack_info {
        Some((iid, spk)) => (Some(iid.as_str()), Some(spk.as_str())),
        None => (None, None),
    };
    if let Ok(store) = ctx.tofu_store.lock() {
        let _ = store.store_psk(&remote_key_hex, &psk);
        if let Some(iid) = peer_install_id {
            if let Err(e) = store.set_installation_identity(
                &remote_key_hex,
                iid,
                None,
                peer_signing_pubkey,
            ) {
                tracing::warn!(
                    audit = "security",
                    error = %e,
                    peer = %&remote_key_hex[..16],
                    "signing key mismatch on reconnection — possible compromise"
                );
                ctx.audit.append(
                    "signing_key_mismatch",
                    &format!("{} {}", &remote_key_hex[..16], e),
                );
            }
        }
    }

    // Step 5: Session creation.
    let session_id = WireSessionId::random();
    let peer_state = PeerState::new(session_id, remote_static, peer_addr, transport, trust_level);

    if !ctx.peer_table.insert(peer_state) {
        Metrics::inc(&ctx.metrics.sessions_rejected_full);
        ctx.audit.append(
            "session_rejected_full",
            &format!("{peer_addr} {remote_key_hex}"),
        );
        return HandshakeOutcome::Rejected {
            reason: "session table full".into(),
        };
    }

    // Step 6: Spawn TCP read loop for post-handshake frame reception.
    let tcp_tx = ctx.tcp_tx.clone();
    tokio::spawn(async move {
        crate::transport::tcp::tcp_read_loop(
            reader,
            peer_addr,
            tcp_tx,
            std::time::Duration::from_mins(5),
        )
        .await;
    });

    // Step 7: IPC notification.
    let remote_uuid = peer_install_id
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .unwrap_or_else(uuid::Uuid::nil);
    emit_session_established(&ctx.bus_client, &session_id, &remote_static, remote_uuid).await;

    Metrics::inc(&ctx.metrics.sessions_established_total);
    ctx.audit.append(
        "session_established",
        &format!("{session_id} {peer_addr} {remote_key_hex} {trust_level:?}"),
    );
    tracing::info!(
        session = %session_id, %peer_addr,
        key = %&remote_key_hex[..16], ?trust_level,
        "session established"
    );

    HandshakeOutcome::Established {
        session_id,
        remote_key_hex,
        trust_level,
    }
}

/// Run the initiator-side handshake to dial a remote peer.
///
/// Attempts `IKpsk2` reconnection if the TOFU store has a cached PSK.
/// Falls back to XX for first contact or PSK mismatch.
pub async fn dial_peer(addr: SocketAddr, ctx: &HandshakeContext) -> HandshakeOutcome {
    // Step 0: UDP knock — prove source address ownership before TCP connect.
    // The responder sends a cookie or PoW challenge; we solve and respond.
    // Failure is non-fatal: if the responder doesn't support knocks (e.g.,
    // direct TCP connect), we proceed anyway. The responder's TCP accept
    // path has its own rate limiter as a fallback.
    if let Err(e) = udp_knock_exchange(addr, ctx).await {
        tracing::debug!(%addr, error = %e, "UDP knock failed, proceeding to TCP");
    }

    let stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            Metrics::inc(&ctx.metrics.handshake_failures_total);
            ctx.audit.append("dial_failed", &format!("{addr} {e}"));
            return HandshakeOutcome::Rejected {
                reason: format!("TCP connect failed: {e}"),
            };
        }
    };

    // Handshake + acquire TCP halves that survive the branch for HandshakeAck.
    // Each branch returns (transport, reader, writer) so the ack exchange has I/O.
    let handshake_result = dial_handshake(stream, addr, ctx).await;
    let (mut transport, mut reader, mut writer) = match handshake_result {
        Ok(triple) => triple,
        Err(outcome) => return outcome,
    };

    let Some(remote_static) = transport.remote_static() else {
        Metrics::inc(&ctx.metrics.handshake_failures_total);
        return HandshakeOutcome::Rejected {
            reason: "no remote static key".into(),
        };
    };

    let remote_key_hex = hex::encode(remote_static);
    let trust_level = match run_tofu_check(
        &remote_key_hex,
        &addr.to_string(),
        &ctx.tofu_store,
        &ctx.metrics,
        &ctx.audit,
        ctx.require_known_peers,
    ) {
        Ok(level) => level,
        Err(reason) => return HandshakeOutcome::Rejected { reason },
    };

    // HandshakeAck exchange over TCP. Initiator sends first.
    let peer_ack_info = exchange_handshake_ack(
        &mut transport,
        &mut reader,
        &mut writer,
        &remote_static,
        ctx,
        true,
    )
    .await;

    // Cache PSK and persist installation identity from verified HandshakeAck.
    let psk = derive_psk_from_handshake(&transport.handshake_hash());
    let (peer_install_id, peer_signing_pubkey) = match &peer_ack_info {
        Some((iid, spk)) => (Some(iid.as_str()), Some(spk.as_str())),
        None => (None, None),
    };
    if let Ok(store) = ctx.tofu_store.lock() {
        let _ = store.store_psk(&remote_key_hex, &psk);
        if let Some(iid) = peer_install_id {
            if let Err(e) = store.set_installation_identity(
                &remote_key_hex,
                iid,
                None,
                peer_signing_pubkey,
            ) {
                tracing::warn!(
                    audit = "security",
                    error = %e,
                    peer = %&remote_key_hex[..16],
                    "signing key mismatch on reconnection — possible compromise"
                );
                ctx.audit.append(
                    "signing_key_mismatch",
                    &format!("{} {}", &remote_key_hex[..16], e),
                );
            }
        }
    }

    let session_id = WireSessionId::random();
    let peer_state = PeerState::new(session_id, remote_static, addr, transport, trust_level);

    if !ctx.peer_table.insert(peer_state) {
        Metrics::inc(&ctx.metrics.sessions_rejected_full);
        return HandshakeOutcome::Rejected {
            reason: "session table full".into(),
        };
    }

    let remote_uuid = peer_install_id
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .unwrap_or_else(uuid::Uuid::nil);
    emit_session_established(&ctx.bus_client, &session_id, &remote_static, remote_uuid).await;

    Metrics::inc(&ctx.metrics.sessions_established_total);
    ctx.audit.append(
        "session_established",
        &format!("{session_id} {addr} {remote_key_hex} {trust_level:?}"),
    );
    tracing::info!(
        session = %session_id, %addr,
        key = %&remote_key_hex[..16], ?trust_level,
        "outbound session established"
    );

    HandshakeOutcome::Established {
        session_id,
        remote_key_hex,
        trust_level,
    }
}

// ---------------------------------------------------------------------------
// UDP knock exchange (cookie/PoW proof-of-address before TCP connect)
// ---------------------------------------------------------------------------

/// Send a UDP `HandshakeInit` knock and process the `CookieRequest` response.
///
/// The responder replies with a `CookieRequest` containing either a cookie
/// (type 0x00) or a `PoW` challenge seed (type 0x01). This function solves
/// the challenge and sends a `CookieResponse`, proving source address ownership
/// before the TCP connection is established.
///
/// Returns `Ok(())` on success (cookie/PoW verified by responder),
/// `Err(reason)` if the knock times out or the `PoW` is unsolvable.
async fn udp_knock_exchange(addr: SocketAddr, ctx: &HandshakeContext) -> Result<(), String> {
    use crate::transport::frame::{Frame, HEADER_SIZE, WireSessionId};
    use crate::transport::udp;

    // Send HandshakeInit knock via UDP.
    let knock = Frame::new(
        core_types::FrameType::HandshakeInit as u8,
        WireSessionId::zero(),
        0,
        vec![],
    );
    udp::udp_send(&ctx.udp_socket, &knock, &addr)
        .await
        .map_err(|e| format!("UDP knock send: {e}"))?;

    // Receive CookieRequest response (2s timeout).
    let mut buf = vec![0u8; 1280];
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ctx.udp_socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "UDP knock timeout — no CookieRequest received".to_string())?
    .map_err(|e| format!("UDP recv: {e}"))?;

    let (len, _src) = response;
    if len < HEADER_SIZE {
        return Err("CookieRequest too short".into());
    }

    let Some(frame) = Frame::parse(&buf[..len]) else {
        return Err("CookieRequest parse failed".into());
    };

    if frame.frame_type != core_types::FrameType::CookieRequest as u8 {
        return Err(format!(
            "expected CookieRequest, got frame type {}",
            frame.frame_type
        ));
    }

    if frame.body.is_empty() {
        return Err("CookieRequest body empty".into());
    }

    let type_byte = frame.body[0];
    let payload = &frame.body[1..];

    let response_body = match type_byte {
        0x00 => {
            // Cookie echo — send it back.
            if payload.len() != 32 {
                return Err("cookie wrong size".into());
            }
            let mut body = vec![0x00u8];
            body.extend_from_slice(payload);
            body
        }
        0x01 => {
            // PoW challenge: [8-byte epoch][32-byte seed]
            if payload.len() != 40 {
                return Err("PoW challenge wrong size (expected 40 bytes)".into());
            }
            let epoch_bytes = &payload[..8];
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&payload[8..40]);
            let solution = crate::flood::pow::PowChallenger::solve(&seed)
                .ok_or("PoW unsolvable for this seed (~1.4% chance, retry)")?;
            let mut body = vec![0x01u8];
            body.extend_from_slice(epoch_bytes); // echo epoch back for verification
            body.extend_from_slice(&solution);
            body
        }
        other => return Err(format!("unknown CookieRequest type {other}")),
    };

    // Send CookieResponse.
    let resp = Frame::new(
        core_types::FrameType::CookieResponse as u8,
        frame.session_id,
        0,
        response_body,
    );
    udp::udp_send(&ctx.udp_socket, &resp, &addr)
        .await
        .map_err(|e| format!("CookieResponse send: {e}"))?;

    ctx.audit.append("knock_completed", &addr.to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// Dial handshake helper (`IKpsk2` with XX fallback)
// ---------------------------------------------------------------------------

/// Perform the Noise handshake for an outbound dial, returning the transport
/// and the TCP stream halves for subsequent `HandshakeAck` exchange.
///
/// Attempts `IKpsk2` if the TOFU store has cached material for this address.
/// Falls back to XX on `IKpsk2` failure or first contact.
#[allow(clippy::type_complexity)]
async fn dial_handshake(
    stream: TcpStream,
    addr: SocketAddr,
    ctx: &HandshakeContext,
) -> Result<
    (
        NoiseTransport,
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
    ),
    HandshakeOutcome,
> {
    use tokio::io::AsyncWriteExt;
    let (mut reader, mut writer) = tokio::io::split(stream);

    let ikpsk2_material = ctx.tofu_store.lock().ok().and_then(|store| {
        let peer = store.lookup_addr(&addr.to_string()).ok()??;
        if peer.trust_level == TofuTrustLevel::Revoked {
            return None;
        }
        let psk_bytes = store.get_psk(&peer.public_key_hex).ok()??;
        if psk_bytes.len() != 32 {
            return None;
        }
        let key_bytes = hex::decode(&peer.public_key_hex).ok()?;
        if key_bytes.len() != 32 {
            return None;
        }
        let mut psk = [0u8; 32];
        psk.copy_from_slice(&psk_bytes);
        let mut remote_static = [0u8; 32];
        remote_static.copy_from_slice(&key_bytes);
        Some((remote_static, psk))
    });

    if let Some((remote_static, psk)) = ikpsk2_material {
        // Send IKpsk2 pattern discriminant (0x02).
        writer.write_all(&[0x02]).await.map_err(|e| {
            Metrics::inc(&ctx.metrics.handshake_failures_total);
            HandshakeOutcome::Rejected {
                reason: format!("pattern byte write: {e}"),
            }
        })?;
        match state::ikpsk2_initiator(
            &mut reader,
            &mut writer,
            &ctx.local_keypair,
            &remote_static,
            &psk,
        )
        .await
        {
            Ok(t) => {
                tracing::info!(%addr, "IKpsk2 reconnection succeeded");
                ctx.audit.append("ikpsk2_reconnection", &addr.to_string());
                return Ok((t, reader, writer));
            }
            Err(e) => {
                tracing::info!(%addr, error = %e, "IKpsk2 failed, falling back to XX");
                ctx.audit
                    .append("ikpsk2_fallback_xx", &format!("{addr} {e}"));
                // Reconnect with a fresh TCP stream for XX.
                let stream2 = TcpStream::connect(addr).await.map_err(|e2| {
                    Metrics::inc(&ctx.metrics.handshake_failures_total);
                    HandshakeOutcome::Rejected {
                        reason: format!("TCP reconnect for XX fallback: {e2}"),
                    }
                })?;
                let (mut r2, mut w2) = tokio::io::split(stream2);
                // Send XX pattern discriminant (0x01) on the fresh connection.
                w2.write_all(&[0x01])
                    .await
                    .map_err(|e3| HandshakeOutcome::Rejected {
                        reason: format!("pattern byte: {e3}"),
                    })?;
                let t = state::xx_initiator(&mut r2, &mut w2, &ctx.local_keypair)
                    .await
                    .map_err(|e2| {
                        Metrics::inc(&ctx.metrics.handshake_failures_total);
                        ctx.audit.append("dial_xx_failed", &format!("{addr} {e2}"));
                        HandshakeOutcome::Rejected {
                            reason: format!("Noise XX fallback: {e2}"),
                        }
                    })?;
                return Ok((t, r2, w2));
            }
        }
    }

    // No cached material — first contact via XX.
    // Send XX pattern discriminant (0x01).
    writer.write_all(&[0x01]).await.map_err(|e| {
        Metrics::inc(&ctx.metrics.handshake_failures_total);
        HandshakeOutcome::Rejected {
            reason: format!("pattern byte write: {e}"),
        }
    })?;
    let t = state::xx_initiator(&mut reader, &mut writer, &ctx.local_keypair)
        .await
        .map_err(|e| {
            Metrics::inc(&ctx.metrics.handshake_failures_total);
            ctx.audit.append("dial_xx_failed", &format!("{addr} {e}"));
            HandshakeOutcome::Rejected {
                reason: format!("Noise XX: {e}"),
            }
        })?;
    Ok((t, reader, writer))
}

// ---------------------------------------------------------------------------
// HandshakeAck exchange
// ---------------------------------------------------------------------------

/// Exchange `HandshakeAck` over the Noise transport via the TCP stream.
///
/// Protocol: initiator sends first, then reads. Responder reads first, then sends.
/// Both sides encrypt/decrypt through the `NoiseTransport`. The TCP stream carries
/// length-prefixed ciphertext: `[4-byte BE length][ciphertext bytes]`.
///
/// Returns `(installation_id, signing_pubkey_hex)` on success, `None` on
/// any failure (signing seed unavailable, I/O error, verification failure).
async fn exchange_handshake_ack<R, W>(
    transport: &mut NoiseTransport,
    reader: &mut R,
    writer: &mut W,
    remote_static: &[u8; 32],
    ctx: &HandshakeContext,
    is_initiator: bool,
) -> Option<(String, String)>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let seed = ctx.signing_seed?;
    let signing_pubkey = ctx.signing_pubkey?;

    // Derive signing key from seed (on demand, dropped after use).
    let seed_secure = core_crypto::SecureBytes::from_slice(&seed);
    let install_uuid = uuid::Uuid::parse_str(&ctx.installation_id).ok()?;
    let signing_key =
        core_crypto::network::derive_signing_keypair(&seed_secure, &install_uuid).ok()?;

    let our_ack = handshake_ack::build_handshake_ack(
        &ctx.installation_id,
        None,
        &ctx.network_pubkey,
        &signing_pubkey,
        state::NOISE_XX,
        &signing_key,
    );
    drop(signing_key);

    // Encrypt our ack.
    let ack_json = serde_json::to_vec(&our_ack).ok()?;
    let our_ct = transport.encrypt(&ack_json).ok()?;

    // Wire exchange: initiator sends first, responder reads first.
    let peer_ct = if is_initiator {
        // Send our ack.
        #[allow(clippy::cast_possible_truncation)]
        let len = (our_ct.len() as u32).to_be_bytes();
        writer.write_all(&len).await.ok()?;
        writer.write_all(&our_ct).await.ok()?;
        writer.flush().await.ok()?;

        // Read peer's ack.
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await.ok()?;
        let peer_len = u32::from_be_bytes(len_buf) as usize;
        if peer_len > 4096 {
            return None;
        } // HandshakeAck JSON is ~500 bytes; 4KB is generous
        let mut peer_buf = vec![0u8; peer_len];
        reader.read_exact(&mut peer_buf).await.ok()?;
        peer_buf
    } else {
        // Read peer's ack first.
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await.ok()?;
        let peer_len = u32::from_be_bytes(len_buf) as usize;
        if peer_len > 4096 {
            return None;
        } // HandshakeAck JSON is ~500 bytes; 4KB is generous
        let mut peer_buf = vec![0u8; peer_len];
        reader.read_exact(&mut peer_buf).await.ok()?;

        // Then send ours.
        #[allow(clippy::cast_possible_truncation)]
        let len = (our_ct.len() as u32).to_be_bytes();
        writer.write_all(&len).await.ok()?;
        writer.write_all(&our_ct).await.ok()?;
        writer.flush().await.ok()?;

        peer_buf
    };

    // Decrypt and verify peer's ack.
    #[allow(clippy::similar_names)]
    let peer_plaintext = transport.decrypt(&peer_ct).ok()?;
    let peer_ack: core_types::HandshakeAck = serde_json::from_slice(&peer_plaintext).ok()?;

    if let Err(e) = handshake_ack::verify_handshake_ack(&peer_ack, remote_static) {
        tracing::warn!(error = %e, "HandshakeAck verification failed");
        return None;
    }

    tracing::info!(
        peer_install = %peer_ack.installation_id,
        "HandshakeAck exchanged and verified"
    );
    Some((peer_ack.installation_id, peer_ack.signing_pubkey))
}

// ---------------------------------------------------------------------------
// IPC notification
// ---------------------------------------------------------------------------

async fn emit_session_established(
    bus_client: &tokio::sync::Mutex<core_ipc::BusClient>,
    session_id: &WireSessionId,
    remote_static: &[u8; 32],
    remote_install_id: uuid::Uuid,
) {
    use core_types::{EventKind, InstallationId, SecurityLevel};

    let event = EventKind::FederationSessionEstablished {
        session_id: uuid::Uuid::from_bytes({
            let mut bytes = [0u8; 16];
            bytes[..12].copy_from_slice(&session_id.0);
            bytes
        }),
        remote_installation: InstallationId {
            id: remote_install_id,
            org_ns: None,
            namespace: uuid::Uuid::nil(),
            machine_binding: None,
            network_pubkey: Some(remote_static.to_vec()),
            signing_pubkey: None,
        },
    };

    let client = bus_client.lock().await;
    if let Err(e) = client.publish(event, SecurityLevel::Internal).await {
        tracing::warn!(error = %e, "failed to emit FederationSessionEstablished");
    }
}

// ---------------------------------------------------------------------------
// TOFU check
// ---------------------------------------------------------------------------

fn run_tofu_check(
    remote_key_hex: &str,
    addr: &str,
    tofu_store: &std::sync::Mutex<TofuStore>,
    metrics: &Metrics,
    audit: &AuditLog,
    require_known_peers: bool,
) -> Result<TofuTrustLevel, String> {
    let store = tofu_store.lock().map_err(|e| format!("TOFU lock: {e}"))?;

    match store.lookup_key(remote_key_hex) {
        Ok(Some(peer)) => match peer.trust_level {
            TofuTrustLevel::Revoked => {
                Metrics::inc(&metrics.tofu_mismatches_total);
                store
                    .record_mismatch(remote_key_hex, remote_key_hex, addr)
                    .unwrap_or_else(|e| tracing::warn!(error = %e, "mismatch record failed"));
                audit.append("tofu_revoked_rejected", &format!("{remote_key_hex} {addr}"));
                Err(format!("peer {remote_key_hex} is REVOKED"))
            }
            TofuTrustLevel::Unpinned => {
                drop(store);
                if let Ok(s) = tofu_store.lock() {
                    let _ = s.pin_with_ttl(
                        remote_key_hex,
                        addr,
                        TofuTrustLevel::Tofu,
                        Some(TOFU_PIN_TTL_SECS),
                    );
                }
                audit.append("tofu_re_pinned", &format!("{remote_key_hex} {addr}"));
                Ok(TofuTrustLevel::Tofu)
            }
            level => {
                if let Err(e) = store.touch(remote_key_hex, addr) {
                    tracing::warn!(error = %e, "TOFU touch failed");
                }
                Ok(level)
            }
        },
        Ok(None) => {
            // First contact with unknown peer.
            if require_known_peers {
                // Strict mode: reject unknown peers entirely. Only Bootstrap
                // and Endorsed peers (pre-configured or coordinator-signed)
                // are accepted. This prevents auto-pinning on untrusted networks.
                audit.append("tofu_rejected_unknown", &format!("{remote_key_hex} {addr}"));
                return Err(format!(
                    "unknown peer {remote_key_hex} rejected (require_known_peers is enabled)"
                ));
            }
            // Pin with a 24h TTL. The pin auto-expires to Unpinned if the
            // peer isn't seen again within the window. This prevents
            // transient peers (coffee shop WiFi, conference LAN) from
            // persisting in the TOFU store indefinitely.
            if let Err(e) = store.pin_with_ttl(
                remote_key_hex,
                addr,
                TofuTrustLevel::Tofu,
                Some(TOFU_PIN_TTL_SECS),
            ) {
                tracing::warn!(error = %e, "TOFU pin failed");
            }
            audit.append("tofu_pinned", &format!("{remote_key_hex} {addr}"));
            Ok(TofuTrustLevel::Tofu)
        }
        Err(e) => Err(format!("TOFU lookup: {e}")),
    }
}
