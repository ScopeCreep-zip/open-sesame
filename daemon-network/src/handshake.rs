//! Handshake orchestration: composes Noise XX/`IKpsk2`, TOFU verification,
//! PSK derivation, session creation, and audit logging into a single async task.

use crate::audit::AuditLog;
use crate::metrics::Metrics;
use crate::noise::state::{self, derive_psk_from_handshake};
use crate::session::state::PeerState;
use crate::session::table::PeerTable;
use crate::tofu::store::TofuStore;
use crate::transport::frame::SessionId;
use core_types::TofuTrustLevel;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

/// Result of a completed handshake.
pub enum HandshakeOutcome {
    /// Session established successfully.
    Established {
        session_id: SessionId,
        remote_key_hex: String,
        trust_level: TofuTrustLevel,
    },
    /// Handshake rejected (TOFU mismatch, revoked, error).
    Rejected { reason: String },
}

/// Shared references needed by the handshake task.
///
/// Groups the `Arc`-wrapped daemon subsystems into a single parameter
/// to avoid exceeding clippy's argument count limit.
pub struct HandshakeContext<'a> {
    pub local_keypair: &'a snow::Keypair,
    pub tofu_store: &'a Arc<std::sync::Mutex<TofuStore>>,
    pub peer_table: &'a Arc<PeerTable>,
    pub bus_client: &'a Arc<tokio::sync::Mutex<core_ipc::BusClient>>,
    pub metrics: &'a Arc<Metrics>,
    pub audit: &'a Arc<AuditLog>,
}

/// Run the responder-side handshake on an inbound TCP connection.
///
/// 1. Noise XX handshake → `NoiseTransport`
/// 2. TOFU check remote static key
/// 3. Derive and cache PSK for future `IKpsk2` reconnection
/// 4. Create `PeerState` and insert into `PeerTable`
/// 5. Emit `FederationSessionEstablished` on IPC bus
/// 6. Audit log the outcome
pub async fn handle_inbound_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    ctx: &HandshakeContext<'_>,
) -> HandshakeOutcome {
    let HandshakeContext {
        local_keypair,
        tofu_store,
        peer_table,
        bus_client,
        metrics,
        audit,
    } = ctx;
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Step 1: Noise XX responder handshake.
    let transport = match state::xx_responder(&mut reader, &mut writer, local_keypair).await {
        Ok(t) => t,
        Err(e) => {
            Metrics::inc(&metrics.handshake_failures_total);
            audit.append("handshake_failed", &format!("{peer_addr} {e}"));
            return HandshakeOutcome::Rejected {
                reason: format!("Noise XX failed: {e}"),
            };
        }
    };

    // Step 2: Extract remote static key and run TOFU check.
    let Some(remote_static) = transport.remote_static() else {
        Metrics::inc(&metrics.handshake_failures_total);
        audit.append("handshake_failed", &format!("{peer_addr} no remote static"));
        return HandshakeOutcome::Rejected {
            reason: "no remote static key after handshake".into(),
        };
    };

    let remote_key_hex = hex::encode(remote_static);
    let trust_level = match run_tofu_check(
        &remote_key_hex,
        &peer_addr.to_string(),
        tofu_store,
        metrics,
        audit,
    ) {
        Ok(level) => level,
        Err(reason) => {
            return HandshakeOutcome::Rejected { reason };
        }
    };

    // Step 3: Derive PSK from handshake hash and cache in TOFU store.
    let psk = derive_psk_from_handshake(&transport.handshake_hash());
    if let Ok(store) = tofu_store.lock()
        && let Err(e) = store.store_psk(&remote_key_hex, &psk)
    {
        tracing::warn!(error = %e, "failed to cache PSK");
    }

    // Step 4: Create PeerState and insert into PeerTable.
    let session_id = SessionId::random();
    let peer_state = PeerState::new(
        session_id,
        remote_static,
        peer_addr,
        transport,
        trust_level,
    );

    if !peer_table.insert(peer_state) {
        Metrics::inc(&metrics.sessions_rejected_full);
        audit.append("session_rejected_full", &format!("{peer_addr} {remote_key_hex}"));
        return HandshakeOutcome::Rejected {
            reason: "session table full".into(),
        };
    }

    // Step 5: Emit FederationSessionEstablished on the IPC bus.
    emit_session_established(bus_client, &session_id, &remote_static).await;

    // Step 6: Record success in metrics and audit log.
    Metrics::inc(&metrics.sessions_established_total);
    audit.append(
        "session_established",
        &format!("{session_id} {peer_addr} {remote_key_hex} {trust_level:?}"),
    );

    tracing::info!(
        session = %session_id,
        %peer_addr,
        key = %&remote_key_hex[..16],
        ?trust_level,
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
/// Connects via TCP, runs Noise XX initiator, then TOFU + PSK + session
/// insertion identical to the responder path.
pub async fn dial_peer(
    addr: SocketAddr,
    local_keypair: &snow::Keypair,
    tofu_store: &Arc<std::sync::Mutex<TofuStore>>,
    peer_table: &Arc<PeerTable>,
    metrics: &Arc<Metrics>,
    audit: &Arc<AuditLog>,
) -> HandshakeOutcome {
    let stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            Metrics::inc(&metrics.handshake_failures_total);
            audit.append("dial_failed", &format!("{addr} {e}"));
            return HandshakeOutcome::Rejected {
                reason: format!("TCP connect failed: {e}"),
            };
        }
    };

    let (mut reader, mut writer) = tokio::io::split(stream);

    // Check TOFU store for cached static key + PSK for IKpsk2 reconnection.
    // IKpsk2 reconnection: look up cached static key + PSK by address.
    // For first contact (no cached key), always use XX.
    // IKpsk2 path is wired when the TOFU store gains address→key reverse lookup.

    let transport = match state::xx_initiator(&mut reader, &mut writer, local_keypair).await {
        Ok(t) => t,
        Err(e) => {
            Metrics::inc(&metrics.handshake_failures_total);
            audit.append("dial_handshake_failed", &format!("{addr} {e}"));
            return HandshakeOutcome::Rejected {
                reason: format!("Noise XX initiator failed: {e}"),
            };
        }
    };

    let Some(remote_static) = transport.remote_static() else {
        Metrics::inc(&metrics.handshake_failures_total);
        return HandshakeOutcome::Rejected {
            reason: "no remote static key".into(),
        };
    };

    let remote_key_hex = hex::encode(remote_static);
    let trust_level = match run_tofu_check(
        &remote_key_hex,
        &addr.to_string(),
        tofu_store,
        metrics,
        audit,
    ) {
        Ok(level) => level,
        Err(reason) => {
            return HandshakeOutcome::Rejected { reason };
        }
    };

    let psk = derive_psk_from_handshake(&transport.handshake_hash());
    if let Ok(store) = tofu_store.lock()
        && let Err(e) = store.store_psk(&remote_key_hex, &psk)
    {
        tracing::warn!(error = %e, "failed to cache PSK");
    }

    let session_id = SessionId::random();
    let peer_state = PeerState::new(session_id, remote_static, addr, transport, trust_level);

    if !peer_table.insert(peer_state) {
        Metrics::inc(&metrics.sessions_rejected_full);
        return HandshakeOutcome::Rejected {
            reason: "session table full".into(),
        };
    }

    Metrics::inc(&metrics.sessions_established_total);
    audit.append(
        "session_established",
        &format!("{session_id} {addr} {remote_key_hex} {trust_level:?}"),
    );

    tracing::info!(
        session = %session_id,
        %addr,
        key = %&remote_key_hex[..16],
        ?trust_level,
        "outbound session established"
    );

    HandshakeOutcome::Established {
        session_id,
        remote_key_hex,
        trust_level,
    }
}

/// Emit `FederationSessionEstablished` on the IPC bus.
///
/// Notifies daemon-profile and other subscribers that a new network peer
/// session is active. The remote installation's `network_pubkey` is set to
/// the Noise static key; other fields are nil until `HandshakeAck` exchange.
async fn emit_session_established(
    bus_client: &Arc<tokio::sync::Mutex<core_ipc::BusClient>>,
    session_id: &SessionId,
    remote_static: &[u8; 32],
) {
    use core_types::{EventKind, InstallationId, SecurityLevel};

    let event = EventKind::FederationSessionEstablished {
        session_id: uuid::Uuid::from_bytes({
            let mut bytes = [0u8; 16];
            bytes[..12].copy_from_slice(&session_id.0);
            bytes
        }),
        remote_installation: InstallationId {
            id: uuid::Uuid::nil(),
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

/// TOFU check: verify a remote static key against the store.
///
/// Returns the trust level on success, or an error string on rejection.
fn run_tofu_check(
    remote_key_hex: &str,
    addr: &str,
    tofu_store: &Arc<std::sync::Mutex<TofuStore>>,
    metrics: &Arc<Metrics>,
    audit: &Arc<AuditLog>,
) -> Result<TofuTrustLevel, String> {
    let store = tofu_store
        .lock()
        .map_err(|e| format!("TOFU store lock poisoned: {e}"))?;

    match store.lookup_key(remote_key_hex) {
        Ok(Some(peer)) => {
            match peer.trust_level {
                TofuTrustLevel::Revoked => {
                    Metrics::inc(&metrics.tofu_mismatches_total);
                    audit.append("tofu_revoked_rejected", &format!("{remote_key_hex} {addr}"));
                    Err(format!("peer {remote_key_hex} is REVOKED"))
                }
                TofuTrustLevel::Unpinned => {
                    // Re-pin on next handshake.
                    drop(store);
                    if let Ok(s) = tofu_store.lock() {
                        let _ = s.pin(remote_key_hex, addr, TofuTrustLevel::Tofu);
                    }
                    audit.append("tofu_re_pinned", &format!("{remote_key_hex} {addr}"));
                    Ok(TofuTrustLevel::Tofu)
                }
                level => {
                    // Known peer — touch to update last_seen.
                    if let Err(e) = store.touch(remote_key_hex, addr) {
                        tracing::warn!(error = %e, "TOFU touch failed");
                    }
                    Ok(level)
                }
            }
        }
        Ok(None) => {
            // First contact — TOFU pin.
            if let Err(e) = store.pin(remote_key_hex, addr, TofuTrustLevel::Tofu) {
                tracing::warn!(error = %e, "TOFU pin failed");
            }
            audit.append("tofu_pinned", &format!("{remote_key_hex} {addr}"));
            Ok(TofuTrustLevel::Tofu)
        }
        Err(e) => Err(format!("TOFU lookup failed: {e}")),
    }
}
