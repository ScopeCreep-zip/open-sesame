//! IPC message dispatch: routes bus messages from daemon-profile.

use crate::handshake::{self, HandshakeContext};
use crate::send;
use crate::state::DaemonState;
use base64::Engine as _;
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
                dns_srv_domains: state.dns_srv_domains.read()
                    .map(|d| d.clone())
                    .unwrap_or_default(),
                #[allow(clippy::cast_possible_truncation)]
                dial_queue_depth: state.discovery.queue_depth() as u32,
                swim_members: 0,
            })
        }
        EventKind::VaultReplicationPullResponse { entries_json, peer_id, last_hlc_json, profile_name, .. } => {
            // Cache the watermark from this response keyed by peer_id so
            // the next pull for this peer doesn't re-fetch from epoch 0.
            if let Some(hlc_json) = &last_hlc_json
                && !peer_id.is_empty()
            {
                // Cache locally for next pull request.
                if let Ok(mut wm_map) = state.replication_watermarks.lock() {
                    wm_map.insert(peer_id.clone(), hlc_json.clone());
                }
                // Publish to daemon-secrets so pull_progress table is updated.
                let client = state.bus_client.lock().await;
                let _ = client.publish(
                    EventKind::ReplicationPullProgressUpdate {
                        peer_id: peer_id.clone(),
                        profile_name: profile_name.clone(),
                        last_hlc_json: hlc_json.clone(),
                    },
                    core_types::SecurityLevel::Internal,
                ).await;
            }
            // Per-destination re-encryption: for each active session, look up
            // the peer's X25519 public key, generate an ephemeral keypair,
            // ECDH + HKDF-BLAKE2b + ChaCha20-Poly1305 seal the entries with
            // the entry batch ID as AAD. Each peer gets a unique ciphertext
            // that only they can decrypt with their private key.
            let sids = state.peer_table.session_ids();
            for sid in &sids {
                let peer_pubkey = {
                    let Some(peer) = state.peer_table.get(sid) else { continue };
                    let key_hex = peer.remote_key_hex();
                    state.tofu_store.lock().ok()
                        .and_then(|store| store.get_network_pubkey(&key_hex).ok().flatten())
                };
                let Some(dest_pubkey) = peer_pubkey else {
                    state.audit.append("replication_skip", &format!("{sid} no_network_pubkey"));
                    tracing::debug!(session = %sid, "skipping replication — no network pubkey for peer");
                    continue;
                };

                // Ephemeral ECDH per destination.
                let (eph_private, eph_public) = match core_crypto::network::generate_x25519_keypair() {
                    Ok(kp) => kp,
                    Err(e) => {
                        state.audit.append("replication_error", &format!("{sid} keygen_failed {e}"));
                        tracing::warn!(error = %e, session = %sid, "ephemeral keypair generation failed");
                        continue;
                    }
                };
                let shared = match core_crypto::network::x25519_dh(&eph_private, &dest_pubkey) {
                    Ok(s) => s,
                    Err(e) => {
                        state.audit.append("replication_error", &format!("{sid} ecdh_failed {e}"));
                        tracing::warn!(error = %e, session = %sid, "ECDH failed for replication re-encryption");
                        continue;
                    }
                };

                // Derive encryption key via HKDF-BLAKE2b.
                let enc_keys = core_crypto::network::hkdf_blake2b(
                    shared.as_bytes(),
                    core_crypto::network::REPLICATION_HKDF_CONTEXT,
                    1,
                );
                let enc_key: [u8; 32] = match enc_keys[0].as_bytes().try_into() {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                // Seal: ChaCha20-Poly1305. AAD binds ciphertext to the batch
                // hash, timestamp, and session ID to prevent replay and
                // cross-session substitution attacks.
                let nonce = core_crypto::network::random_bytes::<12>();
                let plaintext = entries_json.as_bytes();
                let batch_hash = blake3::hash(plaintext);
                let timestamp_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let sid_str = sid.to_string();

                let aad = core_crypto::network::replication_envelope_aad(
                    batch_hash.as_bytes(),
                    timestamp_secs,
                    &sid_str,
                );

                let ciphertext = match core_crypto::network::chacha20_seal(
                    &enc_key, &nonce, &aad, plaintext,
                ) {
                    Ok(ct) => ct,
                    Err(e) => {
                        state.audit.append("replication_error", &format!("{sid} seal_failed {e}"));
                        tracing::warn!(error = %e, session = %sid, "re-encryption seal failed");
                        continue;
                    }
                };

                // Build a JSON envelope with base64-encoded fields so the
                // IPC path (which uses String fields) can carry the binary
                // payload without encoding issues.
                let b64 = base64::engine::general_purpose::STANDARD;
                let envelope = serde_json::json!({
                    "reencrypted": true,
                    "ephemeral_pubkey": b64.encode(eph_public),
                    "nonce": b64.encode(nonce),
                    "ciphertext": b64.encode(&ciphertext),
                    "batch_hash": hex::encode(batch_hash.as_bytes()),
                    "timestamp_secs": timestamp_secs,
                    "session_id": sid_str,
                });
                let envelope_str = serde_json::to_string(&envelope).unwrap_or_default();

                // Frame with NetworkMessageType::VaultReplication prefix.
                let mut framed = vec![0x01, 0x00];
                framed.extend_from_slice(envelope_str.as_bytes());

                let table = Arc::clone(&state.peer_table);
                let socket = Arc::clone(&state.udp_socket);
                let metrics = Arc::clone(&state.metrics);
                let sid = *sid;
                tokio::spawn(async move {
                    let _ = send::send_data(&sid, &framed, &table, &socket, &metrics).await;
                });
            }
            None
        }
        EventKind::NetworkDiscoveryReloadRequest => {
            // Reload bootstrap.json.
            let bootstrap_path = dirs::config_dir()
                .unwrap_or_default()
                .join("pds")
                .join("bootstrap.json");
            let mut added: u32 = 0;
            if let Ok(result) = daemon_discovery::bootstrap::load_bootstrap(&bootstrap_path) {
                for target in &result.targets {
                    if state.discovery.queue.push(daemon_discovery::queue::DialEntry {
                        addr: target.addr,
                        source: daemon_discovery::queue::DiscoverySource::Bootstrap,
                        advisory_pubkey_hex: target.public_key_hex.clone(),
                        next_dial_at: std::time::Instant::now(),
                        consecutive_failures: 0,
                    }) {
                        added += 1;
                    }
                }
            }
            // Reload DNS SRV domains from config.toml [network] section.
            let network_config = core_config::load_config(None)
                .map(|c| c.network)
                .unwrap_or_default();
            if let Ok(mut domains) = state.dns_srv_domains.write() {
                *domains = network_config.discovery.dns_srv.domains;
            }
            state.audit.append("discovery_reload", &format!("added={added}"));
            Some(EventKind::NetworkDiscoveryReloadResponse { added })
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
