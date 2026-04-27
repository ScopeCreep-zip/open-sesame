//! IPC message dispatch: handles all EventKind messages received on the bus,
//! and periodic reconciliation with daemon-secrets.

use core_ipc::{BusServer, Message};
use core_profile::{AuditAction, AuditLogger, ContextEngine};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::collections::HashSet;
use tokio::sync::mpsc;

use crate::{DaemonTracker, KEY_ROTATION_GRACE, KNOWN_DAEMONS};

/// Handle a message received on the bus that daemon-profile is responsible for.
///
/// Returns `Some(response_event)` for RPC requests, `None` for broadcast events.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_bus_message<W: std::io::Write>(
    msg: &Message<EventKind>,
    active_profiles: &mut HashSet<TrustProfileName>,
    _context_engine: &mut ContextEngine,
    audit: &mut AuditLogger<W>,
    default_profile_name: &mut TrustProfileName,
    daemon_id: DaemonId,
    bus: &BusServer,
    daemon_tracker: &mut DaemonTracker,
    locked: &mut bool,
    confirm_tx: &mpsc::Sender<Vec<u8>>,
    confirm_rx: &mut mpsc::Receiver<Vec<u8>>,
    config_profile_names: &[TrustProfileName],
    install_ns: &uuid::Uuid,
    rotation_done_tx: &mpsc::Sender<()>,
) -> Option<EventKind> {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    match &msg.payload {
        // Track daemon start/restart for key revocation.
        EventKind::DaemonStarted {
            daemon_id: announced_id,
            ..
        } => {
            // Require server-verified name from Noise IK registry. Never fall back
            // to self-declared capabilities -- those are spoofable by any client.
            let Some(name) = msg.verified_sender_name.clone() else {
                tracing::warn!(
                    audit = "security",
                    sender = %announced_id,
                    "DaemonStarted from unverified sender — ignoring (no verified_sender_name)"
                );
                return None;
            };
            if let Some(old_id) = daemon_tracker.track(&name, *announced_id) {
                tracing::warn!(
                    audit = "security",
                    event_type = "daemon-restart-detected",
                    daemon_name = %name,
                    old_id = %old_id,
                    new_id = %announced_id,
                    "daemon restart detected — revoking old key and generating new keypair"
                );

                // daemon-secrets restarts locked with no active profiles.
                if name == "daemon-secrets" {
                    *locked = true;
                    active_profiles.clear();
                    tracing::warn!(
                        audit = "security",
                        event_type = "daemon-secrets-restart",
                        "daemon-secrets restarted — resetting lock state and clearing active profiles"
                    );
                }

                // Find the KNOWN_DAEMONS entry for this name.
                if let Some(&(daemon_name, security_level)) =
                    KNOWN_DAEMONS.iter().find(|(n, _)| *n == name)
                {
                    // Revoke old key, generate and register new one.
                    let noise_params: snow::params::NoiseParams =
                        "Noise_IK_25519_ChaChaPoly_BLAKE2s"
                            .parse()
                            .expect("valid noise params");
                    let builder = snow::Builder::new(noise_params);
                    match builder.generate_keypair() {
                        Ok(raw_keypair) => {
                            let new_keypair = core_ipc::ZeroizingKeypair::new(raw_keypair);
                            let mut new_pubkey = [0u8; 32];
                            new_pubkey.copy_from_slice(new_keypair.public());

                            // Write new keypair to disk.
                            if let Err(e) = core_ipc::noise::write_daemon_keypair(
                                daemon_name,
                                new_keypair.as_inner(),
                            )
                            .await
                            {
                                tracing::error!(error = %e, daemon = daemon_name, "failed to write revocation keypair");
                            } else {
                                // Revoke all keys for this daemon (handles dual-key
                                // state during rotation) and re-register with
                                // incremented generation.
                                let mut reg = bus.registry_mut().await;
                                let next_gen = reg
                                    .revoke_by_name(daemon_name)
                                    .map_or(0, |id| id.generation + 1);
                                reg.register_with_generation(
                                    daemon_name.into(),
                                    new_pubkey,
                                    security_level,
                                    next_gen,
                                );
                                drop(reg); // Release lock before I/O.
                                tracing::info!(
                                    audit = "security",
                                    event_type = "key-revocation",
                                    daemon = daemon_name,
                                    generation = next_gen,
                                    "old key revoked, new key registered"
                                );
                                let _ = audit.append(AuditAction::KeyRevoked {
                                    daemon_name: daemon_name.into(),
                                    reason: "crash-restart-detected".into(),
                                    generation: next_gen,
                                });

                                // Announce KeyRotationPending so the restarted daemon
                                // reconnects with the new key.
                                let rotation_event = EventKind::KeyRotationPending {
                                    daemon_name: daemon_name.into(),
                                    new_pubkey,
                                    grace_period_s: KEY_ROTATION_GRACE,
                                };
                                let rotation_msg = Message::new(
                                    &msg_ctx,
                                    rotation_event,
                                    SecurityLevel::Internal,
                                    bus.epoch(),
                                );
                                if let Ok(payload) = core_ipc::encode_frame(&rotation_msg) {
                                    bus.publish(&payload, SecurityLevel::Internal).await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, daemon = daemon_name, "failed to generate revocation keypair");
                        }
                    }
                }
            }
            None
        }

        EventKind::StatusRequest => {
            // Query daemon-secrets for authoritative lock + active profile state
            // rather than relying on shadow state that may be stale.
            match crate::activation::confirmed_rpc(
                bus,
                daemon_id,
                EventKind::SecretsStateRequest,
                confirm_tx,
                confirm_rx,
            )
            .await
            {
                Ok(response) => {
                    if let EventKind::SecretsStateResponse {
                        locked: auth_locked,
                        active_profiles: auth_profiles,
                        lock_state: auth_lock_state,
                    } = response.payload
                    {
                        // Warm the shadow state from the authoritative source.
                        *locked = auth_locked;
                        *active_profiles = auth_profiles.iter().cloned().collect();
                        Some(EventKind::StatusResponse {
                            active_profiles: auth_profiles,
                            default_profile: default_profile_name.clone(),
                            daemon_uptimes_ms: vec![(daemon_id, 0)],
                            locked: auth_locked,
                            lock_state: auth_lock_state,
                        })
                    } else {
                        tracing::warn!(
                            "unexpected response to SecretsStateRequest: {:?}",
                            response.payload
                        );
                        Some(EventKind::StatusResponse {
                            active_profiles: active_profiles.iter().cloned().collect(),
                            default_profile: default_profile_name.clone(),
                            daemon_uptimes_ms: vec![(daemon_id, 0)],
                            locked: *locked,
                            lock_state: std::collections::BTreeMap::new(),
                        })
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to query daemon-secrets for status, using shadow state");
                    Some(EventKind::StatusResponse {
                        active_profiles: active_profiles.iter().cloned().collect(),
                        default_profile: default_profile_name.clone(),
                        daemon_uptimes_ms: vec![(daemon_id, 0)],
                        locked: *locked,
                        lock_state: std::collections::BTreeMap::new(),
                    })
                }
            }
        }

        EventKind::ProfileList => {
            // Iterate config profiles (not just active_profiles) so that
            // `sesame profile list` shows all configured profiles.
            // Use deterministic UUIDs (UUID v5) so ProfileIds are stable across
            // calls and restarts, matching the IDs used in build_activation_rules().
            let profiles = config_profile_names
                .iter()
                .map(|name| {
                    let id = core_types::ProfileId::from_uuid(uuid::Uuid::new_v5(
                        install_ns,
                        format!("profile:{}", name).as_bytes(),
                    ));
                    core_types::ProfileSummary {
                        id,
                        name: name.clone(),
                        is_active: active_profiles.contains(name),
                        is_default: name == &*default_profile_name,
                    }
                })
                .collect();
            Some(EventKind::ProfileListResponse { profiles })
        }

        EventKind::ProfileActivate {
            profile_name,
            target,
        } => {
            if !config_profile_names.contains(profile_name) {
                tracing::warn!(profile = %profile_name, "activate requested but profile not in config");
                return Some(EventKind::ProfileActivateResponse { success: false });
            }
            match crate::activation::activate(
                *target,
                profile_name,
                bus,
                audit,
                daemon_id,
                confirm_tx,
                confirm_rx,
            )
            .await
            {
                Ok(duration_ms) => {
                    active_profiles.insert(profile_name.clone()); // TrustProfileName: Clone
                    tracing::info!(
                        profile = %profile_name,
                        duration_ms,
                        "profile activated"
                    );
                    Some(EventKind::ProfileActivateResponse { success: true })
                }
                Err(e) => {
                    tracing::error!(
                        profile = %profile_name,
                        error = %e,
                        "profile activation failed"
                    );
                    Some(EventKind::ProfileActivateResponse { success: false })
                }
            }
        }

        EventKind::ProfileDeactivate {
            profile_name,
            target,
        } => {
            if !config_profile_names.contains(profile_name) {
                tracing::warn!(profile = %profile_name, "deactivate requested but profile not in config");
                return Some(EventKind::ProfileDeactivateResponse { success: false });
            }
            if !active_profiles.contains(profile_name) {
                tracing::warn!(profile = %profile_name, "deactivate requested but profile not active");
                return Some(EventKind::ProfileDeactivateResponse { success: false });
            }

            match crate::activation::deactivate(
                *target,
                profile_name,
                bus,
                audit,
                daemon_id,
                confirm_tx,
                confirm_rx,
            )
            .await
            {
                Ok(duration_ms) => {
                    active_profiles.remove(profile_name);
                    tracing::info!(
                        profile = %profile_name,
                        duration_ms,
                        "profile deactivated"
                    );
                    Some(EventKind::ProfileDeactivateResponse { success: true })
                }
                Err(e) => {
                    tracing::error!(
                        profile = %profile_name,
                        error = %e,
                        "profile deactivation failed — triggering immediate reconciliation"
                    );
                    reconcile_secrets_state(
                        bus,
                        daemon_id,
                        locked,
                        active_profiles,
                        confirm_tx,
                        confirm_rx,
                    )
                    .await;
                    Some(EventKind::ProfileDeactivateResponse { success: false })
                }
            }
        }

        EventKind::SetDefaultProfile { profile_name } => {
            if !config_profile_names.contains(profile_name) {
                tracing::warn!(profile = %profile_name, "set default requested but profile not in config");
                return Some(EventKind::SetDefaultProfileResponse { success: false });
            }
            tracing::info!(
                previous = %default_profile_name,
                new = %profile_name,
                "set default profile requested"
            );
            *default_profile_name = profile_name.clone();
            Some(EventKind::SetDefaultProfileResponse { success: true })
        }

        EventKind::UnlockResponse {
            success: true,
            profile,
        } => {
            *locked = false; // At least one vault is unlocked.
            tracing::info!(profile = %profile, "vault unlocked, shadow state updated");
            None
        }

        EventKind::LockResponse {
            success: true,
            profiles_locked,
        } => {
            if profiles_locked.is_empty() {
                // Lock-all: clear everything.
                *locked = true;
                active_profiles.clear();
                tracing::info!(
                    audit = "security",
                    "all vaults locked, active profiles cleared"
                );
            } else {
                // Per-profile lock: remove locked profiles from active set.
                for p in profiles_locked {
                    active_profiles.remove(p);
                }
                tracing::info!(audit = "security", profiles = ?profiles_locked, "vault(s) locked");
            }
            None
        }

        // Receive secret operation audit events from daemon-secrets and
        // persist them in the hash-chained audit log.
        EventKind::SecretOperationAudit {
            action,
            profile,
            key,
            requester,
            requester_name,
            outcome,
        } => {
            if let Err(e) = audit.append(AuditAction::SecretOperationAudited {
                action: action.clone(),
                profile: profile.clone(),
                key: key.clone(),
                requester: *requester,
                requester_name: requester_name.clone(),
                outcome: outcome.clone(),
            }) {
                tracing::error!(
                    error = %e,
                    action = %action,
                    profile = %profile,
                    "failed to write secret operation audit entry"
                );
            }
            None
        }

        // Agent and federation lifecycle events — no action needed in profile daemon.
        EventKind::AgentConnected { .. } => None,
        EventKind::AgentDisconnected { .. } => None,
        EventKind::InstallationCreated { .. } => None,
        EventKind::ProfileIdMigrated { .. } => None,
        EventKind::AuthorizationRequired { .. } => None,
        EventKind::AuthorizationGrant { .. } => None,
        EventKind::AuthorizationDenied { .. } => None,
        EventKind::AuthorizationTimeout { .. } => None,
        EventKind::DelegationRevoked { .. } => None,
        EventKind::HeartbeatRenewed { .. } => None,
        EventKind::FederationSessionEstablished { .. } => None,
        EventKind::FederationSessionTerminated { .. } => None,
        EventKind::PostureEvaluated { .. } => None,

        EventKind::KeyRotationRequest => {
            tracing::info!(
                audit = "key-management",
                "on-demand key rotation requested via IPC"
            );
            match crate::key_rotation::rotate_keys_phase1(bus, daemon_id, audit).await {
                Ok(()) => {
                    // Schedule phase 2 via the same channel the timer uses.
                    // The main event loop's rotation_done_rx arm runs phase 2.
                    let tx = rotation_done_tx.clone();
                    let grace = crate::KEY_ROTATION_GRACE;
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(u64::from(grace))).await;
                        let _ = tx.send(()).await;
                    });
                    Some(EventKind::KeyRotationRequestResponse {
                        success: true,
                        error: None,
                    })
                }
                Err(e) => {
                    tracing::error!(error = %e, "on-demand key rotation failed");
                    Some(EventKind::KeyRotationRequestResponse {
                        success: false,
                        error: Some(e.to_string()),
                    })
                }
            }
        }

        // -- Network federation (M1/M2/M3 pre-work: no-op routing) --
        EventKind::NetworkIdentityRequest
        | EventKind::NetworkIdentityResponse { .. }
        | EventKind::VaultLogEntryReceived { .. }
        | EventKind::VaultReplicationPullRequest { .. }
        | EventKind::VaultReplicationPullResponse { .. } => {
            // Routed between daemon-network and daemon-secrets.
            // daemon-profile does not act on these.
            None
        }

        _ => None,
    }
}

/// Reconcile daemon-profile's view of lock/active-profiles with daemon-secrets.
///
/// Sends `SecretsStateRequest` via confirmed RPC and overwrites local state with
/// the authoritative response. On timeout, fails closed: assume locked, empty active set.
pub(crate) async fn reconcile_secrets_state(
    bus: &BusServer,
    daemon_id: DaemonId,
    locked: &mut bool,
    active_profiles: &mut HashSet<TrustProfileName>,
    confirm_tx: &mpsc::Sender<Vec<u8>>,
    confirm_rx: &mut mpsc::Receiver<Vec<u8>>,
) {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    let msg = Message::new(
        &msg_ctx,
        EventKind::SecretsStateRequest,
        SecurityLevel::Internal,
        bus.epoch(),
    );
    let msg_id = msg.msg_id;

    let _guard = bus.register_confirmation(msg_id, confirm_tx.clone()).await;

    // Drain stale messages from confirm_rx to prevent consuming a leftover
    // response from a previous timed-out confirmed RPC.
    while confirm_rx.try_recv().is_ok() {}

    let frame = match core_ipc::encode_frame(&msg) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "reconciliation: failed to encode SecretsStateRequest");
            return;
        }
    };

    if let Err(e) = bus.send_to_named("daemon-secrets", &frame).await {
        // daemon-secrets not connected — fail closed.
        tracing::debug!(error = %e, "reconciliation: daemon-secrets not reachable, assuming locked");
        *locked = true;
        active_profiles.clear();
        return;
    }

    const RECONCILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    match tokio::time::timeout(RECONCILE_TIMEOUT, confirm_rx.recv()).await {
        Ok(Some(raw_frame)) => {
            match core_ipc::decode_frame::<Message<EventKind>>(&raw_frame) {
                Ok(response) => {
                    // Verify correlation_id matches our request (defense-in-depth).
                    if response.correlation_id != Some(msg_id) {
                        tracing::warn!(
                            expected = %msg_id,
                            got = ?response.correlation_id,
                            "reconciliation: correlation_id mismatch, ignoring stale response"
                        );
                        return;
                    }
                    if let EventKind::SecretsStateResponse {
                        locked: auth_locked,
                        active_profiles: auth_profiles,
                        ..
                    } = response.payload
                    {
                        // Log discrepancies before overwriting.
                        if *locked != auth_locked {
                            tracing::warn!(
                                local_locked = *locked,
                                authoritative_locked = auth_locked,
                                "reconciliation: lock state discrepancy corrected"
                            );
                        }
                        let local_set: HashSet<_> = active_profiles.iter().cloned().collect();
                        let auth_set: HashSet<_> = auth_profiles.iter().cloned().collect();
                        if local_set != auth_set {
                            tracing::warn!(
                                local_profiles = ?local_set,
                                authoritative_profiles = ?auth_set,
                                "reconciliation: active profiles discrepancy corrected"
                            );
                        }

                        // Overwrite with authoritative state.
                        *locked = auth_locked;
                        *active_profiles = auth_set;
                    } else {
                        tracing::warn!(
                            payload = ?response.payload,
                            "reconciliation: unexpected response type"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "reconciliation: failed to decode response");
                }
            }
        }
        Ok(None) => {
            tracing::error!("reconciliation: confirmation channel closed");
        }
        Err(_) => {
            // Timeout — fail closed.
            tracing::warn!("reconciliation: SecretsStateRequest timed out — assuming locked");
            *locked = true;
            active_profiles.clear();
        }
    }
}
