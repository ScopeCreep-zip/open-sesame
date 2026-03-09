//! Profile activation/deactivation transaction with confirmed RPC and rollback.
//!
//! Coordinates the multi-step process of activating or deactivating a profile
//! across daemons. Uses confirmed RPC instead of fire-and-forget broadcast
//! for security-critical steps — daemon-profile waits for daemon-secrets to confirm
//! each operation before proceeding.
//!
//! Activation:
//!   1. Emit `ProfileActivationBegun` on IPC bus (informational, fire-and-forget)
//!   2. Send `ProfileActivate` to daemon-secrets via confirmed RPC (unicast + wait)
//!   3. Emit `ProfileActivated` on IPC bus (informational, fire-and-forget)
//!   4. Append audit entry
//!
//! Deactivation:
//!   1. Emit `ProfileDeactivationBegun` on IPC bus (informational, fire-and-forget)
//!   2. Send `ProfileDeactivate` to daemon-secrets via confirmed RPC (unicast + wait)
//!   3. Emit `ProfileDeactivated` on IPC bus (informational, fire-and-forget)
//!   4. Append audit entry
//!
//! If a confirmed RPC times out, the operation fails closed — no state change
//! is committed locally. Rollback steps also use confirmed RPC.

use core_ipc::{BusServer, Message};
use core_profile::AuditLogger;
use core_types::{DaemonId, EventKind, ProfileId, SecurityLevel, TrustProfileName};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
/// Timeout for confirmed RPC calls to daemon-secrets.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

/// Steps completed during an activation/deactivation, for rollback tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletedStep {
    ActivationBegunEmitted,
    SecretsVaultOpened,
    SecretsJitFlushed,
    SecretsVaultClosed,
    ActivationCompletedEmitted,
}

/// Execute a profile activation transaction with confirmed RPC.
///
/// Coordinates with daemon-secrets via unicast confirmed RPC to open the vault,
/// then emits informational bus events and writes an audit entry. Returns the
/// elapsed duration on success, or an error with best-effort rollback on failure.
///
/// Fails closed: if daemon-secrets does not confirm within [`CONFIRM_TIMEOUT`],
/// activation is NOT committed locally.
pub async fn activate<W: std::io::Write>(
    target: ProfileId,
    profile_name: &TrustProfileName,
    bus: &BusServer,
    audit: &mut AuditLogger<W>,
    daemon_id: DaemonId,
    confirm_tx: &mpsc::Sender<Vec<u8>>,
    confirm_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<u32, String> {
    let start = Instant::now();
    let mut completed: Vec<CompletedStep> = Vec::new();

    // Step 1: Emit ActivationBegun broadcast (informational, fire-and-forget).
    let begun_event = EventKind::ProfileActivationBegun {
        target,
        trigger: format!("explicit activation of {profile_name}"),
    };
    if let Err(e) = broadcast(bus, daemon_id, begun_event).await {
        return Err(format!("failed to emit ActivationBegun: {e}"));
    }
    completed.push(CompletedStep::ActivationBegunEmitted);

    // Step 2: Send ProfileActivate to daemon-secrets via confirmed RPC.
    let activate_event = EventKind::ProfileActivate {
        profile_name: profile_name.clone(),
        target,
    };
    match confirmed_rpc(bus, daemon_id, activate_event, confirm_tx, confirm_rx).await {
        Ok(response) => {
            match response.payload {
                EventKind::ProfileActivateResponse { success: true } => {
                    completed.push(CompletedStep::SecretsVaultOpened);
                }
                EventKind::ProfileActivateResponse { success: false } => {
                    rollback(&completed, target, profile_name, bus, audit, daemon_id, confirm_tx, confirm_rx).await;
                    return Err("daemon-secrets rejected ProfileActivate".into());
                }
                other => {
                    rollback(&completed, target, profile_name, bus, audit, daemon_id, confirm_tx, confirm_rx).await;
                    return Err(format!("unexpected response to ProfileActivate: {other:?}"));
                }
            }
        }
        Err(e) => {
            rollback(&completed, target, profile_name, bus, audit, daemon_id, confirm_tx, confirm_rx).await;
            return Err(format!("confirmed RPC failed for ProfileActivate: {e}"));
        }
    }

    // Step 3: Emit ProfileActivated broadcast (informational, fire-and-forget).
    let duration_ms = start.elapsed().as_millis() as u32;
    let activated_event = EventKind::ProfileActivated {
        target,
        duration_ms,
    };
    if let Err(e) = broadcast(bus, daemon_id, activated_event).await {
        // Informational broadcast failure is not security-critical — log and continue.
        tracing::warn!(error = %e, "failed to emit ProfileActivated broadcast (non-critical)");
    }
    completed.push(CompletedStep::ActivationCompletedEmitted);

    // Step 4: Append audit entry.
    if let Err(e) = audit.append(core_profile::AuditAction::ProfileActivated {
        target,
        duration_ms,
    }) {
        tracing::error!(error = %e, "failed to write activation audit entry");
        // Audit failure is logged but does not trigger rollback —
        // the activation itself succeeded.
    }

    Ok(duration_ms)
}

/// Execute a profile deactivation transaction with confirmed RPC.
///
/// Coordinates with daemon-secrets via unicast confirmed RPC to flush JIT cache
/// and close the vault, then emits bus events and writes an audit entry.
pub async fn deactivate<W: std::io::Write>(
    target: ProfileId,
    profile_name: &TrustProfileName,
    bus: &BusServer,
    audit: &mut AuditLogger<W>,
    daemon_id: DaemonId,
    confirm_tx: &mpsc::Sender<Vec<u8>>,
    confirm_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<u32, String> {
    let start = Instant::now();
    let mut completed: Vec<CompletedStep> = Vec::new();

    // Step 1: Emit DeactivationBegun broadcast (informational, fire-and-forget).
    let begun_event = EventKind::ProfileDeactivationBegun { target };
    if let Err(e) = broadcast(bus, daemon_id, begun_event).await {
        return Err(format!("failed to emit DeactivationBegun: {e}"));
    }
    completed.push(CompletedStep::ActivationBegunEmitted);

    // Step 2: Send ProfileDeactivate to daemon-secrets via confirmed RPC.
    let deactivate_event = EventKind::ProfileDeactivate {
        profile_name: profile_name.clone(),
        target,
    };
    match confirmed_rpc(bus, daemon_id, deactivate_event, confirm_tx, confirm_rx).await {
        Ok(response) => {
            match response.payload {
                EventKind::ProfileDeactivateResponse { success: true } => {
                    completed.push(CompletedStep::SecretsJitFlushed);
                    completed.push(CompletedStep::SecretsVaultClosed);
                }
                EventKind::ProfileDeactivateResponse { success: false } => {
                    rollback(&completed, target, profile_name, bus, audit, daemon_id, confirm_tx, confirm_rx).await;
                    return Err("daemon-secrets rejected ProfileDeactivate".into());
                }
                other => {
                    rollback(&completed, target, profile_name, bus, audit, daemon_id, confirm_tx, confirm_rx).await;
                    return Err(format!("unexpected response to ProfileDeactivate: {other:?}"));
                }
            }
        }
        Err(e) => {
            // Deactivation timeout: log error, trigger reconciliation at caller level.
            tracing::error!(
                error = %e,
                profile = %profile_name,
                "confirmed RPC timeout on ProfileDeactivate — reconciliation needed"
            );
            return Err(format!("confirmed RPC failed for ProfileDeactivate: {e}"));
        }
    }

    // Step 3: Emit ProfileDeactivated broadcast (informational, fire-and-forget).
    let duration_ms = start.elapsed().as_millis() as u32;
    let deactivated_event = EventKind::ProfileDeactivated {
        target,
        duration_ms,
    };
    if let Err(e) = broadcast(bus, daemon_id, deactivated_event).await {
        tracing::warn!(error = %e, "failed to emit ProfileDeactivated broadcast (non-critical)");
    }
    completed.push(CompletedStep::ActivationCompletedEmitted);

    // Step 4: Append audit entry.
    if let Err(e) = audit.append(core_profile::AuditAction::ProfileDeactivated {
        target,
        duration_ms,
    }) {
        tracing::error!(error = %e, "failed to write deactivation audit entry");
    }

    Ok(duration_ms)
}

/// Send a confirmed RPC to daemon-secrets and wait for the response.
///
/// 1. Encode the event as a Message with a fresh `msg_id`
/// 2. Register a confirmation route for that `msg_id`
/// 3. Unicast to daemon-secrets via `send_to_named()`
/// 4. Wait for the confirmed response with timeout
/// 5. Decode and return the response Message
///
/// The [`ConfirmationGuard`] automatically deregisters the route on drop,
/// even on timeout or error paths.
async fn confirmed_rpc(
    bus: &BusServer,
    daemon_id: DaemonId,
    event: EventKind,
    confirm_tx: &mpsc::Sender<Vec<u8>>,
    confirm_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<Message<EventKind>, String> {
    let msg = Message::new(daemon_id, event, SecurityLevel::SecretsOnly, bus.epoch());
    let msg_id = msg.msg_id;

    // Register confirmation route — guard deregisters on drop.
    let _guard = bus.register_confirmation(msg_id, confirm_tx.clone()).await;

    // Encode and unicast to daemon-secrets.
    let frame = core_ipc::encode_frame(&msg).map_err(|e| format!("encode failed: {e}"))?;
    bus.send_to_named("daemon-secrets", &frame)
        .await
        .map_err(|e| format!("send_to_named failed: {e}"))?;

    // Wait for confirmed response with timeout.
    match tokio::time::timeout(CONFIRM_TIMEOUT, confirm_rx.recv()).await {
        Ok(Some(raw_frame)) => {
            let response: Message<EventKind> = core_ipc::decode_frame(&raw_frame)
                .map_err(|e| format!("failed to decode confirmation response: {e}"))?;
            // Verify the response is actually correlated to our request.
            if response.correlation_id != Some(msg_id) {
                return Err(format!(
                    "confirmation response correlation_id mismatch: expected {msg_id}, got {:?}",
                    response.correlation_id
                ));
            }
            Ok(response)
        }
        Ok(None) => Err("confirmation channel closed".into()),
        Err(_) => Err(format!(
            "confirmed RPC timed out after {}ms",
            CONFIRM_TIMEOUT.as_millis()
        )),
    }
}

/// Serialize and publish an event on the bus (fire-and-forget, informational).
async fn broadcast(
    bus: &BusServer,
    daemon_id: DaemonId,
    event: EventKind,
) -> Result<(), String> {
    let msg = Message::new(daemon_id, event, SecurityLevel::Internal, bus.epoch());
    let payload = core_ipc::encode_frame(&msg).map_err(|e| e.to_string())?;
    bus.publish(&payload, SecurityLevel::Internal).await;
    Ok(())
}

/// Best-effort rollback of completed steps in reverse order using confirmed RPC.
///
/// Emits `ProfileActivationFailed` if rollback is attempted. Writes an
/// audit entry for the failure. Individual rollback step failures are
/// logged but do not propagate.
#[allow(clippy::too_many_arguments)]
async fn rollback<W: std::io::Write>(
    completed: &[CompletedStep],
    target: ProfileId,
    profile_name: &TrustProfileName,
    bus: &BusServer,
    audit: &mut AuditLogger<W>,
    daemon_id: DaemonId,
    confirm_tx: &mpsc::Sender<Vec<u8>>,
    confirm_rx: &mut mpsc::Receiver<Vec<u8>>,
) {
    tracing::warn!(
        target = %target,
        profile = %profile_name,
        steps = completed.len(),
        "rolling back activation/deactivation"
    );

    for step in completed.iter().rev() {
        match step {
            CompletedStep::SecretsVaultOpened => {
                // Rollback: deactivate the profile we just activated.
                let event = EventKind::ProfileDeactivate {
                    profile_name: profile_name.clone(),
                    target,
                };
                match confirmed_rpc(bus, daemon_id, event, confirm_tx, confirm_rx).await {
                    Ok(_) => tracing::info!("rollback: secrets vault deactivated"),
                    Err(e) => tracing::error!(error = %e, "rollback: failed to deactivate secrets vault (confirmed RPC)"),
                }
            }
            CompletedStep::SecretsJitFlushed | CompletedStep::SecretsVaultClosed => {
                // Rollback: re-activate the profile we just deactivated.
                let event = EventKind::ProfileActivate {
                    profile_name: profile_name.clone(),
                    target,
                };
                match confirmed_rpc(bus, daemon_id, event, confirm_tx, confirm_rx).await {
                    Ok(_) => tracing::info!("rollback: secrets vault re-activated"),
                    Err(e) => tracing::error!(error = %e, "rollback: failed to re-activate secrets vault (confirmed RPC)"),
                }
            }
            CompletedStep::ActivationBegunEmitted
            | CompletedStep::ActivationCompletedEmitted => {}
        }
    }

    // Audit the failure.
    if let Err(e) = audit.append(core_profile::AuditAction::ProfileActivationFailed {
        target,
        reason: "transaction rolled back".into(),
    }) {
        tracing::error!(error = %e, "rollback: failed to write audit entry");
    }

    // Emit failure event on bus (best-effort, fire-and-forget).
    let event = EventKind::ProfileActivationFailed {
        target,
        reason: "transaction rolled back".into(),
    };
    let _ = broadcast(bus, daemon_id, event).await;
}
