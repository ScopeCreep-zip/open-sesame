//! Key rotation: two-phase Noise IK keypair rotation with grace period,
//! and shared keypair generation helper (DRY extraction).

use anyhow::Context;
use core_ipc::{BusServer, Message};
use core_profile::{AuditAction, AuditLogger};
use core_types::{DaemonId, EventKind, SecurityLevel};

use crate::{KEY_ROTATION_GRACE, KNOWN_DAEMONS};

/// Per-daemon baseline: (generation, current_pubkey) captured before rotation.
type RotationBaseline = std::collections::HashMap<String, (u64, [u8; 32])>;

/// Snapshot of daemon generations and current pubkeys at phase 1 start.
/// Used by phase 2 to skip daemons that were revoked during the grace period.
static ROTATION_BASELINE: tokio::sync::Mutex<Option<RotationBaseline>> =
    tokio::sync::Mutex::const_new(None);

/// Key rotation phase 1: generate keypairs, write to disk, pre-register in
/// registry, announce pending.
///
/// Returns immediately — does NOT sleep. The grace period is handled by a
/// spawned background task that signals phase 2 via channel.
pub(crate) async fn rotate_keys_phase1<W: std::io::Write>(
    bus: &BusServer,
    daemon_id: DaemonId,
    audit: &mut AuditLogger<W>,
) -> anyhow::Result<()> {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    let noise_params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("valid noise params");
    let builder = snow::Builder::new(noise_params);

    let mut baseline = std::collections::HashMap::new();

    for &(daemon_name, _security_level) in KNOWN_DAEMONS {
        // Snapshot current generation and pubkey before generating the new key.
        let (current_generation, old_pubkey) = {
            let reg = bus.registry_mut().await;
            match reg.find_by_name(daemon_name) {
                Some(id) => (id.generation, Some(id.current_pubkey)),
                None => (0, None),
            }
        };

        let new_keypair = core_ipc::ZeroizingKeypair::new(
            builder
                .generate_keypair()
                .context(format!("failed to generate new keypair for {daemon_name}"))?,
        );

        let mut new_pubkey = [0u8; 32];
        new_pubkey.copy_from_slice(new_keypair.public());

        core_ipc::noise::write_daemon_keypair(daemon_name, new_keypair.as_inner())
            .await
            .context(format!("failed to write rotated keypair for {daemon_name}"))?;

        // Pre-register the new pubkey so daemons reconnecting during the
        // grace period are immediately recognized by the registry.
        {
            let mut reg = bus.registry_mut().await;
            reg.register_pending(daemon_name, new_pubkey);
        }

        let event = EventKind::KeyRotationPending {
            daemon_name: daemon_name.into(),
            new_pubkey,
            grace_period_s: KEY_ROTATION_GRACE,
        };
        let msg = Message::new(&msg_ctx, event, SecurityLevel::Internal, bus.epoch());
        if let Ok(payload) = core_ipc::encode_frame(&msg) {
            bus.publish(&payload, SecurityLevel::Internal).await;
        }

        tracing::info!(
            audit = "key-management",
            event_type = "key-rotation-pending",
            daemon = daemon_name,
            grace_period_s = KEY_ROTATION_GRACE,
            "key rotation announced"
        );

        // Store baseline for phase 2 generation comparison.
        if let Some(old_pk) = old_pubkey {
            baseline.insert(daemon_name.to_owned(), (current_generation, old_pk));
        }

        let _ = audit.append(AuditAction::KeyRotationStarted {
            daemon_name: daemon_name.into(),
            generation: current_generation,
        });
    }

    // Store baseline for phase 2.
    *ROTATION_BASELINE.lock().await = Some(baseline);

    Ok(())
}

/// Key rotation phase 2: finalize registry, announce completion.
///
/// Called after the grace period expires. Promotes pending pubkeys to current,
/// removes old pubkeys from the registry, increments generation counters.
pub(crate) async fn rotate_keys_phase2<W: std::io::Write>(
    bus: &BusServer,
    daemon_id: DaemonId,
    audit: &mut AuditLogger<W>,
) -> anyhow::Result<()> {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    let baseline = ROTATION_BASELINE
        .lock()
        .await
        .take()
        .context("phase 2 called without phase 1 baseline")?;

    // Single lock acquisition for atomic finalization across all daemons.
    {
        let mut reg = bus.registry_mut().await;
        for &(daemon_name, _security_level) in KNOWN_DAEMONS {
            // Check if the daemon's generation advanced since phase 1
            // (crash-restart revocation during grace period).
            let current_gen = reg.find_by_name(daemon_name).map(|id| id.generation);
            let baseline_gen = baseline.get(daemon_name).map(|(generation, _)| *generation);

            if current_gen != baseline_gen {
                tracing::info!(
                    audit = "key-management",
                    event_type = "rotation-skipped",
                    daemon = daemon_name,
                    baseline_gen = ?baseline_gen,
                    current_gen = ?current_gen,
                    "skipping rotation — daemon was revoked during grace period"
                );
                continue;
            }

            if !reg.finalize_rotation(daemon_name) {
                tracing::warn!(
                    daemon = daemon_name,
                    "finalize_rotation returned false — no pending key found"
                );
            }
        }
    }

    // Announce completion for each daemon.
    for &(daemon_name, _security_level) in KNOWN_DAEMONS {
        let event = EventKind::KeyRotationComplete {
            daemon_name: daemon_name.into(),
        };
        let msg = Message::new(&msg_ctx, event, SecurityLevel::Internal, bus.epoch());
        if let Ok(payload) = core_ipc::encode_frame(&msg) {
            bus.publish(&payload, SecurityLevel::Internal).await;
        }

        tracing::info!(
            audit = "key-management",
            event_type = "key-rotation-complete",
            daemon = daemon_name,
            "key rotation finalized"
        );
        let current_generation = bus
            .registry_mut()
            .await
            .find_by_name(daemon_name)
            .map_or(0, |id| id.generation);
        let _ = audit.append(AuditAction::KeyRotationCompleted {
            daemon_name: daemon_name.to_string(),
            generation: current_generation,
        });
    }

    Ok(())
}
