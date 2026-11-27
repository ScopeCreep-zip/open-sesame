//! Two-phase Noise IK keypair rotation of every known daemon.
//!
//! Phase 1 issues each daemon a new keypair, registers its public key as
//! pending beside the current one, and announces it: the daemon reads the
//! keypair and reconnects with it, while either key authenticates it.
//! Phase 2, after the grace period, promotes each pending key to current
//! and retires the old one. A daemon re-registered under a new generation
//! in between (a restart revocation) already holds a fresh key and is left
//! as it is.

use std::collections::BTreeMap;

use core_profile::AuditAction;
use core_types::{Daemon, EventKind};

use crate::dispatch::Hub;
use crate::{KEY_ROTATION_GRACE, KNOWN_DAEMONS};

/// A rotation between its phases: each daemon phase 1 issued a pending key
/// to, with its registry generation then.
#[derive(Debug, Default)]
pub(crate) struct PendingRotation {
    generations: BTreeMap<Daemon, u64>,
}

impl Hub {
    /// Rotation phase 1: issue, pre-register, and announce a new keypair
    /// for every known daemon, then schedule phase 2 after the grace
    /// period. Returns once the keys are announced; it does not wait.
    ///
    /// A daemon whose keypair cannot be issued keeps its current key and
    /// is left out of the rotation; the others rotate.
    ///
    /// # Errors
    ///
    /// When a rotation is already pending (its daemons' grace period has
    /// not ended), or naming every daemon whose keypair could not be
    /// issued.
    pub(crate) async fn begin_key_rotation(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.pending_rotation.is_none(),
            "a key rotation is already pending"
        );
        let generations = self.bus.registry_mut().await.snapshot_generations();
        let mut pending = PendingRotation::default();
        let mut failed = Vec::new();
        for &(daemon, _) in KNOWN_DAEMONS {
            let Some(&generation) = generations.get(daemon.name()) else {
                tracing::error!(%daemon, "known daemon not registered, not rotated");
                failed.push(daemon.name());
                continue;
            };
            let new_pubkey =
                match core_ipc::noise::issue_daemon_keypair(&self.layout, daemon.name()).await {
                    Ok(public) => public,
                    Err(e) => {
                        tracing::error!(error = %e, %daemon, "failed to issue a rotated keypair");
                        failed.push(daemon.name());
                        continue;
                    }
                };
            // Registered before the announcement, so the daemon's
            // reconnection with the new key is recognized.
            self.bus
                .registry_mut()
                .await
                .register_pending(daemon.name(), new_pubkey);
            pending.generations.insert(daemon, generation);
            self.record(&AuditAction::KeyRotationStarted {
                daemon_name: daemon.name().into(),
                generation,
            });
            self.announce(EventKind::KeyRotationPending {
                daemon_name: daemon.name().into(),
                new_pubkey,
                grace_period_s: KEY_ROTATION_GRACE,
            })
            .await;
            tracing::info!(
                audit = "key-management",
                event_type = "key-rotation-pending",
                %daemon,
                generation,
                grace_period_s = KEY_ROTATION_GRACE,
                "key rotation announced"
            );
        }
        if !pending.generations.is_empty() {
            self.pending_rotation = Some(pending);
            self.schedule_rotation_phase2();
        }
        anyhow::ensure!(
            failed.is_empty(),
            "failed to rotate the keys of {}",
            failed.join(", ")
        );
        Ok(())
    }

    /// Rotation phase 2: promote each pending key to current, retire the
    /// old one, and announce and audit each promotion.
    pub(crate) async fn finish_key_rotation(&mut self) {
        let Some(pending) = self.pending_rotation.take() else {
            tracing::warn!("rotation phase 2 signalled with no rotation pending");
            return;
        };
        let promoted: Vec<(Daemon, u64)> = {
            let mut registry = self.bus.registry_mut().await;
            pending
                .generations
                .into_iter()
                .filter_map(|(daemon, generation)| {
                    let current = registry.find_by_name(daemon.name()).map(|r| r.generation);
                    if current != Some(generation) {
                        tracing::info!(
                            audit = "key-management",
                            event_type = "rotation-skipped",
                            %daemon,
                            rotated_generation = generation,
                            current_generation = ?current,
                            "re-registered during the grace period, rotation skipped"
                        );
                        return None;
                    }
                    if registry.finalize_rotation(daemon.name()) {
                        Some((daemon, generation + 1))
                    } else {
                        tracing::warn!(%daemon, "no pending key to promote");
                        None
                    }
                })
                .collect()
        };
        for (daemon, generation) in promoted {
            self.record(&AuditAction::KeyRotationCompleted {
                daemon_name: daemon.name().into(),
                generation,
            });
            tracing::info!(
                audit = "key-management",
                event_type = "key-rotation-complete",
                %daemon,
                generation,
                "key rotation finalized"
            );
            self.announce(EventKind::KeyRotationComplete {
                daemon_name: daemon.name().into(),
            })
            .await;
        }
    }
}
