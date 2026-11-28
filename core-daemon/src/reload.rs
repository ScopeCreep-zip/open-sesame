//! Consumer-owned configuration application, distinct from source acceptance.

use std::sync::{Arc, Mutex, MutexGuard};

use core_config::{ConfigSnapshot, ConfigState};
use core_ipc::BusClient;
use core_types::{
    ConfigApplication, ConfigConsumerStatus, EventKind, ReconcileStatus, SecurityLevel,
};
use uuid::Uuid;

#[derive(Debug)]
struct Applied {
    snapshot: Option<ConfigSnapshot>,
    application: ConfigApplication,
}

impl Applied {
    /// Whether this consumer applied exactly the observation `observed`:
    /// the one rule authorization and retry decide by.
    fn is_current(&self, observed: &ConfigSnapshot) -> bool {
        matches!(self.application, ConfigApplication::Applied { revision } if revision == observed.revision)
            && self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.observation == observed.observation)
    }
}

/// Readable consumer application state; only a reload acknowledgement publishes into it.
#[derive(Debug, Clone)]
pub struct ConfigApplicationState {
    observed: ConfigState,
    startup: core_config::Config,
    applied: Arc<Mutex<Applied>>,
}

impl ConfigApplicationState {
    pub(crate) fn new(observed: ConfigState, startup: core_config::Config) -> Self {
        Self {
            observed,
            startup,
            applied: Arc::new(Mutex::new(Applied {
                snapshot: None,
                application: ConfigApplication::Pending,
            })),
        }
    }

    /// The application record, under its lock. A panic while holding it
    /// leaves no record that can be trusted, so poisoning is fatal.
    fn lock(&self) -> MutexGuard<'_, Applied> {
        self.applied
            .lock()
            .expect("configuration application lock poisoned")
    }

    /// Whether the latest accepted observation still awaits application: a
    /// failed or abandoned attempt is retried on the reconciliation timer.
    pub(crate) fn needs_retry(&self) -> anyhow::Result<bool> {
        let observed = self.observed.snapshot()?;
        let applied = self.lock();
        Ok(observed.status.reconciliation == ReconcileStatus::Accepted
            && match applied.application {
                ConfigApplication::Pending | ConfigApplication::Rejected { .. } => true,
                ConfigApplication::Applied { .. } => !applied.is_current(&observed),
                ConfigApplication::Applying { .. } | ConfigApplication::RestartRequired { .. } => {
                    false
                }
            })
    }

    /// Record loss of a resource previously acknowledged by this consumer.
    pub fn resource_lost(&self, reason: String) {
        let mut applied = self.lock();
        if let Some(snapshot) = &applied.snapshot {
            applied.application = ConfigApplication::Rejected {
                revision: snapshot.revision,
                reason,
            };
        }
    }

    /// Configuration actually committed by this consumer.
    ///
    /// # Errors
    ///
    /// The consumer has not applied its startup configuration.
    pub fn snapshot(&self) -> anyhow::Result<ConfigSnapshot> {
        self.lock()
            .snapshot
            .clone()
            .ok_or_else(|| anyhow::anyhow!("configuration has not been applied"))
    }

    /// Acquire accepted policy only when the consumer has applied that observation.
    ///
    /// # Errors
    ///
    /// Observation failure, pending application, rejection, or restart-required changes.
    pub fn policy(&self) -> anyhow::Result<core_config::Config> {
        let observed = self.observed.snapshot()?;
        observed.status.reconciliation.clone().into_result()?;
        anyhow::ensure!(
            self.lock().is_current(&observed),
            "accepted authorization policy has not been applied"
        );
        Ok(observed.config)
    }

    /// Observe acceptance and application independently.
    ///
    /// # Errors
    ///
    /// The observation lock is poisoned.
    pub fn status(&self) -> anyhow::Result<ConfigConsumerStatus> {
        let observed = self.observed.snapshot()?;
        let applied = self.lock();
        let application = match &applied.application {
            ConfigApplication::Applied { .. } if !applied.is_current(&observed) => {
                ConfigApplication::Pending
            }
            application => application.clone(),
        };
        Ok(ConfigConsumerStatus {
            accepted: Some(observed.revision),
            applied: applied.snapshot.as_ref().map(|snapshot| snapshot.revision),
            observation: observed.status,
            application,
        })
    }

    /// The fields of `candidate` this process cannot change while running:
    /// those its startup read (sandbox floor, bus, cryptography) and the
    /// installation identity it applied.
    fn restart_fields(
        &self,
        candidate: &ConfigSnapshot,
        previous: Option<&ConfigSnapshot>,
    ) -> anyhow::Result<Vec<String>> {
        let mut fields = Vec::new();
        if candidate.config.global.sandbox != self.startup.global.sandbox {
            fields.push("global.sandbox".into());
        }
        if candidate.config.global.ipc != self.startup.global.ipc {
            fields.push("global.ipc".into());
        }
        if candidate.config.crypto()? != self.startup.crypto()? {
            fields.push("crypto".into());
        }
        if let Some(identity) = previous.and_then(|previous| previous.installation.as_ref())
            && Some(identity.identity()?)
                != candidate
                    .installation
                    .as_ref()
                    .map(core_config::InstallationConfig::identity)
                    .transpose()?
        {
            fields.push("installation".into());
        }
        Ok(fields)
    }

    pub(crate) fn begin(&self) -> anyhow::Result<Reload> {
        let snapshot = self.observed.snapshot()?;
        snapshot.status.reconciliation.clone().into_result()?;
        let attempt = Uuid::new_v4();
        let fields = {
            let mut applied = self.lock();
            let fields = self.restart_fields(&snapshot, applied.snapshot.as_ref())?;
            applied.application = ConfigApplication::Applying {
                revision: snapshot.revision,
                attempt,
            };
            fields
        };
        let reload = Reload {
            snapshot: Box::new(snapshot),
            attempt,
            state: self.clone(),
            finished: false,
        };
        if fields.is_empty() {
            Ok(reload)
        } else {
            let reason = format!("configuration requires restart: {}", fields.join(", "));
            reload.restart_required(fields);
            anyhow::bail!(reason)
        }
    }
}

/// A candidate whose owner must confirm resource application or record its failure.
#[derive(Debug)]
#[must_use = "configuration candidates require a resource acknowledgement or rejection"]
pub struct Reload {
    /// Coherent candidate to prepare and apply. Boxed: a reload travels in
    /// every daemon's wake-up enum beside small variants.
    pub snapshot: Box<ConfigSnapshot>,
    attempt: Uuid,
    state: ConfigApplicationState,
    finished: bool,
}

impl Reload {
    /// Correlates an asynchronous resource acknowledgement with this attempt.
    #[must_use]
    pub fn attempt(&self) -> Uuid {
        self.attempt
    }

    /// Record failure while retaining the previous applied configuration.
    pub fn reject(mut self, reason: String) {
        self.finish_rejected(reason);
    }

    /// Record fields requiring process replacement, retaining the applied configuration.
    pub fn restart_required(mut self, fields: Vec<String>) {
        let revision = self.snapshot.revision;
        self.finish(
            ConfigApplication::RestartRequired { revision, fields },
            false,
        );
    }

    fn finish_rejected(&mut self, reason: String) {
        let revision = self.snapshot.revision;
        self.finish(ConfigApplication::Rejected { revision, reason }, false);
    }

    /// Record `result` for this attempt unless a later attempt superseded
    /// it; with `commit`, record the settings adopted by resources even if
    /// observation advanced, but certify success only for the current observation.
    fn finish(&mut self, result: ConfigApplication, commit: bool) -> bool {
        self.finished = true;
        let mut applied = self.state.lock();
        if !matches!(applied.application, ConfigApplication::Applying { attempt, .. } if attempt == self.attempt)
        {
            return false;
        }
        if commit {
            let revision = self.snapshot.revision;
            // A stale resource completion cannot certify a newer observation.
            let current = match self.state.observed.snapshot() {
                Ok(current) => current,
                Err(error) => {
                    let reason = error.to_string();
                    applied.application = ConfigApplication::Rejected { revision, reason };
                    return false;
                }
            };
            applied.snapshot = Some(ConfigSnapshot::clone(&self.snapshot));
            if current.observation != self.snapshot.observation
                || current.status.reconciliation != ReconcileStatus::Accepted
            {
                applied.application = ConfigApplication::Rejected {
                    revision,
                    reason: "candidate superseded before resource acknowledgement".into(),
                };
                return false;
            }
        }
        applied.application = result;
        true
    }

    /// Commit after resource acknowledgement; only this transition creates a success event.
    #[must_use]
    pub fn applied_event(mut self, daemon_id: core_types::DaemonId) -> Option<EventKind> {
        let revision = self.snapshot.revision;
        self.finish(ConfigApplication::Applied { revision }, true)
            .then_some(EventKind::ConfigReloaded {
                daemon_id,
                revision,
            })
    }

    /// Commit acknowledged resources and announce the applied revision.
    pub async fn applied(self, client: &BusClient) {
        if let Some(event) = self.applied_event(client.daemon_id()) {
            client
                .publish_or_log("ConfigReloaded", event, SecurityLevel::Internal)
                .await;
        }
    }
}

impl Drop for Reload {
    fn drop(&mut self) {
        if !self.finished {
            self.finish_rejected(
                "consumer dropped the candidate without acknowledging its resources".into(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, core_layout::Layout, crate::ConfigWatch) {
        let root = tempfile::tempdir().unwrap();
        let layout = core_layout::Layout::under(root.path());
        layout.bootstrap().unwrap();
        let watch = crate::watch_config(&layout, core_config::Config::default()).unwrap();
        (root, layout, watch)
    }

    #[tokio::test]
    async fn acknowledgement_and_abandonment_preserve_application_truth() {
        let (_root, _layout, mut watch) = fixture();
        assert!(watch.application().policy().is_err());
        let initial = watch.candidate().unwrap();
        let revision = initial.snapshot.revision;
        assert!(initial.applied_event(core_types::DaemonId::new()).is_some());
        assert!(watch.application().policy().is_ok());
        drop(watch.candidate().unwrap());
        let status = watch.application().status().unwrap();
        assert_eq!(status.applied, Some(revision));
        assert!(matches!(
            status.application,
            ConfigApplication::Rejected { .. }
        ));
        assert!(watch.application().policy().is_err());
        assert!(watch.application().needs_retry().unwrap());
    }

    #[tokio::test]
    async fn superseded_attempt_cannot_acknowledge_the_new_attempt() {
        let (_root, _layout, mut watch) = fixture();
        let old = watch.candidate().unwrap();
        let current = watch.candidate().unwrap();
        assert!(old.applied_event(core_types::DaemonId::new()).is_none());
        assert!(matches!(watch.application().status().unwrap().application,
            ConfigApplication::Applying { attempt, .. } if attempt == current.attempt()));
        assert!(current.applied_event(core_types::DaemonId::new()).is_some());
    }

    #[tokio::test]
    async fn failed_observation_and_restart_changes_block_policy() {
        let (_root, layout, mut watch) = fixture();
        let _ = watch
            .candidate()
            .unwrap()
            .applied_event(core_types::DaemonId::new());
        std::fs::write(layout.config_file().unwrap(), "[broken").unwrap();
        assert!(watch.reconcile().await.is_err());
        assert!(watch.application().policy().is_err());
        std::fs::write(
            layout.config_file().unwrap(),
            "[global.ipc]\nchannel_capacity = 17\n",
        )
        .unwrap();
        watch.reconcile().await.unwrap();
        assert!(watch.candidate().is_err());
        assert!(matches!(
            watch.application().status().unwrap().application,
            ConfigApplication::RestartRequired { .. }
        ));
        assert!(watch.application().policy().is_err());
    }

    #[tokio::test]
    async fn stale_observation_completion_reports_adoption_without_convergence() {
        let (_root, layout, mut watch) = fixture();
        let old = watch.candidate().unwrap();
        let old_revision = old.snapshot.revision;
        std::fs::write(layout.config_file().unwrap(), "[profiles.work]\n").unwrap();
        watch.reconcile().await.unwrap();
        assert!(old.applied_event(core_types::DaemonId::new()).is_none());
        let status = watch.application().status().unwrap();
        assert_eq!(status.applied, Some(old_revision));
        assert_ne!(status.accepted, status.applied);
        assert!(status.converged().is_err());
        assert!(watch.application().policy().is_err());
        assert!(
            watch
                .candidate()
                .unwrap()
                .applied_event(core_types::DaemonId::new())
                .is_some()
        );
        assert!(watch.application().policy().is_ok());
        assert!(watch.application().status().unwrap().converged().is_ok());
    }

    #[tokio::test]
    async fn returning_to_identical_sources_requires_a_new_observation_acknowledgement() {
        let (_root, layout, mut watch) = fixture();
        let initial = watch.candidate().unwrap();
        let revision = initial.snapshot.revision;
        assert!(initial.applied_event(core_types::DaemonId::new()).is_some());
        let path = layout.config_file().unwrap();
        std::fs::write(&path, "[profiles.work]\n").unwrap();
        watch.reconcile().await.unwrap();
        std::fs::remove_file(&path).unwrap();
        watch.reconcile().await.unwrap();

        let status = watch.application().status().unwrap();
        assert_eq!(status.accepted, Some(revision));
        assert_eq!(status.applied, Some(revision));
        assert!(status.converged().is_err());
        assert!(watch.application().policy().is_err());
        assert!(watch.application().needs_retry().unwrap());
        assert!(
            watch
                .candidate()
                .unwrap()
                .applied_event(core_types::DaemonId::new())
                .is_some()
        );
        assert!(watch.application().status().unwrap().converged().is_ok());
    }
}
