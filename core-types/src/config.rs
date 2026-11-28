//! Configuration observation and consumer application contracts carried over IPC.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Content identity of the ordered source documents, including installation identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRevision(pub [u8; 32]);

/// Latest observation, independent of resource application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconcileStatus {
    /// No observation has completed.
    Pending,
    /// The latest observed layers passed validation.
    Accepted,
    /// The latest observed layers failed validation.
    Rejected(String),
    /// The layers could not be captured consistently.
    Unreadable(String),
}

impl ReconcileStatus {
    /// Require an accepted observation.
    ///
    /// # Errors
    ///
    /// No observation completed, or the latest observation failed.
    pub fn into_result(self) -> crate::Result<()> {
        match self {
            Self::Accepted => Ok(()),
            Self::Rejected(message) | Self::Unreadable(message) => {
                Err(crate::Error::Config(message))
            }
            Self::Pending => Err(crate::Error::Config(
                "no configuration observation completed".into(),
            )),
        }
    }
}

/// Native event coverage; timer reconciliation remains active in either state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchStatus {
    /// Every requested directory registration succeeded.
    Native,
    /// Some native event coverage is unavailable, with its causes.
    Degraded(Vec<String>),
}

/// Observation health acquired atomically with the accepted configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigStatus {
    /// Latest acquisition and validation result.
    pub reconciliation: ReconcileStatus,
    /// Latest native registration result.
    pub watch: WatchStatus,
}

/// A consumer's result for its latest application attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigApplication {
    /// No candidate has reached the consumer.
    Pending,
    /// Resource preparation or acknowledgement is outstanding.
    Applying {
        revision: ConfigRevision,
        attempt: Uuid,
    },
    /// Every relevant field is applied.
    Applied { revision: ConfigRevision },
    /// Preparation or application failed.
    Rejected {
        revision: ConfigRevision,
        reason: String,
    },
    /// These fields cannot be changed in the running process.
    RestartRequired {
        revision: ConfigRevision,
        fields: Vec<String>,
    },
}

/// The independently observable acquisition and application sides of convergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigConsumerStatus {
    /// Most recently accepted source revision; absent before first acceptance.
    pub accepted: Option<ConfigRevision>,
    /// Last fully applied revision, retained when a subsequent attempt fails.
    pub applied: Option<ConfigRevision>,
    /// Current observation and event coverage.
    pub observation: ConfigStatus,
    /// Current consumer-owned application result.
    pub application: ConfigApplication,
}

impl ConfigConsumerStatus {
    /// The revision this consumer accepted and fully applied: the one
    /// definition of convergence every reporter uses.
    ///
    /// # Errors
    ///
    /// Why the consumer has not converged: a failed or pending observation,
    /// or an application that is outstanding, rejected, restart-required,
    /// or of an older revision than the accepted one.
    pub fn converged(&self) -> Result<ConfigRevision, String> {
        if self.observation.reconciliation != ReconcileStatus::Accepted {
            return Err(format!(
                "observation: {:?}",
                self.observation.reconciliation
            ));
        }
        match (&self.application, self.accepted, self.applied) {
            (ConfigApplication::Applied { revision }, Some(accepted), Some(applied))
                if *revision == accepted && applied == accepted =>
            {
                Ok(accepted)
            }
            (application, ..) => Err(format!("application: {application:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(
        application: ConfigApplication,
        applied: Option<ConfigRevision>,
    ) -> ConfigConsumerStatus {
        ConfigConsumerStatus {
            accepted: Some(ConfigRevision([1; 32])),
            applied,
            observation: ConfigStatus {
                reconciliation: ReconcileStatus::Accepted,
                watch: WatchStatus::Native,
            },
            application,
        }
    }

    #[test]
    fn only_the_applied_accepted_revision_is_converged() {
        let (current, older) = (ConfigRevision([1; 32]), ConfigRevision([2; 32]));
        assert_eq!(
            status(
                ConfigApplication::Applied { revision: current },
                Some(current)
            )
            .converged(),
            Ok(current)
        );
        assert!(
            status(ConfigApplication::Applied { revision: older }, Some(older))
                .converged()
                .is_err()
        );
        assert!(
            status(
                ConfigApplication::RestartRequired {
                    revision: current,
                    fields: vec!["crypto".into()],
                },
                Some(older)
            )
            .converged()
            .is_err()
        );
        let mut rejected = status(
            ConfigApplication::Applied { revision: current },
            Some(current),
        );
        rejected.observation.reconciliation = ReconcileStatus::Rejected("bad".into());
        assert!(rejected.converged().is_err());
    }
}
