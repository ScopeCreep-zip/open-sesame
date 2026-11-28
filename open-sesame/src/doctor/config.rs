//! Configuration convergence: each daemon, asked through its own targeted
//! RPC (the bus delivers `ConfigStatusRequest { daemon }` to that daemon
//! alone and accepts only its answer), against the revision of the sources
//! on disk.

use core_layout::Layout;
use core_types::{ConfigConsumerStatus, ConfigRevision, EventKind, SecurityLevel, WatchStatus};

use super::{Check, Status};

const CATEGORY: &str = "config";

/// The check of a daemon reporting `status` while the sources on disk are
/// `expected` (`ConfigConsumerStatus::converged`).
fn convergence(status: &ConfigConsumerStatus, expected: ConfigRevision) -> (Status, String) {
    match status.converged() {
        Err(reason) => (Status::Fail, reason),
        Ok(revision) if revision != expected => (
            Status::Fail,
            "applied sources differ from the sources on disk".into(),
        ),
        Ok(_) => match &status.observation.watch {
            WatchStatus::Native => (
                Status::Pass,
                "accepted and applied the sources on disk".into(),
            ),
            WatchStatus::Degraded(errors) => (
                Status::Warn,
                format!(
                    "converged; timer reconciliation only: {}",
                    errors.join("; ")
                ),
            ),
        },
    }
}

/// One check per daemon, and a failed `config.sources` check when the
/// sources cannot be read or change while the daemons are asked.
pub(super) async fn checks(layout: &Layout) -> Vec<Check> {
    let daemons = match super::probe::expected_daemons() {
        Ok(daemons) => daemons,
        Err(error) => {
            return vec![Check::probe_failed(
                "config.applicability",
                CATEGORY,
                &error,
            )];
        }
    };
    let sources_failed = |error: core_types::Error| {
        vec![Check::probe_failed(
            "config.sources",
            CATEGORY,
            &error.into(),
        )]
    };
    let expected = match core_config::source_revision(layout) {
        Ok(revision) => revision,
        Err(error) => return sources_failed(error),
    };
    let client = match crate::ipc::connect(layout).await {
        Ok(client) => client,
        Err(error) => return vec![Check::probe_failed("config.bus", CATEGORY, &error)],
    };
    let mut checks = Vec::new();
    for daemon in daemons {
        let id = format!("config.{}.convergence", daemon.short_name());
        let response = crate::ipc::rpc(
            &client,
            EventKind::ConfigStatusRequest { daemon },
            SecurityLevel::Internal,
        )
        .await;
        checks.push(match response {
            Ok(EventKind::ConfigStatusResponse {
                daemon: responder,
                status,
            }) if responder == daemon => {
                let (severity, value) = convergence(&status, expected);
                Check::new(
                    id,
                    CATEGORY,
                    severity,
                    value,
                    "source acceptance, consumer acknowledgement, and native watch health",
                )
            }
            Ok(other) => Check::probe_failed(id, CATEGORY, &crate::helpers::unexpected(&other)),
            Err(error) => Check::probe_failed(id, CATEGORY, &error),
        });
    }
    match core_config::source_revision(layout) {
        Ok(revision) if revision == expected => {}
        Ok(_) => checks.push(Check::new(
            "config.sources",
            CATEGORY,
            Status::Fail,
            "sources changed during the probe",
            "repeat the convergence check",
        )),
        Err(error) => checks.extend(sources_failed(error)),
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{ConfigApplication, ConfigStatus, ReconcileStatus};

    fn current() -> ConfigConsumerStatus {
        let revision = ConfigRevision([1; 32]);
        ConfigConsumerStatus {
            accepted: Some(revision),
            applied: Some(revision),
            observation: ConfigStatus {
                reconciliation: ReconcileStatus::Accepted,
                watch: WatchStatus::Native,
            },
            application: ConfigApplication::Applied { revision },
        }
    }

    #[test]
    fn native_convergence_passes_and_timer_fallback_warns() {
        let mut status = current();
        let revision = status.accepted.unwrap();
        assert!(matches!(convergence(&status, revision).0, Status::Pass));
        status.observation.watch = WatchStatus::Degraded(vec!["watch limit".into()]);
        assert!(matches!(convergence(&status, revision).0, Status::Warn));
        assert!(matches!(
            convergence(&status, ConfigRevision([2; 32])).0,
            Status::Fail
        ));
    }

    #[test]
    fn observation_and_application_failures_never_report_convergence() {
        let revision = ConfigRevision([1; 32]);
        for observation in [
            ReconcileStatus::Pending,
            ReconcileStatus::Rejected("invalid policy".into()),
            ReconcileStatus::Unreadable("permission denied".into()),
        ] {
            let mut status = current();
            status.observation.reconciliation = observation;
            assert!(matches!(convergence(&status, revision).0, Status::Fail));
        }
        for application in [
            ConfigApplication::Pending,
            ConfigApplication::Applying {
                revision,
                attempt: uuid::Uuid::new_v4(),
            },
            ConfigApplication::Rejected {
                revision,
                reason: "resource unavailable".into(),
            },
            ConfigApplication::RestartRequired {
                revision,
                fields: vec!["crypto".into()],
            },
        ] {
            let mut status = current();
            status.application = application;
            assert!(matches!(convergence(&status, revision).0, Status::Fail));
        }
    }
}
