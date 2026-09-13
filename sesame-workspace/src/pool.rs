//! Bounded worker pool for parallel repository inspection.
//!
//! Spawns `num_workers` OS threads via [`std::thread::scope`]. Workers pull
//! jobs from a bounded [`crossbeam_channel`]. Results flow back through a
//! second bounded channel. No persistent pool, no global state, no cache.
//!
//! # Parallelism budget
//!
//! This layer owns the entire parallelism budget. gitoxide is compiled with
//! `default-features = false` (verified in workspace `Cargo.toml`), so its
//! internal parallel feature is disabled. Each worker runs single-threaded
//! gitoxide calls serially, preventing `num_workers * gix_threads`
//! oversubscription.
//!
//! # Dispatch order
//!
//! Jobs are sorted by estimated cost (descending) before entering the
//! channel. The channel is FIFO, so workers pick up the most expensive repos
//! first, preventing head-of-line blocking from the slowest repo arriving
//! last.
//!
//! # Panic safety
//!
//! Each job is wrapped in [`std::panic::catch_unwind`] inside
//! [`inspect_one_job`]. A panicking `inspect()` call produces an
//! `Err(InspectError)` for that job; the worker continues processing
//! subsequent jobs. This prevents [`std::thread::scope`] from discarding
//! all collected results when a single repo triggers a panic in gitoxide.
//!
//! # Cancellation
//!
//! A shared [`AtomicBool`] enables fleet-wide cancellation. Workers check it
//! before starting each job (not mid-repo). In-flight status checks run to
//! completion. Worst-case overshoot is one repo's status time.

use crossbeam_channel::{bounded, Receiver, Sender};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::inspection::{InspectionRequest, InspectionResult};

/// A unit of work dispatched to a pool worker.
pub struct InspectJob {
    pub path: PathBuf,
    pub request: InspectionRequest,
    pub index: usize,
    pub estimated_cost: u64,
}

/// Result of a single repo inspection, tagged with its dispatch index.
pub struct InspectResult {
    pub index: usize,
    pub result: Result<InspectionResult, InspectError>,
    pub elapsed_ms: u64,
}

/// Inspection error with diagnostic context.
#[derive(Debug)]
pub struct InspectError {
    pub path: PathBuf,
    pub message: String,
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for InspectError {}

/// Estimate inspection cost from `.git/index` file size in KB.
#[must_use]
pub fn estimate_cost(path: &Path) -> u64 {
    let index_path = path.join(".git").join("index");
    std::fs::metadata(&index_path).map_or(100, |m| m.len() / 1024)
}

/// Inspect a single job with panic recovery.
///
/// Wraps `crate::inspection::inspect` in `catch_unwind` so a panic
/// in gitoxide for one repository produces an error result instead
/// of killing the worker thread. Returns the inspection result or
/// an error with the panic message.
fn inspect_one_job(
    job: &InspectJob,
    cancel: &AtomicBool,
) -> Result<InspectionResult, InspectError> {
    if cancel.load(Ordering::Relaxed) {
        return Ok(InspectionResult::skipped());
    }

    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::inspection::inspect(&job.path, &job.request)
    })) {
        Ok(Ok(insp)) => Ok(insp),
        Ok(Err(e)) => Err(InspectError {
            path: job.path.clone(),
            message: format!("{e:#}"),
        }),
        Err(panic_payload) => {
            let msg = panic_payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            tracing::error!(
                path = %job.path.display(),
                panic = %msg,
                "inspection panicked"
            );
            Err(InspectError {
                path: job.path.clone(),
                message: format!("panic: {msg}"),
            })
        }
    }
}

/// Run `jobs` across `num_workers` threads, returning results in completion order.
///
/// See module docs for dispatch order, panic safety, and cancellation semantics.
pub fn run_inspections<F>(
    mut jobs: Vec<InspectJob>,
    num_workers: usize,
    cancel: &AtomicBool,
    on_complete: F,
) -> Vec<InspectResult>
where
    F: Fn(usize, usize, &str, u64) + Send + Sync,
{
    let total = jobs.len();
    if total == 0 {
        return Vec::new();
    }

    let num_workers = num_workers.clamp(1, 64).min(total);
    let completed = AtomicUsize::new(0);

    // Sort descending by cost so most expensive repos dispatch first.
    jobs.sort_unstable_by_key(|j| std::cmp::Reverse(j.estimated_cost));

    let (job_tx, job_rx): (Sender<InspectJob>, Receiver<InspectJob>) = bounded(num_workers);
    let (result_tx, result_rx): (Sender<InspectResult>, Receiver<InspectResult>) = bounded(total);

    std::thread::scope(|scope| {
        for worker_id in 0..num_workers {
            let rx = job_rx.clone();
            let tx = result_tx.clone();
            let cancel = &cancel;
            let completed = &completed;
            let on_complete = &on_complete;

            scope.spawn(move || {
                tracing::debug!(worker_id, "inspection worker started");

                for job in &rx {
                    let start = std::time::Instant::now();
                    let job_index = job.index;
                    let job_path = job.path.clone();
                    let repo_name = job.path.file_name()
                        .map_or_else(|| "?".into(), |n| n.to_string_lossy().into_owned());

                    let result = inspect_one_job(&job, cancel);

                    let elapsed_ms = u64::try_from(start.elapsed().as_millis())
                        .unwrap_or(u64::MAX);
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    on_complete(done, total, &repo_name, elapsed_ms);

                    if elapsed_ms > 100 {
                        tracing::debug!(
                            worker_id,
                            path = %job_path.display(),
                            elapsed_ms,
                            "slow inspection"
                        );
                    }

                    if tx.send(InspectResult {
                        index: job_index,
                        result,
                        elapsed_ms,
                    }).is_err() {
                        tracing::debug!(worker_id, "result channel closed, worker exiting");
                        break;
                    }
                }

                tracing::debug!(worker_id, "inspection worker finished");
            });
        }

        // Drop worker-side channel endpoints so channels close when all
        // workers finish.
        drop(job_rx);
        drop(result_tx);

        // Feed jobs into channel. bounded(num_workers) provides
        // natural backpressure.
        for job in jobs {
            if job_tx.send(job).is_err() {
                tracing::warn!("all inspection workers exited, aborting job dispatch");
                break;
            }
        }
        drop(job_tx);

        let results: Vec<InspectResult> = result_rx.iter().collect();

        tracing::debug!(
            total_results = results.len(),
            total_jobs = total,
            "inspection pool complete"
        );

        results
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn all_results_returned() {
        let jobs: Vec<InspectJob> = (0..8)
            .map(|i| InspectJob {
                path: PathBuf::from(format!("/tmp/fake-repo-{i}")),
                request: InspectionRequest::default(),
                index: i,
                estimated_cost: 0,
            })
            .collect();

        let cancel = AtomicBool::new(false);
        let results = run_inspections(jobs, 4, &cancel, |_, _, _, _| {});

        assert_eq!(results.len(), 8);
        let mut indices: Vec<usize> = results.iter().map(|r| r.index).collect();
        indices.sort();
        assert_eq!(indices, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn cancellation_skips_remaining() {
        let jobs: Vec<InspectJob> = (0..4)
            .map(|i| InspectJob {
                path: PathBuf::from(format!("/tmp/fake-repo-{i}")),
                request: InspectionRequest::default(),
                index: i,
                estimated_cost: 0,
            })
            .collect();

        let cancel = AtomicBool::new(true);
        let results = run_inspections(jobs, 2, &cancel, |_, _, _, _| {});

        assert_eq!(results.len(), 4);
        for r in &results {
            assert!(r.result.is_ok());
        }
    }

    #[test]
    fn cost_sorted_dispatch() {
        use std::sync::Mutex;

        let dispatch_order = std::sync::Arc::new(Mutex::new(Vec::new()));
        let order_clone = dispatch_order.clone();

        let jobs: Vec<InspectJob> = vec![
            InspectJob {
                path: PathBuf::from("/tmp/cheap"),
                request: InspectionRequest::default(),
                index: 0,
                estimated_cost: 10,
            },
            InspectJob {
                path: PathBuf::from("/tmp/expensive"),
                request: InspectionRequest::default(),
                index: 1,
                estimated_cost: 10000,
            },
            InspectJob {
                path: PathBuf::from("/tmp/medium"),
                request: InspectionRequest::default(),
                index: 2,
                estimated_cost: 500,
            },
        ];

        let cancel = AtomicBool::new(false);

        let _ = run_inspections(jobs, 1, &cancel, move |_, _, name, _| {
            order_clone.lock().unwrap().push(name.to_string());
        });

        let order = dispatch_order.lock().unwrap();
        assert_eq!(order[0], "expensive");
        assert_eq!(order[1], "medium");
        assert_eq!(order[2], "cheap");
    }

    #[test]
    fn inspect_one_job_cancelled() {
        let job = InspectJob {
            path: PathBuf::from("/tmp/fake"),
            request: InspectionRequest::default(),
            index: 0,
            estimated_cost: 0,
        };
        let cancel = AtomicBool::new(true);
        let result = inspect_one_job(&job, &cancel);
        assert!(result.is_ok());
    }

    #[test]
    fn inspect_one_job_nonexistent_repo() {
        let job = InspectJob {
            path: PathBuf::from("/tmp/nonexistent-repo-for-test"),
            request: InspectionRequest::all(),
            index: 0,
            estimated_cost: 0,
        };
        let cancel = AtomicBool::new(false);
        let result = inspect_one_job(&job, &cancel);
        assert!(result.is_err());
    }
}
