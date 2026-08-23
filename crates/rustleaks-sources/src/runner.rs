use std::num::NonZeroUsize;
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;

use rustleaks_core::model::{ByteText, Finding, Fragment, ScanOptions};
use rustleaks_core::session::{ScanSession, SessionBatch, SessionPolicy};
use rustleaks_core::{Engine, ScanControl, ScanOutcome};

use crate::{
    CallbackError, CancellationToken, Source, SourceConfigError, SourceControl, SourceError,
    SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

/// Terminal state of a bounded source run.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceTermination {
    /// The source and all workers completed normally.
    Completed,
    /// The source callback requested a normal stop.
    Stopped,
    /// Cooperative cancellation was observed and all workers were joined.
    Cancelled,
    /// The source stopped with a terminal error after workers were joined.
    SourceError(SourceError),
    /// At least one detection worker panicked; every worker was still joined.
    WorkerPanic,
}

/// Owned results of scanning one source.
#[derive(Clone, Debug)]
pub struct SourceOutcome {
    findings: Vec<Finding>,
    issues: Vec<SourceIssue>,
    termination: SourceTermination,
    scanned_bytes: u64,
    unique_commits: Vec<ByteText>,
}

struct SourceStatistics {
    scanned_bytes: u64,
    unique_commits: Vec<ByteText>,
    maximum_unique_commits: usize,
}

const MAX_UNIQUE_COMMITS: usize = 1_000_000;

impl Default for SourceStatistics {
    fn default() -> Self {
        Self {
            scanned_bytes: 0,
            unique_commits: Vec::new(),
            maximum_unique_commits: MAX_UNIQUE_COMMITS,
        }
    }
}

impl SourceStatistics {
    fn observe(&mut self, fragment: &Fragment) -> Result<(), CallbackError> {
        let fragment_bytes = u64::try_from(fragment.content().len()).map_err(|_| {
            CallbackError::new("fragment byte count does not fit source statistics")
        })?;
        self.scanned_bytes = self
            .scanned_bytes
            .checked_add(fragment_bytes)
            .ok_or_else(|| CallbackError::new("source scanned-byte count overflowed"))?;
        if !fragment.commit().is_empty() {
            let commit = fragment.commit();
            if !self.unique_commits.iter().any(|known| known == commit) {
                if self.unique_commits.len() == self.maximum_unique_commits {
                    return Err(CallbackError::new(format!(
                        "source unique commit count exceeds the {}-commit safety limit",
                        self.maximum_unique_commits
                    )));
                }
                self.unique_commits.try_reserve(1).map_err(|error| {
                    CallbackError::new(format!("could not retain source commit: {error}"))
                })?;
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(commit.len()).map_err(|error| {
                    CallbackError::new(format!("could not copy source commit: {error}"))
                })?;
                bytes.extend_from_slice(commit.as_bytes());
                self.unique_commits.push(ByteText::new(bytes));
            }
        }
        Ok(())
    }
}

impl SourceOutcome {
    /// Returns accepted, policy-filtered findings.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Returns all recoverable source issues in producer order, followed by
    /// runner issues.
    #[must_use]
    pub fn issues(&self) -> &[SourceIssue] {
        &self.issues
    }

    /// Returns how the run terminated after every worker was joined.
    #[must_use]
    pub const fn termination(&self) -> &SourceTermination {
        &self.termination
    }

    /// Returns the total bytes in error-free fragments presented for scanning.
    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    /// Returns the number of distinct nonempty fragment commit identifiers.
    #[must_use]
    pub fn unique_commit_count(&self) -> usize {
        self.unique_commits.len()
    }

    /// Returns the distinct nonempty fragment commit identifiers in discovery
    /// order.
    ///
    /// The borrowed view lets callers compute an exact union with identities
    /// observed outside the runner without allocating another collection.
    #[must_use]
    pub fn unique_commits(&self) -> &[ByteText] {
        &self.unique_commits
    }

    /// Consumes the outcome into accepted findings.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

/// Caller-configured bounded standard-thread source runner.
///
/// The runner owns no global pool and exports no synchronization primitive.
/// Both single-worker and multi-worker operation use the same bounded queue and
/// session-batch path. Finding order is not a compatibility contract; complete
/// duplicate-preserving multisets are invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRunner {
    workers: NonZeroUsize,
    queue_capacity: NonZeroUsize,
}

impl SourceRunner {
    /// Creates a runner with positive worker and queue bounds.
    ///
    /// # Errors
    ///
    /// Returns [`SourceConfigError`] when either value is zero.
    pub fn new(workers: usize, queue_capacity: usize) -> Result<Self, SourceConfigError> {
        let workers =
            NonZeroUsize::new(workers).ok_or_else(|| SourceConfigError::positive("workers"))?;
        let queue_capacity = NonZeroUsize::new(queue_capacity)
            .ok_or_else(|| SourceConfigError::positive("queue_capacity"))?;
        Ok(Self {
            workers,
            queue_capacity,
        })
    }

    /// Returns the configured worker count.
    #[must_use]
    pub const fn workers(self) -> usize {
        self.workers.get()
    }

    /// Returns the bounded queue capacity.
    #[must_use]
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity.get()
    }

    /// Produces source events, scans fragments, applies one immutable session
    /// policy, joins every worker, and returns owned results.
    #[must_use]
    pub fn run(
        &self,
        source: &mut dyn Source,
        engine: &Engine,
        scan_options: ScanOptions,
        policy: &SessionPolicy,
        cancellation: &CancellationToken,
    ) -> SourceOutcome {
        let (sender, receiver) = mpsc::sync_channel::<Fragment>(self.queue_capacity());
        let receiver = Arc::new(Mutex::new(receiver));
        let mut issues = Vec::new();
        let mut source_result = Ok(SourceControl::Continue);
        let mut worker_panicked = false;
        let mut batches = Vec::new();
        let mut statistics = SourceStatistics::default();

        thread::scope(|scope| {
            let mut handles = Vec::new();
            let mut setup_error = handles
                .try_reserve_exact(self.workers())
                .err()
                .map(|error| {
                    worker_terminal(format!("could not allocate worker handles: {error}"))
                });
            if setup_error.is_none() {
                for index in 0..self.workers() {
                    let receiver = Arc::clone(&receiver);
                    let spawned = thread::Builder::new()
                        .name(format!("rustleaks-source-{index}"))
                        .spawn_scoped(scope, move || {
                            worker_loop(
                                receiver.as_ref(),
                                engine,
                                scan_options,
                                policy,
                                cancellation,
                            )
                        });
                    match spawned {
                        Ok(handle) => handles.push(handle),
                        Err(error) => {
                            setup_error = Some(worker_terminal(format!(
                                "could not spawn detection worker: {error}"
                            )));
                            break;
                        }
                    }
                }
            }

            if let Some(error) = setup_error {
                source_result = Err(error);
            } else {
                source_result = source.visit(cancellation, &mut |event| {
                    ensure_active(
                        cancellation,
                        "source runner cancelled while receiving an event",
                    )?;
                    let fragment = match event {
                        SourceEvent::Issue(issue) => {
                            issues.push(issue);
                            return Ok(SourceControl::Continue);
                        }
                        SourceEvent::Fragment { fragment, issue } => {
                            if let Some(issue) = issue {
                                issues.push(issue);
                                // Pinned DetectSource treats any callback issue
                                // as non-scannable even when the same read
                                // returned bytes. The source event retains them
                                // for lower-level protocol consumers.
                                return Ok(SourceControl::Continue);
                            }
                            *fragment
                        }
                    };

                    statistics.observe(&fragment)?;

                    let mut pending = fragment;
                    loop {
                        ensure_active(cancellation, "source runner cancelled while scheduling")?;
                        match sender.try_send(pending) {
                            Ok(()) => return Ok(SourceControl::Continue),
                            Err(TrySendError::Full(fragment)) => {
                                pending = fragment;
                                thread::yield_now();
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                return Err(CallbackError::new(
                                    "all source runner workers disconnected",
                                ));
                            }
                        }
                    }
                });
            }
            drop(sender);

            for handle in handles {
                match handle.join() {
                    Ok(batch) => batches.push(batch),
                    Err(_) => worker_panicked = true,
                }
            }
        });

        finish_run(
            policy,
            batches,
            issues,
            source_result,
            worker_panicked,
            cancellation.is_cancelled(),
            statistics,
        )
    }
}

fn ensure_active(
    cancellation: &CancellationToken,
    message: &'static str,
) -> Result<(), CallbackError> {
    if cancellation.is_cancelled() {
        Err(CallbackError::new(message))
    } else {
        Ok(())
    }
}

fn worker_terminal(message: String) -> SourceError {
    SourceError::Terminal {
        stage: SourceStage::Worker,
        path: None,
        message,
    }
}

fn worker_loop(
    receiver: &Mutex<mpsc::Receiver<Fragment>>,
    engine: &Engine,
    scan_options: ScanOptions,
    policy: &SessionPolicy,
    cancellation: &CancellationToken,
) -> rustleaks_core::session::SessionBatch {
    let mut batch = policy.new_batch();
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let job = match receiver.lock() {
            Ok(guard) => guard.recv(),
            Err(poisoned) => poisoned.into_inner().recv(),
        };
        let Ok(fragment) = job else {
            break;
        };
        if cancellation.is_cancelled() {
            break;
        }
        let control = ScanControl::cancellable(cancellation);
        let detected = engine.scan_fragment_controlled(&fragment, &scan_options, &control);
        if !merge_complete_scan(&mut batch, detected) {
            break;
        }
        if cancellation.is_cancelled() {
            break;
        }
    }
    batch
}

fn merge_complete_scan(batch: &mut SessionBatch, outcome: ScanOutcome) -> bool {
    if !outcome.is_complete() {
        return false;
    }
    for finding in outcome.into_findings() {
        batch.add_finding(finding);
    }
    true
}

fn finish_run(
    policy: &SessionPolicy,
    batches: Vec<rustleaks_core::session::SessionBatch>,
    mut issues: Vec<SourceIssue>,
    source_result: Result<SourceControl, SourceError>,
    worker_panicked: bool,
    cancelled: bool,
    statistics: SourceStatistics,
) -> SourceOutcome {
    let mut session = ScanSession::new(policy.clone());
    for batch in batches {
        if let Err(error) = session.merge(batch) {
            issues.push(SourceIssue::new(
                SourceStage::Worker,
                SourceIssueKind::Limit,
                None,
                error.to_string(),
            ));
        }
    }
    if worker_panicked {
        issues.push(SourceIssue::new(
            SourceStage::Worker,
            SourceIssueKind::WorkerPanic,
            None,
            "detection worker panicked",
        ));
    }

    let termination = if worker_panicked {
        SourceTermination::WorkerPanic
    } else if cancelled || matches!(source_result, Err(SourceError::Cancelled)) {
        SourceTermination::Cancelled
    } else {
        match source_result {
            Ok(SourceControl::Continue) => SourceTermination::Completed,
            Ok(SourceControl::Stop) => SourceTermination::Stopped,
            Err(error) => SourceTermination::SourceError(error),
        }
    };
    SourceOutcome {
        findings: session.into_findings(),
        issues,
        termination,
        scanned_bytes: statistics.scanned_bytes,
        unique_commits: statistics.unique_commits,
    }
}

impl Default for SourceRunner {
    fn default() -> Self {
        Self {
            workers: NonZeroUsize::new(1).expect("one worker is positive"),
            queue_capacity: NonZeroUsize::new(1).expect("one queue slot is positive"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustleaks_core::config::ConfigLoader;

    use super::*;

    #[test]
    fn commit_statistics_limit_fails_before_unbounded_growth() {
        let mut statistics = SourceStatistics {
            maximum_unique_commits: 1,
            ..SourceStatistics::default()
        };
        statistics
            .observe(&Fragment::builder("a").commit("first").build())
            .unwrap();
        statistics
            .observe(&Fragment::builder("b").commit("first").build())
            .unwrap();
        let error = statistics
            .observe(&Fragment::builder("c").commit("second").build())
            .unwrap_err();
        assert!(error.to_string().contains("1-commit safety limit"));
        assert_eq!(statistics.unique_commits.len(), 1);
    }

    #[test]
    fn partial_fragment_findings_are_not_merged_into_a_source_batch() {
        let config = ConfigLoader::new()
            .load_toml(
                r#"
[[rules]]
id = "a-first"
regex = '''A'''

[[rules]]
id = "b-second"
regex = '''B'''
"#,
            )
            .unwrap();
        let engine = Engine::builder(config).build().unwrap();
        let polls = AtomicUsize::new(0);
        let cancellation = || polls.fetch_add(1, Ordering::SeqCst) >= 5;
        let outcome = engine.scan_fragment_controlled(
            &Fragment::new(b"A B"),
            &ScanOptions::default(),
            &ScanControl::cancellable(&cancellation),
        );
        assert!(!outcome.is_complete());
        assert_eq!(outcome.findings().len(), 1);

        let mut batch = SessionPolicy::default().new_batch();
        assert!(!merge_complete_scan(&mut batch, outcome));
        assert!(batch.findings().is_empty());
    }
}
