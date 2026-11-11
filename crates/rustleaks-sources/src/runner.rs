use std::collections::HashSet;
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

mod budget;

pub use budget::{
    SourceBudget, SourceBudgetError, SourceBudgetExceeded, SourceBudgetKind, SourceBudgetScope,
    SourceUsage,
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
    /// An opt-in source budget stopped the operation; every worker was joined.
    BudgetExceeded(SourceBudgetExceeded),
}

/// Owned results of scanning one source.
#[derive(Clone, Debug)]
pub struct SourceOutcome {
    findings: Vec<Finding>,
    issues: Vec<SourceIssue>,
    termination: SourceTermination,
    scanned_bytes: u64,
    unique_commits: Vec<ByteText>,
    usage: Option<SourceUsage>,
}

struct SourceStatistics {
    scanned_bytes: u64,
    unique_commits: Vec<ByteText>,
    commit_index: HashSet<ByteText>,
    maximum_unique_commits: usize,
}

const MAX_UNIQUE_COMMITS: usize = 1_000_000;

impl Default for SourceStatistics {
    fn default() -> Self {
        Self {
            scanned_bytes: 0,
            unique_commits: Vec::new(),
            commit_index: HashSet::new(),
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
            self.observe_commit(fragment.commit())?;
        }
        Ok(())
    }

    fn observe_commit(&mut self, commit: &ByteText) -> Result<(), CallbackError> {
        // Fragments of one commit are contiguous in Git sources, so the last
        // discovered identity answers most repeats without hashing.
        if self.unique_commits.last() == Some(commit)
            || self.commit_index.contains(commit.as_bytes())
        {
            return Ok(());
        }
        if self.unique_commits.len() == self.maximum_unique_commits {
            return Err(CallbackError::new(format!(
                "source unique commit count exceeds the {}-commit safety limit",
                self.maximum_unique_commits
            )));
        }
        self.unique_commits.try_reserve(1).map_err(|error| {
            CallbackError::new(format!("could not retain source commit: {error}"))
        })?;
        self.commit_index.try_reserve(1).map_err(|error| {
            CallbackError::new(format!("could not retain source commit: {error}"))
        })?;
        let retained = copy_commit(commit)?;
        let indexed = copy_commit(commit)?;
        self.commit_index.insert(indexed);
        self.unique_commits.push(retained);
        Ok(())
    }
}

fn copy_commit(commit: &ByteText) -> Result<ByteText, CallbackError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(commit.len())
        .map_err(|error| CallbackError::new(format!("could not copy source commit: {error}")))?;
    bytes.extend_from_slice(commit.as_bytes());
    Ok(ByteText::new(bytes))
}

impl SourceOutcome {
    /// Returns accepted, policy-filtered findings.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Returns retained source issues in producer order, followed by runner
    /// issues. An explicit source budget can cap the collection; rejecting a
    /// further source issue returns incomplete budget termination.
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

    /// Returns operation accounting when an explicit source budget was installed.
    #[must_use]
    pub const fn usage(&self) -> Option<SourceUsage> {
        self.usage
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
    /// observed outside the runner.
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
/// session-batch path. Findings are merged in producer fragment order, so a
/// complete run returns the single-worker order for any worker count. Finding
/// order is not a compatibility contract with the pinned upstream; complete
/// duplicate-preserving multisets are invariant for complete runs. Budget stops
/// can return a scheduling-dependent subset of completely scanned fragments,
/// and their finding order remains unspecified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRunner {
    workers: NonZeroUsize,
    queue_capacity: NonZeroUsize,
    budget: Option<SourceBudget>,
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
            budget: None,
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

    /// Installs an opt-in operation policy without changing the worker count.
    ///
    /// # Errors
    ///
    /// Returns an error if a finite aggregate scan limit lacks a matching
    /// finite per-fragment reservation ceiling.
    pub fn with_budget(mut self, budget: SourceBudget) -> Result<Self, SourceBudgetError> {
        self.budget = Some(budget.validate()?);
        Ok(self)
    }

    /// Returns the installed operation policy, or `None` for the default path.
    #[must_use]
    pub const fn budget(self) -> Option<SourceBudget> {
        self.budget
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
        if let Some(budget) = self.budget {
            return budget::run(
                self,
                source,
                engine,
                scan_options,
                policy,
                cancellation,
                budget,
            );
        }
        self.run_with_worker(source, policy, cancellation, |receiver| {
            worker_loop(receiver, engine, scan_options, policy, cancellation)
        })
    }

    fn run_with_worker(
        &self,
        source: &mut dyn Source,
        policy: &SessionPolicy,
        cancellation: &CancellationToken,
        worker: impl Fn(&Mutex<mpsc::Receiver<Job>>) -> Vec<FragmentBatch> + Sync,
    ) -> SourceOutcome {
        let (sender, receiver) = mpsc::sync_channel::<Job>(self.queue_capacity());
        let receiver = Arc::new(Mutex::new(receiver));
        let mut issues = Vec::new();
        let mut source_result = Ok(SourceControl::Continue);
        let mut worker_panicked = false;
        let mut batches = Vec::new();
        let mut statistics = SourceStatistics::default();
        let mut next_sequence = 0_u64;

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
                    let worker = &worker;
                    let spawned = thread::Builder::new()
                        .name(format!("rustleaks-source-{index}"))
                        .spawn_scoped(scope, move || worker(receiver.as_ref()));
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
            // Only workers may retain receivers while the producer is active.
            // Otherwise their failure cannot disconnect a full queue.
            drop(receiver);

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

                    let sequence = next_sequence;
                    next_sequence += 1;
                    let mut pending = Job { sequence, fragment };
                    loop {
                        ensure_active(cancellation, "source runner cancelled while scheduling")?;
                        match sender.try_send(pending) {
                            Ok(()) => return Ok(SourceControl::Continue),
                            Err(TrySendError::Full(job)) => {
                                pending = job;
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
                    Ok(worker_batches) => batches.extend(worker_batches),
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

/// One fragment and its position in producer order.
struct Job {
    sequence: u64,
    fragment: Fragment,
}

/// Accepted findings of one completely scanned fragment.
struct FragmentBatch {
    sequence: u64,
    batch: SessionBatch,
}

fn worker_loop(
    receiver: &Mutex<mpsc::Receiver<Job>>,
    engine: &Engine,
    scan_options: ScanOptions,
    policy: &SessionPolicy,
    cancellation: &CancellationToken,
) -> Vec<FragmentBatch> {
    let mut batches = Vec::new();
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let job = match receiver.lock() {
            Ok(guard) => guard.recv(),
            Err(poisoned) => poisoned.into_inner().recv(),
        };
        let Ok(job) = job else {
            break;
        };
        if cancellation.is_cancelled() {
            break;
        }
        let control = ScanControl::cancellable(cancellation);
        let detected = engine.scan_fragment_controlled(&job.fragment, &scan_options, &control);
        if !merge_complete_scan(&mut batches, policy, job.sequence, detected) {
            break;
        }
        if cancellation.is_cancelled() {
            break;
        }
    }
    batches
}

/// Records the findings of a complete scan. Classification is a pure function
/// of one finding and the immutable policy, so per-fragment batches are
/// equivalent to one worker-wide batch apart from their merge order.
fn merge_complete_scan(
    batches: &mut Vec<FragmentBatch>,
    policy: &SessionPolicy,
    sequence: u64,
    outcome: ScanOutcome,
) -> bool {
    if !outcome.is_complete() {
        return false;
    }
    let mut batch = policy.new_batch();
    for finding in outcome.into_findings() {
        batch.add_finding(finding);
    }
    if !batch.findings().is_empty() {
        batches.push(FragmentBatch { sequence, batch });
    }
    true
}

fn finish_run(
    policy: &SessionPolicy,
    mut batches: Vec<FragmentBatch>,
    mut issues: Vec<SourceIssue>,
    source_result: Result<SourceControl, SourceError>,
    worker_panicked: bool,
    cancelled: bool,
    statistics: SourceStatistics,
) -> SourceOutcome {
    // One producer assigns every sequence, so the keys are unique.
    batches.sort_unstable_by_key(|fragment| fragment.sequence);
    let mut session = ScanSession::new(policy.clone());
    for FragmentBatch { batch, .. } in batches {
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
        usage: None,
    }
}

impl Default for SourceRunner {
    fn default() -> Self {
        Self {
            workers: NonZeroUsize::new(1).expect("one worker is positive"),
            queue_capacity: NonZeroUsize::new(1).expect("one queue slot is positive"),
            budget: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Condvar;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rustleaks_core::config::ConfigLoader;
    use rustleaks_core::session::Baseline;

    use super::*;

    #[test]
    fn all_workers_panicking_disconnects_the_full_queue_and_joins_every_worker() {
        struct Fragments;
        impl Source for Fragments {
            fn visit(
                &mut self,
                _: &dyn crate::Cancellation,
                emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
            ) -> Result<SourceControl, SourceError> {
                for _ in 0..32 {
                    let control = emit(SourceEvent::Fragment {
                        fragment: Box::new(Fragment::new(b"synthetic")),
                        issue: None,
                    })
                    .map_err(SourceError::Callback)?;
                    if control == SourceControl::Stop {
                        return Ok(control);
                    }
                }
                Ok(SourceControl::Continue)
            }
        }

        struct WorkerExited(Arc<AtomicUsize>);
        impl Drop for WorkerExited {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        for workers in [1, 4] {
            let cancellation = CancellationToken::new();
            let rescue = cancellation.clone();
            let forced = Arc::new(AtomicUsize::new(0));
            let forced_by_watchdog = Arc::clone(&forced);
            let (done, completion) = mpsc::channel();
            let watchdog = thread::spawn(move || {
                if completion.recv_timeout(Duration::from_secs(5)).is_err() {
                    forced_by_watchdog.store(1, Ordering::SeqCst);
                    rescue.cancel();
                }
            });
            let exited = Arc::new(AtomicUsize::new(0));
            let outcome = SourceRunner::new(workers, 1).unwrap().run_with_worker(
                &mut Fragments,
                &SessionPolicy::default(),
                &cancellation,
                |receiver| {
                    let _exited = WorkerExited(Arc::clone(&exited));
                    let _first = receiver.lock().unwrap().recv().unwrap();
                    panic!("synthetic detection worker failure");
                },
            );
            let _ = done.send(());
            watchdog.join().unwrap();
            assert_eq!(exited.load(Ordering::SeqCst), workers);
            assert_eq!(outcome.termination(), &SourceTermination::WorkerPanic);
            assert!(outcome.findings().is_empty());
            assert_eq!(
                forced.load(Ordering::SeqCst),
                0,
                "worker failure must terminate without watchdog cancellation"
            );
        }
    }

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
    fn commit_statistics_keep_discovery_order_for_non_contiguous_repeats() {
        let mut statistics = SourceStatistics::default();
        for commit in ["b", "a", "b", "c", "a", "", "d", "c"] {
            statistics
                .observe(&Fragment::builder("x").commit(commit).build())
                .unwrap();
        }
        let expected = [
            ByteText::from("b"),
            ByteText::from("a"),
            ByteText::from("c"),
            ByteText::from("d"),
        ];
        assert_eq!(statistics.unique_commits, expected);
        assert_eq!(statistics.scanned_bytes, 8);
    }

    #[test]
    fn commit_statistics_match_a_linear_model_at_and_past_the_limit() {
        // Commit identities repeat at varying distances. The model below is
        // the specification: first occurrences are retained in order until
        // the limit, repeats are always accepted, and an unseen commit past
        // the limit is an error.
        let mut statistics = SourceStatistics {
            maximum_unique_commits: 64,
            ..SourceStatistics::default()
        };
        let mut model: Vec<Vec<u8>> = Vec::new();
        let mut state = 0x9e37_79b9_u32;
        for step in 0..4096 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let commit = format!("{:02x}", (state >> 24) % 96);
            let known = model.iter().any(|value| value == commit.as_bytes());
            let result =
                statistics.observe(&Fragment::builder("x").commit(commit.as_str()).build());
            if known || model.len() < 64 {
                assert!(result.is_ok(), "step {step}");
                if !known {
                    model.push(commit.into_bytes());
                }
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("64-commit safety limit"),
                    "step {step}"
                );
            }
        }
        let retained = statistics
            .unique_commits
            .iter()
            .map(|commit| commit.as_bytes().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(retained, model);
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

        let mut batches = Vec::new();
        assert!(!merge_complete_scan(
            &mut batches,
            &SessionPolicy::default(),
            0,
            outcome
        ));
        assert!(batches.is_empty());
    }

    /// Emits `count` fragments whose findings identify their producer position.
    struct TokenFragments(usize);

    impl Source for TokenFragments {
        fn visit(
            &mut self,
            _: &dyn crate::Cancellation,
            emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
        ) -> Result<SourceControl, SourceError> {
            for index in 0..self.0 {
                let content = format!("token-{index}a token-{index}b\n");
                let control = emit(SourceEvent::fragment(Fragment::new(content)))
                    .map_err(SourceError::Callback)?;
                if control == SourceControl::Stop {
                    return Ok(control);
                }
            }
            Ok(SourceControl::Continue)
        }
    }

    fn token_engine() -> Engine {
        let config = ConfigLoader::new()
            .load_toml("[[rules]]\nid = 'token'\nregex = '''token-[0-9]+[ab]'''\n")
            .unwrap();
        Engine::builder(config).build().unwrap()
    }

    /// Source order of the secrets emitted by `TokenFragments`.
    fn expected_tokens(indices: impl IntoIterator<Item = usize>) -> Vec<String> {
        indices
            .into_iter()
            .flat_map(|index| [format!("token-{index}a"), format!("token-{index}b")])
            .collect()
    }

    fn secrets(outcome: &SourceOutcome) -> Vec<String> {
        outcome
            .findings()
            .iter()
            .map(|finding| finding.secret().to_string_lossy().into_owned())
            .collect()
    }

    #[derive(Default)]
    struct Latch(Mutex<bool>, Condvar);

    impl Latch {
        fn open(&self) {
            *self.0.lock().unwrap() = true;
            self.1.notify_all();
        }

        fn wait(&self) {
            let guard = self.0.lock().unwrap();
            let (guard, timeout) = self
                .1
                .wait_timeout_while(guard, Duration::from_secs(5), |open| !*open)
                .unwrap();
            assert!(*guard && !timeout.timed_out(), "latch never opened");
        }
    }

    #[test]
    fn ordered_merge_restores_producer_order_when_workers_finish_out_of_order() {
        let engine = token_engine();
        let policy = SessionPolicy::default();
        let first_taken = Latch::default();
        let second_taken = Latch::default();
        let outcome = SourceRunner::new(2, 1).unwrap().run_with_worker(
            &mut TokenFragments(2),
            &policy,
            &CancellationToken::new(),
            |receiver| {
                // Worker 1 takes fragment 0 and worker 0 takes fragment 1, so
                // merging batches in join order would reverse the fragments.
                let is_worker_one = thread::current().name() == Some("rustleaks-source-1");
                let mut batches = Vec::new();
                if !is_worker_one {
                    first_taken.wait();
                }
                let mut taken = 0;
                loop {
                    let job = receiver.lock().unwrap().recv();
                    let Ok(job) = job else {
                        break;
                    };
                    let detected = engine.scan_fragment_controlled(
                        &job.fragment,
                        &ScanOptions::default(),
                        &ScanControl::unlimited(),
                    );
                    assert!(merge_complete_scan(
                        &mut batches,
                        &policy,
                        job.sequence,
                        detected
                    ));
                    taken += 1;
                    if taken == 1 {
                        if is_worker_one {
                            first_taken.open();
                            second_taken.wait();
                        } else {
                            second_taken.open();
                        }
                    }
                }
                batches
            },
        );
        assert_eq!(outcome.termination(), &SourceTermination::Completed);
        assert_eq!(secrets(&outcome), expected_tokens([0, 1]));
    }

    #[test]
    fn any_worker_count_returns_source_order_with_and_without_a_budget() {
        const FRAGMENTS: usize = 96;
        let engine = token_engine();
        for workers in [1, 2, 3, 8] {
            for capacity in [1, 4] {
                let run = |runner: SourceRunner| {
                    runner.run(
                        &mut TokenFragments(FRAGMENTS),
                        &engine,
                        ScanOptions::default(),
                        &SessionPolicy::default(),
                        &CancellationToken::new(),
                    )
                };
                let plain = run(SourceRunner::new(workers, capacity).unwrap());
                assert_eq!(plain.termination(), &SourceTermination::Completed);
                assert_eq!(
                    secrets(&plain),
                    expected_tokens(0..FRAGMENTS),
                    "{workers}/{capacity}"
                );
                let budgeted = run(SourceRunner::new(workers, capacity)
                    .unwrap()
                    .with_budget(SourceBudget::unlimited())
                    .unwrap());
                assert_eq!(budgeted.termination(), &SourceTermination::Completed);
                assert_eq!(
                    secrets(&budgeted),
                    expected_tokens(0..FRAGMENTS),
                    "budgeted {workers}/{capacity}"
                );
            }
        }
    }

    #[test]
    fn policy_suppression_is_independent_of_worker_count() {
        const FRAGMENTS: usize = 48;
        let engine = token_engine();
        let reference = SourceRunner::new(1, 1).unwrap().run(
            &mut TokenFragments(FRAGMENTS),
            &engine,
            ScanOptions::default(),
            &SessionPolicy::default(),
            &CancellationToken::new(),
        );
        let baselined = reference
            .findings()
            .iter()
            .filter(|finding| {
                let secret = finding.secret().to_string_lossy().into_owned();
                let digits = secret.trim_start_matches("token-");
                digits[..digits.len() - 1].parse::<usize>().unwrap() % 3 == 0
            })
            .cloned()
            .collect::<Vec<_>>();
        let policy = SessionPolicy::builder()
            .baseline(Baseline::from_findings(&baselined))
            .build();
        let expected = expected_tokens((0..FRAGMENTS).filter(|index| index % 3 != 0));
        for workers in [1, 4] {
            let outcome = SourceRunner::new(workers, 2).unwrap().run(
                &mut TokenFragments(FRAGMENTS),
                &engine,
                ScanOptions::default(),
                &policy,
                &CancellationToken::new(),
            );
            assert_eq!(secrets(&outcome), expected, "{workers} workers");
        }
    }
}
