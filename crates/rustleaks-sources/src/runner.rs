use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread;
use std::time::Duration;

use rustleaks_core::model::{ByteText, Finding, Fragment, ScanOptions};
use rustleaks_core::session::{ScanSession, SessionBatch, SessionPolicy};
use rustleaks_core::{Engine, ScanControl, ScanOutcome};

use crate::{
    CallbackError, Cancellation, CancellationToken, Source, SourceConfigError, SourceControl,
    SourceError, SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
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
    omitted_issues: u64,
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

// Far above the commit count of large public histories, such as about
// 1.3 million in Linux. It bounds the retained commit identities.
const MAX_UNIQUE_COMMITS: usize = 100_000_000;

/// Source issues that a run without a budget keeps. Later source issues are
/// only counted. A budget run keeps its own explicit issue limit instead.
const MAX_RETAINED_ISSUES: usize = 10_000;

/// Keeps the first [`MAX_RETAINED_ISSUES`] issues and counts the rest.
fn retain_issue(issues: &mut Vec<SourceIssue>, omitted: &mut u64, issue: SourceIssue) {
    if issues.len() < MAX_RETAINED_ISSUES {
        issues.push(issue);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

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
    /// further source issue returns incomplete budget termination. Without a
    /// budget, the first 10,000 source issues are retained and later ones are
    /// counted by [`Self::omitted_issues`].
    #[must_use]
    pub fn issues(&self) -> &[SourceIssue] {
        &self.issues
    }

    const fn with_omitted_issues(mut self, omitted: u64) -> Self {
        self.omitted_issues = omitted;
        self
    }

    /// Returns the number of source issues that a run without a budget did not
    /// retain because it already held 10,000. Budget runs return 0.
    #[must_use]
    pub const fn omitted_issues(&self) -> u64 {
        self.omitted_issues
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
/// complete run returns the single-worker order for any worker count. Budget stops
/// can return a scheduling-dependent subset of completely scanned fragments,
/// and their finding order remains unspecified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRunner {
    workers: NonZeroUsize,
    queue_capacity: NonZeroUsize,
    budget: Option<SourceBudget>,
    fail_on_coverage_error: bool,
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
            fail_on_coverage_error: false,
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

    /// Stops on failed eligible coverage, retaining earlier complete targets.
    ///
    /// Intentional exclusions remain recoverable. The default is `false`, the
    /// issue handling of a normal scan. Complete-target command profiles should
    /// enable this for every source, including Git and caller-defined adapters.
    #[must_use]
    pub const fn fail_on_coverage_error(mut self, enabled: bool) -> Self {
        self.fail_on_coverage_error = enabled;
        self
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
        if self.fail_on_coverage_error {
            return self.run_inner(
                &mut CompleteCoverageSource(source),
                engine,
                scan_options,
                policy,
                cancellation,
            );
        }
        self.run_inner(source, engine, scan_options, policy, cancellation)
    }

    fn run_inner(
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
        worker: impl Fn(&WorkerReceiver<'_>) -> Vec<FragmentBatch> + Sync,
    ) -> SourceOutcome {
        self.run_with_worker_setup(
            source,
            policy,
            cancellation,
            worker,
            &QueueWait::default(),
            |_| Ok(()),
        )
    }

    fn run_with_worker_setup(
        &self,
        source: &mut dyn Source,
        policy: &SessionPolicy,
        cancellation: &CancellationToken,
        worker: impl Fn(&WorkerReceiver<'_>) -> Vec<FragmentBatch> + Sync,
        queue_wait: &QueueWait,
        before_spawn: impl Fn(usize) -> std::io::Result<()>,
    ) -> SourceOutcome {
        let run = run_scheduled(
            self,
            source,
            &Unbudgeted(cancellation),
            queue_wait,
            before_spawn,
            worker,
        );
        finish_run(
            policy,
            run.batches,
            run.issues,
            run.source_result,
            run.worker_panicked,
            cancellation.is_cancelled(),
            run.statistics,
        )
        .with_omitted_issues(run.omitted_issues)
    }
}

/// What a run with a budget adds to the shared producer loop. A run without
/// a budget uses [`Unbudgeted`], which never stops on its own.
trait RunControl: Sync {
    /// The caller's cancellation.
    fn token(&self) -> &CancellationToken;

    /// The cancellation that the source sees.
    fn source_cancellation(&self) -> &dyn Cancellation;

    /// The run stopped itself or was cancelled; the producer stops without an
    /// error.
    fn stopped(&self) -> bool;

    /// Keeps or counts one issue. Returns `false` to stop the source.
    fn retain_issue(
        &self,
        issues: &mut Vec<SourceIssue>,
        omitted: &mut u64,
        issue: SourceIssue,
    ) -> bool;

    /// Accounts for one fragment. Returns `false` to stop the source.
    fn admit(&self, bytes: usize) -> bool;

    /// Records that a worker could not start.
    fn spawn_failed(&self);

    /// The run stopped itself, so a disconnected queue is a stop, not an
    /// error.
    fn stopped_internally(&self) -> bool;
}

/// The run control of a run without a budget.
struct Unbudgeted<'a>(&'a CancellationToken);

impl RunControl for Unbudgeted<'_> {
    fn token(&self) -> &CancellationToken {
        self.0
    }

    fn source_cancellation(&self) -> &dyn Cancellation {
        self.0
    }

    fn stopped(&self) -> bool {
        false
    }

    fn retain_issue(
        &self,
        issues: &mut Vec<SourceIssue>,
        omitted: &mut u64,
        issue: SourceIssue,
    ) -> bool {
        retain_issue(issues, omitted, issue);
        true
    }

    fn admit(&self, _bytes: usize) -> bool {
        true
    }

    fn spawn_failed(&self) {}

    fn stopped_internally(&self) -> bool {
        false
    }
}

/// What the producer and the workers left after a run.
struct ScheduledRun {
    source_result: Result<SourceControl, SourceError>,
    batches: Vec<FragmentBatch>,
    issues: Vec<SourceIssue>,
    omitted_issues: u64,
    worker_panicked: bool,
    statistics: SourceStatistics,
}

/// Starts the workers, feeds them the source's fragments in order, closes the
/// queue and joins every worker.
#[allow(clippy::result_large_err)] // A full queue hands the unsent job back without another allocation.
fn run_scheduled(
    runner: &SourceRunner,
    source: &mut dyn Source,
    control: &impl RunControl,
    queue_wait: &QueueWait,
    before_spawn: impl Fn(usize) -> std::io::Result<()>,
    worker: impl Fn(&WorkerReceiver<'_>) -> Vec<FragmentBatch> + Sync,
) -> ScheduledRun {
    let queue = JobQueue::new(runner.queue_capacity(), queue_wait);
    let mut issues = Vec::new();
    let mut omitted_issues = 0_u64;
    let mut source_result = Ok(SourceControl::Continue);
    let mut worker_panicked = false;
    let mut batches = Vec::new();
    let mut statistics = SourceStatistics::default();
    let mut next_sequence = 0_u64;

    thread::scope(|scope| {
        let mut handles = Vec::new();
        let mut setup_error = handles
            .try_reserve_exact(runner.workers())
            .err()
            .map(|error| {
                SourceError::terminal(
                    SourceStage::Worker,
                    None,
                    format!("could not allocate worker handles: {error}"),
                )
            });
        if setup_error.is_none() {
            for index in 0..runner.workers() {
                let receiver = queue.receiver();
                let worker = &worker;
                let spawned = before_spawn(index).and_then(|()| {
                    thread::Builder::new()
                        .name(format!("rustleaks-source-{index}"))
                        .spawn_scoped(scope, move || worker(&receiver))
                });
                match spawned {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        setup_error = Some(SourceError::terminal(
                            SourceStage::Worker,
                            None,
                            format!("could not spawn detection worker: {error}"),
                        ));
                        control.spawn_failed();
                        break;
                    }
                }
            }
        }
        if let Some(error) = setup_error {
            source_result = Err(error);
        } else {
            source_result = source.visit(control.source_cancellation(), &mut |event| {
                ensure_active(
                    control.token(),
                    "source runner cancelled while receiving an event",
                )?;
                if control.stopped() {
                    return Ok(SourceControl::Stop);
                }
                let fragment = match event {
                    SourceEvent::Issue(issue) => {
                        return Ok(retained(control.retain_issue(
                            &mut issues,
                            &mut omitted_issues,
                            issue,
                        )));
                    }
                    SourceEvent::Fragment { fragment, issue } => {
                        if let Some(issue) = issue {
                            // A read that reported an issue is not scanned,
                            // even when it returned bytes. The source event
                            // keeps the bytes for lower-level consumers.
                            return Ok(retained(control.retain_issue(
                                &mut issues,
                                &mut omitted_issues,
                                issue,
                            )));
                        }
                        *fragment
                    }
                };
                if !control.admit(fragment.content().len()) {
                    return Ok(SourceControl::Stop);
                }
                statistics.observe(&fragment)?;
                let sequence = next_sequence;
                next_sequence += 1;
                schedule(control, Job { sequence, fragment }, queue_wait, |pending| {
                    queue.try_send(pending)
                })
            });
        }
        queue.close();
        for handle in handles {
            match handle.join() {
                Ok(worker_batches) => batches.extend(worker_batches),
                Err(_) => worker_panicked = true,
            }
        }
    });

    ScheduledRun {
        source_result,
        batches,
        issues,
        omitted_issues,
        worker_panicked,
        statistics,
    }
}

const fn retained(kept: bool) -> SourceControl {
    if kept {
        SourceControl::Continue
    } else {
        SourceControl::Stop
    }
}

/// Offers one job to the queue until a worker takes it, the run stops, or
/// the caller cancels.
fn schedule(
    control: &impl RunControl,
    job: Job,
    queue_wait: &QueueWait,
    mut try_send: impl FnMut(Job) -> Result<(), TrySendError<Job>>,
) -> Result<SourceControl, CallbackError> {
    let mut pending = job;
    let mut waiting = None;
    let mut remaining_retries = INITIAL_QUEUE_RETRIES;
    loop {
        ensure_active(control.token(), "source runner cancelled while scheduling")?;
        #[cfg(test)]
        if let Some(after_external_check) = &queue_wait.after_external_check {
            after_external_check();
        }
        if control.stopped() {
            return Ok(SourceControl::Stop);
        }
        match try_send(pending) {
            Ok(()) => return Ok(SourceControl::Continue),
            Err(TrySendError::Full(job)) => {
                pending = job;
                waiting = queue_wait.retry(waiting, &mut remaining_retries);
            }
            Err(TrySendError::Disconnected(_)) => {
                // The last worker can exhaust its budget or panic after the
                // check above and drop the receiver before this send. Keep
                // that internal stop instead of making a source error.
                if control.stopped_internally() {
                    return Ok(SourceControl::Stop);
                }
                return Err(CallbackError::new("all source runner workers disconnected"));
            }
        }
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

const INITIAL_QUEUE_RETRIES: usize = 32;

/// Attempts to take the job queue lock without blocking before waiting on it.
const QUEUE_LOCK_SPINS: usize = 128;

/// Serializes notifications with the producer's transition from Full to sleep.
struct QueueWait {
    gate: Mutex<()>,
    changed: Condvar,
    interval: Duration,
    #[cfg(test)]
    before_wait: Option<mpsc::Sender<()>>,
    #[cfg(test)]
    before_receive: Option<mpsc::Sender<()>>,
    #[cfg(test)]
    receiver_dropped: Option<mpsc::Sender<()>>,
    #[cfg(test)]
    after_external_check: Option<Box<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    after_yield: Option<mpsc::Sender<()>>,
}

impl Default for QueueWait {
    fn default() -> Self {
        Self {
            gate: Mutex::new(()),
            changed: Condvar::new(),
            // The public cancellation token has no notification registration.
            interval: Duration::from_micros(100),
            #[cfg(test)]
            before_wait: None,
            #[cfg(test)]
            before_receive: None,
            #[cfg(test)]
            receiver_dropped: None,
            #[cfg(test)]
            after_external_check: None,
            #[cfg(test)]
            after_yield: None,
        }
    }
}

impl QueueWait {
    fn lock(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn retry<'a>(
        &'a self,
        guard: Option<MutexGuard<'a, ()>>,
        remaining_retries: &mut usize,
    ) -> Option<MutexGuard<'a, ()>> {
        if *remaining_retries != 0 {
            // Brief handoffs may finish before parking is worthwhile. Spend
            // this fixed allowance once per pending job, never after a wake.
            *remaining_retries -= 1;
            thread::yield_now();
            #[cfg(test)]
            if let Some(after_yield) = &self.after_yield {
                let _ = after_yield.send(());
            }
            guard
        } else {
            Some(self.wait(guard))
        }
    }

    fn wait<'a>(&'a self, guard: Option<MutexGuard<'a, ()>>) -> MutexGuard<'a, ()> {
        let Some(guard) = guard else {
            // Retry under the gate before sleeping, in case the ungated Full
            // raced a dequeue or the last receiver's destruction.
            return self.lock();
        };
        #[cfg(test)]
        if let Some(before_wait) = &self.before_wait {
            let _ = before_wait.send(());
        }
        self.changed
            .wait_timeout(guard, self.interval)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }

    fn notify(&self) {
        let _guard = self.lock();
        self.changed.notify_one();
    }
}

/// Bounded first-in, first-out queue from the producer to the detection
/// workers.
///
/// Workers lock the queue only to take a job. While it is empty, an idle
/// worker parks its thread without holding a lock, and only the job that ends
/// its wait wakes it. The producer never sleeps on this lock: a full queue
/// returns the job to the producer, which waits on [`QueueWait`]. The first
/// job taken after the producer saw the queue full, and the exit of any
/// receiver, notify that gate. The producer also polls at the gate interval,
/// so no notification is required for progress.
///
/// A producer retrying a full queue does not take the lock. It publishes
/// `producer_blocked` and then reads `queued`, while a worker publishes
/// `queued` after taking a job and then reads `producer_blocked`. All four are
/// sequentially consistent, so either the worker notifies the producer or the
/// producer sees the free slot.
struct JobQueue<'a> {
    state: Mutex<JobState>,
    /// Number of queued jobs, written only under the lock.
    queued: AtomicUsize,
    /// Live [`WorkerReceiver`] handles, written only under the lock. Zero
    /// means disconnected.
    receivers: AtomicUsize,
    /// The producer saw the queue full since the last taken job.
    producer_blocked: AtomicBool,
    capacity: usize,
    wait: &'a QueueWait,
}

struct JobState {
    jobs: VecDeque<Job>,
    /// The producer has finished; workers drain the queue and then stop.
    closed: bool,
    /// Parked workers, most recent last. A worker stays here until a waker
    /// removes it and sets its flag.
    sleepers: Vec<Sleeper>,
    /// A parked worker was woken and has not yet taken the lock. While this is
    /// set, new jobs do not wake another worker; the woken worker wakes the
    /// next one if jobs remain, so the producer pays for at most one wake-up
    /// at a time.
    waking: bool,
}

/// One parked worker thread and the flag that ends its wait.
struct Sleeper {
    thread: thread::Thread,
    woken: Arc<AtomicBool>,
}

impl Sleeper {
    fn wake(self) {
        self.woken.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

impl JobState {
    /// Claims one parked worker to wake for a queued job. The caller wakes it
    /// after releasing the lock.
    fn wake_one(&mut self) -> Option<Sleeper> {
        if self.waking || self.jobs.is_empty() {
            return None;
        }
        let sleeper = self.sleepers.pop()?;
        self.waking = true;
        Some(sleeper)
    }
}

impl<'a> JobQueue<'a> {
    fn new(capacity: usize, wait: &'a QueueWait) -> Self {
        Self {
            state: Mutex::new(JobState {
                jobs: VecDeque::new(),
                closed: false,
                sleepers: Vec::new(),
                waking: false,
            }),
            queued: AtomicUsize::new(0),
            receivers: AtomicUsize::new(0),
            producer_blocked: AtomicBool::new(false),
            capacity,
            wait,
        }
    }

    fn lock(&self) -> MutexGuard<'_, JobState> {
        // Every critical section is a few operations long. A short spin
        // avoids parking in the kernel when another thread holds the lock
        // only briefly, which a contended platform mutex may otherwise do.
        for _ in 0..QUEUE_LOCK_SPINS {
            match self.state.try_lock() {
                Ok(guard) => return guard,
                Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => std::hint::spin_loop(),
            }
        }
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers one worker's receiver.
    fn receiver(&self) -> WorkerReceiver<'_> {
        let state = self.lock();
        self.receivers.fetch_add(1, Ordering::SeqCst);
        drop(state);
        WorkerReceiver {
            queue: self,
            woken: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            after_receive: None,
        }
    }

    /// Enqueues without blocking, with the results of a bounded channel.
    #[allow(clippy::result_large_err)] // The queue returns ownership of an unsent fragment without another allocation.
    fn try_send(&self, job: Job) -> Result<(), TrySendError<Job>> {
        if self.is_full_without_lock() {
            return Err(TrySendError::Full(job));
        }
        let mut state = self.lock();
        if self.receivers.load(Ordering::SeqCst) == 0 {
            return Err(TrySendError::Disconnected(job));
        }
        if state.jobs.len() >= self.capacity {
            self.producer_blocked.store(true, Ordering::SeqCst);
            return Err(TrySendError::Full(job));
        }
        state.jobs.push_back(job);
        self.queued.store(state.jobs.len(), Ordering::SeqCst);
        let sleeper = state.wake_one();
        drop(state);
        if let Some(sleeper) = sleeper {
            sleeper.wake();
        }
        Ok(())
    }

    /// Reports a full queue with live receivers without taking the lock. The
    /// blocked flag is published before the second read, so a job taken
    /// after this read notifies the producer. Any other state, including
    /// disconnection, takes the locked path.
    fn is_full_without_lock(&self) -> bool {
        if self.receivers.load(Ordering::SeqCst) == 0
            || self.queued.load(Ordering::SeqCst) < self.capacity
        {
            return false;
        }
        self.producer_blocked.store(true, Ordering::SeqCst);
        self.queued.load(Ordering::SeqCst) >= self.capacity
            && self.receivers.load(Ordering::SeqCst) != 0
    }

    /// Lets the workers take the queued jobs and then stop.
    fn close(&self) {
        let sleepers = {
            let mut state = self.lock();
            state.closed = true;
            std::mem::take(&mut state.sleepers)
        };
        for sleeper in sleepers {
            sleeper.wake();
        }
    }
}

/// One worker's handle on the [`JobQueue`]. Dropping it unregisters the
/// worker before it notifies the producer about the exit.
struct WorkerReceiver<'a> {
    queue: &'a JobQueue<'a>,
    /// Set by the waker that removes this worker from the sleepers.
    woken: Arc<AtomicBool>,
    #[cfg(test)]
    after_receive: Option<mpsc::Sender<()>>,
}

impl WorkerReceiver<'_> {
    fn recv(&self) -> Result<Job, mpsc::RecvError> {
        #[cfg(test)]
        if let Some(before_receive) = &self.queue.wait.before_receive {
            let _ = before_receive.send(());
        }
        let mut state = self.queue.lock();
        let job = loop {
            if let Some(job) = state.jobs.pop_front() {
                break job;
            }
            if state.closed {
                return Err(mpsc::RecvError);
            }
            self.woken.store(false, Ordering::Relaxed);
            state.sleepers.push(Sleeper {
                thread: thread::current(),
                woken: Arc::clone(&self.woken),
            });
            drop(state);
            // Parking can return early; only the waker's flag ends the wait.
            while !self.woken.load(Ordering::Acquire) {
                thread::park();
            }
            state = self.queue.lock();
            state.waking = false;
        };
        self.queue.queued.store(state.jobs.len(), Ordering::SeqCst);
        let notify = self.queue.producer_blocked.swap(false, Ordering::SeqCst);
        let next = state.wake_one();
        drop(state);
        if let Some(next) = next {
            next.wake();
        }
        #[cfg(test)]
        if let Some(after_receive) = &self.after_receive {
            let _ = after_receive.send(());
        }
        if notify {
            // Release the queue lock before acquiring the notification gate.
            self.queue.wait.notify();
        }
        Ok(job)
    }
}

impl Drop for WorkerReceiver<'_> {
    fn drop(&mut self) {
        let state = self.queue.lock();
        self.queue.receivers.fetch_sub(1, Ordering::SeqCst);
        drop(state);
        #[cfg(test)]
        if let Some(receiver_dropped) = &self.queue.wait.receiver_dropped {
            let _ = receiver_dropped.send(());
        }
        self.queue.wait.notify();
    }
}

fn worker_loop(
    receiver: &WorkerReceiver<'_>,
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
        let job = receiver.recv();
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
        omitted_issues: 0,
        termination,
        scanned_bytes: statistics.scanned_bytes,
        unique_commits: statistics.unique_commits,
        usage: None,
    }
}

struct CompleteCoverageSource<'a>(&'a mut dyn Source);

impl Source for CompleteCoverageSource<'_> {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        crate::source::visit_with_coverage(true, emit, |emit| self.0.visit(cancellation, emit))
    }
}

impl Default for SourceRunner {
    fn default() -> Self {
        Self {
            workers: NonZeroUsize::MIN,
            queue_capacity: NonZeroUsize::MIN,
            budget: None,
            fail_on_coverage_error: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar};
    use std::time::Duration;

    use rustleaks_core::config::ConfigLoader;
    use rustleaks_core::session::Baseline;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const NOTIFICATION_ONLY_INTERVAL: Duration = Duration::from_secs(30);

    fn queue_job(sequence: u64) -> Job {
        Job {
            sequence,
            fragment: Fragment::new("A"),
        }
    }

    pub(super) struct HeldWorkers {
        entered: mpsc::Sender<()>,
        release: Latch,
    }

    impl HeldWorkers {
        pub(super) fn hold(&self) {
            self.entered.send(()).unwrap();
            self.release.wait();
        }
    }

    struct FullQueueSource {
        workers: usize,
        capacity: usize,
        entered: mpsc::Receiver<()>,
        ready: mpsc::Sender<()>,
        schedule: mpsc::Receiver<()>,
        acknowledged: mpsc::Sender<Result<SourceControl, CallbackError>>,
    }

    impl Source for FullQueueSource {
        fn visit(
            &mut self,
            _: &dyn crate::Cancellation,
            emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
        ) -> Result<SourceControl, SourceError> {
            for _ in 0..self.workers {
                assert_eq!(
                    emit(SourceEvent::fragment(Fragment::new("A"))).unwrap(),
                    SourceControl::Continue
                );
            }
            for _ in 0..self.workers {
                self.entered.recv_timeout(TEST_TIMEOUT).unwrap();
            }
            for _ in 0..self.capacity {
                assert_eq!(
                    emit(SourceEvent::fragment(Fragment::new("A"))).unwrap(),
                    SourceControl::Continue
                );
            }
            self.ready.send(()).unwrap();
            self.schedule.recv_timeout(TEST_TIMEOUT).unwrap();
            let result = emit(SourceEvent::fragment(Fragment::new("A")));
            self.acknowledged.send(result.clone()).unwrap();
            result.map_err(SourceError::Callback)
        }
    }

    pub(super) fn assert_full_queue_cancellation(
        workers: usize,
        capacity: usize,
        run: impl FnOnce(&mut dyn Source, &CancellationToken, &QueueWait, &HeldWorkers) -> SourceOutcome,
    ) {
        let (entered, entries) = mpsc::channel();
        let held = HeldWorkers {
            entered,
            release: Latch::default(),
        };
        let (ready, readiness) = mpsc::channel();
        let (schedule, scheduling) = mpsc::channel();
        let (acknowledged, acknowledgement) = mpsc::channel();
        let (before_wait, waits) = mpsc::channel();
        let queue_wait = QueueWait {
            before_wait: Some(before_wait),
            ..QueueWait::default()
        };
        let cancellation = CancellationToken::new();
        let mut source = FullQueueSource {
            workers,
            capacity,
            entered: entries,
            ready,
            schedule: scheduling,
            acknowledged,
        };
        let (outcome, observed) = thread::scope(|scope| {
            let signal = &cancellation;
            let release = &held.release;
            let notification = &queue_wait;
            let controller = scope.spawn(move || {
                let observed = (|| {
                    readiness.recv_timeout(TEST_TIMEOUT).ok()?;
                    while waits.try_recv().is_ok() {}
                    schedule.send(()).ok()?;
                    waits.recv_timeout(TEST_TIMEOUT).ok()?;
                    // Publish while the producer is asleep or waiting for its
                    // gate, so this case cannot select the between-check race.
                    let guard = notification.lock();
                    signal.cancel();
                    drop(guard);
                    acknowledgement.recv_timeout(TEST_TIMEOUT).ok()
                })();
                // Release workers even when the callback failed to respond.
                release.open();
                observed
            });
            let outcome = run(&mut source, &cancellation, &queue_wait, &held);
            (outcome, controller.join().unwrap())
        });
        let error = observed
            .expect("source must acknowledge cancellation before workers are released")
            .unwrap_err();
        assert_eq!(error.message(), "source runner cancelled while scheduling");
        assert_eq!(outcome.termination(), &SourceTermination::Cancelled);
        assert_eq!(
            outcome.scanned_bytes(),
            u64::try_from(workers + capacity + 1).unwrap()
        );
        if let Some(usage) = outcome.usage() {
            assert_eq!(usage.fragments(), workers + capacity + 1);
            assert_eq!(usage.completed_fragments(), 0);
            assert!(usage.is_exact());
        }
    }

    #[test]
    fn full_queue_cancellation_reaches_source_before_workers_are_released() {
        for workers in [1, 4] {
            for capacity in [1, 3] {
                assert_full_queue_cancellation(
                    workers,
                    capacity,
                    |source, cancellation, wait, held| {
                        SourceRunner::new(workers, capacity)
                            .unwrap()
                            .run_with_worker_setup(
                                source,
                                &SessionPolicy::default(),
                                cancellation,
                                |receiver| {
                                    let _job = receiver.recv().unwrap();
                                    held.hold();
                                    Vec::new()
                                },
                                wait,
                                |_| Ok(()),
                            )
                    },
                );
            }
        }
    }

    #[test]
    fn dequeue_before_gated_retry_does_not_require_a_notification_to_be_remembered() {
        let wait = QueueWait::default();
        let queue = JobQueue::new(1, &wait);
        let receiver = queue.receiver();
        assert!(queue.try_send(queue_job(0)).is_ok());
        let Err(TrySendError::Full(pending)) = queue.try_send(queue_job(1)) else {
            panic!("the occupied queue must reject the pending job");
        };
        assert_eq!(receiver.recv().unwrap().sequence, 0);
        let guard = wait.wait(None);
        assert!(queue.try_send(pending).is_ok());
        drop(guard);
        assert_eq!(receiver.recv().unwrap().sequence, 1);
    }

    #[test]
    fn dequeue_after_gated_full_notifies_the_atomic_transition_to_sleep() {
        let wait = QueueWait {
            interval: NOTIFICATION_ONLY_INTERVAL,
            ..QueueWait::default()
        };
        let queue = JobQueue::new(1, &wait);
        let (after_receive, dequeued) = mpsc::channel();
        let mut receiver = queue.receiver();
        receiver.after_receive = Some(after_receive);
        assert!(queue.try_send(queue_job(0)).is_ok());
        let guard = wait.wait(None);
        assert!(matches!(
            queue.try_send(queue_job(1)),
            Err(TrySendError::Full(_))
        ));
        thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let sequence = receiver.recv().unwrap().sequence;
                // Keep receiver ownership in the join result until the producer
                // records its wake, so exit notification cannot mask a failure.
                (sequence, receiver)
            });
            // The receive is finished; its normal notification is waiting for
            // this gate. No production callback or hook blocks under the gate.
            dequeued.recv_timeout(TEST_TIMEOUT).unwrap();
            let (done, completion) = mpsc::channel();
            let notification = &wait;
            let watchdog = scope.spawn(move || {
                let rescued = completion.recv_timeout(TEST_TIMEOUT).is_err();
                if rescued {
                    notification.notify();
                }
                rescued
            });
            drop(wait.wait(Some(guard)));
            let completion_reported = done.send(());
            let rescued = watchdog.join().unwrap();
            let (sequence, receiver) = worker.join().unwrap();
            drop(receiver);
            assert!(!rescued, "notification must precede the polling timeout");
            assert!(completion_reported.is_ok());
            assert_eq!(sequence, 0);
        });
    }

    #[test]
    fn receiver_exit_notifies_only_after_its_channel_ownership_is_dropped() {
        let (receiver_dropped, dropped) = mpsc::channel();
        let wait = QueueWait {
            interval: NOTIFICATION_ONLY_INTERVAL,
            receiver_dropped: Some(receiver_dropped),
            ..QueueWait::default()
        };
        let queue = JobQueue::new(1, &wait);
        let receiver = queue.receiver();
        assert!(queue.try_send(queue_job(0)).is_ok());
        let guard = wait.wait(None);
        thread::scope(|scope| {
            let worker = scope.spawn(move || drop(receiver));
            dropped.recv_timeout(TEST_TIMEOUT).unwrap();
            assert!(matches!(
                queue.try_send(queue_job(1)),
                Err(TrySendError::Disconnected(_))
            ));
            let (done, completion) = mpsc::channel();
            let notification = &wait;
            let watchdog = scope.spawn(move || {
                let rescued = completion.recv_timeout(TEST_TIMEOUT).is_err();
                if rescued {
                    notification.notify();
                }
                rescued
            });
            drop(wait.wait(Some(guard)));
            done.send(()).unwrap();
            worker.join().unwrap();
            assert!(
                !watchdog.join().unwrap(),
                "receiver exit must notify before the polling timeout"
            );
        });
    }

    #[test]
    fn one_receiver_exit_keeps_the_surviving_worker_connected() {
        let wait = QueueWait::default();
        let queue = JobQueue::new(1, &wait);
        let first = queue.receiver();
        let second = queue.receiver();
        assert!(queue.try_send(queue_job(0)).is_ok());
        drop(first);
        assert!(matches!(
            queue.try_send(queue_job(1)),
            Err(TrySendError::Full(_))
        ));
        assert_eq!(second.recv().unwrap().sequence, 0);
        assert!(queue.try_send(queue_job(1)).is_ok());
        drop(second);
        assert!(matches!(
            queue.try_send(queue_job(2)),
            Err(TrySendError::Disconnected(_))
        ));
    }

    #[test]
    fn closing_wakes_idle_receivers_after_they_take_the_queued_jobs() {
        let wait = QueueWait::default();
        let queue = JobQueue::new(4, &wait);
        thread::scope(|scope| {
            let workers = (0..3)
                .map(|_| {
                    let receiver = queue.receiver();
                    scope.spawn(move || {
                        let mut taken = Vec::new();
                        while let Ok(job) = receiver.recv() {
                            taken.push(job.sequence);
                        }
                        taken
                    })
                })
                .collect::<Vec<_>>();
            for sequence in 0..4 {
                assert!(queue.try_send(queue_job(sequence)).is_ok());
            }
            queue.close();
            let mut taken = workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>();
            taken.sort_unstable();
            assert_eq!(taken, [0, 1, 2, 3]);
        });
    }

    #[test]
    fn many_workers_receive_every_job_exactly_once() {
        const JOBS: usize = 20_000;
        for (workers, capacity) in [(2, 1), (8, 1), (8, 16), (16, 3)] {
            let received = Mutex::new(Vec::with_capacity(JOBS));
            let outcome = SourceRunner::new(workers, capacity)
                .unwrap()
                .run_with_worker(
                    &mut TokenFragments(JOBS),
                    &SessionPolicy::default(),
                    &CancellationToken::new(),
                    |receiver| {
                        let mut taken = Vec::new();
                        while let Ok(job) = receiver.recv() {
                            taken.push(job.sequence);
                        }
                        received.lock().unwrap().extend(taken);
                        Vec::new()
                    },
                );
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            let mut received = received.into_inner().unwrap();
            received.sort_unstable();
            assert!(
                received.iter().copied().eq(0..u64::try_from(JOBS).unwrap()),
                "{workers} workers, capacity {capacity}: each job must arrive exactly once"
            );
        }
    }

    #[test]
    fn poisoned_gate_and_poison_during_wait_are_recovered() {
        let (before_wait, waits) = mpsc::channel();
        let wait = QueueWait {
            interval: NOTIFICATION_ONLY_INTERVAL,
            before_wait: Some(before_wait),
            ..QueueWait::default()
        };
        thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                let mut guard = wait.wait(None);
                while !wait.gate.is_poisoned() {
                    guard = wait.wait(Some(guard));
                }
                drop(guard);
            });
            waits.recv_timeout(TEST_TIMEOUT).unwrap();
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = wait.lock();
                    panic!("synthetic notification gate poison");
                }))
                .is_err()
            );
            wait.notify();
            waiter.join().unwrap();
        });
        // The poisoned gate also remains usable by a new producer or exit guard.
        drop(wait.wait(None));
        wait.notify();
    }

    pub(super) struct UnvisitedSource(pub(super) bool);

    impl Source for UnvisitedSource {
        fn visit(
            &mut self,
            _: &dyn crate::Cancellation,
            _: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
        ) -> Result<SourceControl, SourceError> {
            self.0 = true;
            Ok(SourceControl::Continue)
        }
    }

    #[test]
    fn partial_spawn_failure_closes_idle_receivers_and_joins_started_workers() {
        let (before_receive, receives) = mpsc::channel();
        let (receiver_dropped, drops) = mpsc::channel();
        let wait = QueueWait {
            before_receive: Some(before_receive),
            receiver_dropped: Some(receiver_dropped),
            ..QueueWait::default()
        };
        let exited = AtomicUsize::new(0);
        let cancellation = CancellationToken::new();
        let mut source = UnvisitedSource(false);
        let outcome = SourceRunner::new(4, 1).unwrap().run_with_worker_setup(
            &mut source,
            &SessionPolicy::default(),
            &cancellation,
            |receiver| {
                assert!(receiver.recv().is_err());
                exited.fetch_add(1, Ordering::SeqCst);
                Vec::new()
            },
            &wait,
            |index| {
                if index == 1 {
                    receives.recv_timeout(TEST_TIMEOUT).unwrap();
                    Err(std::io::Error::other("synthetic spawn failure"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(!source.0);
        assert_eq!(exited.load(Ordering::SeqCst), 1);
        assert_eq!(drops.try_iter().count(), 2);
        assert!(!cancellation.is_cancelled());
        assert!(matches!(
            outcome.termination(),
            SourceTermination::SourceError(SourceError::Terminal {
                stage: SourceStage::Worker,
                ..
            })
        ));
    }

    #[test]
    fn cancellation_after_sender_closure_is_observed_when_workers_are_joined() {
        let cancellation = CancellationToken::new();
        let outcome = SourceRunner::new(1, 1).unwrap().run_with_worker(
            &mut TokenFragments(1),
            &SessionPolicy::default(),
            &cancellation,
            |receiver| {
                let _job = receiver.recv().unwrap();
                // Only source return and sender closure permit this receive to
                // finish; cancellation is deliberately later than the callback.
                assert!(receiver.recv().is_err());
                cancellation.cancel();
                Vec::new()
            },
        );
        assert_eq!(outcome.termination(), &SourceTermination::Cancelled);
    }

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
                    let _first = receiver.recv().unwrap();
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
                    let job = receiver.recv();
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

    /// Emits `issues` source issues, alternating plain and fragment-coupled
    /// issues, then one fragment with a token.
    struct ManyIssues(usize);

    impl Source for ManyIssues {
        fn visit(
            &mut self,
            _: &dyn crate::Cancellation,
            emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
        ) -> Result<SourceControl, SourceError> {
            for index in 0..self.0 {
                let issue = SourceIssue::new(
                    SourceStage::Traverse,
                    SourceIssueKind::Read,
                    None,
                    format!("issue {index}"),
                );
                let event = if index % 2 == 0 {
                    SourceEvent::Issue(issue)
                } else {
                    SourceEvent::Fragment {
                        fragment: Box::new(Fragment::new("token-0a")),
                        issue: Some(issue),
                    }
                };
                emit(event).map_err(SourceError::Callback)?;
            }
            emit(SourceEvent::fragment(Fragment::new("token-1a"))).map_err(SourceError::Callback)
        }
    }

    #[test]
    fn runs_without_a_budget_keep_the_first_10_000_source_issues() {
        assert_eq!(MAX_RETAINED_ISSUES, 10_000);
        let engine = token_engine();
        for (issues, omitted) in [
            (0, 0),
            (9_999, 0),
            (10_000, 0),
            (10_001, 1),
            (25_000, 15_000),
        ] {
            let outcome = SourceRunner::new(2, 2).unwrap().run(
                &mut ManyIssues(issues),
                &engine,
                ScanOptions::default(),
                &SessionPolicy::default(),
                &CancellationToken::new(),
            );
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(outcome.issues().len(), issues.min(10_000), "{issues}");
            assert_eq!(outcome.omitted_issues(), omitted, "{issues}");
            for (index, issue) in outcome.issues().iter().enumerate() {
                assert_eq!(issue.message(), format!("issue {index}"));
            }
            // Fragments coupled to an issue are not scanned, whether or not
            // the issue was kept.
            assert_eq!(secrets(&outcome), ["token-1a"], "{issues}");
        }
    }

    #[test]
    fn runner_issues_are_kept_after_the_source_issue_limit() {
        let outcome = SourceRunner::new(1, 1).unwrap().run_with_worker(
            &mut ManyIssues(10_001),
            &SessionPolicy::default(),
            &CancellationToken::new(),
            |_| panic!("worker panic for the test"),
        );
        assert_eq!(outcome.termination(), &SourceTermination::WorkerPanic);
        assert_eq!(outcome.issues().len(), 10_001);
        assert_eq!(outcome.omitted_issues(), 1);
        assert_eq!(
            outcome.issues().last().unwrap().kind(),
            SourceIssueKind::WorkerPanic
        );
    }
}
