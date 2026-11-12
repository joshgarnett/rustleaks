use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{MutexGuard, PoisonError};

use rustleaks_core::{ScanBudget, ScanBudgetKind, ScanTermination, ScanUsage};

use super::{
    Arc, CallbackError, CancellationToken, Engine, Fragment, INITIAL_QUEUE_RETRIES, Job, Mutex,
    QueueWait, ScanControl, ScanOptions, ScanOutcome, SessionPolicy, Source, SourceControl,
    SourceError, SourceEvent, SourceIssue, SourceOutcome, SourceRunner, SourceStatistics,
    SourceTermination, TrySendError, WorkerReceiver, ensure_active, finish_run,
    merge_complete_scan, mpsc, thread, worker_terminal,
};
use crate::Cancellation;

/// Opt-in inclusive limits for one source operation.
///
/// Every finite operation scan limit requires a finite matching per-fragment
/// limit. A worker reserves that fragment allowance before scanning and returns
/// unused units afterwards. Enough remaining capacity permits concurrent scans;
/// near exhaustion workers wait for reservations to settle before using the
/// remainder. Limits never multiply with the worker count.
///
/// ```
/// use rustleaks_core::ScanBudget;
/// use rustleaks_sources::{SourceBudget, SourceRunner};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let runner = SourceRunner::new(4, 8)?.with_budget(
///     SourceBudget::unlimited()
///         .max_fragment_bytes(1024 * 1024)
///         .max_original_bytes(16 * 1024 * 1024)
///         .max_fragments(1_000)
///         .max_issues(100)
///         .per_fragment(
///             ScanBudget::unlimited()
///                 .max_decoded_bytes(1024 * 1024)
///                 .max_work_units(100_000)
///                 .max_finding_records(100),
///         )
///         .aggregate(
///             ScanBudget::unlimited()
///                 .max_decoded_bytes(8 * 1024 * 1024)
///                 .max_work_units(1_000_000)
///                 .max_finding_records(1_000),
///         ),
/// )?;
/// assert_eq!(runner.workers(), 4);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceBudget {
    fragment: ScanBudget,
    operation: ScanBudget,
    fragment_bytes: Option<usize>,
    original_bytes: Option<usize>,
    fragments: Option<usize>,
    issues: Option<usize>,
}

impl SourceBudget {
    /// Returns an unlimited policy. Installing it still enables usage reporting.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            fragment: ScanBudget::unlimited(),
            operation: ScanBudget::unlimited(),
            fragment_bytes: None,
            original_bytes: None,
            fragments: None,
            issues: None,
        }
    }

    /// Sets each fragment's decoded-byte, work-unit and finding-record limits.
    #[must_use]
    pub const fn per_fragment(mut self, budget: ScanBudget) -> Self {
        self.fragment = budget;
        self
    }

    /// Sets totals across every scan, including discarded partial scans.
    #[must_use]
    pub const fn aggregate(mut self, budget: ScanBudget) -> Self {
        self.operation = budget;
        self
    }

    /// Sets the maximum original content bytes admitted in a single fragment.
    #[must_use]
    pub const fn max_fragment_bytes(mut self, maximum: usize) -> Self {
        self.fragment_bytes = Some(maximum);
        self
    }

    /// Sets total original content bytes admitted for scheduling.
    #[must_use]
    pub const fn max_original_bytes(mut self, maximum: usize) -> Self {
        self.original_bytes = Some(maximum);
        self
    }

    /// Sets the maximum number of error-free fragments admitted for scheduling.
    #[must_use]
    pub const fn max_fragments(mut self, maximum: usize) -> Self {
        self.fragments = Some(maximum);
        self
    }

    /// Sets the number of retained source issues. A further issue stops the run.
    #[must_use]
    pub const fn max_issues(mut self, maximum: usize) -> Self {
        self.issues = Some(maximum);
        self
    }

    /// Returns the per-fragment scan limits.
    #[must_use]
    pub const fn fragment_budget(self) -> ScanBudget {
        self.fragment
    }

    /// Returns the operation scan limits.
    #[must_use]
    pub const fn aggregate_budget(self) -> ScanBudget {
        self.operation
    }

    pub(super) fn validate(self) -> Result<Self, SourceBudgetError> {
        for index in 0..3 {
            if limits(self.operation)[index].is_some() && limits(self.fragment)[index].is_none() {
                return Err(SourceBudgetError {
                    kind: engine_kind(index),
                });
            }
        }
        Ok(self)
    }
}

/// A finite operation scan limit has no per-fragment reservation ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceBudgetError {
    kind: ScanBudgetKind,
}

impl SourceBudgetError {
    /// Returns the resource needing a per-fragment ceiling.
    #[must_use]
    pub const fn kind(self) -> ScanBudgetKind {
        self.kind
    }
}

impl fmt::Display for SourceBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "operation {:?} limit requires a per-fragment limit",
            self.kind
        )
    }
}

impl std::error::Error for SourceBudgetError {}

/// The scope of an exhausted source budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceBudgetScope {
    /// The configured ceiling for one fragment.
    Fragment,
    /// The configured ceiling for the complete source operation.
    Operation,
}

/// Resource whose next admission would exceed its inclusive ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceBudgetKind {
    /// Original fragment content, excluding metadata and producer buffering.
    OriginalBytes,
    /// Error-free fragments admitted for scheduling, including empty fragments.
    Fragments,
    /// Retained source diagnostics.
    Issues,
    /// Bytes in successful decoded passes.
    DecodedBytes,
    /// Engine work checkpoints.
    WorkUnits,
    /// Primary, auxiliary and projected finding records before session filtering.
    FindingRecords,
}

/// Why the runner returned incomplete results after joining every worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceBudgetExceeded {
    scope: SourceBudgetScope,
    kind: SourceBudgetKind,
    limit: usize,
    consumed: usize,
    requested: usize,
}

impl SourceBudgetExceeded {
    /// Returns whether the limit applied to one fragment or the operation.
    #[must_use]
    pub const fn scope(self) -> SourceBudgetScope {
        self.scope
    }

    /// Returns the exhausted resource.
    #[must_use]
    pub const fn kind(self) -> SourceBudgetKind {
        self.kind
    }

    /// Returns the configured inclusive limit.
    #[must_use]
    pub const fn limit(self) -> usize {
        self.limit
    }

    /// Returns consumed units when the operation was rejected.
    ///
    /// Other admitted scans can consume reserved units before cancellation is
    /// observed. The final totals are in [`SourceUsage`].
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    /// Returns units requested by the rejected operation.
    #[must_use]
    pub const fn requested(self) -> usize {
        self.requested
    }
}

/// Accounted resources for a run with an explicit [`SourceBudget`].
///
/// Consumed engine units include partial scans whose findings were discarded.
/// A panicking scan retains its full reservation and makes usage inexact.
/// Limits on counts and content are not a heap-allocation or wall-time quota.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceUsage {
    original_bytes: usize,
    fragments: usize,
    completed_fragments: usize,
    engine: [usize; 3],
    inexact: bool,
}

impl SourceUsage {
    /// Returns original bytes admitted for scheduling, including queued work.
    #[must_use]
    pub const fn original_bytes(self) -> usize {
        self.original_bytes
    }

    /// Returns error-free fragments admitted for scheduling.
    #[must_use]
    pub const fn fragments(self) -> usize {
        self.fragments
    }

    /// Returns fragments whose engine scans completed, before session filtering.
    ///
    /// A worker panic can discard that worker's earlier completed batch.
    #[must_use]
    pub const fn completed_fragments(self) -> usize {
        self.completed_fragments
    }

    /// Returns admitted fragments not completely scanned, including queued work.
    #[must_use]
    pub const fn incomplete_fragments(self) -> usize {
        self.fragments - self.completed_fragments
    }

    /// Returns accounted decoded bytes; see [`Self::is_exact`] after a panic.
    #[must_use]
    pub const fn decoded_bytes(self) -> usize {
        self.engine[0]
    }

    /// Returns accounted work units; see [`Self::is_exact`] after a panic.
    #[must_use]
    pub const fn work_units(self) -> usize {
        self.engine[1]
    }

    /// Returns accounted finding records; see [`Self::is_exact`] after a panic.
    #[must_use]
    pub const fn finding_records(self) -> usize {
        self.engine[2]
    }

    /// Returns whether every engine scan reported its exact consumed usage.
    ///
    /// When false, configured operation dimensions retain the full reservation
    /// of panicking scans. Unbounded dimensions have unknown additional usage.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        !self.inexact
    }
}

fn limits(budget: ScanBudget) -> [Option<usize>; 3] {
    [
        budget.decoded_bytes(),
        budget.work_units(),
        budget.finding_records(),
    ]
}

fn usage(usage: ScanUsage) -> [usize; 3] {
    [
        usage.decoded_bytes(),
        usage.work_units(),
        usage.finding_records(),
    ]
}

fn engine_kind(index: usize) -> ScanBudgetKind {
    match index {
        0 => ScanBudgetKind::DecodedBytes,
        1 => ScanBudgetKind::WorkUnits,
        _ => ScanBudgetKind::FindingRecords,
    }
}

fn source_kind(index: usize) -> SourceBudgetKind {
    match index {
        0 => SourceBudgetKind::DecodedBytes,
        1 => SourceBudgetKind::WorkUnits,
        _ => SourceBudgetKind::FindingRecords,
    }
}

fn index(kind: ScanBudgetKind) -> Option<usize> {
    match kind {
        ScanBudgetKind::DecodedBytes => Some(0),
        ScanBudgetKind::WorkUnits => Some(1),
        ScanBudgetKind::FindingRecords => Some(2),
        _ => None,
    }
}

#[derive(Default)]
struct Accounting {
    usage: SourceUsage,
    reserved: [usize; 3],
    active: usize,
    exceeded: Option<SourceBudgetExceeded>,
}

struct Operation<'a> {
    budget: SourceBudget,
    cancellation: &'a CancellationToken,
    stopped: AtomicBool,
    accounting: Mutex<Accounting>,
}

impl Cancellation for Operation<'_> {
    fn is_cancelled(&self) -> bool {
        self.stopped.load(Ordering::Acquire) || self.cancellation.is_cancelled()
    }
}

impl Operation<'_> {
    fn lock(&self) -> MutexGuard<'_, Accounting> {
        self.accounting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn stop(&self, accounting: &mut Accounting, exceeded: SourceBudgetExceeded) {
        accounting.exceeded.get_or_insert(exceeded);
        self.stopped.store(true, Ordering::Release);
    }

    fn admit(&self, bytes: usize) -> bool {
        let mut state = self.lock();
        if self.is_cancelled() {
            return false;
        }
        for (kind, consumed, requested, limit, scope) in [
            (
                SourceBudgetKind::OriginalBytes,
                0,
                bytes,
                self.budget.fragment_bytes,
                SourceBudgetScope::Fragment,
            ),
            (
                SourceBudgetKind::OriginalBytes,
                state.usage.original_bytes,
                bytes,
                self.budget.original_bytes,
                SourceBudgetScope::Operation,
            ),
            (
                SourceBudgetKind::Fragments,
                state.usage.fragments,
                1,
                self.budget.fragments,
                SourceBudgetScope::Operation,
            ),
        ] {
            let limit = limit.unwrap_or(usize::MAX);
            if requested > limit.saturating_sub(consumed) {
                self.stop(
                    &mut state,
                    SourceBudgetExceeded {
                        scope,
                        kind,
                        limit,
                        consumed,
                        requested,
                    },
                );
                return false;
            }
        }
        state.usage.original_bytes += bytes;
        state.usage.fragments += 1;
        true
    }

    fn retain_issue(&self, issues: &mut Vec<SourceIssue>, issue: SourceIssue) -> bool {
        if let Some(limit) = self.budget.issues
            && issues.len() == limit
        {
            self.stop(
                &mut self.lock(),
                SourceBudgetExceeded {
                    scope: SourceBudgetScope::Operation,
                    kind: SourceBudgetKind::Issues,
                    limit,
                    consumed: limit,
                    requested: 1,
                },
            );
            return false;
        }
        issues.push(issue);
        true
    }

    fn reserve(&self) -> Option<Reservation<'_>> {
        let fragment = limits(self.budget.fragment);
        let aggregate = limits(self.budget.operation);
        loop {
            if self.is_cancelled() {
                return None;
            }
            let mut state = self.lock();
            let available = std::array::from_fn::<_, 3, _>(|index| {
                aggregate[index]
                    .map(|limit| limit - state.usage.engine[index] - state.reserved[index])
            });
            let must_wait = state.active != 0
                && (0..3).any(|index| {
                    available[index]
                        .is_some_and(|remaining| remaining < fragment[index].unwrap_or(0))
                });
            if must_wait {
                drop(state);
                thread::yield_now();
                continue;
            }
            let mut budget = self.budget.fragment;
            let reserved = std::array::from_fn(|index| {
                available[index].map_or(0, |remaining| remaining.min(fragment[index].unwrap_or(0)))
            });
            if aggregate[0].is_some() {
                budget = budget.max_decoded_bytes(reserved[0]);
            }
            if aggregate[1].is_some() {
                budget = budget.max_work_units(reserved[1]);
            }
            if aggregate[2].is_some() {
                budget = budget.max_finding_records(reserved[2]);
            }
            for (index, amount) in reserved.iter().enumerate() {
                state.reserved[index] += amount;
            }
            state.active += 1;
            return Some(Reservation {
                operation: self,
                reserved,
                budget,
                settled: false,
            });
        }
    }
}

struct Reservation<'a> {
    operation: &'a Operation<'a>,
    reserved: [usize; 3],
    budget: ScanBudget,
    settled: bool,
}

impl Reservation<'_> {
    fn settle(mut self, outcome: &ScanOutcome) {
        let mut state = self.operation.lock();
        for (index, amount) in usage(outcome.usage()).iter().enumerate() {
            state.reserved[index] -= self.reserved[index];
            if let Some(next) = state.usage.engine[index].checked_add(*amount) {
                state.usage.engine[index] = next;
            } else {
                let consumed = state.usage.engine[index];
                self.operation.stop(
                    &mut state,
                    SourceBudgetExceeded {
                        scope: SourceBudgetScope::Operation,
                        kind: source_kind(index),
                        limit: usize::MAX,
                        consumed,
                        requested: *amount,
                    },
                );
                state.usage.engine[index] = usize::MAX;
                state.usage.inexact = true;
            }
        }
        if outcome.is_complete() {
            state.usage.completed_fragments += 1;
        }
        if let Some(ScanTermination::BudgetExceeded {
            kind,
            limit,
            consumed,
            requested,
        }) = outcome.termination()
            && let Some(index) = index(*kind)
        {
            let aggregate = limits(self.operation.budget.operation)[index];
            let fragment = limits(self.operation.budget.fragment)[index];
            // Equal ceilings are attributed to the explicit fragment cap.
            let operation_limited = fragment.is_some_and(|fragment| *limit < fragment);
            let scope = if operation_limited {
                SourceBudgetScope::Operation
            } else {
                SourceBudgetScope::Fragment
            };
            let limit = if operation_limited {
                aggregate.unwrap_or(*limit)
            } else {
                *limit
            };
            let consumed = if operation_limited {
                state.usage.engine[index]
            } else {
                *consumed
            };
            self.operation.stop(
                &mut state,
                SourceBudgetExceeded {
                    scope,
                    kind: source_kind(index),
                    limit,
                    consumed,
                    requested: *requested,
                },
            );
        }
        state.active -= 1;
        self.settled = true;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.settled {
            let mut state = self.operation.lock();
            for (index, reserved) in self.reserved.iter().enumerate() {
                state.reserved[index] -= reserved;
                state.usage.engine[index] += reserved;
            }
            state.active -= 1;
            state.usage.inexact = true;
            self.operation.stopped.store(true, Ordering::Release);
        }
    }
}

struct WorkerGuard<'a>(&'a Operation<'a>);

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.stopped.store(true, Ordering::Release);
        }
    }
}

fn schedule(
    operation: &Operation<'_>,
    job: Job,
    queue_wait: &QueueWait,
    mut try_send: impl FnMut(Job) -> Result<(), TrySendError<Job>>,
) -> Result<SourceControl, CallbackError> {
    let mut pending = job;
    let mut waiting = None;
    let mut remaining_retries = INITIAL_QUEUE_RETRIES;
    loop {
        ensure_active(
            operation.cancellation,
            "source runner cancelled while scheduling",
        )?;
        #[cfg(test)]
        if let Some(after_external_check) = &queue_wait.after_external_check {
            after_external_check();
        }
        if operation.is_cancelled() {
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
                // check above and drop the receiver before this send. Preserve
                // that internal stop instead of manufacturing a source error.
                if operation.stopped.load(Ordering::Acquire) {
                    return Ok(SourceControl::Stop);
                }
                return Err(CallbackError::new("all source runner workers disconnected"));
            }
        }
    }
}

pub(super) fn run(
    runner: &SourceRunner,
    source: &mut dyn Source,
    engine: &Engine,
    scan_options: ScanOptions,
    policy: &SessionPolicy,
    cancellation: &CancellationToken,
    budget: SourceBudget,
) -> SourceOutcome {
    run_with_scan(
        runner,
        source,
        policy,
        cancellation,
        budget,
        |fragment, control| engine.scan_fragment_controlled(fragment, &scan_options, control),
    )
}

fn run_with_scan(
    runner: &SourceRunner,
    source: &mut dyn Source,
    policy: &SessionPolicy,
    cancellation: &CancellationToken,
    budget: SourceBudget,
    scan: impl Fn(&Fragment, &ScanControl<'_>) -> ScanOutcome + Sync,
) -> SourceOutcome {
    run_with_scan_setup(
        runner,
        source,
        policy,
        cancellation,
        budget,
        scan,
        &QueueWait::default(),
        |_| Ok(()),
    )
}

#[allow(clippy::result_large_err)] // The bounded channel returns ownership of an unsent fragment without another allocation.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Keep setup failure injection and mandatory joins in one ownership scope.
fn run_with_scan_setup(
    runner: &SourceRunner,
    source: &mut dyn Source,
    policy: &SessionPolicy,
    cancellation: &CancellationToken,
    budget: SourceBudget,
    scan: impl Fn(&Fragment, &ScanControl<'_>) -> ScanOutcome + Sync,
    queue_wait: &QueueWait,
    before_spawn: impl Fn(usize) -> std::io::Result<()>,
) -> SourceOutcome {
    let operation = Operation {
        budget,
        cancellation,
        stopped: AtomicBool::new(false),
        accounting: Mutex::new(Accounting::default()),
    };
    let (sender, receiver) = mpsc::sync_channel::<Job>(runner.queue_capacity());
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
            .try_reserve_exact(runner.workers())
            .err()
            .map(|error| worker_terminal(format!("could not allocate worker handles: {error}")));
        if setup_error.is_none() {
            for index in 0..runner.workers() {
                let receiver = WorkerReceiver::new(Arc::clone(&receiver), queue_wait);
                let operation = &operation;
                let scan = &scan;
                match before_spawn(index).and_then(|()| {
                    thread::Builder::new()
                        .name(format!("rustleaks-source-{index}"))
                        .spawn_scoped(scope, move || {
                            // This local guard publishes panic stop before the
                            // captured receiver owner drops and notifies.
                            let _guard = WorkerGuard(operation);
                            let mut batches = Vec::new();
                            loop {
                                if operation.is_cancelled() {
                                    break;
                                }
                                let job = receiver.recv();
                                let Ok(job) = job else { break };
                                let Some(reservation) = operation.reserve() else {
                                    break;
                                };
                                let signal = || operation.is_cancelled();
                                let control = ScanControl::cancellable(&signal)
                                    .with_budget(reservation.budget);
                                let detected = scan(&job.fragment, &control);
                                reservation.settle(&detected);
                                if !merge_complete_scan(
                                    &mut batches,
                                    policy,
                                    job.sequence,
                                    detected,
                                ) {
                                    break;
                                }
                            }
                            batches
                        })
                }) {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        setup_error = Some(worker_terminal(format!(
                            "could not spawn detection worker: {error}"
                        )));
                        operation.stopped.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        }
        drop(receiver);
        if let Some(error) = setup_error {
            source_result = Err(error);
        } else {
            source_result = source.visit(&operation, &mut |event| {
                ensure_active(
                    cancellation,
                    "source runner cancelled while receiving an event",
                )?;
                if operation.is_cancelled() {
                    return Ok(SourceControl::Stop);
                }
                let fragment = match event {
                    SourceEvent::Issue(issue) => {
                        return Ok(if operation.retain_issue(&mut issues, issue) {
                            SourceControl::Continue
                        } else {
                            SourceControl::Stop
                        });
                    }
                    SourceEvent::Fragment { fragment, issue } => {
                        if let Some(issue) = issue {
                            return Ok(if operation.retain_issue(&mut issues, issue) {
                                SourceControl::Continue
                            } else {
                                SourceControl::Stop
                            });
                        }
                        *fragment
                    }
                };
                if !operation.admit(fragment.content().len()) {
                    return Ok(SourceControl::Stop);
                }
                statistics.observe(&fragment)?;
                let sequence = next_sequence;
                next_sequence += 1;
                schedule(
                    &operation,
                    Job { sequence, fragment },
                    queue_wait,
                    |pending| sender.try_send(pending),
                )
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
    let state = operation.lock();
    let stopped_for_budget =
        state.exceeded.is_some() && matches!(source_result, Ok(_) | Err(SourceError::Cancelled));
    let mut outcome = finish_run(
        policy,
        batches,
        issues,
        source_result,
        worker_panicked,
        cancellation.is_cancelled(),
        statistics,
    );
    if !worker_panicked
        && !cancellation.is_cancelled()
        && stopped_for_budget
        && let Some(exceeded) = state.exceeded
    {
        outcome.termination = SourceTermination::BudgetExceeded(exceeded);
    }
    if let Some(maximum) = budget.issues {
        outcome.issues.truncate(maximum);
    }
    outcome.usage = Some(state.usage);
    outcome
}

#[cfg(test)]
mod tests {
    use std::sync::Condvar;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use rustleaks_core::config::ConfigLoader;

    use super::*;
    use crate::SourceStage;

    fn engine() -> Engine {
        Engine::builder(
            ConfigLoader::new()
                .load_toml("[[rules]]\nid = 'synthetic'\nregex = 'A'\n")
                .unwrap(),
        )
        .build()
        .unwrap()
    }

    fn job() -> Job {
        Job {
            sequence: 0,
            fragment: Fragment::new("A"),
        }
    }

    fn unlimited_operation(cancellation: &CancellationToken) -> Operation<'_> {
        Operation {
            budget: SourceBudget::unlimited(),
            cancellation,
            stopped: AtomicBool::new(false),
            accounting: Mutex::new(Accounting::default()),
        }
    }

    #[test]
    fn full_queue_cancellation_reaches_source_before_reserved_workers_are_released() {
        let detector = engine();
        for workers in [1, 4] {
            for capacity in [1, 3] {
                super::super::tests::assert_full_queue_cancellation(
                    workers,
                    capacity,
                    |source, cancellation, wait, held| {
                        run_with_scan_setup(
                            &SourceRunner::new(workers, capacity).unwrap(),
                            source,
                            &SessionPolicy::default(),
                            cancellation,
                            policy(3 * workers, workers),
                            |fragment, control| {
                                held.hold();
                                detector.scan_fragment_controlled(
                                    fragment,
                                    &ScanOptions::default(),
                                    control,
                                )
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
    fn cancellation_between_existing_checks_preserves_normal_callback_stop() {
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let wait = QueueWait {
            after_external_check: Some(Box::new(move || signal.cancel())),
            ..QueueWait::default()
        };
        let operation = unlimited_operation(&cancellation);
        let result = schedule(&operation, job(), &wait, |_| {
            panic!("the second cancellation check must stop before sending")
        });
        assert_eq!(result.unwrap(), SourceControl::Stop);
        assert!(!operation.stopped.load(Ordering::Acquire));
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn cancellation_after_checks_does_not_reclassify_a_successful_enqueue() {
        let cancellation = CancellationToken::new();
        let operation = unlimited_operation(&cancellation);
        let wait = QueueWait::default();
        let (sender, receiver) = mpsc::sync_channel(1);
        let result = schedule(&operation, job(), &wait, |pending| {
            cancellation.cancel();
            sender.try_send(pending)
        });
        assert_eq!(result.unwrap(), SourceControl::Continue);
        assert!(receiver.try_recv().is_ok());
    }

    #[test]
    fn cancellation_after_checks_does_not_replace_the_disconnect_callback_error() {
        let cancellation = CancellationToken::new();
        let operation = unlimited_operation(&cancellation);
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let result = schedule(&operation, job(), &QueueWait::default(), |pending| {
            cancellation.cancel();
            sender.try_send(pending)
        });
        assert_eq!(
            result.unwrap_err().message(),
            "all source runner workers disconnected"
        );
        assert!(!operation.stopped.load(Ordering::Acquire));
    }

    #[test]
    fn external_cancellation_already_present_precedes_internal_stop() {
        let cancellation = CancellationToken::new();
        let operation = unlimited_operation(&cancellation);
        operation.stopped.store(true, Ordering::Release);
        cancellation.cancel();
        let result = schedule(&operation, job(), &QueueWait::default(), |_| {
            panic!("cancelled scheduling must not attempt a send")
        });
        assert_eq!(
            result.unwrap_err().message(),
            "source runner cancelled while scheduling"
        );
    }

    #[test]
    fn sleeping_producer_observes_internal_stop_without_worker_progress() {
        let cancellation = CancellationToken::new();
        let operation = unlimited_operation(&cancellation);
        let (before_wait, waits) = mpsc::channel();
        let wait = QueueWait {
            before_wait: Some(before_wait),
            ..QueueWait::default()
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        assert!(sender.try_send(job()).is_ok());
        thread::scope(|scope| {
            let operation = &operation;
            let notification = &wait;
            let (done, completion) = mpsc::channel();
            let stopper = scope.spawn(move || {
                waits.recv_timeout(Duration::from_secs(5)).unwrap();
                operation.stopped.store(true, Ordering::Release);
                let rescued = completion.recv_timeout(Duration::from_secs(5)).is_err();
                if rescued {
                    notification.notify();
                }
                rescued
            });
            let result = schedule(operation, job(), &wait, |pending| sender.try_send(pending));
            done.send(()).unwrap();
            assert_eq!(result.unwrap(), SourceControl::Stop);
            assert!(
                !stopper.join().unwrap(),
                "internal stop must be polled before watchdog notification"
            );
        });
        assert!(!cancellation.is_cancelled());
        assert!(receiver.try_recv().is_ok());
    }

    #[test]
    fn initial_retries_observe_cancellation_and_stop_before_acquiring_the_gate() {
        for internal_stop in [false, true] {
            let cancellation = CancellationToken::new();
            let operation = unlimited_operation(&cancellation);
            let wait = QueueWait::default();
            let guard = wait.lock();
            let (done, completion) = mpsc::channel();
            thread::scope(|scope| {
                let signal = &cancellation;
                let operation = &operation;
                let notification = &wait;
                let producer = scope.spawn(move || {
                    let mut attempts = 0;
                    let result = schedule(operation, job(), notification, |pending| {
                        attempts += 1;
                        if attempts == 2 {
                            if internal_stop {
                                operation.stopped.store(true, Ordering::Release);
                            } else {
                                signal.cancel();
                            }
                        }
                        Err(TrySendError::Full(pending))
                    });
                    let _ = done.send((result, attempts));
                });
                let observed = completion.recv_timeout(Duration::from_secs(5));
                if observed.is_err() {
                    cancellation.cancel();
                }
                // Release the gate and join even if early polling regresses.
                drop(guard);
                wait.notify();
                producer.join().unwrap();
                let (result, attempts) =
                    observed.expect("initial retries must poll before acquiring the gate");
                assert_eq!(attempts, 2);
                if internal_stop {
                    assert_eq!(result.unwrap(), SourceControl::Stop);
                    assert!(!cancellation.is_cancelled());
                } else {
                    assert_eq!(
                        result.unwrap_err().message(),
                        "source runner cancelled while scheduling"
                    );
                }
            });
        }
    }

    #[test]
    fn initial_retries_are_bounded_across_spurious_notifications_and_timeouts() {
        for notify in [false, true] {
            let cancellation = CancellationToken::new();
            let operation = unlimited_operation(&cancellation);
            let (before_wait, waits) = mpsc::channel();
            let (after_yield, yields) = mpsc::channel();
            let wait = QueueWait {
                interval: if notify {
                    Duration::from_secs(30)
                } else {
                    Duration::from_micros(100)
                },
                before_wait: Some(before_wait),
                after_yield: Some(after_yield),
                ..QueueWait::default()
            };
            let (sender, receiver) = mpsc::sync_channel(1);
            assert!(sender.try_send(job()).is_ok());
            let observed = thread::scope(|scope| {
                let notification = &wait;
                let signal = &cancellation;
                let notifier = scope.spawn(move || {
                    let observed = (|| {
                        waits.recv_timeout(Duration::from_secs(5)).ok()?;
                        let guard = notification.lock();
                        let initial_yields = yields.try_iter().count();
                        while waits.try_recv().is_ok() {}
                        drop(guard);
                        if notify {
                            notification.notify();
                        }
                        waits.recv_timeout(Duration::from_secs(5)).ok()?;
                        let guard = notification.lock();
                        let repeated_yields = yields.try_iter().count();
                        drop(guard);
                        Some((initial_yields, repeated_yields))
                    })();
                    let guard = notification.lock();
                    signal.cancel();
                    notification.changed.notify_one();
                    drop(guard);
                    observed
                });
                let result = schedule(&operation, job(), &wait, |pending| sender.try_send(pending));
                let observed = notifier.join().unwrap();
                assert_eq!(
                    result.unwrap_err().message(),
                    "source runner cancelled while scheduling"
                );
                observed
            });
            assert_eq!(
                observed,
                Some((32, 0)),
                "a full pending job gets one bounded retry phase, including after a wake"
            );
            assert!(receiver.try_recv().is_ok());
            assert!(receiver.try_recv().is_err());
        }
    }

    #[test]
    fn partial_spawn_failure_skips_source_and_releases_idle_budget_workers() {
        let (before_receive, receives) = mpsc::channel();
        let (receiver_dropped, drops) = mpsc::channel();
        let wait = QueueWait {
            before_receive: Some(before_receive),
            receiver_dropped: Some(receiver_dropped),
            ..QueueWait::default()
        };
        let mut source = super::super::tests::UnvisitedSource(false);
        let cancellation = CancellationToken::new();
        let outcome = run_with_scan_setup(
            &SourceRunner::new(4, 1).unwrap(),
            &mut source,
            &SessionPolicy::default(),
            &cancellation,
            SourceBudget::unlimited(),
            |_, _| panic!("setup failure must not scan fragments"),
            &wait,
            |index| {
                if index == 1 {
                    receives.recv_timeout(Duration::from_secs(5)).unwrap();
                    Err(std::io::Error::other("synthetic spawn failure"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(!source.0);
        assert_eq!(drops.try_iter().count(), 2);
        assert!(!cancellation.is_cancelled());
        assert_eq!(outcome.usage().unwrap().fragments(), 0);
        assert!(matches!(
            outcome.termination(),
            SourceTermination::SourceError(SourceError::Terminal {
                stage: SourceStage::Worker,
                ..
            })
        ));
    }

    struct Fragments(usize);

    impl Source for Fragments {
        fn visit(
            &mut self,
            cancellation: &dyn Cancellation,
            emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
        ) -> Result<SourceControl, SourceError> {
            for _ in 0..self.0 {
                if cancellation.is_cancelled() {
                    return Err(SourceError::Cancelled);
                }
                let control = emit(SourceEvent::fragment(Fragment::new("A")))
                    .map_err(SourceError::Callback)?;
                if control == SourceControl::Stop {
                    return Ok(control);
                }
            }
            Ok(SourceControl::Continue)
        }
    }

    fn policy(work: usize, records: usize) -> SourceBudget {
        SourceBudget::unlimited()
            .per_fragment(
                ScanBudget::unlimited()
                    .max_work_units(3)
                    .max_finding_records(1),
            )
            .aggregate(
                ScanBudget::unlimited()
                    .max_work_units(work)
                    .max_finding_records(records),
            )
    }

    #[test]
    #[allow(clippy::result_large_err)] // Exercise the real channel ownership result at the scheduling boundary.
    fn last_worker_budget_stop_between_check_and_send_preserves_stop() {
        let detector = engine();
        let cancellation = CancellationToken::new();
        let operation = Operation {
            budget: policy(0, 1),
            cancellation: &cancellation,
            stopped: AtomicBool::new(false),
            accounting: Mutex::new(Accounting::default()),
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut receiver = Some(receiver);
        let scheduled = schedule(&operation, job(), &QueueWait::default(), |pending| {
            // This closure runs after the scheduling cancellation check. Force
            // the worker's exhaustion and last-receiver drop before try_send.
            assert!(!operation.is_cancelled());
            let reservation = operation.reserve().unwrap();
            let detected = detector.scan_fragment_controlled(
                &Fragment::new("A"),
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(reservation.budget),
            );
            reservation.settle(&detected);
            drop(receiver.take().unwrap());
            sender.try_send(pending)
        });
        assert_eq!(scheduled.unwrap(), SourceControl::Stop);
        assert_eq!(
            operation.lock().exceeded,
            Some(SourceBudgetExceeded {
                scope: SourceBudgetScope::Operation,
                kind: SourceBudgetKind::WorkUnits,
                limit: 0,
                consumed: 0,
                requested: 1,
            }),
        );
        assert!(!cancellation.is_cancelled());
    }

    #[test]
    #[allow(clippy::result_large_err)] // Exercise the real channel ownership result at the scheduling boundary.
    fn disconnection_without_an_internal_stop_remains_a_callback_error() {
        let cancellation = CancellationToken::new();
        let operation = Operation {
            budget: SourceBudget::unlimited(),
            cancellation: &cancellation,
            stopped: AtomicBool::new(false),
            accounting: Mutex::new(Accounting::default()),
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let error = schedule(&operation, job(), &QueueWait::default(), |pending| {
            sender.try_send(pending)
        })
        .unwrap_err();
        assert_eq!(error.message(), "all source runner workers disconnected");
        assert!(operation.lock().exceeded.is_none());
    }

    #[test]
    fn reservations_allow_parallel_scans_when_capacity_is_available() {
        let detector = engine();
        let rendezvous = (Mutex::new(0), Condvar::new());
        let outcome = run_with_scan(
            &SourceRunner::new(2, 1).unwrap(),
            &mut Fragments(2),
            &SessionPolicy::default(),
            &CancellationToken::new(),
            policy(6, 2),
            |fragment, control| {
                let (arrivals, changed) = &rendezvous;
                let mut arrived = arrivals.lock().unwrap();
                *arrived += 1;
                changed.notify_all();
                let (arrived, _) = changed
                    .wait_timeout_while(arrived, Duration::from_secs(5), |arrived| *arrived < 2)
                    .unwrap();
                assert_eq!(*arrived, 2, "two reserved scans must enter concurrently");
                drop(arrived);
                detector.scan_fragment_controlled(fragment, &ScanOptions::default(), control)
            },
        );
        assert_eq!(outcome.termination(), &SourceTermination::Completed);
        assert_eq!(outcome.findings().len(), 2);
        assert_eq!(outcome.usage().unwrap().work_units(), 6);
    }

    #[test]
    fn unused_reservations_are_refunded_before_admitting_the_remainder() {
        let detector = engine();
        // Each fragment actually requires three units. A six-unit reservation
        // first excludes peers; refunding three allows both fragments to finish.
        for workers in [1, 4] {
            let budget = SourceBudget::unlimited()
                .per_fragment(ScanBudget::unlimited().max_work_units(6))
                .aggregate(ScanBudget::unlimited().max_work_units(6));
            let outcome = SourceRunner::new(workers, 1)
                .unwrap()
                .with_budget(budget)
                .unwrap()
                .run(
                    &mut Fragments(2),
                    &detector,
                    ScanOptions::default(),
                    &SessionPolicy::default(),
                    &CancellationToken::new(),
                );
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(outcome.findings().len(), 2);
            assert_eq!(outcome.usage().unwrap().work_units(), 6);
        }
    }

    #[test]
    fn panic_keeps_reservation_and_joins_workers_without_external_cancellation() {
        struct Exited<'a>(&'a AtomicUsize);
        impl Drop for Exited<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        for workers in [1, 4] {
            let entered = AtomicUsize::new(0);
            let exited = AtomicUsize::new(0);
            let cancellation = CancellationToken::new();
            let rescue = cancellation.clone();
            let (done, completion) = mpsc::channel();
            let watchdog = thread::spawn(move || {
                if completion.recv_timeout(Duration::from_secs(5)).is_err() {
                    rescue.cancel();
                }
            });
            let outcome = run_with_scan(
                &SourceRunner::new(workers, 1).unwrap(),
                &mut Fragments(128),
                &SessionPolicy::default(),
                &cancellation,
                policy(3 * workers, workers),
                |_, _| {
                    entered.fetch_add(1, Ordering::SeqCst);
                    let _guard = Exited(&exited);
                    panic!("synthetic reserved scan failure");
                },
            );
            done.send(()).unwrap();
            watchdog.join().unwrap();
            assert!(
                !cancellation.is_cancelled(),
                "failure cleanup must not need the watchdog"
            );
            assert_eq!(outcome.termination(), &SourceTermination::WorkerPanic);
            assert_eq!(
                entered.load(Ordering::SeqCst),
                exited.load(Ordering::SeqCst)
            );
            let usage = outcome.usage().unwrap();
            assert!(!usage.is_exact());
            assert_eq!(usage.work_units(), 3 * exited.load(Ordering::SeqCst));
            assert_eq!(usage.finding_records(), exited.load(Ordering::SeqCst));
            assert!(usage.work_units() <= workers * 3);
            assert!(outcome.findings().is_empty());
        }
    }

    #[test]
    fn cancelled_reservation_is_settled_and_queued_work_is_discarded() {
        for workers in [1, 4] {
            let detector = engine();
            let cancellation = CancellationToken::new();
            let outcome = run_with_scan(
                &SourceRunner::new(workers, 1).unwrap(),
                &mut Fragments(128),
                &SessionPolicy::default(),
                &cancellation,
                policy(3 * workers, workers),
                |fragment, control| {
                    cancellation.cancel();
                    detector.scan_fragment_controlled(fragment, &ScanOptions::default(), control)
                },
            );
            assert_eq!(outcome.termination(), &SourceTermination::Cancelled);
            assert!(outcome.findings().is_empty());
            let usage = outcome.usage().unwrap();
            assert_eq!(usage.work_units(), 0);
            assert_eq!(usage.completed_fragments(), 0);
            assert!(usage.fragments() > 0);
            assert!(
                usage.fragments() <= workers + 2,
                "one queued and one producer-held fragment at most"
            );
            assert!(usage.is_exact());
        }
    }

    #[test]
    fn source_failure_and_normal_stop_join_workers_and_keep_complete_batches() {
        struct EndingSource(bool);
        impl Source for EndingSource {
            fn visit(
                &mut self,
                _: &dyn Cancellation,
                emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
            ) -> Result<SourceControl, SourceError> {
                emit(SourceEvent::fragment(Fragment::new("A"))).map_err(SourceError::Callback)?;
                if self.0 {
                    Err(SourceError::Terminal {
                        stage: SourceStage::Read,
                        path: None,
                        message: "synthetic source failure".to_owned(),
                    })
                } else {
                    Ok(SourceControl::Stop)
                }
            }
        }
        for workers in [1, 4] {
            for failed in [false, true] {
                let cancellation = CancellationToken::new();
                let outcome = SourceRunner::new(workers, 1)
                    .unwrap()
                    .with_budget(policy(3, 1))
                    .unwrap()
                    .run(
                        &mut EndingSource(failed),
                        &engine(),
                        ScanOptions::default(),
                        &SessionPolicy::default(),
                        &cancellation,
                    );
                if failed {
                    assert!(matches!(
                        outcome.termination(),
                        SourceTermination::SourceError(SourceError::Terminal {
                            stage: SourceStage::Read,
                            ..
                        })
                    ));
                } else {
                    assert_eq!(outcome.termination(), &SourceTermination::Stopped);
                }
                assert_eq!(outcome.findings().len(), 1);
                assert_eq!(outcome.usage().unwrap().completed_fragments(), 1);
                assert!(outcome.usage().unwrap().is_exact());
                assert!(!cancellation.is_cancelled());
            }
        }
    }
}
