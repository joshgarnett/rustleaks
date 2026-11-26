//! The objects behind the C handles, in safe Rust.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use rustleaks_core::config::{CompiledConfig, ConfigLoader};
use rustleaks_core::model::{Base64Mode, ByteText, Finding, Fragment, ScanOptions};
use rustleaks_core::{
    Engine, ScanBudget, ScanBudgetKind, ScanControl, ScanOutcome, ScanScratch, ScanTermination,
};

use crate::abi::{
    BASE64_COMPATIBLE, BASE64_EXTENDED, BUDGET_COLLECTED_SPANS, BUDGET_DECODED_BYTES,
    BUDGET_FINDING_PAYLOAD_BYTES, BUDGET_FINDING_RECORDS, BUDGET_NONE, BUDGET_NORMALIZATION_BYTES,
    BUDGET_WORK_UNITS, Bytes, ERROR_CONFIG, ERROR_ENGINE, ERROR_INPUT_TOO_LARGE,
    ERROR_INVALID_ARGUMENT, ERROR_PANIC, ERROR_RULE_SELECTION, FindingView, MAX_WORKERS,
    OPTION_ALLOW_COMMENTS, OPTION_BASE64_MODE, OPTION_DECODE_DEPTH, OPTION_MAX_COLLECTED_SPANS,
    OPTION_MAX_DECODED_BYTES, OPTION_MAX_FINDING_PAYLOAD_BYTES, OPTION_MAX_FINDING_RECORDS,
    OPTION_MAX_INPUT_BYTES, OPTION_MAX_NORMALIZATION_BYTES, OPTION_MAX_WORK_UNITS,
    OPTION_REDACTION_PERCENT, OPTION_SCAN_ON_CALLER_THREAD, OPTION_WORKERS, RuleView,
    SCAN_SET_ALLOW_COMMENTS, SCAN_SET_BASE64_MODE, SCAN_SET_DEADLINE, SCAN_SET_DECODE_DEPTH,
    SCAN_SET_MAX_COLLECTED_SPANS, SCAN_SET_MAX_DECODED_BYTES, SCAN_SET_MAX_FINDING_PAYLOAD_BYTES,
    SCAN_SET_MAX_FINDING_RECORDS, SCAN_SET_MAX_NORMALIZATION_BYTES, SCAN_SET_MAX_WORK_UNITS,
    SCAN_SET_REDACTION_PERCENT, StatusView, TERMINATION_BUDGET, TERMINATION_CANCELLED,
    TERMINATION_COMPLETE, TERMINATION_DEADLINE, TERMINATION_OTHER, UNLIMITED,
};
use crate::cancel::{CancelFlag, ScanSignal};
use crate::threads::{ScanThreads, on_scan_stack};

/// Default inclusive input limit in bytes.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 10_000_000;
/// Default finding record budget.
pub const DEFAULT_MAX_FINDING_RECORDS: u64 = 100_000;
/// Most workers that the default count gives, as in the `rustleaks` command.
const MAX_DEFAULT_WORKERS: usize = 12;
/// Estimated search cache bytes that all workers of an engine keep together.
const SEARCH_CACHE_BYTES: usize = 128 << 20;
/// Estimated search cache bytes that one worker can always keep.
const WORKER_SEARCH_CACHE_FLOOR: usize = 8 << 20;

/// An error that a call returns through a `rustleaks_error` handle.
#[derive(Debug)]
pub struct FfiError {
    kind: i32,
    message: String,
}

impl FfiError {
    /// An error of `kind` with `message`.
    pub fn new(kind: i32, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The error for a caught panic. It holds no text from the panic, which
    /// could quote scanned bytes.
    #[must_use]
    pub fn panic() -> Self {
        Self::new(ERROR_PANIC, "rustleaks caught an internal panic")
    }

    /// The `ERROR_*` kind.
    #[must_use]
    pub const fn kind(&self) -> i32 {
        self.kind
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Optional limits of one scan, as given to the options or a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Budgets {
    decoded_bytes: u64,
    work_units: u64,
    finding_records: u64,
    finding_payload_bytes: u64,
    collected_spans: u64,
    normalization_bytes: u64,
}

impl Budgets {
    fn scan_budget(self) -> ScanBudget {
        let mut budget = ScanBudget::unlimited();
        if let Some(value) = limit(self.decoded_bytes) {
            budget = budget.max_decoded_bytes(value);
        }
        if let Some(value) = limit(self.work_units) {
            budget = budget.max_work_units(value);
        }
        if let Some(value) = limit(self.finding_records) {
            budget = budget.max_finding_records(value);
        }
        if let Some(value) = limit(self.finding_payload_bytes) {
            budget = budget.max_finding_payload_bytes(value);
        }
        if let Some(value) = limit(self.collected_spans) {
            budget = budget.max_collected_spans(value);
        }
        if let Some(value) = limit(self.normalization_bytes) {
            budget = budget.max_normalization_bytes(value);
        }
        budget
    }
}

/// `None` for `UNLIMITED`, otherwise the value as a `usize`, which holds
/// every other `u64` on the supported 64-bit targets.
fn limit(value: u64) -> Option<usize> {
    (value != UNLIMITED).then(|| usize::try_from(value).unwrap_or(usize::MAX))
}

fn to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn base64_mode(value: u64) -> Option<Base64Mode> {
    match value {
        BASE64_COMPATIBLE => Some(Base64Mode::Compatible),
        BASE64_EXTENDED => Some(Base64Mode::Extended),
        _ => None,
    }
}

/// Detection settings of one scan.
#[derive(Clone, Copy, Debug)]
struct Detection {
    decode_depth: u64,
    base64_mode: Base64Mode,
    redaction_percent: u64,
    allow_comments: bool,
    budgets: Budgets,
}

impl Detection {
    fn scan_options(self) -> ScanOptions {
        ScanOptions::builder()
            .max_decode_depth(to_usize(self.decode_depth))
            .base64_mode(self.base64_mode)
            .redaction_percent(to_usize(self.redaction_percent))
            .honor_allow_markers(self.allow_comments)
            .build()
    }
}

/// The settings behind a `rustleaks_options` handle.
#[derive(Clone, Debug)]
pub struct Options {
    config: Option<Vec<u8>>,
    rule_ids: Option<Vec<String>>,
    detection: Detection,
    max_input_bytes: u64,
    workers: u64,
    scan_on_caller_thread: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            config: None,
            rule_ids: None,
            detection: Detection {
                decode_depth: 0,
                base64_mode: Base64Mode::Compatible,
                redaction_percent: 0,
                allow_comments: true,
                budgets: Budgets {
                    decoded_bytes: UNLIMITED,
                    work_units: UNLIMITED,
                    finding_records: DEFAULT_MAX_FINDING_RECORDS,
                    finding_payload_bytes: UNLIMITED,
                    collected_spans: UNLIMITED,
                    normalization_bytes: UNLIMITED,
                },
            },
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            workers: 0,
            scan_on_caller_thread: false,
        }
    }
}

impl Options {
    /// Replaces the built-in rules with this TOML configuration.
    pub fn set_config(&mut self, bytes: &[u8]) {
        self.config = Some(bytes.to_vec());
    }

    /// Adds one rule ID to the selection. Without a selection, every rule
    /// of the configuration reports findings.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INVALID_ARGUMENT` when the ID is not UTF-8 or the
    /// selection already holds the most IDs that core accepts.
    pub fn add_rule_id(&mut self, bytes: &[u8]) -> Result<(), i32> {
        let id = std::str::from_utf8(bytes).map_err(|_| ERROR_INVALID_ARGUMENT)?;
        let ids = self.rule_ids.get_or_insert_with(Vec::new);
        if ids.len() >= CompiledConfig::MAX_SELECTED_RULES {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        ids.push(id.to_owned());
        Ok(())
    }

    /// Sets a numeric option.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INVALID_ARGUMENT` for an unknown key or a value that
    /// the key does not accept.
    pub fn set_u64(&mut self, key: u32, value: u64) -> Result<(), i32> {
        let detection = &mut self.detection;
        let budgets = &mut detection.budgets;
        match key {
            OPTION_DECODE_DEPTH => detection.decode_depth = value,
            OPTION_BASE64_MODE => {
                detection.base64_mode = base64_mode(value).ok_or(ERROR_INVALID_ARGUMENT)?;
            }
            OPTION_REDACTION_PERCENT => detection.redaction_percent = value,
            OPTION_MAX_INPUT_BYTES => self.max_input_bytes = value,
            OPTION_MAX_DECODED_BYTES => budgets.decoded_bytes = value,
            OPTION_MAX_WORK_UNITS => budgets.work_units = value,
            OPTION_MAX_FINDING_RECORDS => budgets.finding_records = value,
            OPTION_MAX_FINDING_PAYLOAD_BYTES => budgets.finding_payload_bytes = value,
            OPTION_MAX_COLLECTED_SPANS => budgets.collected_spans = value,
            OPTION_MAX_NORMALIZATION_BYTES => budgets.normalization_bytes = value,
            OPTION_WORKERS if value <= MAX_WORKERS => self.workers = value,
            _ => return Err(ERROR_INVALID_ARGUMENT),
        }
        Ok(())
    }

    /// Sets a boolean option.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INVALID_ARGUMENT` for an unknown key.
    pub fn set_bool(&mut self, key: u32, value: bool) -> Result<(), i32> {
        match key {
            OPTION_ALLOW_COMMENTS => self.detection.allow_comments = value,
            OPTION_SCAN_ON_CALLER_THREAD => self.scan_on_caller_thread = value,
            _ => return Err(ERROR_INVALID_ARGUMENT),
        }
        Ok(())
    }
}

/// Per-scan arguments after the pointer checks.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanRequest<'a> {
    /// Path bytes, or empty.
    pub path: &'a [u8],
    /// `SCAN_SET_*` bits. Unknown bits were rejected.
    pub overrides: u64,
    /// Decode depth.
    pub decode_depth: u64,
    /// `BASE64_*` value.
    pub base64_mode: u64,
    /// Redaction percent.
    pub redaction_percent: u64,
    /// Whether to honor allow comments.
    pub allow_comments: bool,
    /// Decoded byte budget.
    pub max_decoded_bytes: u64,
    /// Work unit budget.
    pub max_work_units: u64,
    /// Finding record budget.
    pub max_finding_records: u64,
    /// Finding payload byte budget.
    pub max_finding_payload_bytes: u64,
    /// Collected span budget.
    pub max_collected_spans: u64,
    /// Normalization byte budget.
    pub max_normalization_bytes: u64,
    /// Nanoseconds until the deadline.
    pub deadline_ns: u64,
}

impl ScanRequest<'_> {
    fn has(&self, bit: u64) -> bool {
        self.overrides & bit != 0
    }

    fn apply(&self, defaults: Detection) -> Result<Detection, FfiError> {
        let mut detection = defaults;
        let budgets = &mut detection.budgets;
        if self.has(SCAN_SET_DECODE_DEPTH) {
            detection.decode_depth = self.decode_depth;
        }
        if self.has(SCAN_SET_BASE64_MODE) {
            detection.base64_mode = base64_mode(self.base64_mode).ok_or_else(|| {
                FfiError::new(
                    ERROR_INVALID_ARGUMENT,
                    "unknown base64 mode in scan arguments",
                )
            })?;
        }
        if self.has(SCAN_SET_REDACTION_PERCENT) {
            detection.redaction_percent = self.redaction_percent;
        }
        if self.has(SCAN_SET_ALLOW_COMMENTS) {
            detection.allow_comments = self.allow_comments;
        }
        for (bit, value, target) in [
            (
                SCAN_SET_MAX_DECODED_BYTES,
                self.max_decoded_bytes,
                &mut budgets.decoded_bytes,
            ),
            (
                SCAN_SET_MAX_WORK_UNITS,
                self.max_work_units,
                &mut budgets.work_units,
            ),
            (
                SCAN_SET_MAX_FINDING_RECORDS,
                self.max_finding_records,
                &mut budgets.finding_records,
            ),
            (
                SCAN_SET_MAX_FINDING_PAYLOAD_BYTES,
                self.max_finding_payload_bytes,
                &mut budgets.finding_payload_bytes,
            ),
            (
                SCAN_SET_MAX_COLLECTED_SPANS,
                self.max_collected_spans,
                &mut budgets.collected_spans,
            ),
            (
                SCAN_SET_MAX_NORMALIZATION_BYTES,
                self.max_normalization_bytes,
                &mut budgets.normalization_bytes,
            ),
        ] {
            if self.overrides & bit != 0 {
                *target = value;
            }
        }
        Ok(detection)
    }

    fn deadline(&self) -> Option<Duration> {
        self.has(SCAN_SET_DEADLINE)
            .then(|| Duration::from_nanos(self.deadline_ns))
    }
}

/// Views of byte strings that a handle owns.
///
/// The pointers point into strings that the same handle owns and never
/// changes, and the views themselves are never changed after construction.
#[derive(Debug, Default)]
struct ViewList(Box<[Bytes]>);

// SAFETY: a `ViewList` only holds pointers into immutable bytes owned by the
// handle that owns the list, and nothing writes through them. Moving it to
// another thread moves no access rights that the owning handle lacks.
unsafe impl Send for ViewList {}
// SAFETY: shared access only reads the pointer values; nothing writes the
// views or the bytes they point to while the handle exists.
unsafe impl Sync for ViewList {}

impl ViewList {
    fn of<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Self {
        Self(values.into_iter().map(Bytes::of).collect())
    }

    fn pointer(&self) -> *const Bytes {
        if self.0.is_empty() {
            std::ptr::null()
        } else {
            self.0.as_ptr()
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// One rule of an engine, copied out of the compiled configuration.
#[derive(Debug)]
struct RuleEntry {
    id: String,
    description: String,
    #[expect(dead_code, reason = "owns the bytes that `tag_views` points to")]
    tags: Vec<String>,
    #[expect(dead_code, reason = "owns the bytes that `keyword_views` points to")]
    keywords: Vec<String>,
    tag_views: ViewList,
    keyword_views: ViewList,
}

impl RuleEntry {
    fn new(id: &str, description: &str, tags: &[String], keywords: &[String]) -> Self {
        let tags = tags.to_vec();
        let keywords = keywords.to_vec();
        // The views point into the heap buffers of these strings, which stay
        // in place when the vectors and the entry move.
        let tag_views = ViewList::of(tags.iter().map(String::as_bytes));
        let keyword_views = ViewList::of(keywords.iter().map(String::as_bytes));
        Self {
            id: id.to_owned(),
            description: description.to_owned(),
            tags,
            keywords,
            tag_views,
            keyword_views,
        }
    }

    fn view(&self) -> RuleView {
        RuleView {
            id: Bytes::of(self.id.as_bytes()),
            description: Bytes::of(self.description.as_bytes()),
            tags: self.tag_views.pointer(),
            tag_count: self.tag_views.len(),
            keywords: self.keyword_views.pointer(),
            keyword_count: self.keyword_views.len(),
        }
    }
}

/// Search cache bytes for each worker: an equal share of
/// `SEARCH_CACHE_BYTES`, but at least `WORKER_SEARCH_CACHE_FLOOR`.
fn cache_limit(workers: usize) -> usize {
    (SEARCH_CACHE_BYTES / workers.max(1)).max(WORKER_SEARCH_CACHE_FLOOR)
}

/// Returns the default worker count: one per available CPU, up to 12.
fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(1, |cpus| cpus.get().min(MAX_DEFAULT_WORKERS))
}

/// The engine and its settings, shared with the scan threads.
#[derive(Debug)]
pub(crate) struct EngineInner {
    engine: Engine,
    detection: Detection,
    max_input_bytes: u64,
    workers: usize,
    cache_limit: usize,
    scratch: Mutex<Vec<ScanScratch>>,
    rules: Vec<RuleEntry>,
}

/// One scan, with everything it needs copied, so that a scan thread can run
/// it after the caller's pointers are no longer read.
#[derive(Debug)]
pub(crate) struct ScanJob {
    fragment: Fragment,
    path: Vec<u8>,
    detection: Detection,
    deadline: Option<Instant>,
    cancel: Option<Arc<CancelFlag>>,
}

impl EngineInner {
    /// Loads the configuration, selects the rules and builds the engine.
    fn build(options: &Options) -> Result<Self, FfiError> {
        // The default loader reads no files, so `[extend] path` fails.
        let loader = ConfigLoader::new();
        let config = match &options.config {
            None => loader.load_default(),
            Some(bytes) => {
                let text = std::str::from_utf8(bytes).map_err(|error| {
                    FfiError::new(
                        ERROR_CONFIG,
                        format!(
                            "configuration is not valid UTF-8 at byte {}",
                            error.valid_up_to()
                        ),
                    )
                })?;
                loader.load_toml(text)
            }
        }
        .map_err(|error| FfiError::new(ERROR_CONFIG, error.to_string()))?;
        let config = match &options.rule_ids {
            None => config,
            Some(ids) => config
                .select_rules(ids.iter().map(String::as_str))
                .map_err(|error| FfiError::new(ERROR_RULE_SELECTION, error.to_string()))?,
        };
        let mut rules: Vec<RuleEntry> = Vec::new();
        for rule in config.ordered_rules() {
            if rule.skip_report() || rules.iter().any(|entry| entry.id == rule.id()) {
                continue;
            }
            rules.push(RuleEntry::new(
                rule.id(),
                rule.description(),
                rule.tags(),
                rule.keywords(),
            ));
        }
        let engine = Engine::builder(config)
            .build()
            .map_err(|error| FfiError::new(ERROR_ENGINE, error.to_string()))?;
        let workers = match options.workers {
            0 => default_workers(),
            value => to_usize(value),
        };
        Ok(Self {
            engine,
            detection: options.detection,
            max_input_bytes: options.max_input_bytes,
            workers,
            cache_limit: cache_limit(workers),
            scratch: Mutex::new(Vec::new()),
            rules,
        })
    }

    fn take_scratch(&self) -> ScanScratch {
        let pooled = self
            .scratch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        pooled.unwrap_or_else(|| ScanScratch::with_cache_limit(self.cache_limit))
    }

    /// Returns a scratch value to the pool, which keeps one for each worker.
    fn return_scratch(&self, scratch: ScanScratch) {
        let mut pool = self.scratch.lock().unwrap_or_else(PoisonError::into_inner);
        if pool.len() < self.workers {
            pool.push(scratch);
        }
    }

    /// Runs one scan on the current thread.
    ///
    /// A scan that panics drops the scratch value it took instead of
    /// returning it to the pool, because its caches may be half updated.
    pub(crate) fn run(&self, job: ScanJob) -> ResultHandle {
        let options = job.detection.scan_options();
        let signal = ScanSignal::new(job.cancel.as_deref(), job.deadline);
        let control = if signal.is_active() {
            ScanControl::cancellable(&signal)
        } else {
            ScanControl::unlimited()
        }
        .with_budget(job.detection.budgets.scan_budget());
        let mut scratch = self.take_scratch();
        #[cfg(test)]
        crate::tests::panic_if_requested(job.fragment.content().as_bytes());
        let outcome =
            self.engine
                .scan_fragment_with_scratch(&job.fragment, &options, &control, &mut scratch);
        self.return_scratch(scratch);
        let termination = match outcome.termination() {
            None => TERMINATION_COMPLETE,
            Some(ScanTermination::Cancelled) => {
                if !signal.flag_set() && signal.deadline_expired() {
                    TERMINATION_DEADLINE
                } else {
                    TERMINATION_CANCELLED
                }
            }
            Some(ScanTermination::BudgetExceeded { .. }) => TERMINATION_BUDGET,
            Some(_) => TERMINATION_OTHER,
        };
        ResultHandle::new(outcome, job.path, termination)
    }
}

/// The engine behind a `rustleaks_engine` handle.
#[derive(Debug)]
pub struct EngineHandle {
    inner: Arc<EngineInner>,
    threads: Option<ScanThreads>,
}

impl EngineHandle {
    /// Loads the configuration, selects the rules and builds the engine on
    /// a thread with a known stack, then starts the scan threads unless the
    /// options ask for scans on the calling thread.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_CONFIG`, `ERROR_RULE_SELECTION` or `ERROR_ENGINE`
    /// with the core message, `ERROR_ENGINE` when a thread cannot start, and
    /// `ERROR_PANIC` when the build panics.
    pub fn build(options: &Options) -> Result<Self, FfiError> {
        let copy = options.clone();
        let inner = Arc::new(on_scan_stack(move || EngineInner::build(&copy))??);
        let threads = if options.scan_on_caller_thread {
            None
        } else {
            Some(ScanThreads::start(inner.workers)?)
        };
        Ok(Self { inner, threads })
    }

    /// The number of workers that share the search caches.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.inner.workers
    }

    /// The inclusive input limit in bytes, or `UNLIMITED`.
    #[must_use]
    pub fn max_input_bytes(&self) -> u64 {
        self.inner.max_input_bytes
    }

    /// The number of rules that can report findings.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.inner.rules.len()
    }

    /// The view of rule `index`, in report order.
    #[must_use]
    pub fn rule(&self, index: usize) -> Option<RuleView> {
        self.inner.rules.get(index).map(RuleEntry::view)
    }

    #[cfg(test)]
    pub(crate) fn pooled_scratch(&self) -> usize {
        self.inner
            .scratch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    pub(crate) fn has_scan_threads(&self) -> bool {
        self.threads.is_some()
    }

    /// Scans one input. The input and path are copied once, before the scan
    /// starts, and the deadline counts from this call.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INPUT_TOO_LARGE` when the input is over the limit,
    /// `ERROR_INVALID_ARGUMENT` for a bad scan argument value, and
    /// `ERROR_PANIC` when the scan panics.
    pub fn scan(
        &self,
        input: &[u8],
        request: &ScanRequest<'_>,
        cancel: Option<Arc<CancelFlag>>,
    ) -> Result<ResultHandle, FfiError> {
        let deadline = request
            .deadline()
            .and_then(|after| Instant::now().checked_add(after));
        self.check_input_size(input.len())?;
        let detection = request.apply(self.inner.detection)?;
        let (file_path, windows_path) = source_paths(request.path, cfg!(windows));
        let fragment = Fragment::new(input.to_vec()).with_source_paths(
            file_path,
            ByteText::default(),
            windows_path,
        );
        let job = ScanJob {
            fragment,
            path: request.path.to_vec(),
            detection,
            deadline,
            cancel,
        };
        match &self.threads {
            None => Ok(self.inner.run(job)),
            Some(threads) => threads.run(Arc::clone(&self.inner), job),
        }
    }

    /// Checks `len` against the input limit without scanning.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INPUT_TOO_LARGE` when `len` is over the limit.
    pub fn check_input_size(&self, len: usize) -> Result<(), FfiError> {
        check_input_size(len, self.inner.max_input_bytes)
    }
}

fn check_input_size(len: usize, max: u64) -> Result<(), FfiError> {
    if max != UNLIMITED && u64::try_from(len).unwrap_or(u64::MAX) > max {
        return Err(FfiError::new(
            ERROR_INPUT_TOO_LARGE,
            format!("input is {len} bytes, more than the limit of {max} bytes"),
        ));
    }
    Ok(())
}

/// Returns the `/`-separated path and, on Windows when the path holds a
/// `\`, the original path, as `Fragment::with_source_paths` takes them.
fn source_paths(path: &[u8], windows: bool) -> (ByteText, ByteText) {
    if windows && path.contains(&b'\\') {
        let normalized = path
            .iter()
            .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
            .collect::<Vec<_>>();
        (ByteText::new(normalized), ByteText::new(path.to_vec()))
    } else {
        (ByteText::new(path.to_vec()), ByteText::default())
    }
}

/// The outcome behind a `rustleaks_result` handle.
#[derive(Debug)]
pub struct ResultHandle {
    outcome: ScanOutcome,
    path: Vec<u8>,
    termination: i32,
    /// Tag views of every finding, built at the first `finding` call. A C
    /// caller only reaches a result through the pointer of its box, so by
    /// then the result has its final address and never moves again, and the
    /// views stay valid whatever storage `ByteText` uses.
    tags: OnceLock<Vec<ViewList>>,
}

impl ResultHandle {
    fn new(outcome: ScanOutcome, path: Vec<u8>, termination: i32) -> Self {
        Self {
            outcome,
            path,
            termination,
            tags: OnceLock::new(),
        }
    }

    /// How the scan ended and what it used.
    #[must_use]
    pub fn status(&self) -> StatusView {
        let usage = self.outcome.usage();
        let mut status = StatusView {
            termination: self.termination,
            budget: BUDGET_NONE,
            decoded_bytes: as_u64(usage.decoded_bytes()),
            work_units: as_u64(usage.work_units()),
            finding_records: as_u64(usage.finding_records()),
            finding_payload_bytes: as_u64(usage.finding_payload_bytes()),
            collected_spans: as_u64(usage.collected_spans()),
            normalization_bytes: as_u64(usage.normalization_bytes()),
            ..StatusView::default()
        };
        if let Some(ScanTermination::BudgetExceeded {
            kind,
            limit,
            consumed,
            requested,
        }) = self.outcome.termination()
        {
            status.budget = budget_code(*kind);
            status.limit = as_u64(*limit);
            status.consumed = as_u64(*consumed);
            status.requested = as_u64(*requested);
        }
        status
    }

    /// The number of findings.
    #[must_use]
    pub fn count(&self) -> usize {
        self.outcome.findings().len()
    }

    /// The view of finding `index`. Its pointers are valid while the result
    /// stays at this address, as it does behind a C handle.
    #[must_use]
    pub fn finding(&self, index: usize) -> Option<FindingView> {
        let finding = self.outcome.findings().get(index)?;
        let tags = self.tags.get_or_init(|| {
            self.outcome
                .findings()
                .iter()
                .map(|finding| ViewList::of(finding.tags().iter().map(ByteText::as_bytes)))
                .collect()
        });
        let tags = tags.get(index)?;
        Some(finding_view(finding, tags, &self.path))
    }
}

fn finding_view(finding: &Finding, tags: &ViewList, path: &[u8]) -> FindingView {
    let location = finding.location();
    let secret = finding.secret_range().exact();
    let matched = finding.match_range().exact();
    FindingView {
        rule_id: Bytes::of(finding.rule_id().as_bytes()),
        description: Bytes::of(finding.description().as_bytes()),
        tags: tags.pointer(),
        tag_count: tags.len(),
        secret: Bytes::of(finding.secret().as_bytes()),
        match_text: Bytes::of(finding.match_text().as_bytes()),
        line: Bytes::of(finding.line().as_bytes()),
        path: Bytes::of(path),
        start_line: as_u64(location.start_line()),
        end_line: as_u64(location.end_line()),
        start_column: as_u64(location.start_column()),
        end_column: as_u64(location.end_column()),
        secret_start: secret.map_or(0, |range| as_u64(range.start())),
        secret_end: secret.map_or(0, |range| as_u64(range.end())),
        match_start: matched.map_or(0, |range| as_u64(range.start())),
        match_end: matched.map_or(0, |range| as_u64(range.end())),
        entropy: f64::from(finding.entropy()),
        secret_range_exact: u8::from(secret.is_some()),
        match_range_exact: u8::from(matched.is_some()),
    }
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn budget_code(kind: ScanBudgetKind) -> i32 {
    match kind {
        ScanBudgetKind::DecodedBytes => BUDGET_DECODED_BYTES,
        ScanBudgetKind::WorkUnits => BUDGET_WORK_UNITS,
        ScanBudgetKind::FindingRecords => BUDGET_FINDING_RECORDS,
        ScanBudgetKind::FindingPayloadBytes => BUDGET_FINDING_PAYLOAD_BYTES,
        ScanBudgetKind::CollectedSpans => BUDGET_COLLECTED_SPANS,
        ScanBudgetKind::NormalizationBytes => BUDGET_NORMALIZATION_BYTES,
        _ => BUDGET_NONE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_paths_keep_the_original_beside_the_slash_form() {
        let (file, windows) = source_paths(br"config\app.env", true);
        assert_eq!(file.as_bytes(), b"config/app.env");
        assert_eq!(windows.as_bytes(), br"config\app.env");

        let (file, windows) = source_paths(b"config/app.env", true);
        assert_eq!(file.as_bytes(), b"config/app.env");
        assert!(windows.is_empty());

        let (file, windows) = source_paths(br"config\app.env", false);
        assert_eq!(file.as_bytes(), br"config\app.env");
        assert!(windows.is_empty());
    }

    #[test]
    fn input_limit_includes_its_value() {
        assert!(check_input_size(10, 10).is_ok());
        assert_eq!(
            check_input_size(11, 10).unwrap_err().kind(),
            ERROR_INPUT_TOO_LARGE
        );
        assert!(check_input_size(usize::MAX, UNLIMITED).is_ok());
    }

    #[test]
    fn options_reject_unknown_keys_and_values() {
        let mut options = Options::default();
        assert_eq!(options.set_u64(0, 1), Err(ERROR_INVALID_ARGUMENT));
        assert_eq!(options.set_u64(12, 1), Err(ERROR_INVALID_ARGUMENT));
        assert_eq!(
            options.set_u64(OPTION_BASE64_MODE, 2),
            Err(ERROR_INVALID_ARGUMENT)
        );
        assert_eq!(options.set_bool(3, true), Err(ERROR_INVALID_ARGUMENT));
        assert_eq!(
            options.set_u64(OPTION_WORKERS, MAX_WORKERS + 1),
            Err(ERROR_INVALID_ARGUMENT)
        );
        assert_eq!(options.set_u64(OPTION_WORKERS, MAX_WORKERS), Ok(()));
        assert_eq!(options.add_rule_id(b"\xff"), Err(ERROR_INVALID_ARGUMENT));
        for _ in 0..CompiledConfig::MAX_SELECTED_RULES {
            options.add_rule_id(b"rule").unwrap();
        }
        assert_eq!(options.add_rule_id(b"rule"), Err(ERROR_INVALID_ARGUMENT));
    }

    #[test]
    fn default_workers_follow_the_cli_rule() {
        let workers = default_workers();
        assert!((1..=MAX_DEFAULT_WORKERS).contains(&workers));
        assert_eq!(cache_limit(1), 128 << 20);
        assert_eq!(cache_limit(12), (128 << 20) / 12);
        assert_eq!(cache_limit(16), 8 << 20);
        assert_eq!(cache_limit(32), 8 << 20);
    }
}
