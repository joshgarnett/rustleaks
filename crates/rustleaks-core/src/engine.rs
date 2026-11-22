//! Immutable raw-fragment detection engine.

use std::borrow::Cow;
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};

use crate::config::{
    CompiledAllowlist, CompiledConfig, CompiledRule, Condition, RegexTarget, RequiredRuleSpec,
};
use crate::decoder::{
    DecodeCheckpoint, Decoder, EncodedSegment, adjust_match_index, current_line,
    segments_with_decoded_overlap, tags as decoder_tags,
};
use crate::explanation::{
    ExplanationCollector, ExplanationLog, ExplanationOptions, ExplanationReason,
};
use crate::go_unicode::{chars as go_chars, lowercase_bytes as go_lowercase_bytes};
use crate::model::{
    ByteRange, ByteText, Finding, FindingRange, Fragment, Location, RequiredFinding, ScanOptions,
};
use crate::native::{NativeKeyword, NativeRelation, NativeRequired};
use crate::regex::{
    ATTEMPT_COST_FLOOR, ByteSpan, CaptureScratch, GoRegex, NativeByteRegex, NormalizedHaystack,
};

/// Largest total keyword length that receives a full DFA prefilter.
///
/// States are bounded by keyword bytes and a full table can reach one
/// kilobyte per state, so this cap keeps the table at about 17 MiB. Larger
/// keyword sets keep the automaton kind chosen by the builder.
const KEYWORD_DFA_BYTE_LIMIT: usize = 16 * 1024;
/// Largest summed length of all keyword prefixes that receives a full DFA.
///
/// Building a state's row follows a failure chain for each byte class the
/// state has no transition on, and that chain is no longer than the state's
/// depth. Every state is a keyword prefix, so this sum bounds the summed
/// depths, and a long keyword counts quadratically. The default keywords
/// sum to 9,339 and the longest is 34 bytes. Larger sums keep the automaton
/// kind chosen by the builder.
const KEYWORD_DFA_PREFIX_LIMIT: usize = 64 * 1024;
const ALLOW_SIGNATURE: &[u8] = b"gitleaks:allow";
const RUSTLEAKS_ALLOW_SIGNATURE: &[u8] = b"rustleaks:allow";

/// A synchronous, runtime-independent cancellation signal for one scan.
///
/// The engine polls this signal between bounded units of owned work. A regular
/// expression search and one individual encoding transform are indivisible.
/// Without a collected-span limit, whole-rule enumeration is also indivisible.
/// A collected-span limit adds a cancellation poll before each span append.
/// Candidate work checkpoints follow eager enumeration; decoder candidate
/// loops are checkpointed between transforms.
/// Cancellation requested inside an indivisible operation is observed at the
/// next checkpoint.
pub trait ScanCancellation: Send + Sync {
    /// Returns whether the current scan should stop.
    fn is_cancelled(&self) -> bool;
}

impl ScanCancellation for AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(Ordering::Acquire)
    }
}

impl<F> ScanCancellation for F
where
    F: Fn() -> bool + Send + Sync,
{
    fn is_cancelled(&self) -> bool {
        self()
    }
}

/// Inclusive aggregate limits for one controlled fragment scan.
///
/// All limits are optional. `decoded_bytes` counts the byte length of every
/// successful decoded pass before that pass is scanned. `work_units` counts
/// explicit engine checkpoints: scan-pass starts, decode attempts, emitted
/// keyword matches, decoder matches/candidates/segments and predecessor
/// comparisons, rule evaluations, content-match candidates, required-rule
/// specifications, required-to-primary proximity comparisons, bounded native
/// predicate transforms and decoded-pattern checks, and tokenizer pieces and
/// merge iterations. Predicate transforms do not consume `decoded_bytes`. An admitted
/// `finding_record` is a primary finding, an auxiliary finding candidate, or a
/// projected required finding. These units are defensive resource controls,
/// not stable performance measurements. Finding payload, collected spans and
/// regex normalization have separate preallocation admission limits. These
/// count logical payload, not allocator capacities or total process memory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanBudget {
    decoded_bytes: Option<usize>,
    work_units: Option<usize>,
    finding_records: Option<usize>,
    finding_payload_bytes: Option<usize>,
    collected_spans: Option<usize>,
    normalization_bytes: Option<usize>,
}

impl ScanBudget {
    /// Returns an unlimited budget.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            decoded_bytes: None,
            work_units: None,
            finding_records: None,
            finding_payload_bytes: None,
            collected_spans: None,
            normalization_bytes: None,
        }
    }

    /// Sets the inclusive cumulative decoded-byte limit.
    #[must_use]
    pub const fn max_decoded_bytes(mut self, maximum: usize) -> Self {
        self.decoded_bytes = Some(maximum);
        self
    }

    /// Sets the inclusive engine work-unit limit.
    #[must_use]
    pub const fn max_work_units(mut self, maximum: usize) -> Self {
        self.work_units = Some(maximum);
        self
    }

    /// Sets the inclusive admitted finding-record limit.
    #[must_use]
    pub const fn max_finding_records(mut self, maximum: usize) -> Self {
        self.finding_records = Some(maximum);
        self
    }

    /// Limits cumulative owned finding byte fields, admitted before copying.
    ///
    /// Counts primary, auxiliary and projected fields even if later discarded.
    /// Excludes capacities, record overhead, session decoration and redaction.
    #[must_use]
    pub const fn max_finding_payload_bytes(mut self, maximum: usize) -> Self {
        self.finding_payload_bytes = Some(maximum);
        self
    }

    /// Limits cumulative whole-match spans collected for rules and decoding.
    ///
    /// Admission precedes each append. Decoder candidate and filtered vectors
    /// have at most one entry per admitted decoder span. This is not a heap cap.
    #[must_use]
    pub const fn max_collected_spans(mut self, maximum: usize) -> Self {
        self.collected_spans = Some(maximum);
        self
    }

    /// Limits cumulative regex normalization bytes and offset-map payload.
    ///
    /// Valid UTF-8 is borrowed and costs zero. Each invalid source byte costs
    /// three normalized bytes and one `usize` map entry, plus valid bytes copied
    /// into that normalization. Admission precedes allocation. Capacities,
    /// lowercase buffers, regex caches and other scratch are excluded.
    #[must_use]
    pub const fn max_normalization_bytes(mut self, maximum: usize) -> Self {
        self.normalization_bytes = Some(maximum);
        self
    }

    /// Returns the cumulative finding byte-field limit, or `None`.
    #[must_use]
    pub const fn finding_payload_bytes(self) -> Option<usize> {
        self.finding_payload_bytes
    }

    /// Returns the cumulative collected whole-match span limit, or `None`.
    #[must_use]
    pub const fn collected_spans(self) -> Option<usize> {
        self.collected_spans
    }

    /// Returns the cumulative regex normalization payload limit, or `None`.
    #[must_use]
    pub const fn normalization_bytes(self) -> Option<usize> {
        self.normalization_bytes
    }

    /// Returns the cumulative decoded-byte limit, or `None`.
    #[must_use]
    pub const fn decoded_bytes(self) -> Option<usize> {
        self.decoded_bytes
    }

    /// Returns the engine work-unit limit, or `None`.
    #[must_use]
    pub const fn work_units(self) -> Option<usize> {
        self.work_units
    }

    /// Returns the admitted finding-record limit, or `None`.
    #[must_use]
    pub const fn finding_records(self) -> Option<usize> {
        self.finding_records
    }
}

/// Caller-provided controls for one synchronous fragment scan.
///
/// A control borrows an optional cancellation signal and owns a copyable
/// budget. It creates no thread, timer, or runtime dependency. Callers that
/// need a deadline can update their signal from their own scheduler.
#[derive(Clone, Copy)]
pub struct ScanControl<'a> {
    cancellation: Option<&'a dyn ScanCancellation>,
    budget: ScanBudget,
}

impl ScanControl<'static> {
    /// Creates a non-cancellable control with unlimited budgets.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            cancellation: None,
            budget: ScanBudget::unlimited(),
        }
    }
}

impl<'a> ScanControl<'a> {
    /// Creates an unlimited control that polls `cancellation`.
    #[must_use]
    pub fn cancellable(cancellation: &'a dyn ScanCancellation) -> Self {
        Self {
            cancellation: Some(cancellation),
            budget: ScanBudget::unlimited(),
        }
    }

    /// Replaces the aggregate budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: ScanBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Returns the aggregate budget.
    #[must_use]
    pub const fn budget(self) -> ScanBudget {
        self.budget
    }

    fn is_cancelled(self) -> bool {
        self.cancellation
            .is_some_and(ScanCancellation::is_cancelled)
    }
}

impl fmt::Debug for ScanControl<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanControl")
            .field("cancellable", &self.cancellation.is_some())
            .field("budget", &self.budget)
            .finish()
    }
}

/// Aggregate resources consumed by one scan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanUsage {
    decoded_bytes: usize,
    work_units: usize,
    finding_records: usize,
    finding_payload_bytes: usize,
    collected_spans: usize,
    normalization_bytes: usize,
}

impl ScanUsage {
    /// Returns cumulative bytes in successful decoded passes.
    #[must_use]
    pub const fn decoded_bytes(self) -> usize {
        self.decoded_bytes
    }

    /// Returns consumed engine work units.
    #[must_use]
    pub const fn work_units(self) -> usize {
        self.work_units
    }

    /// Returns admitted finding records, including auxiliary records.
    #[must_use]
    pub const fn finding_records(self) -> usize {
        self.finding_records
    }
    /// Returns cumulative admitted owned finding byte-field lengths.
    #[must_use]
    pub const fn finding_payload_bytes(self) -> usize {
        self.finding_payload_bytes
    }

    /// Returns cumulative collected rule and decoder whole-match spans.
    #[must_use]
    pub const fn collected_spans(self) -> usize {
        self.collected_spans
    }

    /// Returns cumulative regex normalization byte and offset-map payload.
    #[must_use]
    pub const fn normalization_bytes(self) -> usize {
        self.normalization_bytes
    }
}

/// The aggregate resource whose inclusive limit stopped a scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScanBudgetKind {
    /// Cumulative bytes in successful decoded passes.
    DecodedBytes,
    /// Explicit engine work checkpoints.
    WorkUnits,
    /// Admitted primary, auxiliary, and projected finding records.
    FindingRecords,
    /// Owned finding byte-field lengths, including auxiliary projections.
    FindingPayloadBytes,
    /// Collected rule and decoder whole-match spans.
    CollectedSpans,
    /// Regex normalized bytes and replacement offset-map payload.
    NormalizationBytes,
}

/// Why a controlled scan returned a partial outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScanTermination {
    /// The caller's synchronous signal requested cancellation.
    Cancelled,
    /// Starting one more aggregate unit would exceed an inclusive limit.
    BudgetExceeded {
        /// The exceeded resource.
        kind: ScanBudgetKind,
        /// The configured inclusive maximum.
        limit: usize,
        /// Units consumed before the rejected operation.
        consumed: usize,
        /// Units requested by the rejected operation.
        requested: usize,
    },
}

impl fmt::Display for ScanTermination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("fragment scan cancelled"),
            Self::BudgetExceeded {
                kind,
                limit,
                consumed,
                requested,
            } => write!(
                formatter,
                "fragment scan {kind:?} budget exceeded: limit {limit}, consumed {consumed}, requested {requested}"
            ),
        }
    }
}

impl Error for ScanTermination {}

/// Immutable, shareable detector state.
///
/// `Engine` is `Send + Sync`. Scanning is synchronous and stateless: callers
/// own scheduling and can supply runtime-independent cancellation and aggregate
/// budgets through [`ScanControl`]. Session APIs own only cross-fragment
/// baseline, ignore, fingerprint, and collection policy. Raw source and finding
/// text remain byte-preserving.
#[derive(Clone, Debug)]
pub struct Engine {
    config: CompiledConfig,
    prefilter: Option<AhoCorasick>,
    keyword_count: usize,
    /// Prefilter pattern indexes of each rule, aligned with `config.rules`.
    rule_keyword_indexes: Vec<Box<[usize]>>,
    /// Literal-anchored search plan of each rule, aligned with `config.rules`.
    rule_literal_anchors: Vec<Option<RuleLiteralAnchor>>,
    /// Prefilter patterns whose occurrences some plan consumes; empty if none.
    recorded_keywords: Vec<bool>,
    /// One ASCII case-insensitive automaton over every native ASCII keyword.
    native_keyword_matcher: Option<AhoCorasick>,
    /// Native keyword pattern IDs of each rule, aligned with `config.rules`
    /// and with each rule's `native_keywords`. `None` marks a keyword that
    /// the automaton does not cover.
    native_keyword_patterns: Vec<Option<Box<[Option<u32>]>>>,
    /// For each native rule without keywords, aligned with `config.rules`,
    /// the pattern IDs of literals of which every match contains one.
    native_required_patterns: Vec<Option<Box<[u32]>>>,
    /// Rules whose findings a reviewed rule overlap can replace.
    replaced_by: ReplacedBy,
}

/// For each rule with reviewed `[[overlaps]]` entries, the IDs of the rules
/// whose finding replaces its finding of the same secret at the same place.
/// Empty for configurations without native rule packs.
#[derive(Clone, Debug, Default)]
struct ReplacedBy(BTreeMap<RuleIdBytes, Box<[RuleIdBytes]>>);

/// The bytes of a rule ID.
type RuleIdBytes = Box<[u8]>;

/// File, commit, secret range start and end, and secret of a finding.
type Occurrence<'a> = (&'a [u8], &'a [u8], usize, usize, &'a [u8]);

impl ReplacedBy {
    fn new(config: &CompiledConfig) -> Self {
        Self(
            config
                .rules
                .values()
                .filter(|rule| !rule.native_replaced_by.is_empty())
                .map(|rule| {
                    (
                        rule.id.as_bytes().into(),
                        rule.native_replaced_by
                            .iter()
                            .map(|id| id.as_bytes().into())
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    fn keepers(&self, rule_id: &[u8]) -> Option<&[RuleIdBytes]> {
        self.0.get(rule_id).map(AsRef::as_ref)
    }

    /// Marks each finding whose rule lists the rule of another finding with
    /// the same file, commit, secret and exact secret range. A finding
    /// without an exact secret range is never replaced. Calls `cancelled`
    /// before each finding is visited, at most twice per finding, and returns
    /// `None` as soon as it reports cancellation.
    fn replaced(
        &self,
        findings: &[Finding],
        mut cancelled: impl FnMut() -> bool,
    ) -> Option<Vec<bool>> {
        let mut replaced = vec![false; findings.len()];
        if self.0.is_empty()
            || !findings
                .iter()
                .any(|finding| self.keepers(finding.rule_id().as_bytes()).is_some())
        {
            return Some(replaced);
        }
        let mut by_occurrence = BTreeMap::<_, Vec<usize>>::new();
        for (index, finding) in findings.iter().enumerate() {
            if cancelled() {
                return None;
            }
            if let Some(key) = occurrence(finding) {
                by_occurrence.entry(key).or_default().push(index);
            }
        }
        for (index, finding) in findings.iter().enumerate() {
            if cancelled() {
                return None;
            }
            let (Some(keepers), Some(key)) = (
                self.keepers(finding.rule_id().as_bytes()),
                occurrence(finding),
            ) else {
                continue;
            };
            replaced[index] = by_occurrence[&key].iter().any(|&other| {
                keepers
                    .iter()
                    .any(|keeper| keeper.as_ref() == findings[other].rule_id().as_bytes())
            });
        }
        Some(replaced)
    }
}

/// The occurrence of a finding, when its secret range is exact.
fn occurrence(finding: &Finding) -> Option<Occurrence<'_>> {
    let range = finding.secret_range().exact()?;
    Some((
        finding.file().as_bytes(),
        finding.commit().as_bytes(),
        range.start(),
        range.end(),
        finding.secret().as_bytes(),
    ))
}

/// Where one rule's literal-anchored search takes its occurrences from.
#[derive(Clone, Debug)]
struct RuleLiteralAnchor {
    /// Index into the regex's literal-node candidates.
    candidate: usize,
    /// Prefilter patterns covering every literal of that candidate.
    keyword_indexes: Box<[usize]>,
}

/// Keyword start offsets recorded by one pure-ASCII keyword pass.
///
/// Offsets index the raw haystack: ASCII lowercasing preserves them. A
/// saturated keyword is too dense for anchored search, so its rules use the
/// unanchored path. Limits only choose a path and never change results.
#[derive(Default)]
struct KeywordOccurrences {
    active: bool,
    keyword_count: usize,
    starts: Vec<Vec<usize>>,
    saturated: Vec<bool>,
    per_keyword_limit: usize,
    remaining: usize,
}

impl KeywordOccurrences {
    /// Starts a pass; `ascii_len` is `None` unless occurrences are usable.
    fn begin_pass(&mut self, ascii_len: Option<usize>, keyword_count: usize) {
        for starts in &mut self.starts {
            starts.clear();
        }
        self.saturated.fill(false);
        self.active = ascii_len.is_some();
        self.keyword_count = keyword_count;
        let length = ascii_len.unwrap_or(0);
        self.per_keyword_limit = length / ATTEMPT_COST_FLOOR + 1;
        self.remaining = length / 16 + 1;
    }

    fn record(&mut self, keyword: usize, start: usize) {
        if self.starts.is_empty() {
            self.starts.resize_with(self.keyword_count, Vec::new);
            self.saturated.resize(self.keyword_count, false);
        }
        let starts = &mut self.starts[keyword];
        if starts.len() >= self.per_keyword_limit || self.remaining == 0 {
            self.saturated[keyword] = true;
            return;
        }
        starts.push(start);
        self.remaining -= 1;
    }

    /// Returns sorted unique occurrences of `indexes`, or `None` if unusable.
    fn rule_starts(&self, indexes: &[usize]) -> Option<Cow<'_, [usize]>> {
        if !self.active {
            return None;
        }
        if indexes
            .iter()
            .any(|&index| self.saturated.get(index).copied().unwrap_or(false))
        {
            return None;
        }
        if let [index] = indexes {
            return Some(Cow::Borrowed(
                self.starts.get(*index).map_or(&[], Vec::as_slice),
            ));
        }
        let mut merged = indexes
            .iter()
            .filter_map(|&index| self.starts.get(index))
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        merged.sort_unstable();
        merged.dedup();
        Some(Cow::Owned(merged))
    }
}

/// Original-source helpers live for one fragment, including its decoded passes.
#[derive(Default)]
struct OriginalFragmentContext {
    newlines: OnceCell<Vec<usize>>,
    marker: Cell<Option<(usize, usize, bool)>>,
    tail: Cell<Option<(usize, usize)>>,
    line: RefCell<Option<SharedLine>>,
}

struct SharedLine {
    start: usize,
    end: usize,
    bytes: Weak<Vec<u8>>,
}

impl OriginalFragmentContext {
    // Call only after full logical finding admission. One weak entry cannot
    // retain line bytes after all admitted findings have been dropped.
    fn admitted_line(&self, line: &[u8], start: usize, end: usize) -> ByteText {
        if line.len() < 4096 {
            return line.into();
        }
        let mut previous = self.line.borrow_mut();
        if let Some(entry) = previous.as_ref()
            && entry.start == start
            && entry.end == end
            && let Some(bytes) = entry.bytes.upgrade()
        {
            return ByteText::from_shared(bytes);
        }
        let bytes = Arc::new(line.to_vec());
        *previous = Some(SharedLine {
            start,
            end,
            bytes: Arc::downgrade(&bytes),
        });
        ByteText::from_shared(bytes)
    }

    fn has_allow_marker(&self, line: &[u8], start: usize, end: usize) -> bool {
        if let Some((previous_start, previous_end, matched)) = self.marker.get()
            && previous_start == start
            && previous_end == end
        {
            return matched;
        }
        let matched = contains_bytes(line, RUSTLEAKS_ALLOW_SIGNATURE)
            || contains_bytes(line, ALLOW_SIGNATURE);
        self.marker.set(Some((start, end, matched)));
        matched
    }
}

#[derive(Clone, Copy)]
struct LineRegexResult<'a> {
    allowlist: &'a CompiledAllowlist,
    line: &'a [u8],
    matched: bool,
}

/// Only the last line regex result per allowlist is retained within one rule pass.
#[derive(Default)]
struct LineAllowlistMemo<'a> {
    global: Vec<Option<LineRegexResult<'a>>>,
    rule: Vec<Option<LineRegexResult<'a>>>,
}

#[derive(Clone, Copy)]
struct DetectionPass<'a> {
    current_raw: &'a [u8],
    encoded_segments: &'a [EncodedSegment],
    original: &'a OriginalFragmentContext,
    rule_ordinal: usize,
    decoded_pass: usize,
    candidate_ordinal: usize,
}

#[derive(Clone, Copy)]
struct RulePass<'a> {
    current_raw: &'a [u8],
    normalized: &'a OnceCell<NormalizedHaystack<'a>>,
    original: &'a OriginalFragmentContext,
    encoded_segments: &'a [EncodedSegment],
    inherited_from_finding: bool,
    rule_ordinal: usize,
    decoded_pass: usize,
    literal_anchor: Option<&'a RuleLiteralAnchor>,
    keyword_occurrences: &'a KeywordOccurrences,
}

/// Metadata exists only for an explicitly buffer-local native evaluation.
struct NativeCandidate {
    finding: Finding,
    input: NativeInputId,
    whole: ByteSpan,
    // Selected capture in input coordinates; source/report ranges stay separate.
    _secret: Option<ByteSpan>,
    start_line: usize,
    end_line: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeInputId {
    pass: usize,
    segment: Option<usize>,
}

/// Identifies one native input buffer within one fragment scan.
///
/// The address and length guard against a decoded pass buffer that a later
/// pass could reuse; pass and segment numbers alone are already unique.
#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeHitKey {
    input: NativeInputId,
    address: usize,
    length: usize,
}

impl NativeHitKey {
    fn new(input: &NativeInput<'_>) -> Self {
        Self {
            input: input.id,
            address: input.bytes.as_ptr() as usize,
            length: input.bytes.len(),
        }
    }
}

/// How a native rule's ASCII keywords are answered.
#[derive(Clone, Copy)]
struct NativeKeywordLookup<'a> {
    matcher: Option<&'a AhoCorasick>,
    patterns: Option<&'a [Option<u32>]>,
    input: Option<NativeHitKey>,
}

impl NativeKeywordLookup<'_> {
    /// Searches each keyword on its own, without a shared automaton.
    #[cfg(test)]
    const UNSHARED: Self = Self {
        matcher: None,
        patterns: None,
        input: None,
    };
}

#[derive(Clone, Copy)]
struct NativeInput<'a> {
    id: NativeInputId,
    bytes: &'a [u8],
    pass_offset: usize,
}

struct ScanContext<'a> {
    control: ScanControl<'a>,
    usage: ScanUsage,
    explanations: ExplanationCollector,
    /// Native patterns found in each native input of the current decode
    /// pass, by slot: 0 for the whole pass and `segment + 1` for a decoded
    /// segment. Rules run pass by pass, so a new pass clears the slots.
    native_keyword_hits: Vec<Option<NativeKeywordHits>>,
    /// Decode pass that `native_keyword_hits` belongs to.
    native_keyword_pass: usize,
}

/// Native patterns found in one native input.
struct NativeKeywordHits {
    /// The input these results belong to.
    key: NativeHitKey,
    /// Bit set indexed by pattern ID.
    words: Box<[u64]>,
    /// Whether a keyword check already charged this input's length.
    input_charged: bool,
}

/// Runs the shared native automaton once over `bytes`.
fn native_keyword_words(matcher: &AhoCorasick, bytes: &[u8]) -> Box<[u64]> {
    let count = matcher.patterns_len();
    let mut words = vec![0_u64; count.div_ceil(64)];
    let mut remaining = count;
    for found in matcher.find_overlapping_iter(bytes) {
        let index = found.pattern().as_usize();
        let bit = 1_u64 << (index % 64);
        if words[index / 64] & bit == 0 {
            words[index / 64] |= bit;
            remaining -= 1;
            if remaining == 0 {
                break;
            }
        }
    }
    words.into_boxed_slice()
}

impl<'a> ScanContext<'a> {
    fn new(control: ScanControl<'a>) -> Self {
        Self {
            control,
            usage: ScanUsage {
                decoded_bytes: 0,
                work_units: 0,
                finding_records: 0,
                finding_payload_bytes: 0,
                collected_spans: 0,
                normalization_bytes: 0,
            },
            explanations: ExplanationCollector::new(ExplanationOptions::disabled(), false),
            native_keyword_hits: Vec::new(),
            native_keyword_pass: 0,
        }
    }

    /// Returns whether native pattern `pattern` occurs in this input.
    ///
    /// The first lookup for an input runs the shared automaton once over the
    /// whole input and keeps the result for the fragment. Like one regex
    /// search, the pass is indivisible and stops once every pattern has been
    /// seen. With `charge_input`, as for a keyword check, the input length is
    /// charged once per input before the result is first read, whether or not
    /// an earlier uncharged lookup already ran the pass.
    fn native_keyword_hit(
        &mut self,
        key: NativeHitKey,
        matcher: &AhoCorasick,
        bytes: &[u8],
        pattern: u32,
        charge_input: bool,
    ) -> Result<bool, ScanTermination> {
        if key.input.pass != self.native_keyword_pass {
            self.native_keyword_hits.clear();
            self.native_keyword_pass = key.input.pass;
        }
        let slot = key
            .input
            .segment
            .map_or(0, |segment| segment.saturating_add(1));
        if self.native_keyword_hits.len() <= slot {
            self.native_keyword_hits.resize_with(slot + 1, || None);
        }
        let charged = self.native_keyword_hits[slot]
            .as_ref()
            .is_some_and(|hits| hits.key == key && hits.input_charged);
        if charge_input && !charged {
            self.work_many(bytes.len())?;
        }
        let entry = &mut self.native_keyword_hits[slot];
        if entry.as_ref().is_none_or(|hits| hits.key != key) {
            *entry = Some(NativeKeywordHits {
                key,
                words: native_keyword_words(matcher, bytes),
                input_charged: false,
            });
        }
        let hits = entry.as_mut().expect("the slot holds this input's results");
        hits.input_charged |= charge_input;
        let index = usize::try_from(pattern).unwrap_or(usize::MAX);
        Ok(hits
            .words
            .get(index / 64)
            .is_some_and(|word| word & (1_u64 << (index % 64)) != 0))
    }

    fn check_cancelled(&self) -> Result<(), ScanTermination> {
        if self.control.is_cancelled() {
            Err(ScanTermination::Cancelled)
        } else {
            Ok(())
        }
    }

    fn work(&mut self) -> Result<(), ScanTermination> {
        self.check_cancelled()?;
        charge_counter(
            &mut self.usage.work_units,
            1,
            self.control.budget.work_units,
            ScanBudgetKind::WorkUnits,
        )
    }

    /// Charges `units` consecutive work checkpoints with the observable
    /// effect of `units` calls to [`Self::work`].
    ///
    /// Without a cancellation signal each call polls nothing and adds one to
    /// the counter, so the run reduces to one bounded addition that stops at
    /// the same checkpoint. A signal observes each poll, so that path keeps
    /// one call per unit.
    fn work_many(&mut self, units: usize) -> Result<(), ScanTermination> {
        if self.control.cancellation.is_some() {
            for _ in 0..units {
                self.work()?;
            }
            return Ok(());
        }
        let capacity = self.control.budget.work_units.unwrap_or(usize::MAX);
        if units <= capacity - self.usage.work_units {
            self.usage.work_units += units;
            return Ok(());
        }
        self.usage.work_units = capacity;
        charge_counter(
            &mut self.usage.work_units,
            1,
            self.control.budget.work_units,
            ScanBudgetKind::WorkUnits,
        )
    }

    fn decoded_bytes(&mut self, amount: usize) -> Result<(), ScanTermination> {
        self.check_cancelled()?;
        charge_counter(
            &mut self.usage.decoded_bytes,
            amount,
            self.control.budget.decoded_bytes,
            ScanBudgetKind::DecodedBytes,
        )
    }

    fn collected_spans(&mut self, amount: usize) -> Result<(), ScanTermination> {
        if self.control.budget.collected_spans.is_some() {
            self.check_cancelled()?;
        }
        charge_counter(
            &mut self.usage.collected_spans,
            amount,
            self.control.budget.collected_spans,
            ScanBudgetKind::CollectedSpans,
        )
    }

    fn normalization_bytes(&mut self, amount: Option<usize>) -> Result<(), ScanTermination> {
        if self.control.budget.normalization_bytes.is_some() {
            self.check_cancelled()?;
        }
        let amount = amount.ok_or(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::NormalizationBytes,
            limit: self
                .control
                .budget
                .normalization_bytes
                .unwrap_or(usize::MAX),
            consumed: self.usage.normalization_bytes,
            requested: usize::MAX,
        })?;
        charge_counter(
            &mut self.usage.normalization_bytes,
            amount,
            self.control.budget.normalization_bytes,
            ScanBudgetKind::NormalizationBytes,
        )
    }

    fn normalize<'b>(
        &mut self,
        bytes: &'b [u8],
    ) -> Result<NormalizedHaystack<'b>, ScanTermination> {
        if self.control.budget.normalization_bytes.is_some() {
            self.normalization_bytes(NormalizedHaystack::required_owned_bytes(bytes))?;
            Ok(NormalizedHaystack::new(bytes))
        } else {
            let normalized = NormalizedHaystack::new(bytes);
            self.normalization_bytes(Some(normalized.owned_bytes()))?;
            Ok(normalized)
        }
    }

    fn is_match(&mut self, regex: &GoRegex, bytes: &[u8]) -> Result<bool, ScanTermination> {
        Ok(regex.is_match_normalized(&self.normalize(bytes)?))
    }

    fn admit_finding(
        &mut self,
        fields: impl IntoIterator<Item = usize>,
    ) -> Result<(), ScanTermination> {
        // Poll for cancellation once per finding record. Commit both
        // reservations only when the whole record is admitted.
        self.check_cancelled()?;
        let mut records = self.usage.finding_records;
        charge_counter(
            &mut records,
            1,
            self.control.budget.finding_records,
            ScanBudgetKind::FindingRecords,
        )?;
        let requested = fields
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .ok_or(ScanTermination::BudgetExceeded {
                kind: ScanBudgetKind::FindingPayloadBytes,
                limit: self
                    .control
                    .budget
                    .finding_payload_bytes
                    .unwrap_or(usize::MAX),
                consumed: self.usage.finding_payload_bytes,
                requested: usize::MAX,
            })?;
        charge_counter(
            &mut self.usage.finding_payload_bytes,
            requested,
            self.control.budget.finding_payload_bytes,
            ScanBudgetKind::FindingPayloadBytes,
        )?;
        self.usage.finding_records = records;
        Ok(())
    }
}

fn charge_counter(
    consumed: &mut usize,
    requested: usize,
    limit: Option<usize>,
    kind: ScanBudgetKind,
) -> Result<(), ScanTermination> {
    let Some(next) = consumed.checked_add(requested) else {
        return Err(ScanTermination::BudgetExceeded {
            kind,
            limit: limit.unwrap_or(usize::MAX),
            consumed: *consumed,
            requested,
        });
    };
    if limit.is_some_and(|maximum| next > maximum) {
        return Err(ScanTermination::BudgetExceeded {
            kind,
            limit: limit.unwrap_or(usize::MAX),
            consumed: *consumed,
            requested,
        });
    }
    *consumed = next;
    Ok(())
}

impl Engine {
    /// Starts an engine builder from a validated configuration.
    #[must_use]
    pub fn builder(config: CompiledConfig) -> EngineBuilder {
        EngineBuilder { config }
    }

    /// Returns the immutable effective configuration.
    #[must_use]
    pub const fn config(&self) -> &CompiledConfig {
        &self.config
    }

    /// Scans one fragment without retaining cross-fragment state.
    ///
    /// This allocates a Go-compatible lowercase view for keyword filtering and
    /// an outcome vector. `max_target_bytes` is checked before content-regexp
    /// matching, after the keyword and path gates; path-only rules bypass it.
    /// This compatibility entry point has no aggregate budgets and cannot be
    /// cancelled. Use [`Engine::scan_fragment_controlled`] for defensive
    /// embedding limits.
    #[must_use]
    pub fn scan_fragment(&self, fragment: &Fragment, options: &ScanOptions) -> ScanOutcome {
        self.scan_fragment_controlled(fragment, options, &ScanControl::unlimited())
    }

    /// Scans one fragment under synchronous cancellation and aggregate limits.
    ///
    /// A partial outcome contains only findings from top-level rules completed
    /// before termination. A composite top-level rule is committed only after
    /// all of its required-rule projection completes. Generic suppression and
    /// redaction are then applied to that committed prefix. If cancellation is
    /// first observed during final filtering, only the already finalized prefix
    /// is returned. Inspect [`ScanOutcome::termination`] before treating the
    /// findings as a complete scan.
    ///
    /// Cancellation is cooperative. The signal is polled between the work
    /// units documented by [`ScanBudget`], including inside decoder candidate
    /// loops. A collected-span limit additionally polls before each rule or
    /// decoder span append; without it, enumeration stays indivisible. Each
    /// regex search, individual encoding transform, admitted finding copy and
    /// redaction of one finding remain indivisible.
    #[must_use]
    pub fn scan_fragment_controlled(
        &self,
        fragment: &Fragment,
        options: &ScanOptions,
        control: &ScanControl<'_>,
    ) -> ScanOutcome {
        self.scan_fragment_with_context(fragment, options, &mut ScanContext::new(*control))
    }

    pub(crate) fn scan_fragment_explained(
        &self,
        fragment: &Fragment,
        options: &ScanOptions,
        control: &ScanControl<'_>,
        explanations: ExplanationOptions,
        github_classic: bool,
    ) -> (ScanOutcome, ExplanationLog) {
        let mut context = ScanContext::new(*control);
        context.explanations = ExplanationCollector::new(explanations, github_classic);
        let outcome = self.scan_fragment_with_context(fragment, options, &mut context);
        if let Some(termination) = outcome.termination() {
            let reason = match termination {
                ScanTermination::Cancelled => ExplanationReason::ScanCancelled,
                ScanTermination::BudgetExceeded { kind, .. } => match kind {
                    ScanBudgetKind::DecodedBytes => ExplanationReason::DecodedByteBudgetExceeded,
                    ScanBudgetKind::WorkUnits => ExplanationReason::WorkBudgetExceeded,
                    ScanBudgetKind::FindingRecords => ExplanationReason::FindingBudgetExceeded,
                    ScanBudgetKind::FindingPayloadBytes => {
                        ExplanationReason::FindingPayloadBudgetExceeded
                    }
                    ScanBudgetKind::CollectedSpans => {
                        ExplanationReason::CollectedSpanBudgetExceeded
                    }
                    ScanBudgetKind::NormalizationBytes => {
                        ExplanationReason::NormalizationBudgetExceeded
                    }
                },
            };
            context.explanations.record(None, 0, None, reason);
        }
        (outcome, context.explanations.log)
    }

    #[allow(clippy::too_many_lines)] // Keep pass ordering and partial-result accounting in one auditable flow.
    fn scan_fragment_with_context(
        &self,
        fragment: &Fragment,
        options: &ScanOptions,
        context: &mut ScanContext<'_>,
    ) -> ScanOutcome {
        if let Err(termination) = context.check_cancelled() {
            return ScanOutcome::partial(Vec::new(), context.usage, termination);
        }
        let allowed = match commit_or_path_allowed(fragment, &self.config.allowlists, context) {
            Ok(allowed) => allowed,
            Err(termination) => {
                return ScanOutcome::partial(Vec::new(), context.usage, termination);
            }
        };
        if allowed {
            context
                .explanations
                .record(None, 0, None, ExplanationReason::AllowlistMatched);
            return ScanOutcome::complete(Vec::new(), context.usage);
        }
        context
            .explanations
            .record(None, 0, None, ExplanationReason::AllowlistNotMatched);

        let mut findings = Vec::new();
        let mut current_raw = Cow::Borrowed(fragment.content().as_bytes());
        let original = OriginalFragmentContext::default();
        let mut encoded_segments = Vec::new();
        let mut decoder = None;
        let mut decode_depth = 0;
        let mut matched_keywords = vec![false; self.keyword_count];
        let mut keyword_occurrences = KeywordOccurrences::default();
        loop {
            if let Err(termination) = context.work() {
                return finish_partial(
                    findings,
                    &self.replaced_by,
                    options,
                    context.usage,
                    termination,
                );
            }
            matched_keywords.fill(false);
            let record_occurrences = context.control.budget.collected_spans.is_none()
                && !self.recorded_keywords.is_empty()
                && current_raw.is_ascii();
            keyword_occurrences.begin_pass(
                record_occurrences.then_some(current_raw.len()),
                self.keyword_count,
            );
            if let Some(prefilter) = &self.prefilter {
                let normalized = go_lowercase_bytes(&current_raw);
                for found in prefilter.find_overlapping_iter(&normalized) {
                    if let Err(termination) = context.work() {
                        return finish_partial(
                            findings,
                            &self.replaced_by,
                            options,
                            context.usage,
                            termination,
                        );
                    }
                    let keyword = found.pattern().as_usize();
                    matched_keywords[keyword] = true;
                    if record_occurrences && self.recorded_keywords[keyword] {
                        keyword_occurrences.record(keyword, found.start());
                    }
                }
            }

            {
                let regex_haystack = OnceCell::new();
                for (((rule_ordinal, rule), keyword_indexes), literal_anchor) in self
                    .config
                    .rules
                    .values()
                    .enumerate()
                    .zip(&self.rule_keyword_indexes)
                    .zip(&self.rule_literal_anchors)
                {
                    context.explanations.record(
                        Some(rule_ordinal),
                        decode_depth,
                        None,
                        ExplanationReason::RuleSelected,
                    );
                    if rule.native_required.is_some() || rule.native_byte_matcher.is_some() {
                        let detected = self.detect_native_rule(
                            fragment,
                            options,
                            rule,
                            rule.native_required.as_ref(),
                            false,
                            RulePass {
                                current_raw: &current_raw,
                                normalized: &regex_haystack,
                                original: &original,
                                encoded_segments: &encoded_segments,
                                inherited_from_finding: fragment.inherited_from_finding(),
                                rule_ordinal,
                                decoded_pass: decode_depth,
                                literal_anchor: None,
                                keyword_occurrences: &keyword_occurrences,
                            },
                            context,
                        );
                        match detected {
                            Ok(detected) => findings.extend(detected),
                            Err(termination) => {
                                return finish_partial(
                                    findings,
                                    &self.replaced_by,
                                    options,
                                    context.usage,
                                    termination,
                                );
                            }
                        }
                        continue;
                    }
                    if !keyword_gate_open(rule, keyword_indexes, &matched_keywords) {
                        context.explanations.record(
                            Some(rule_ordinal),
                            decode_depth,
                            None,
                            ExplanationReason::KeywordMissed,
                        );
                        continue;
                    }
                    context.explanations.record(
                        Some(rule_ordinal),
                        decode_depth,
                        None,
                        if rule.keywords.is_empty() {
                            ExplanationReason::KeywordNotRequired
                        } else {
                            ExplanationReason::KeywordMatched
                        },
                    );
                    let detected = self.detect_rule(
                        fragment,
                        options,
                        rule,
                        RulePass {
                            current_raw: &current_raw,
                            normalized: &regex_haystack,
                            original: &original,
                            encoded_segments: &encoded_segments,
                            inherited_from_finding: fragment.inherited_from_finding(),
                            rule_ordinal,
                            decoded_pass: decode_depth,
                            literal_anchor: literal_anchor.as_ref(),
                            keyword_occurrences: &keyword_occurrences,
                        },
                        context,
                    );
                    match detected {
                        Ok(detected) => findings.extend(detected),
                        Err(termination) => {
                            return finish_partial(
                                findings,
                                &self.replaced_by,
                                options,
                                context.usage,
                                termination,
                            );
                        }
                    }
                }
            } // Drop the normalized pass before replacing decoded content.
            decode_depth += 1;
            if decode_depth > options.max_decode_depth() {
                break;
            }
            if let Err(termination) = context.work() {
                return finish_partial(
                    findings,
                    &self.replaced_by,
                    options,
                    context.usage,
                    termination,
                );
            }
            let bounded_spans = context.control.budget.collected_spans.is_some();
            let decode_result = decoder
                .get_or_insert_with(|| Decoder::with_base64_mode(options.base64_mode()))
                .decode_with_resources(&current_raw, &encoded_segments, bounded_spans, |event| {
                    match event {
                        DecodeCheckpoint::Work(units) => context.work_many(units),
                        DecodeCheckpoint::CollectedSpans(spans) => context.collected_spans(spans),
                        DecodeCheckpoint::NormalizationBytes(bytes) => {
                            context.normalization_bytes(bytes)
                        }
                    }
                });
            let (decoded_output, segments) = match decode_result {
                Ok(output) => output,
                Err(termination) => {
                    return finish_partial(
                        findings,
                        &self.replaced_by,
                        options,
                        context.usage,
                        termination,
                    );
                }
            };
            if let Err(termination) = context.check_cancelled() {
                return finish_partial(
                    findings,
                    &self.replaced_by,
                    options,
                    context.usage,
                    termination,
                );
            }
            if segments.is_empty() {
                break;
            }
            if let Err(termination) = context.decoded_bytes(decoded_output.len()) {
                return finish_partial(
                    findings,
                    &self.replaced_by,
                    options,
                    context.usage,
                    termination,
                );
            }
            current_raw = Cow::Owned(decoded_output);
            encoded_segments = segments;
        }
        finish_complete(findings, &self.replaced_by, options, context)
    }

    #[allow(clippy::too_many_lines)] // Rule decisions and their bounded annotations share the same control flow.
    fn detect_rule<'a>(
        &'a self,
        fragment: &'a Fragment,
        options: &ScanOptions,
        rule: &'a CompiledRule,
        rule_pass: RulePass<'a>,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<Finding>, ScanTermination> {
        if rule.native_byte_matcher.is_some() {
            return self.detect_native_rule(
                fragment,
                options,
                rule,
                None,
                rule_pass.inherited_from_finding,
                rule_pass,
                context,
            );
        }
        context.work()?;
        if rule.skip_report && !rule_pass.inherited_from_finding {
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                None,
                ExplanationReason::RuleReportSkipped,
            );
            return Ok(Vec::new());
        }
        if commit_or_path_allowed(fragment, &rule.allowlists, context)? {
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                None,
                ExplanationReason::AllowlistMatched,
            );
            return Ok(Vec::new());
        }
        context.explanations.record(
            Some(rule_pass.rule_ordinal),
            rule_pass.decoded_pass,
            None,
            ExplanationReason::AllowlistNotMatched,
        );

        if let Some(path) = &rule.path_matcher {
            let path_matches = context.is_match(path, fragment.file_path().as_bytes())?
                || (!fragment.windows_file_path().is_empty()
                    && context.is_match(path, fragment.windows_file_path().as_bytes())?);
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                None,
                if path_matches {
                    ExplanationReason::PathMatched
                } else {
                    ExplanationReason::PathMissed
                },
            );
            if rule.regex_matcher.is_none() {
                let finding = if rule_pass.encoded_segments.is_empty() && path_matches {
                    context.admit_finding(finding_base_payload(fragment, rule).chain([
                        b"file detected: ".len(),
                        fragment.file_path().as_bytes().len(),
                    ]))?;
                    path_finding(fragment, rule).into_iter().collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                if !finding.is_empty() {
                    context.explanations.record(
                        Some(rule_pass.rule_ordinal),
                        rule_pass.decoded_pass,
                        None,
                        ExplanationReason::CandidateAccepted,
                    );
                }
                return Ok(finding);
            }
            if !path_matches {
                return Ok(Vec::new());
            }
        }

        let Some(regex) = &rule.regex_matcher else {
            return Ok(Vec::new());
        };
        if options
            .max_target_bytes()
            .is_some_and(|maximum| rule_pass.current_raw.len() > maximum)
        {
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                None,
                ExplanationReason::TargetByteLimit,
            );
            return Ok(Vec::new());
        }

        if rule.keywords.is_empty()
            && rule.native_keywords.is_none()
            && !self.required_literals_present(
                rule_pass.rule_ordinal,
                NativeHitKey {
                    input: NativeInputId {
                        pass: rule_pass.decoded_pass,
                        segment: None,
                    },
                    address: rule_pass.current_raw.as_ptr() as usize,
                    length: rule_pass.current_raw.len(),
                },
                rule_pass.current_raw,
                context,
            )?
        {
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                None,
                ExplanationReason::PatternMissed,
            );
            return Ok(Vec::new());
        }

        let pass = DetectionPass {
            current_raw: rule_pass.current_raw,
            encoded_segments: rule_pass.encoded_segments,
            original: rule_pass.original,
            rule_ordinal: rule_pass.rule_ordinal,
            decoded_pass: rule_pass.decoded_pass,
            candidate_ordinal: 0,
        };
        let mut findings = Vec::new();
        let mut any_match = false;
        let mut line_allowlists = LineAllowlistMemo::default();
        // One rule pass searches only this rule's expression.
        let mut capture_scratch = None;
        for (candidate_ordinal, span) in Self::content_match_spans(regex, rule_pass, context)?
            .into_iter()
            .enumerate()
        {
            context.work()?;
            any_match = true;
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                Some(candidate_ordinal),
                ExplanationReason::PatternMatched,
            );
            if let Some(finding) = self.content_finding(
                fragment,
                options,
                rule,
                DetectionPass {
                    candidate_ordinal,
                    ..pass
                },
                span,
                &mut line_allowlists,
                &mut capture_scratch,
                None,
                context,
            )? {
                findings.push(finding);
            }
        }
        if !any_match {
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                None,
                ExplanationReason::PatternMissed,
            );
        }
        if rule_pass.inherited_from_finding || rule.required.is_empty() || findings.is_empty() {
            return Ok(findings);
        }

        self.project_required_findings(fragment, options, rule, rule_pass, findings, context)
    }

    /// Returns whether `bytes` contains one of the literals of which every
    /// match of this rule's expression contains one. Returns `true` when no
    /// such set is known. The check charges no work: it reads at most
    /// 64 bits from the shared pass, which is indivisible like the
    /// regex search it can skip, so usage stays as it was without the check.
    fn required_literals_present(
        &self,
        rule_ordinal: usize,
        key: NativeHitKey,
        bytes: &[u8],
        context: &mut ScanContext<'_>,
    ) -> Result<bool, ScanTermination> {
        let (Some(required), Some(matcher)) = (
            self.native_required_patterns
                .get(rule_ordinal)
                .and_then(Option::as_deref),
            self.native_keyword_matcher.as_ref(),
        ) else {
            return Ok(true);
        };
        for pattern in required {
            if context.native_keyword_hit(key, matcher, bytes, *pattern, false)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // Complete all accepted buffers before publishing this rule, preserving
    // completed-rule partial-result atomicity when a later buffer exhausts work.
    #[allow(clippy::too_many_arguments)]
    fn detect_native_rule<'a>(
        &'a self,
        fragment: &'a Fragment,
        options: &ScanOptions,
        rule: &'a CompiledRule,
        required: Option<&NativeRequired>,
        helper: bool,
        pass: RulePass<'a>,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<Finding>, ScanTermination> {
        let mut completed = Vec::new();
        if pass.encoded_segments.is_empty() {
            let input = NativeInput {
                id: NativeInputId {
                    pass: pass.decoded_pass,
                    segment: None,
                },
                bytes: pass.current_raw,
                pass_offset: 0,
            };
            self.detect_native_input(
                fragment,
                options,
                rule,
                required,
                helper,
                pass,
                input,
                &mut completed,
                context,
            )?;
        } else {
            for (segment_ordinal, segment) in pass.encoded_segments.iter().enumerate() {
                context.work()?;
                let Ok(pass_offset) = usize::try_from(segment.decoded().start) else {
                    continue;
                };
                let input = NativeInput {
                    id: NativeInputId {
                        pass: pass.decoded_pass,
                        segment: Some(segment_ordinal),
                    },
                    bytes: segment.decoded_value(),
                    pass_offset,
                };
                self.detect_native_input(
                    fragment,
                    options,
                    rule,
                    required,
                    helper,
                    pass,
                    input,
                    &mut completed,
                    context,
                )?;
            }
        }
        if required.is_none() && !helper && !rule.required.is_empty() {
            return self
                .project_required_findings(fragment, options, rule, pass, completed, context);
        }
        Ok(completed)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn detect_native_input<'a>(
        &'a self,
        fragment: &'a Fragment,
        options: &ScanOptions,
        rule: &'a CompiledRule,
        required: Option<&NativeRequired>,
        helper: bool,
        pass: RulePass<'a>,
        input: NativeInput<'a>,
        completed: &mut Vec<Finding>,
        context: &mut ScanContext<'_>,
    ) -> Result<(), ScanTermination> {
        let normalized = OnceCell::new();
        let unicode_lower = OnceCell::new();
        let primary = self.native_candidates(
            fragment,
            options,
            rule,
            pass,
            input,
            &normalized,
            &unicode_lower,
            helper,
            context,
        )?;
        if primary.is_empty() {
            return Ok(());
        }
        let Some(required) = required else {
            completed.extend(primary.into_iter().map(|candidate| candidate.finding));
            return Ok(());
        };
        let mut helpers = Vec::new();
        for edge in &required.edges {
            context.work()?;
            let candidates = if let Some(helper) = self.config.rules.get(&edge.id) {
                let rule_ordinal = self
                    .config
                    .rules
                    .keys()
                    .position(|id| id == &edge.id)
                    .unwrap_or(pass.rule_ordinal);
                context.explanations.record(
                    Some(rule_ordinal),
                    pass.decoded_pass,
                    None,
                    ExplanationReason::RuleSelected,
                );
                self.native_candidates(
                    fragment,
                    options,
                    helper,
                    RulePass {
                        rule_ordinal,
                        ..pass
                    },
                    input,
                    &normalized,
                    &unicode_lower,
                    true,
                    context,
                )?
            } else {
                Vec::new()
            };
            helpers.push(candidates);
        }
        if required
            .edges
            .iter()
            .all(|edge| edge.relation == NativeRelation::FullMatchWindow(None))
        {
            return attach_shared_helpers(primary, required, &helpers, pass, completed, context);
        }
        // Helpers arrive in ascending, non-overlapping match order (see
        // `native_candidates`), so each relation selects one contiguous run
        // that a binary search finds.
        debug_assert!(helpers.iter().all(|helpers| {
            helpers.windows(2).all(|pair| {
                pair[0].whole.start <= pair[1].whole.start
                    && pair[0].start_line <= pair[1].start_line
            })
        }));
        for mut candidate in primary {
            let mut projected = Vec::new();
            let mut has_all = true;
            for (edge, helpers) in required.edges.iter().zip(&helpers) {
                context.work()?;
                let before = projected.len();
                let run = native_relation_run(&candidate, helpers, edge.relation);
                for helper in &helpers[run] {
                    context.work()?;
                    if native_relation_matches(&candidate, helper, edge.relation) {
                        let finding = &helper.finding;
                        context.admit_finding([
                            finding.rule_id().as_bytes().len(),
                            finding.line().as_bytes().len(),
                            finding.match_text().as_bytes().len(),
                            finding.secret().as_bytes().len(),
                        ])?;
                        projected.push(RequiredFinding::from_finding(finding));
                    }
                }
                has_all &= projected.len() > before;
            }
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                None,
                if has_all {
                    ExplanationReason::RequiredRulesMatched
                } else {
                    ExplanationReason::RequiredRulesMissing
                },
            );
            if has_all {
                candidate.finding.add_required_findings(projected);
                completed.push(candidate.finding);
            }
        }
        Ok(())
    }

    // Helpers inherit only the buffer/coordinate contract, never a caller's
    // public inherited flag. As for any helper rule, their own required edges
    // are not run recursively; primary relations are always enforced.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn native_candidates<'a>(
        &'a self,
        fragment: &'a Fragment,
        options: &ScanOptions,
        rule: &'a CompiledRule,
        pass: RulePass<'a>,
        input: NativeInput<'a>,
        normalized: &OnceCell<NormalizedHaystack<'a>>,
        unicode_lower: &OnceCell<String>,
        helper: bool,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<NativeCandidate>, ScanTermination> {
        context.work()?;
        if rule.skip_report && !helper {
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                None,
                ExplanationReason::RuleReportSkipped,
            );
            return Ok(Vec::new());
        }
        let patterns = self
            .native_keyword_patterns
            .get(pass.rule_ordinal)
            .and_then(Option::as_deref)
            .filter(|patterns| {
                rule.native_keywords
                    .as_ref()
                    .is_some_and(|keywords| keywords.len() == patterns.len())
            });
        let lookup = NativeKeywordLookup {
            matcher: self.native_keyword_matcher.as_ref(),
            patterns,
            input: Some(NativeHitKey::new(&input)),
        };
        let matched = native_keyword_gate(rule, lookup, input.bytes, unicode_lower, context)?;
        context.explanations.record(
            Some(pass.rule_ordinal),
            pass.decoded_pass,
            None,
            if rule.keywords.is_empty() {
                ExplanationReason::KeywordNotRequired
            } else if matched {
                ExplanationReason::KeywordMatched
            } else {
                ExplanationReason::KeywordMissed
            },
        );
        if !matched {
            return Ok(Vec::new());
        }
        if commit_or_path_allowed(fragment, &rule.allowlists, context)? {
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                None,
                ExplanationReason::AllowlistMatched,
            );
            return Ok(Vec::new());
        }
        context.explanations.record(
            Some(pass.rule_ordinal),
            pass.decoded_pass,
            None,
            ExplanationReason::AllowlistNotMatched,
        );
        if let Some(path) = &rule.path_matcher {
            let matched = context.is_match(path, fragment.file_path().as_bytes())?
                || (!fragment.windows_file_path().is_empty()
                    && context.is_match(path, fragment.windows_file_path().as_bytes())?);
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                None,
                if matched {
                    ExplanationReason::PathMatched
                } else {
                    ExplanationReason::PathMissed
                },
            );
            if !matched {
                return Ok(Vec::new());
            }
        }
        if options
            .max_target_bytes()
            .is_some_and(|maximum| input.bytes.len() > maximum)
        {
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                None,
                ExplanationReason::TargetByteLimit,
            );
            return Ok(Vec::new());
        }
        if rule.native_keywords.as_ref().is_some_and(Vec::is_empty)
            && !self.required_literals_present(
                pass.rule_ordinal,
                NativeHitKey::new(&input),
                input.bytes,
                context,
            )?
        {
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                None,
                ExplanationReason::PatternMissed,
            );
            return Ok(Vec::new());
        }
        let regex = if let Some(regex) = &rule.native_byte_matcher {
            NativeContentMatcher::Bytes(regex)
        } else if let Some(regex) = &rule.regex_matcher {
            if normalized.get().is_none() {
                let _ = normalized.set(context.normalize(input.bytes)?);
            }
            NativeContentMatcher::Go(
                regex,
                normalized.get().expect("the native input was normalized"),
            )
        } else {
            return Ok(Vec::new());
        };
        let spans = regex.find_all(input.bytes, context)?;
        if spans.is_empty() {
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                None,
                ExplanationReason::PatternMissed,
            );
        }
        let mut candidates = Vec::new();
        let mut line_allowlists = LineAllowlistMemo::default();
        let mut capture_scratch = None;
        // The byte offset and 1-based line of the last admitted whole-match
        // end. Spans arrive in ascending, non-overlapping order, so each
        // input byte is counted once for line coordinates.
        let mut line_cursor = (0_usize, 1_usize);
        for (candidate_ordinal, whole) in spans.into_iter().enumerate() {
            context.work()?;
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                Some(candidate_ordinal),
                ExplanationReason::PatternMatched,
            );
            let Some(start) = input.pass_offset.checked_add(whole.start) else {
                continue;
            };
            let Some(end) = input.pass_offset.checked_add(whole.end) else {
                continue;
            };
            context.work()?;
            let Some(extracted) = extract_native_secret(
                regex,
                input.bytes,
                whole,
                rule.secret_group,
                &mut capture_scratch,
            ) else {
                context.explanations.record(
                    Some(pass.rule_ordinal),
                    pass.decoded_pass,
                    Some(candidate_ordinal),
                    ExplanationReason::SecretGroupUnavailable,
                );
                continue;
            };
            let secret = extracted.span;
            let Some(absolute_secret) = secret.and_then(|span| {
                Some(ByteSpan {
                    start: input.pass_offset.checked_add(span.start)?,
                    end: input.pass_offset.checked_add(span.end)?,
                })
            }) else {
                continue;
            };
            if let Some(finding) = self.content_finding(
                fragment,
                options,
                rule,
                DetectionPass {
                    current_raw: pass.current_raw,
                    encoded_segments: pass.encoded_segments,
                    original: pass.original,
                    rule_ordinal: pass.rule_ordinal,
                    decoded_pass: pass.decoded_pass,
                    candidate_ordinal,
                },
                ByteSpan { start, end },
                &mut line_allowlists,
                &mut capture_scratch,
                Some(ExtractedSecret {
                    bytes: extracted.bytes,
                    span: Some(absolute_secret),
                }),
                context,
            )? {
                // Count LF bytes at their actual input positions, including a
                // trailing LF at the exclusive whole-match endpoint. Counting
                // resumes at the previous admitted end, so one unit is charged
                // per byte counted and a rule's candidates in one input cost
                // the last admitted end in total. A span that starts before the
                // cursor, which `find_all` does not produce, recounts from the
                // input start. No index or coordinate registry is retained
                // outside admitted records.
                debug_assert!(
                    whole.start >= line_cursor.0,
                    "native spans arrive in ascending, non-overlapping order"
                );
                let (from, line_at) = if whole.start >= line_cursor.0 {
                    line_cursor
                } else {
                    (0, 1)
                };
                context.work_many(whole.end - from)?;
                // No byte-counting dependency is admitted; the scan is already
                // charged above as bounded work.
                #[allow(clippy::naive_bytecount)]
                let start_line = line_at
                    + input.bytes[from..whole.start]
                        .iter()
                        .filter(|&&byte| byte == b'\n')
                        .count();
                #[allow(clippy::naive_bytecount)]
                let end_line = start_line
                    + input.bytes[whole.start..whole.end]
                        .iter()
                        .filter(|&&byte| byte == b'\n')
                        .count();
                line_cursor = (whole.end, end_line);
                candidates.push(NativeCandidate {
                    finding,
                    input: input.id,
                    whole,
                    _secret: secret,
                    start_line,
                    end_line,
                });
            }
        }
        Ok(candidates)
    }

    /// Enumerates one rule's whole matches for the current pass.
    fn content_match_spans(
        regex: &GoRegex,
        rule_pass: RulePass<'_>,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<ByteSpan>, ScanTermination> {
        if rule_pass.normalized.get().is_none() {
            let normalized = context.normalize(rule_pass.current_raw)?;
            let _ = rule_pass.normalized.set(normalized);
        }
        let normalized = rule_pass.normalized.get().expect("the pass was normalized");
        if context.control.budget.collected_spans.is_some() {
            // Avoid speculative anchored collection and its abandoned spans.
            // This exact collector has no unlimited fallback on exhaustion.
            return regex.find_all_normalized_controlled(normalized, || context.collected_spans(1));
        }
        if let Some(anchor) = rule_pass.literal_anchor
            && let Some(starts) = rule_pass
                .keyword_occurrences
                .rule_starts(&anchor.keyword_indexes)
        {
            let (spans, collected) =
                regex.find_all_literal_anchored_counted(normalized, anchor.candidate, &starts);
            context.collected_spans(collected)?;
            if let Some(spans) = spans {
                return Ok(spans);
            }
        }
        let spans = regex.find_all_normalized(normalized);
        context.collected_spans(spans.len())?;
        Ok(spans)
    }

    fn project_required_findings<'a>(
        &'a self,
        fragment: &'a Fragment,
        options: &ScanOptions,
        primary_rule: &'a CompiledRule,
        rule_pass: RulePass<'a>,
        primary_findings: Vec<Finding>,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<Finding>, ScanTermination> {
        let mut required_by_id = BTreeMap::<&str, Vec<Finding>>::new();
        for required in &primary_rule.required {
            context.work()?;
            let Some(rule) = self.config.rules.get(&required.id) else {
                continue;
            };
            let rule_ordinal = if context.explanations.has_room() {
                self.config
                    .rules
                    .keys()
                    .position(|id| id == &required.id)
                    .unwrap_or(rule_pass.rule_ordinal)
            } else {
                rule_pass.rule_ordinal
            };
            context.explanations.record(
                Some(rule_ordinal),
                rule_pass.decoded_pass,
                None,
                ExplanationReason::RuleSelected,
            );
            let findings = self.detect_rule(
                fragment,
                options,
                rule,
                RulePass {
                    inherited_from_finding: true,
                    rule_ordinal,
                    // Required rules have no plan lookup here. The unanchored
                    // path is exact and this runs only after primary findings.
                    literal_anchor: None,
                    ..rule_pass
                },
                context,
            )?;
            required_by_id.insert(required.id.as_str(), findings);
        }

        let mut completed = Vec::new();
        for mut primary in primary_findings {
            let mut projected = Vec::new();
            for required in &primary_rule.required {
                context.work()?;
                let Some(findings) = required_by_id.get(required.id.as_str()) else {
                    continue;
                };
                for finding in findings {
                    context.work()?;
                    if within_proximity(&primary, finding, required) {
                        context.admit_finding([
                            finding.rule_id().as_bytes().len(),
                            finding.line().as_bytes().len(),
                            finding.match_text().as_bytes().len(),
                            finding.secret().as_bytes().len(),
                        ])?;
                        projected.push(RequiredFinding::from_finding(finding));
                    }
                }
            }

            let has_all = primary_rule.required.iter().all(|required| {
                projected
                    .iter()
                    .any(|finding| finding.rule_id().as_bytes() == required.id.as_bytes())
            });
            if projected.is_empty() || !has_all {
                context.explanations.record(
                    Some(rule_pass.rule_ordinal),
                    rule_pass.decoded_pass,
                    None,
                    ExplanationReason::RequiredRulesMissing,
                );
                continue;
            }
            context.explanations.record(
                Some(rule_pass.rule_ordinal),
                rule_pass.decoded_pass,
                None,
                ExplanationReason::RequiredRulesMatched,
            );
            primary.add_required_findings(projected);
            completed.push(primary);
        }
        Ok(completed)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Keep local caching separate from scan accounting and preserve decision order.
    fn content_finding<'a>(
        &'a self,
        fragment: &'a Fragment,
        options: &ScanOptions,
        rule: &'a CompiledRule,
        pass: DetectionPass<'a>,
        whole: ByteSpan,
        line_allowlists: &mut LineAllowlistMemo<'a>,
        capture_scratch: &mut Option<CaptureScratch>,
        native_secret: Option<ExtractedSecret<'a>>,
        context: &mut ScanContext<'_>,
    ) -> Result<Option<Finding>, ScanTermination> {
        macro_rules! candidate {
            ($value:expr) => {
                match $value {
                    Some(value) => value,
                    None => return Ok(None),
                }
            };
        }
        macro_rules! explain {
            ($reason:expr) => {
                context.explanations.record(
                    Some(pass.rule_ordinal),
                    pass.decoded_pass,
                    Some(pass.candidate_ordinal),
                    $reason,
                )
            };
        }
        let original_raw = fragment.content().as_bytes();
        let matched = candidate!(pass.current_raw.get(whole.start..whole.end));
        let (trimmed_offset, trimmed) = trim_newlines(matched);
        let direct_match_start = candidate!(whole.start.checked_add(trimmed_offset));
        let direct_match_end = candidate!(direct_match_start.checked_add(trimmed.len()));
        let (adjusted_start, adjusted_end, decoded_line, meta_segments) =
            if pass.encoded_segments.is_empty() {
                (
                    whole.start,
                    candidate!(whole.start.checked_add(trimmed.len())),
                    None,
                    &[][..],
                )
            } else {
                let overlapping =
                    segments_with_decoded_overlap(pass.encoded_segments, whole.start, whole.end);
                if overlapping.is_empty() {
                    explain!(ExplanationReason::DecodedMappingUnavailable);
                    return Ok(None);
                }
                let (start, end) =
                    candidate!(adjust_match_index(overlapping, whole.start, whole.end));
                (
                    start,
                    end,
                    Some(current_line(overlapping, pass.current_raw)),
                    overlapping,
                )
            };
        // Decoded passes project back onto the original fragment. Keep this
        // index scan-local and construct it only when a candidate needs it.
        let newlines = pass
            .original
            .newlines
            .get_or_init(|| newline_indices(original_raw));
        let source = upstream_location(
            newlines,
            original_raw,
            adjusted_start,
            adjusted_end,
            &pass.original.tail,
        );
        let line = candidate!(original_raw.get(source.start_line_index..source.end_line_index));
        if options.honor_allow_markers()
            && pass
                .original
                .has_allow_marker(line, source.start_line_index, source.end_line_index)
        {
            explain!(ExplanationReason::AllowMarkerMatched);
            return Ok(None);
        }

        let secret_origin = if native_secret.is_some() {
            0
        } else {
            direct_match_start
        };
        let extracted_secret = if let Some(secret) = native_secret {
            secret
        } else {
            let Some(secret) = extract_secret_controlled(
                candidate!(rule.regex_matcher.as_ref()),
                trimmed,
                rule.secret_group,
                capture_scratch,
                context,
            )?
            else {
                explain!(ExplanationReason::SecretGroupUnavailable);
                return Ok(None);
            };
            secret
        };
        let secret = extracted_secret.bytes;
        // Native predicates remain on the compiled rule through projections.
        // A scalar `entropy` of zero defers the calculation until finding
        // construction.
        let threshold_entropy = rule.native_entropy.map_or_else(
            || (rule.entropy != 0.0).then(|| shannon_entropy(secret)),
            |policy| Some(policy.calculate(secret)),
        );
        if threshold_entropy.is_some_and(|entropy| match rule.native_entropy {
            Some(policy) => policy.rejects(entropy),
            None => entropy <= rule.entropy,
        }) {
            explain!(ExplanationReason::EntropyRejected);
            return Ok(None);
        }
        explain!(if threshold_entropy.is_none() {
            ExplanationReason::EntropyNotRequired
        } else {
            ExplanationReason::EntropyAccepted
        });
        if let Some(predicate) = &rule.native_predicate {
            use crate::native::predicate::{MAX_DECODED_BYTES, NativePredicate, vercel};
            let accepted = match predicate {
                NativePredicate::Base64UrlSegment(predicate) => {
                    context.work()?;
                    let mut output = [0_u8; MAX_DECODED_BYTES];
                    if let Some(decoded) = predicate.decode(secret, &mut output) {
                        context.work()?;
                        context.is_match(&predicate.matcher, decoded)?
                    } else {
                        false
                    }
                }
                NativePredicate::VercelCl100kRatio => {
                    vercel::accepts(secret, &mut || context.work())?
                }
            };
            explain!(if accepted {
                ExplanationReason::NativePredicateAccepted
            } else {
                ExplanationReason::NativePredicateRejected
            });
            if !accepted {
                return Ok(None);
            }
        }
        let allowlist_line = decoded_line.filter(|line| !line.is_empty()).unwrap_or(line);
        if finding_allowed_controlled(
            fragment,
            trimmed,
            secret,
            allowlist_line,
            &self.config.allowlists,
            &mut line_allowlists.global,
            context,
        )? || finding_allowed_controlled(
            fragment,
            trimmed,
            secret,
            allowlist_line,
            &rule.allowlists,
            &mut line_allowlists.rule,
            context,
        )? {
            explain!(ExplanationReason::AllowlistMatched);
            return Ok(None);
        }
        explain!(ExplanationReason::AllowlistNotMatched);
        explain!(ExplanationReason::CandidateAccepted);
        if context.explanations.github_classic && context.explanations.begin_annotation() {
            let isolated = extracted_secret.span.is_some_and(|span| {
                let start = secret_origin.checked_add(span.start);
                let end = secret_origin.checked_add(span.end);
                start.zip(end).is_some_and(|(start, end)| {
                    let continues = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_';
                    !start
                        .checked_sub(1)
                        .and_then(|index| pass.current_raw.get(index))
                        .is_some_and(continues)
                        && !pass.current_raw.get(end).is_some_and(continues)
                })
            });
            for assessment in crate::validation::github_classic_pat_in_context(secret, isolated) {
                context.explanations.record(
                    Some(pass.rule_ordinal),
                    pass.decoded_pass,
                    Some(pass.candidate_ordinal),
                    ExplanationReason::OfflineValidation {
                        check: assessment.check(),
                        state: assessment.state(),
                        reason: assessment.reason(),
                    },
                );
            }
        }

        let location = Location::from_upstream(
            fragment.start_line().saturating_add(source.start_line),
            fragment.start_line().saturating_add(source.end_line),
            source.start_column,
            source.end_column,
        );
        let (match_range, secret_range) = if pass.encoded_segments.is_empty() {
            let match_range = FindingRange::Exact(candidate!(
                ByteRange::new(direct_match_start, direct_match_end).ok()
            ));
            let secret_range = match extracted_secret.span {
                Some(span) => {
                    let start = candidate!(secret_origin.checked_add(span.start));
                    let end = candidate!(secret_origin.checked_add(span.end));
                    FindingRange::Exact(candidate!(ByteRange::new(start, end).ok()))
                }
                None => FindingRange::Unavailable,
            };
            (match_range, secret_range)
        } else {
            (FindingRange::Unavailable, FindingRange::Unavailable)
        };
        context.admit_finding(finding_base_payload(fragment, rule).chain([
            line.len(),
            trimmed.len(),
            secret.len(),
            crate::decoder::tags_payload_bytes(meta_segments),
        ]))?;
        let meta_tags = decoder_tags(meta_segments);
        let mut builder = Finding::builder()
            .rule_id(rule.id.as_str())
            .description(rule.description.as_str())
            .location(location)
            .match_range(match_range)
            .secret_range(secret_range)
            .line(
                pass.original
                    .admitted_line(line, source.start_line_index, source.end_line_index),
            )
            .match_text(trimmed)
            .secret(secret)
            .file(fragment.file_path().as_bytes())
            .symlink_file(fragment.symlink_file().as_bytes())
            .commit(fragment.commit().as_bytes())
            .entropy(entropy_to_f32(
                threshold_entropy.unwrap_or_else(|| shannon_entropy(secret)),
            ))
            .tags(rule.tags.iter().cloned().chain(meta_tags));
        if let Some(metadata) = fragment.commit_metadata() {
            builder = builder
                .author(metadata.author_name().as_bytes())
                .email(metadata.author_email().as_bytes())
                .date(metadata.date().as_bytes())
                .message(metadata.message().as_bytes());
        }
        Ok(builder.build().ok())
    }
}

/// `rule.keywords` decides whether a gate exists. `indexes` omits keywords with
/// no prefilter pattern, so a rule with only empty keywords remains closed.
fn keyword_gate_open(rule: &CompiledRule, indexes: &[usize], matched_keywords: &[bool]) -> bool {
    rule.keywords.is_empty() || indexes.iter().any(|&index| matched_keywords[index])
}

fn path_allowed_controlled(
    allowlist: &CompiledAllowlist,
    path: &[u8],
    context: &mut ScanContext<'_>,
) -> Result<bool, ScanTermination> {
    match &allowlist.path_matcher {
        Some(matcher) if !path.is_empty() => context.is_match(matcher, path),
        _ => Ok(false),
    }
}

/// Checks the fragment path, then its Windows spelling when one is set.
fn fragment_path_allowed(
    allowlist: &CompiledAllowlist,
    fragment: &Fragment,
    context: &mut ScanContext<'_>,
) -> Result<bool, ScanTermination> {
    Ok(
        path_allowed_controlled(allowlist, fragment.file_path().as_bytes(), context)?
            || (!fragment.windows_file_path().is_empty()
                && path_allowed_controlled(
                    allowlist,
                    fragment.windows_file_path().as_bytes(),
                    context,
                )?),
    )
}

fn regex_allowed(
    allowlist: &CompiledAllowlist,
    target: &[u8],
    context: &mut ScanContext<'_>,
) -> Result<bool, ScanTermination> {
    match &allowlist.regex_matcher {
        Some(matcher) if !target.is_empty() => context.is_match(matcher, target),
        _ => Ok(false),
    }
}

fn commit_or_path_allowed(
    fragment: &Fragment,
    allowlists: &[CompiledAllowlist],
    context: &mut ScanContext<'_>,
) -> Result<bool, ScanTermination> {
    // Preserve the pinned Windows-only guard.
    if fragment.file_path().is_empty() && fragment.commit().is_empty() {
        return Ok(false);
    }
    for allowlist in allowlists {
        let commit = allowlist.commit_allowed(fragment.commit().as_bytes());
        let path = fragment_path_allowed(allowlist, fragment, context)?;
        let allowed = match allowlist.condition {
            Condition::Or => commit || path,
            Condition::And => {
                allowlist.regexes.is_empty()
                    && allowlist.stop_words.is_empty()
                    && (allowlist.commits.is_empty() || commit)
                    && (allowlist.paths.is_empty() || path)
            }
            Condition::Unknown(_) => false,
        };
        if allowed {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn finding_allowed_controlled<'a>(
    fragment: &Fragment,
    full_match: &[u8],
    secret: &[u8],
    current_line: &'a [u8],
    allowlists: &'a [CompiledAllowlist],
    line_cache: &mut Vec<Option<LineRegexResult<'a>>>,
    context: &mut ScanContext<'_>,
) -> Result<bool, ScanTermination> {
    for (index, allowlist) in allowlists.iter().enumerate() {
        let regex = match allowlist.regex_target {
            RegexTarget::Secret | RegexTarget::Unknown(_) => {
                regex_allowed(allowlist, secret, context)?
            }
            RegexTarget::Match => regex_allowed(allowlist, full_match, context)?,
            RegexTarget::Line => line_regex_allowed_controlled(
                allowlist,
                current_line,
                index,
                allowlists.len(),
                line_cache,
                context,
            )?,
        };
        let stopword = allowlist.contains_stop_word(secret);
        let allowed = match allowlist.condition {
            Condition::Or => regex || stopword,
            Condition::And => {
                let commit = allowlist.commit_allowed(fragment.commit().as_bytes());
                let path = fragment_path_allowed(allowlist, fragment, context)?;
                (allowlist.commits.is_empty() || commit)
                    && (allowlist.paths.is_empty() || path)
                    && (allowlist.regexes.is_empty() || regex)
                    && (allowlist.stop_words.is_empty() || stopword)
            }
            Condition::Unknown(_) => false,
        };
        if allowed {
            return Ok(true);
        }
    }
    Ok(false)
}

fn line_regex_allowed_controlled<'a>(
    allowlist: &'a CompiledAllowlist,
    line: &'a [u8],
    index: usize,
    slots: usize,
    cache: &mut Vec<Option<LineRegexResult<'a>>>,
    context: &mut ScanContext<'_>,
) -> Result<bool, ScanTermination> {
    if line.is_empty() || allowlist.regex_matcher.is_none() {
        return Ok(false);
    }
    if cache.is_empty() {
        cache.resize(slots, None);
    }
    let slot = &mut cache[index];
    if let Some(previous) = slot
        && std::ptr::eq(previous.allowlist, allowlist)
        && std::ptr::eq(previous.line, line)
    {
        return Ok(previous.matched);
    }
    let matched = regex_allowed(allowlist, line, context)?;
    *slot = Some(LineRegexResult {
        allowlist,
        line,
        matched,
    });
    Ok(matched)
}

#[cfg(test)]
fn finding_allowed<'a>(
    fragment: &Fragment,
    full_match: &[u8],
    secret: &[u8],
    current_line: &'a [u8],
    allowlists: &'a [CompiledAllowlist],
    line_cache: &mut Vec<Option<LineRegexResult<'a>>>,
) -> bool {
    finding_allowed_controlled(
        fragment,
        full_match,
        secret,
        current_line,
        allowlists,
        line_cache,
        &mut ScanContext::new(ScanControl::unlimited()),
    )
    .unwrap()
}

#[cfg(test)]
fn line_regex_allowed<'a>(
    allowlist: &'a CompiledAllowlist,
    line: &'a [u8],
    index: usize,
    slots: usize,
    cache: &mut Vec<Option<LineRegexResult<'a>>>,
) -> bool {
    line_regex_allowed_controlled(
        allowlist,
        line,
        index,
        slots,
        cache,
        &mut ScanContext::new(ScanControl::unlimited()),
    )
    .unwrap()
}

#[cfg(test)]
mod native_relation_tests {
    use super::*;

    fn candidate(pass: usize, segment: Option<usize>, end: usize) -> NativeCandidate {
        NativeCandidate {
            finding: Finding::builder()
                .rule_id("synthetic")
                .location(Location::new(1, 1, 1, 1).unwrap())
                .build()
                .unwrap(),
            input: NativeInputId { pass, segment },
            whole: ByteSpan { start: 2, end },
            _secret: Some(ByteSpan { start: 3, end: 4 }),
            start_line: 2,
            end_line: 4,
        }
    }

    #[test]
    fn identity_uses_both_whole_endpoints_and_scan_local_input() {
        let primary = candidate(1, Some(0), 8);
        assert!(native_relation_matches(
            &primary,
            &candidate(1, Some(0), 8),
            NativeRelation::SameCandidate
        ));
        for helper in [
            candidate(1, Some(0), 9),
            candidate(1, Some(1), 8),
            candidate(2, Some(0), 8),
            candidate(0, None, 8),
        ] {
            assert!(!native_relation_matches(
                &primary,
                &helper,
                NativeRelation::SameCandidate
            ));
        }
        for helper in [
            candidate(1, Some(1), 8),
            candidate(2, Some(0), 8),
            candidate(0, None, 8),
        ] {
            assert!(!native_relation_matches(
                &primary,
                &helper,
                NativeRelation::FullMatchWindow(None)
            ));
        }
    }
}

fn native_relation_matches(
    primary: &NativeCandidate,
    helper: &NativeCandidate,
    relation: NativeRelation,
) -> bool {
    primary.input == helper.input
        && match relation {
            NativeRelation::SameCandidate => primary.whole == helper.whole,
            NativeRelation::FullMatchWindow(None) => true,
            NativeRelation::FullMatchWindow(Some(expansion)) => {
                helper.start_line >= primary.start_line.saturating_sub(expansion)
                    && helper.start_line <= primary.end_line.saturating_add(expansion)
            }
        }
}

/// Attaches helpers through edges that all have no line limit.
///
/// Every helper in the input then relates to every primary, so all
/// primaries get the same list. It is projected and admitted once, when
/// the first primary needs it, and shared. Each primary still charges one
/// work unit for each edge. Work and memory grow with primaries plus
/// helpers, not with their product.
fn attach_shared_helpers(
    primary: Vec<NativeCandidate>,
    required: &NativeRequired,
    helpers: &[Vec<NativeCandidate>],
    pass: RulePass<'_>,
    completed: &mut Vec<Finding>,
    context: &mut ScanContext<'_>,
) -> Result<(), ScanTermination> {
    let has_all = helpers.iter().all(|helpers| !helpers.is_empty());
    let mut shared: Option<Arc<[RequiredFinding]>> = None;
    for mut candidate in primary {
        context.work_many(required.edges.len())?;
        let projected = if has_all {
            if let Some(projected) = &shared {
                Some(Arc::clone(projected))
            } else {
                let mut projected = Vec::new();
                for helper in helpers.iter().flatten() {
                    context.work()?;
                    debug_assert!(native_relation_matches(
                        &candidate,
                        helper,
                        NativeRelation::FullMatchWindow(None)
                    ));
                    let finding = &helper.finding;
                    context.admit_finding([
                        finding.rule_id().as_bytes().len(),
                        finding.line().as_bytes().len(),
                        finding.match_text().as_bytes().len(),
                        finding.secret().as_bytes().len(),
                    ])?;
                    projected.push(RequiredFinding::from_finding(finding));
                }
                let projected = Arc::<[RequiredFinding]>::from(projected);
                shared = Some(Arc::clone(&projected));
                Some(projected)
            }
        } else {
            None
        };
        context.explanations.record(
            Some(pass.rule_ordinal),
            pass.decoded_pass,
            None,
            if has_all {
                ExplanationReason::RequiredRulesMatched
            } else {
                ExplanationReason::RequiredRulesMissing
            },
        );
        if let Some(projected) = projected {
            candidate.finding.set_shared_required_findings(projected);
            completed.push(candidate.finding);
        }
    }
    Ok(())
}

/// Returns the run of ordered helpers that can relate to `primary`.
///
/// `helpers` must be in ascending match start and start line order. Every
/// helper outside the run fails [`native_relation_matches`].
fn native_relation_run(
    primary: &NativeCandidate,
    helpers: &[NativeCandidate],
    relation: NativeRelation,
) -> Range<usize> {
    match relation {
        NativeRelation::SameCandidate => {
            let start = helpers.partition_point(|helper| helper.whole.start < primary.whole.start);
            let end = helpers.partition_point(|helper| helper.whole.start <= primary.whole.start);
            start..end
        }
        NativeRelation::FullMatchWindow(None) => 0..helpers.len(),
        NativeRelation::FullMatchWindow(Some(expansion)) => {
            let low = primary.start_line.saturating_sub(expansion);
            let high = primary.end_line.saturating_add(expansion);
            let start = helpers.partition_point(|helper| helper.start_line < low);
            let end = helpers.partition_point(|helper| helper.start_line <= high);
            start..end.max(start)
        }
    }
}

fn within_proximity(
    primary: &Finding,
    required: &Finding,
    specification: &RequiredRuleSpec,
) -> bool {
    fn within(left: usize, right: usize, bound: i64) -> bool {
        !bound.is_negative() && left.abs_diff(right) <= usize::try_from(bound).unwrap_or(usize::MAX)
    }

    specification.within_lines.is_none_or(|bound| {
        within(
            primary.location().start_line(),
            required.location().start_line(),
            bound,
        )
    }) && specification.within_columns.is_none_or(|bound| {
        within(
            primary.location().start_column(),
            required.location().start_column(),
            bound,
        )
    })
}

fn finish_partial(
    findings: Vec<Finding>,
    replaced_by: &ReplacedBy,
    options: &ScanOptions,
    usage: ScanUsage,
    termination: ScanTermination,
) -> ScanOutcome {
    // Completed rules are finalized even when the signal remains set. This is
    // the atomic cleanup needed to avoid exposing unsuppressed/unredacted raw
    // candidates as partial findings. `max_finding_records` bounds this phase
    // when callers require a hard cardinality ceiling.
    ScanOutcome::partial(
        filter_findings(replaced_by, findings, options.redaction_percent()),
        usage,
        termination,
    )
}

fn finish_complete(
    findings: Vec<Finding>,
    replaced_by: &ReplacedBy,
    options: &ScanOptions,
    context: &ScanContext<'_>,
) -> ScanOutcome {
    let (findings, termination) = filter_findings_cancellable(
        replaced_by,
        findings,
        options.redaction_percent(),
        context.control,
    );
    match termination {
        Some(termination) => ScanOutcome::partial(findings, context.usage, termination),
        None => ScanOutcome::complete(findings, context.usage),
    }
}

fn filter_findings_cancellable(
    replaced_by: &ReplacedBy,
    findings: Vec<Finding>,
    redact: usize,
    control: ScanControl<'_>,
) -> (Vec<Finding>, Option<ScanTermination>) {
    if control.cancellation.is_none() {
        return (filter_findings(replaced_by, findings, redact), None);
    }
    filter_findings_with_cancellation(
        replaced_by,
        findings,
        redact,
        control,
        suppresses_generic_finding,
    )
}

/// Applies the same bucketed selection as [`filter_findings`] with a
/// cancellation poll before every visit to a finding.
///
/// Index construction polls once per finding classified and, when any finding
/// is generic, once per finding indexed. The filter then polls once per
/// finding and once before each comparison with a candidate from the generic
/// finding's bucket, so no bucket is searched in advance and the polls are
/// linear in the findings plus the comparisons made. On cancellation the
/// findings decided so far are returned, as a prefix of the list.
fn filter_findings_with_cancellation(
    replaced_by: &ReplacedBy,
    findings: Vec<Finding>,
    redact: usize,
    control: ScanControl<'_>,
    mut suppresses: impl FnMut(&Finding, &Finding) -> bool,
) -> (Vec<Finding>, Option<ScanTermination>) {
    let Some(replaced) = replaced_by.replaced(&findings, || control.is_cancelled()) else {
        return (Vec::new(), Some(ScanTermination::Cancelled));
    };
    let Some(suppression) = GenericSuppression::build(&findings, || control.is_cancelled()) else {
        return (Vec::new(), Some(ScanTermination::Cancelled));
    };
    let mut include = Vec::with_capacity(findings.len());
    let mut cancelled = false;
    'findings: for (index, finding) in findings.iter().enumerate() {
        if control.is_cancelled() {
            cancelled = true;
            break;
        }
        if replaced[index] {
            include.push(false);
            continue;
        }
        if !suppression.is_generic(index) {
            include.push(true);
            continue;
        }
        let mut retained = true;
        for &candidate in suppression.bucket(index) {
            if control.is_cancelled() {
                cancelled = true;
                break 'findings;
            }
            if suppresses(finding, &findings[candidate]) {
                retained = false;
                break;
            }
        }
        include.push(retained);
    }
    let termination = cancelled.then_some(ScanTermination::Cancelled);
    (apply_finding_filter(findings, include, redact), termination)
}

fn suppresses_generic_finding(finding: &Finding, other: &Finding) -> bool {
    finding.location().start_line() == other.location().start_line()
        && finding.commit() == other.commit()
        && finding.rule_id() != other.rule_id()
        && contains_bytes(other.secret().as_bytes(), finding.secret().as_bytes())
        && !contains_bytes(&go_lowercase_bytes(other.rule_id().as_bytes()), b"generic")
}

/// Pair selection for generic-rule suppression over one immutable finding list.
///
/// A finding can suppress a generic finding only when it is non-generic, has
/// the same start line, and has the byte-identical commit. Each bucket holds
/// exactly the non-generic findings for one such key, in list order, so the
/// remaining predicate terms see the same candidates in the same order.
struct GenericSuppression<'a> {
    findings: &'a [Finding],
    generic: Vec<bool>,
    specific_by_line_and_commit: BTreeMap<(usize, &'a [u8]), Vec<usize>>,
}

impl<'a> GenericSuppression<'a> {
    fn new(findings: &'a [Finding]) -> Self {
        Self::build(findings, || false).expect("an unpolled index is never cancelled")
    }

    /// Builds the index, calling `cancelled` before each finding is
    /// classified and before each finding is indexed. Returns `None` as soon
    /// as it reports cancellation.
    fn build(findings: &'a [Finding], mut cancelled: impl FnMut() -> bool) -> Option<Self> {
        let mut generic = Vec::with_capacity(findings.len());
        // Findings arrive grouped by rule; the flag depends only on the ID bytes.
        let mut previous = None;
        for finding in findings {
            if cancelled() {
                return None;
            }
            let rule_id = finding.rule_id().as_bytes();
            let flag = match previous {
                Some((previous_id, flag)) if previous_id == rule_id => flag,
                _ => contains_bytes(&go_lowercase_bytes(rule_id), b"generic"),
            };
            previous = Some((rule_id, flag));
            generic.push(flag);
        }
        let mut specific_by_line_and_commit = BTreeMap::<_, Vec<usize>>::new();
        if generic.contains(&true) {
            for (index, finding) in findings.iter().enumerate() {
                if cancelled() {
                    return None;
                }
                if !generic[index] {
                    specific_by_line_and_commit
                        .entry((finding.location().start_line(), finding.commit().as_bytes()))
                        .or_default()
                        .push(index);
                }
            }
        }
        Some(Self {
            findings,
            generic,
            specific_by_line_and_commit,
        })
    }

    fn is_generic(&self, index: usize) -> bool {
        self.generic[index]
    }

    /// Returns, in list order, the non-generic findings with the same start
    /// line and commit as the finding at `index`: the only findings that can
    /// suppress it.
    fn bucket(&self, index: usize) -> &[usize] {
        let finding = &self.findings[index];
        self.specific_by_line_and_commit
            .get(&(finding.location().start_line(), finding.commit().as_bytes()))
            .map_or(&[], Vec::as_slice)
    }

    /// Returns the lowest list index that suppresses the generic finding.
    fn first_suppressor(&self, index: usize) -> Option<usize> {
        let finding = &self.findings[index];
        self.bucket(index).iter().copied().find(|&candidate| {
            let other = &self.findings[candidate];
            finding.rule_id() != other.rule_id()
                && contains_bytes(other.secret().as_bytes(), finding.secret().as_bytes())
        })
    }
}

fn apply_finding_filter(findings: Vec<Finding>, include: Vec<bool>, redact: usize) -> Vec<Finding> {
    findings
        .into_iter()
        .zip(include)
        .filter_map(|(finding, include)| {
            if !include {
                return None;
            }
            Some(if redact > 0 {
                finding.redacted(redact)
            } else {
                finding
            })
        })
        .collect()
}

fn filter_findings(
    replaced_by: &ReplacedBy,
    findings: Vec<Finding>,
    redact: usize,
) -> Vec<Finding> {
    let replaced = replaced_by
        .replaced(&findings, || false)
        .expect("an unpolled filter is never cancelled");
    let suppression = GenericSuppression::new(&findings);
    let include = (0..findings.len())
        .map(|index| {
            !replaced[index]
                && (!suppression.is_generic(index) || suppression.first_suppressor(index).is_none())
        })
        .collect::<Vec<_>>();

    apply_finding_filter(findings, include, redact)
}

/// Builder for [`Engine`].
#[derive(Clone, Debug)]
pub struct EngineBuilder {
    config: CompiledConfig,
}

impl EngineBuilder {
    /// Compiles the global keyword prefilter.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError`] when the keyword automaton cannot be built.
    pub fn build(self) -> Result<Engine, ScanError> {
        let keywords = self
            .config
            .keywords
            .iter()
            .filter(|keyword| !keyword.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        let keyword_ids = keywords
            .iter()
            .enumerate()
            .map(|(index, keyword)| (keyword.as_str(), index))
            .collect::<BTreeMap<_, _>>();
        let keyword_count = keyword_ids.len();
        let rule_keyword_indexes = self
            .config
            .rules
            .values()
            .map(|rule| {
                rule.keywords
                    .iter()
                    .filter_map(|keyword| keyword_ids.get(keyword.as_str()).copied())
                    .collect()
            })
            .collect();
        let rule_literal_anchors = self
            .config
            .rules
            .values()
            .map(|rule| plan_literal_anchor(rule, &keyword_ids))
            .collect::<Vec<_>>();
        let mut recorded_keywords = Vec::new();
        if rule_literal_anchors.iter().any(Option::is_some) {
            recorded_keywords = vec![false; keyword_count];
            for keyword in rule_literal_anchors
                .iter()
                .flatten()
                .flat_map(|plan| plan.keyword_indexes.iter())
            {
                recorded_keywords[*keyword] = true;
            }
        }
        let prefilter = if keywords.is_empty() {
            None
        } else {
            let mut builder = AhoCorasickBuilder::new();
            builder.match_kind(MatchKind::Standard);
            if keyword_dfa_is_bounded(&keywords) {
                builder.kind(Some(AhoCorasickKind::DFA));
            }
            Some(
                builder
                    .build(&keywords)
                    .map_err(|error| ScanError::Prefilter {
                        message: error.to_string(),
                    })?,
            )
        };
        let NativeKeywordIndex {
            matcher: native_keyword_matcher,
            keywords: native_keyword_patterns,
            required: native_required_patterns,
        } = build_native_keyword_matcher(&self.config)?;
        let replaced_by = ReplacedBy::new(&self.config);
        Ok(Engine {
            config: self.config,
            prefilter,
            keyword_count,
            rule_keyword_indexes,
            rule_literal_anchors,
            recorded_keywords,
            native_keyword_matcher,
            native_keyword_patterns,
            native_required_patterns,
            replaced_by,
        })
    }
}

/// Native keyword automaton and the pattern IDs each rule reads from it.
struct NativeKeywordIndex {
    matcher: Option<AhoCorasick>,
    keywords: Vec<Option<Box<[Option<u32>]>>>,
    required: Vec<Option<Box<[u32]>>>,
}

/// Builds one ASCII case-insensitive automaton over all native ASCII keywords.
///
/// Every rule's ASCII keyword maps to the pattern of its ASCII-lowercase
/// text, so one pass over a native input answers every rule's ASCII keyword
/// checks. Matching ignores only ASCII case, like the per-keyword search it
/// replaces; other bytes compare exactly. A native rule without keywords
/// also adds the literals of which every match of its expression contains
/// one, so a buffer without any of them can skip that expression.
fn build_native_keyword_matcher(config: &CompiledConfig) -> Result<NativeKeywordIndex, ScanError> {
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    let mut ids: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
    let mut intern = |folded: Vec<u8>| -> Result<u32, ScanError> {
        if let Some(id) = ids.get(&folded) {
            return Ok(*id);
        }
        let id = u32::try_from(patterns.len()).map_err(|_| ScanError::Prefilter {
            message: "too many native keywords".to_owned(),
        })?;
        ids.insert(folded.clone(), id);
        patterns.push(folded);
        Ok(id)
    };
    let mut keywords = Vec::with_capacity(config.rules.len());
    let mut required = Vec::with_capacity(config.rules.len());
    for rule in config.rules.values() {
        let Some(rule_keywords) = &rule.native_keywords else {
            keywords.push(None);
            // A Gitleaks-format pack rule without keywords runs its
            // expression on every pass, so it gains the same literal check.
            let literals = if rule.native_pack && rule.keywords.is_empty() {
                rule.regex_matcher
                    .as_ref()
                    .and_then(GoRegex::required_literals)
            } else {
                None
            };
            required.push(match literals {
                Some(literals) => Some(
                    literals
                        .iter()
                        .map(|literal| intern(literal.to_vec()))
                        .collect::<Result<Box<[u32]>, _>>()?,
                ),
                None => None,
            });
            continue;
        };
        let mut mapped = Vec::with_capacity(rule_keywords.len());
        for keyword in rule_keywords {
            mapped.push(match keyword {
                NativeKeyword::Ascii(text) => Some(intern(text.as_bytes().to_ascii_lowercase())?),
                NativeKeyword::Empty | NativeKeyword::UnicodeLower(_) => None,
            });
        }
        keywords.push(Some(mapped.into_boxed_slice()));
        let literals = if rule.native_pack && rule_keywords.is_empty() {
            rule.native_byte_matcher.as_ref().map_or_else(
                || {
                    rule.regex_matcher
                        .as_ref()
                        .and_then(GoRegex::required_literals)
                },
                NativeByteRegex::required_literals,
            )
        } else {
            None
        };
        required.push(match literals {
            Some(literals) => Some(
                literals
                    .iter()
                    .map(|literal| intern(literal.to_vec()))
                    .collect::<Result<Box<[u32]>, _>>()?,
            ),
            None => None,
        });
    }
    if patterns.is_empty() {
        return Ok(NativeKeywordIndex {
            matcher: None,
            keywords,
            required,
        });
    }
    let mut builder = AhoCorasickBuilder::new();
    builder
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard);
    if keyword_dfa_is_bounded(&patterns) {
        builder.kind(Some(AhoCorasickKind::DFA));
    }
    let matcher = builder
        .build(&patterns)
        .map_err(|error| ScanError::Prefilter {
            message: error.to_string(),
        })?;
    Ok(NativeKeywordIndex {
        matcher: Some(matcher),
        keywords,
        required,
    })
}

/// Returns whether a full keyword DFA has bounded size and build work.
fn keyword_dfa_is_bounded(keywords: &[impl AsRef<[u8]>]) -> bool {
    let mut bytes = 0_usize;
    let mut prefixes = 0_usize;
    for keyword in keywords {
        let length = keyword.as_ref().len();
        bytes = bytes.saturating_add(length);
        prefixes = prefixes.saturating_add(length.saturating_mul(length.saturating_add(1)) / 2);
    }
    bytes <= KEYWORD_DFA_BYTE_LIMIT && prefixes <= KEYWORD_DFA_PREFIX_LIMIT
}

/// Selects the longest literal-node candidate covered by the rule's keywords.
///
/// Every literal must be a keyword of this rule, so the keyword pass reports
/// each occurrence the anchored search depends on.
fn plan_literal_anchor(
    rule: &CompiledRule,
    keyword_ids: &BTreeMap<&str, usize>,
) -> Option<RuleLiteralAnchor> {
    let shape = rule.regex_matcher.as_ref()?.literal_anchor()?;
    shape
        .candidates()
        .iter()
        .enumerate()
        .rev()
        .find_map(|(candidate, choice)| {
            let mut keyword_indexes = Vec::with_capacity(choice.literals().len());
            for literal in choice.literals() {
                let literal = std::str::from_utf8(literal).ok()?;
                if !rule.keywords.iter().any(|keyword| keyword == literal) {
                    return None;
                }
                keyword_indexes.push(*keyword_ids.get(literal)?);
            }
            keyword_indexes.sort_unstable();
            keyword_indexes.dedup();
            Some(RuleLiteralAnchor {
                candidate,
                keyword_indexes: keyword_indexes.into_boxed_slice(),
            })
        })
}

/// Result of one stateless fragment scan.
///
/// Equality is structural: findings, measured usage, and termination must all
/// match. This prevents a partial scan from comparing equal to a complete scan
/// that happened to retain the same findings.
#[derive(Clone, PartialEq)]
pub struct ScanOutcome {
    findings: Vec<Finding>,
    usage: ScanUsage,
    termination: Option<ScanTermination>,
}

impl fmt::Debug for ScanOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanOutcome")
            .field("finding_count", &self.findings.len())
            .field("usage", &self.usage)
            .field("termination", &self.termination)
            .finish()
    }
}

impl ScanOutcome {
    fn complete(findings: Vec<Finding>, usage: ScanUsage) -> Self {
        Self {
            findings,
            usage,
            termination: None,
        }
    }

    fn partial(findings: Vec<Finding>, usage: ScanUsage, termination: ScanTermination) -> Self {
        Self {
            findings,
            usage,
            termination: Some(termination),
        }
    }

    /// Returns findings in deterministic rule/match order.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Returns aggregate resources consumed before completion or termination.
    #[must_use]
    pub const fn usage(&self) -> ScanUsage {
        self.usage
    }

    /// Returns why this scan stopped early, or `None` when it completed.
    #[must_use]
    pub const fn termination(&self) -> Option<&ScanTermination> {
        self.termination.as_ref()
    }

    /// Returns whether the complete fragment and final filtering were scanned.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.termination.is_none()
    }

    /// Consumes the outcome and returns its findings.
    ///
    /// This intentionally discards termination metadata. Callers of
    /// [`Engine::scan_fragment_controlled`] should check
    /// [`ScanOutcome::termination`] first.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

/// Error while constructing or running detector state.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScanError {
    /// The global keyword prefilter could not be constructed.
    Prefilter {
        /// Backend construction diagnostic.
        message: String,
    },
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prefilter { message } => write!(formatter, "keyword prefilter error: {message}"),
        }
    }
}

impl Error for ScanError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceLocation {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    start_line_index: usize,
    end_line_index: usize,
}

fn newline_indices(raw: &[u8]) -> Vec<usize> {
    let mut newlines = Vec::new();
    let (chunks, remainder) = raw.as_chunks::<8>();
    for (index, chunk) in chunks.iter().enumerate() {
        let compared = u64::from_ne_bytes(*chunk) ^ 0x0a0a_0a0a_0a0a_0a0a;
        if compared.wrapping_sub(0x0101_0101_0101_0101) & !compared & 0x8080_8080_8080_8080 == 0 {
            continue;
        }
        // The zero-byte test is endian-independent, but its individual bits
        // can include adjacent bytes due to borrowing. Check exact bytes.
        for (offset, byte) in chunk.iter().enumerate() {
            if *byte == b'\n' {
                newlines.push(index * 8 + offset);
            }
        }
    }
    let remainder_start = raw.len() - remainder.len();
    for (offset, byte) in remainder.iter().enumerate() {
        if *byte == b'\n' {
            newlines.push(remainder_start + offset);
        }
    }
    newlines
}

fn upstream_location(
    newlines: &[usize],
    raw: &[u8],
    start: usize,
    end: usize,
    tail: &Cell<Option<(usize, usize)>>,
) -> SourceLocation {
    let fallback;
    let newlines = if newlines.is_empty() {
        fallback = [raw.len()];
        &fallback[..]
    } else {
        newlines
    };
    let start_line = newlines.partition_point(|newline| *newline <= start);
    if start_line == newlines.len() {
        let previous = newlines[newlines.len() - 1];
        // Preserve the pinned helper's no-line-matched path, including the
        // zero start index and its special search for a trailing CR or LF.
        return SourceLocation {
            start_line,
            end_line: start_line,
            start_column: start - previous + 1,
            end_column: end - previous,
            start_line_index: 0,
            end_line_index: next_line_break(raw, end, tail),
        };
    }

    let previous = start_line.checked_sub(1).map_or(0, |line| newlines[line]);
    let mut location = SourceLocation {
        start_line,
        end_line: start_line,
        start_column: start - previous + 1,
        end_column: 0,
        start_line_index: previous,
        end_line_index: newlines[start_line],
    };
    let end_line = newlines.partition_point(|newline| *newline < end);
    if end > 0 && end_line < newlines.len() {
        let previous = end_line.checked_sub(1).map_or(0, |line| newlines[line]);
        location.end_column = end - previous;
        // For an empty match on a newline, Gitleaks sets the end column in
        // the previous iteration, then overwrites the end line and index when
        // it assigns the start. Keep that order.
        if end_line >= start_line {
            location.end_line = end_line;
            location.end_line_index = newlines[end_line];
        }
    }
    location.end_line_index = location.end_line_index.max(end);
    location
}

fn next_line_break(raw: &[u8], from: usize, cache: &Cell<Option<(usize, usize)>>) -> usize {
    if let Some((searched_from, next_break)) = cache.get()
        && searched_from <= from
        && from <= next_break
    {
        return next_break;
    }
    let next_break = raw[from..]
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\r'))
        .map_or(raw.len(), |distance| from + distance);
    // The interval is inclusive: starting at the break must return that break.
    // Earlier or later queries rescan, so reordered rules and decoded spans
    // cannot reuse a result from outside the covered original-source suffix.
    cache.set(Some((from, next_break)));
    next_break
}

fn trim_newlines(mut bytes: &[u8]) -> (usize, &[u8]) {
    let mut start = 0;
    while bytes.first() == Some(&b'\n') {
        bytes = &bytes[1..];
        start += 1;
    }
    while bytes.last() == Some(&b'\n') {
        bytes = &bytes[..bytes.len() - 1];
    }
    (start, bytes)
}

struct ExtractedSecret<'a> {
    bytes: &'a [u8],
    span: Option<ByteSpan>,
}

#[cfg(test)]
fn extract_secret<'a>(
    regex: &GoRegex,
    matched: &'a [u8],
    secret_group: i64,
    scratch: &mut Option<CaptureScratch>,
) -> Option<ExtractedSecret<'a>> {
    extract_secret_controlled(
        regex,
        matched,
        secret_group,
        scratch,
        &mut ScanContext::new(ScanControl::unlimited()),
    )
    .unwrap()
}

#[derive(Clone, Copy)]
enum NativeContentMatcher<'r, 'h> {
    Go(&'r GoRegex, &'r NormalizedHaystack<'h>),
    Bytes(&'r NativeByteRegex),
}

impl NativeContentMatcher<'_, '_> {
    fn capture_scratch(self) -> CaptureScratch {
        match self {
            Self::Go(regex, _) => regex.capture_scratch(),
            Self::Bytes(regex) => regex.capture_scratch(),
        }
    }

    fn find_all(
        self,
        bytes: &[u8],
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<ByteSpan>, ScanTermination> {
        match self {
            Self::Bytes(regex) => regex.find_all_controlled(bytes, || context.collected_spans(1)),
            Self::Go(regex, normalized) => {
                if context.control.budget.collected_spans.is_some() {
                    regex.find_all_normalized_controlled(normalized, || context.collected_spans(1))
                } else {
                    let spans = regex.find_all_normalized(normalized);
                    context.collected_spans(spans.len())?;
                    Ok(spans)
                }
            }
        }
    }

    fn captures_at<'s>(
        self,
        bytes: &[u8],
        whole: ByteSpan,
        scratch: &'s mut CaptureScratch,
    ) -> Option<&'s [Option<ByteSpan>]> {
        match self {
            Self::Go(regex, normalized) => regex.captures_at_normalized(normalized, whole, scratch),
            Self::Bytes(regex) => regex.captures_at(bytes, whole, scratch),
        }
    }
}

fn native_keyword_gate(
    rule: &CompiledRule,
    lookup: NativeKeywordLookup<'_>,
    bytes: &[u8],
    unicode_lower: &OnceCell<String>,
    context: &mut ScanContext<'_>,
) -> Result<bool, ScanTermination> {
    if let Some(keywords) = &rule.native_keywords {
        if keywords.is_empty() {
            return Ok(true);
        }
        for (position, keyword) in keywords.iter().enumerate() {
            context.work()?;
            let matched = match keyword {
                NativeKeyword::Empty => true,
                NativeKeyword::Ascii(keyword) => {
                    let shared = lookup
                        .patterns
                        .and_then(|patterns| patterns.get(position).copied().flatten());
                    if let (Some(matcher), Some(key), Some(pattern)) =
                        (lookup.matcher, lookup.input, shared)
                    {
                        context.native_keyword_hit(key, matcher, bytes, pattern, true)?
                    } else {
                        context.work_many(bytes.len())?;
                        contains_ascii_ignore_case(bytes, keyword.as_bytes())
                    }
                }
                NativeKeyword::UnicodeLower(keyword) => {
                    if unicode_lower.get().is_none() {
                        // Both lossy conversion and whole-string lowercase are
                        // input-sized transient work, charged before execution.
                        context.work_many(bytes.len())?;
                        context.work_many(bytes.len())?;
                        let _ = unicode_lower.set(String::from_utf8_lossy(bytes).to_lowercase());
                    }
                    let lowered = unicode_lower
                        .get()
                        .expect("native Unicode keyword input was folded");
                    context.work_many(lowered.len())?;
                    lowered.contains(keyword.as_str())
                }
            };
            if matched {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    // Native rules without a byte or buffer contract reach this fallback. It
    // uses the Gitleaks keyword gate and work accounting.
    if rule.keywords.is_empty() {
        return Ok(true);
    }
    context.work_many(bytes.len())?;
    let lowered = go_lowercase_bytes(bytes);
    let mut matched = false;
    for keyword in &rule.keywords {
        context.work()?;
        matched |= !keyword.is_empty() && contains_bytes(&lowered, keyword.as_bytes());
    }
    Ok(matched)
}

/// Returns whether `needle` occurs in `haystack`, ignoring ASCII case only.
fn contains_ascii_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn extract_native_secret<'a>(
    regex: NativeContentMatcher<'_, '_>,
    bytes: &'a [u8],
    whole: ByteSpan,
    secret_group: i64,
    scratch: &mut Option<CaptureScratch>,
) -> Option<ExtractedSecret<'a>> {
    let scratch = scratch.get_or_insert_with(|| regex.capture_scratch());
    let spans = regex.captures_at(bytes, whole, scratch)?;
    let span = if secret_group > 0 {
        spans
            .get(usize::try_from(secret_group).ok()?)
            .copied()
            .flatten()?
    } else {
        spans
            .iter()
            .skip(1)
            .flatten()
            .find(|span| span.start != span.end)
            .copied()
            .unwrap_or(whole)
    };
    Some(ExtractedSecret {
        bytes: bytes.get(span.start..span.end)?,
        span: Some(span),
    })
}

fn extract_secret_controlled<'a>(
    regex: &GoRegex,
    matched: &'a [u8],
    secret_group: i64,
    scratch: &mut Option<CaptureScratch>,
    context: &mut ScanContext<'_>,
) -> Result<Option<ExtractedSecret<'a>>, ScanTermination> {
    let whole_match = || ExtractedSecret {
        bytes: matched,
        span: Some(ByteSpan {
            start: 0,
            end: matched.len(),
        }),
    };
    // A search reports one span per entry in `capture_names`. With fewer than
    // two entries, a hit and a miss both produce the whole slice and neither
    // reads `secret_group`, so the search result cannot be observed.
    if regex.capture_names().len() < 2 {
        return Ok(Some(whole_match()));
    }
    let scratch = scratch.get_or_insert_with(|| regex.capture_scratch());
    let normalized = context.normalize(matched)?;
    let Some(spans) = regex.captures_into_normalized(&normalized, scratch) else {
        // Trimming leading/trailing newlines can make an anchored full-match
        // expression stop matching. Go leaves the already-trimmed secret
        // unchanged when FindStringSubmatch consequently returns nil.
        return Ok(Some(whole_match()));
    };
    Ok((|| {
        if secret_group > 0 {
            let index = usize::try_from(secret_group).ok()?;
            let span = spans.get(index)?;
            return match span {
                Some(span) => Some(ExtractedSecret {
                    bytes: matched.get(span.start..span.end)?,
                    span: Some(*span),
                }),
                // FindStringSubmatch represents a nonparticipating group as an
                // empty string, which is observably different from an invalid
                // group index (the latter suppresses the finding).
                None => Some(ExtractedSecret {
                    bytes: matched.get(..0)?,
                    span: None,
                }),
            };
        }
        let span = spans
            .iter()
            .skip(1)
            .flatten()
            .find(|span| span.start != span.end)
            .copied()
            .unwrap_or(ByteSpan {
                start: 0,
                end: matched.len(),
            });
        Some(ExtractedSecret {
            bytes: matched.get(span.start..span.end)?,
            span: Some(span),
        })
    })())
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let inverse_length = 1.0 / usize_to_f64(bytes.len());
    let add_symbol = |entropy: f64, count: usize| {
        let frequency = usize_to_f64(count) * inverse_length;
        entropy - frequency * frequency.log2()
    };
    if bytes.is_ascii() {
        // Each byte is its own symbol. Nonzero counters in index order are the
        // same counts, in the same ascending symbol order, as the map below.
        let mut counts = [0_usize; 128];
        for &byte in bytes {
            counts[usize::from(byte)] += 1;
        }
        return counts
            .into_iter()
            .filter(|count| *count != 0)
            .fold(0.0, add_symbol);
    }
    let mut counts = BTreeMap::<char, usize>::new();
    for character in go_chars(bytes) {
        *counts.entry(character).or_default() += 1;
    }
    counts.into_values().fold(0.0, add_symbol)
}

#[allow(clippy::cast_precision_loss)]
fn usize_to_f64(value: usize) -> f64 {
    value as f64
}

#[allow(clippy::cast_possible_truncation)]
fn entropy_to_f32(value: f64) -> f32 {
    value as f32
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn finding_base_payload<'a>(
    fragment: &'a Fragment,
    rule: &'a CompiledRule,
) -> impl Iterator<Item = usize> + 'a {
    [
        rule.id.len(),
        rule.description.len(),
        fragment.file_path().as_bytes().len(),
        fragment.symlink_file().as_bytes().len(),
        fragment.commit().as_bytes().len(),
    ]
    .into_iter()
    .chain(rule.tags.iter().map(String::len))
    .chain(fragment.commit_metadata().into_iter().flat_map(|metadata| {
        [
            metadata.author_name().as_bytes().len(),
            metadata.author_email().as_bytes().len(),
            metadata.date().as_bytes().len(),
            metadata.message().as_bytes().len(),
        ]
    }))
}

fn path_finding(fragment: &Fragment, rule: &CompiledRule) -> Option<Finding> {
    let mut matched = b"file detected: ".to_vec();
    matched.extend_from_slice(fragment.file_path().as_bytes());
    let mut builder = Finding::builder()
        .rule_id(rule.id.as_str())
        .description(rule.description.as_str())
        .location(Location::from_upstream(0, 0, 0, 0))
        .match_text(matched)
        .file(fragment.file_path().as_bytes())
        .symlink_file(fragment.symlink_file().as_bytes())
        .commit(fragment.commit().as_bytes())
        .tags(rule.tags.iter().map(String::as_str));
    if let Some(metadata) = fragment.commit_metadata() {
        builder = builder
            .author(metadata.author_name().as_bytes())
            .email(metadata.author_email().as_bytes())
            .date(metadata.date().as_bytes())
            .message(metadata.message().as_bytes());
    }
    builder.build().ok()
}

#[cfg(test)]
mod literal_anchor_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod native_keyword_budget_tests {
    use super::*;
    use crate::config::ConfigLoader;

    #[test]
    fn every_keyword_search_and_unicode_fold_is_admitted_before_execution() {
        let config = ConfigLoader::new()
            .load_toml("[[rules]]\nid='probe'\nregex='X'\n")
            .unwrap();
        let mut rule = config.rule("probe").unwrap().clone();
        let bytes = b"abc\xe2\x82";
        let lower = OnceCell::new();
        rule.native_keywords = Some(vec![
            NativeKeyword::Ascii("none".to_owned()),
            NativeKeyword::Ascii("absent".to_owned()),
        ]);
        let mut context = ScanContext::new(ScanControl::unlimited());
        assert!(
            !native_keyword_gate(
                &rule,
                NativeKeywordLookup::UNSHARED,
                bytes,
                &lower,
                &mut context
            )
            .unwrap()
        );
        assert_eq!(context.usage.work_units(), 2 * (bytes.len() + 1));
        assert!(lower.get().is_none());
        rule.native_keywords = Some(vec![NativeKeyword::UnicodeLower("ø".to_owned())]);
        let mut context = ScanContext::new(
            ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_work_units(2 * bytes.len())),
        );
        assert!(
            native_keyword_gate(
                &rule,
                NativeKeywordLookup::UNSHARED,
                bytes,
                &lower,
                &mut context
            )
            .is_err()
        );
        assert!(lower.get().is_none());
        let mut context = ScanContext::new(ScanControl::unlimited());
        assert!(
            !native_keyword_gate(
                &rule,
                NativeKeywordLookup::UNSHARED,
                bytes,
                &lower,
                &mut context
            )
            .unwrap()
        );
        // One lossy replacement for the incomplete two-byte suffix gives six
        // folded UTF-8 bytes. A later rule shares only this owning input's fold.
        assert_eq!(lower.get().unwrap(), "abc�");
        assert_eq!(context.usage.work_units(), 1 + 2 * bytes.len() + 6);
        assert!(
            !native_keyword_gate(
                &rule,
                NativeKeywordLookup::UNSHARED,
                bytes,
                &lower,
                &mut context
            )
            .unwrap()
        );
        assert_eq!(context.usage.work_units(), 2 + 2 * bytes.len() + 12);
        assert_eq!(context.usage.normalization_bytes(), 0);
    }

    #[test]
    fn shared_native_keyword_pass_matches_each_keyword_search() {
        let keywords = ["abc", "bcd", "ab", "key_", "x", "longer-than-input", "k"];
        let mut builder = AhoCorasickBuilder::new();
        builder
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard);
        let matcher = builder.build(keywords).unwrap();
        let inputs: [&[u8]; 8] = [
            b"",
            b"ABCD",
            b"aBc",
            b"zzKEY_zz",
            // The Kelvin sign is not an ASCII k, and invalid UTF-8 stays raw.
            "\u{212a}EY_".as_bytes(),
            b"\xff\xfeab\xc3",
            b"xbcdab",
            b"no hits here",
        ];
        for (pass, bytes) in inputs.iter().enumerate() {
            let mut context = ScanContext::new(ScanControl::unlimited());
            let key = NativeHitKey {
                input: NativeInputId {
                    pass,
                    segment: None,
                },
                address: bytes.as_ptr() as usize,
                length: bytes.len(),
            };
            for (pattern, keyword) in keywords.iter().enumerate() {
                let shared = context
                    .native_keyword_hit(key, &matcher, bytes, u32::try_from(pattern).unwrap(), true)
                    .unwrap();
                assert_eq!(
                    shared,
                    contains_ascii_ignore_case(bytes, keyword.as_bytes()),
                    "{keyword} in {bytes:?}"
                );
            }
            // A keyword check charges the whole input once.
            assert_eq!(context.usage.work_units(), bytes.len());
        }
    }
}
