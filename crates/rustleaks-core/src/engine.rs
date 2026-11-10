//! Immutable raw-fragment detection engine.

use std::borrow::Cow;
use std::cell::{Cell, OnceCell};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::config::{
    CompiledAllowlist, CompiledConfig, CompiledRule, Condition, RegexTarget, RequiredRuleSpec,
};
use crate::decoder::{
    Decoder, EncodedSegment, adjust_match_index, current_line, segments_with_decoded_overlap,
    tags as decoder_tags,
};
use crate::explanation::{
    ExplanationCollector, ExplanationLog, ExplanationOptions, ExplanationReason,
};
use crate::go_unicode::{chars as go_chars, lowercase_bytes as go_lowercase_bytes};
use crate::model::{
    ByteRange, Finding, FindingRange, Fragment, Location, RequiredFinding, ScanOptions,
};
use crate::regex::{ByteSpan, CaptureScratch, GoRegex, NormalizedHaystack};

const ALLOW_SIGNATURE: &[u8] = b"gitleaks:allow";
const RUSTLEAKS_ALLOW_SIGNATURE: &[u8] = b"rustleaks:allow";

/// A synchronous, runtime-independent cancellation signal for one scan.
///
/// The engine polls this signal between bounded units of owned work. A regular
/// expression search, eager enumeration of all matches for one rule, and one
/// individual encoding transform are indivisible. Candidate checkpoints run
/// after the complete rule match list has been collected; decoder candidate
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
/// specifications, and required-to-primary proximity comparisons. An admitted
/// `finding_record` is a primary finding, an auxiliary finding candidate, or a
/// projected required finding. These units are defensive resource controls,
/// not stable performance measurements.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanBudget {
    decoded_bytes: Option<usize>,
    work_units: Option<usize>,
    finding_records: Option<usize>,
}

impl ScanBudget {
    /// Returns an unlimited budget.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            decoded_bytes: None,
            work_units: None,
            finding_records: None,
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
}

/// Original-source helpers live for one fragment, including its decoded passes.
#[derive(Default)]
struct OriginalFragmentContext {
    newlines: OnceCell<Vec<usize>>,
    marker: Cell<Option<(usize, usize, bool)>>,
    tail: Cell<Option<(usize, usize)>>,
}

impl OriginalFragmentContext {
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
}

struct ScanContext<'a> {
    control: ScanControl<'a>,
    usage: ScanUsage,
    explanations: ExplanationCollector,
}

impl<'a> ScanContext<'a> {
    fn new(control: ScanControl<'a>) -> Self {
        Self {
            control,
            usage: ScanUsage {
                decoded_bytes: 0,
                work_units: 0,
                finding_records: 0,
            },
            explanations: ExplanationCollector::new(ExplanationOptions::disabled(), false),
        }
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

    fn decoded_bytes(&mut self, amount: usize) -> Result<(), ScanTermination> {
        self.check_cancelled()?;
        charge_counter(
            &mut self.usage.decoded_bytes,
            amount,
            self.control.budget.decoded_bytes,
            ScanBudgetKind::DecodedBytes,
        )
    }

    fn finding_record(&mut self) -> Result<(), ScanTermination> {
        self.check_cancelled()?;
        charge_counter(
            &mut self.usage.finding_records,
            1,
            self.control.budget.finding_records,
            ScanBudgetKind::FindingRecords,
        )
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
    /// loops. Regex searches and eager enumeration of all matches for one rule,
    /// one individual encoding transform, finding construction, and redaction
    /// of one finding are indivisible.
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
        if commit_or_path_allowed(fragment, &self.config.allowlists) {
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
        let mut decoder = Decoder::new();
        let mut decode_depth = 0;
        let mut matched_keywords = vec![false; self.keyword_count];
        loop {
            if let Err(termination) = context.work() {
                return finish_partial(findings, options, context.usage, termination);
            }
            matched_keywords.fill(false);
            if let Some(prefilter) = &self.prefilter {
                let normalized = go_lowercase_bytes(&current_raw);
                for found in prefilter.find_overlapping_iter(&normalized) {
                    if let Err(termination) = context.work() {
                        return finish_partial(findings, options, context.usage, termination);
                    }
                    matched_keywords[found.pattern().as_usize()] = true;
                }
            }

            {
                let regex_haystack = OnceCell::new();
                for ((rule_ordinal, rule), keyword_indexes) in self
                    .config
                    .rules
                    .values()
                    .enumerate()
                    .zip(&self.rule_keyword_indexes)
                {
                    context.explanations.record(
                        Some(rule_ordinal),
                        decode_depth,
                        None,
                        ExplanationReason::RuleSelected,
                    );
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
                        },
                        context,
                    );
                    match detected {
                        Ok(detected) => findings.extend(detected),
                        Err(termination) => {
                            return finish_partial(findings, options, context.usage, termination);
                        }
                    }
                }
            } // Drop the normalized pass before replacing decoded content.
            decode_depth += 1;
            if decode_depth > options.max_decode_depth() {
                break;
            }
            if let Err(termination) = context.work() {
                return finish_partial(findings, options, context.usage, termination);
            }
            let decode_result =
                decoder.decode_controlled(&current_raw, &encoded_segments, || context.work());
            let (decoded_output, segments) = match decode_result {
                Ok(output) => output,
                Err(termination) => {
                    return finish_partial(findings, options, context.usage, termination);
                }
            };
            if let Err(termination) = context.check_cancelled() {
                return finish_partial(findings, options, context.usage, termination);
            }
            if segments.is_empty() {
                break;
            }
            if let Err(termination) = context.decoded_bytes(decoded_output.len()) {
                return finish_partial(findings, options, context.usage, termination);
            }
            current_raw = Cow::Owned(decoded_output);
            encoded_segments = segments;
        }
        finish_complete(findings, options, context)
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
        if commit_or_path_allowed(fragment, &rule.allowlists) {
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
            let path_matches = path.is_match(fragment.file_path().as_bytes())
                || (!fragment.windows_file_path().is_empty()
                    && path.is_match(fragment.windows_file_path().as_bytes()));
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
                let finding = (rule_pass.encoded_segments.is_empty() && path_matches)
                    .then(|| path_finding(fragment, rule))
                    .flatten()
                    .into_iter()
                    .collect::<Vec<_>>();
                if !finding.is_empty() {
                    context.finding_record()?;
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
        for (candidate_ordinal, span) in regex
            .find_all_normalized(
                rule_pass
                    .normalized
                    .get_or_init(|| NormalizedHaystack::new(rule_pass.current_raw)),
            )
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
                context,
            ) {
                context.finding_record()?;
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
                        context.finding_record()?;
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
        context: &mut ScanContext<'_>,
    ) -> Option<Finding> {
        let mut explain = |reason| {
            context.explanations.record(
                Some(pass.rule_ordinal),
                pass.decoded_pass,
                Some(pass.candidate_ordinal),
                reason,
            );
        };
        let original_raw = fragment.content().as_bytes();
        let matched = pass.current_raw.get(whole.start..whole.end)?;
        let (trimmed_offset, trimmed) = trim_newlines(matched);
        let direct_match_start = whole.start.checked_add(trimmed_offset)?;
        let direct_match_end = direct_match_start.checked_add(trimmed.len())?;
        let (adjusted_start, adjusted_end, decoded_line, meta_tags) =
            if pass.encoded_segments.is_empty() {
                (
                    whole.start,
                    whole.start.checked_add(trimmed.len())?,
                    None,
                    Vec::new(),
                )
            } else {
                let overlapping =
                    segments_with_decoded_overlap(pass.encoded_segments, whole.start, whole.end);
                if overlapping.is_empty() {
                    explain(ExplanationReason::DecodedMappingUnavailable);
                    return None;
                }
                let (start, end) = adjust_match_index(&overlapping, whole.start, whole.end)?;
                (
                    start,
                    end,
                    Some(current_line(&overlapping, pass.current_raw)),
                    decoder_tags(&overlapping),
                )
            };
        // Decoded passes project back onto the original fragment. Keep this
        // index scan-local and construct it only when a candidate needs it.
        let newlines = pass.original.newlines.get_or_init(|| {
            original_raw
                .iter()
                .enumerate()
                .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
                .collect()
        });
        let source = upstream_location(
            newlines,
            original_raw,
            adjusted_start,
            adjusted_end,
            &pass.original.tail,
        );
        let line = original_raw.get(source.start_line_index..source.end_line_index)?;
        if options.honor_allow_markers()
            && pass
                .original
                .has_allow_marker(line, source.start_line_index, source.end_line_index)
        {
            explain(ExplanationReason::AllowMarkerMatched);
            return None;
        }

        let Some(extracted_secret) = extract_secret(
            rule.regex_matcher.as_ref()?,
            trimmed,
            rule.secret_group,
            capture_scratch,
        ) else {
            explain(ExplanationReason::SecretGroupUnavailable);
            return None;
        };
        let secret = extracted_secret.bytes;
        // Only a nonzero threshold reads entropy before finding construction.
        let threshold_entropy = (rule.entropy != 0.0).then(|| shannon_entropy(secret));
        if threshold_entropy.is_some_and(|entropy| entropy <= rule.entropy) {
            explain(ExplanationReason::EntropyRejected);
            return None;
        }
        explain(if rule.entropy == 0.0 {
            ExplanationReason::EntropyNotRequired
        } else {
            ExplanationReason::EntropyAccepted
        });
        let allowlist_line = decoded_line.filter(|line| !line.is_empty()).unwrap_or(line);
        if finding_allowed(
            fragment,
            trimmed,
            secret,
            allowlist_line,
            &self.config.allowlists,
            &mut line_allowlists.global,
        ) || finding_allowed(
            fragment,
            trimmed,
            secret,
            allowlist_line,
            &rule.allowlists,
            &mut line_allowlists.rule,
        ) {
            explain(ExplanationReason::AllowlistMatched);
            return None;
        }
        explain(ExplanationReason::AllowlistNotMatched);
        explain(ExplanationReason::CandidateAccepted);
        if context.explanations.github_classic && context.explanations.begin_annotation() {
            let isolated = extracted_secret.span.is_some_and(|span| {
                let start = direct_match_start.checked_add(span.start);
                let end = direct_match_start.checked_add(span.end);
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
        let mut finding_tags = rule.tags.clone();
        finding_tags.extend(meta_tags);
        let (match_range, secret_range) = if pass.encoded_segments.is_empty() {
            let match_range =
                FindingRange::Exact(ByteRange::new(direct_match_start, direct_match_end).ok()?);
            let secret_range = match extracted_secret.span {
                Some(span) => {
                    let start = direct_match_start.checked_add(span.start)?;
                    let end = direct_match_start.checked_add(span.end)?;
                    FindingRange::Exact(ByteRange::new(start, end).ok()?)
                }
                None => FindingRange::Unavailable,
            };
            (match_range, secret_range)
        } else {
            (FindingRange::Unavailable, FindingRange::Unavailable)
        };
        let mut builder = Finding::builder()
            .rule_id(rule.id.as_str())
            .description(rule.description.as_str())
            .location(location)
            .match_range(match_range)
            .secret_range(secret_range)
            .line(line)
            .match_text(trimmed)
            .secret(secret)
            .file(fragment.file_path().as_bytes())
            .symlink_file(fragment.symlink_file().as_bytes())
            .commit(fragment.commit().as_bytes())
            .entropy(entropy_to_f32(
                threshold_entropy.unwrap_or_else(|| shannon_entropy(secret)),
            ))
            .tags(finding_tags.iter().map(String::as_str));
        if let Some(metadata) = fragment.commit_metadata() {
            builder = builder
                .author(metadata.author_name().as_bytes())
                .email(metadata.author_email().as_bytes())
                .date(metadata.date().as_bytes())
                .message(metadata.message().as_bytes());
        }
        builder.build().ok()
    }
}

/// `rule.keywords` decides whether a gate exists. `indexes` omits keywords with
/// no prefilter pattern, so a rule with only empty keywords remains closed.
fn keyword_gate_open(rule: &CompiledRule, indexes: &[usize], matched_keywords: &[bool]) -> bool {
    rule.keywords.is_empty() || indexes.iter().any(|&index| matched_keywords[index])
}

fn commit_or_path_allowed(fragment: &Fragment, allowlists: &[CompiledAllowlist]) -> bool {
    // This preserves the pinned Windows-only guard: the original Windows path
    // is not enough to enter the early helper when file and commit are empty.
    if fragment.file_path().is_empty() && fragment.commit().is_empty() {
        return false;
    }
    allowlists.iter().any(|allowlist| {
        let commit = allowlist.commit_allowed(fragment.commit().as_bytes());
        let path = allowlist.path_allowed(fragment.file_path().as_bytes())
            || (!fragment.windows_file_path().is_empty()
                && allowlist.path_allowed(fragment.windows_file_path().as_bytes()));
        match allowlist.condition {
            Condition::Or => commit || path,
            Condition::And => {
                if !allowlist.regexes.is_empty() || !allowlist.stop_words.is_empty() {
                    return false;
                }
                (!allowlist.commits.is_empty())
                    .then_some(commit)
                    .into_iter()
                    .chain((!allowlist.paths.is_empty()).then_some(path))
                    .all(|check| check)
            }
            Condition::Unknown(_) => false,
        }
    })
}

fn finding_allowed<'a>(
    fragment: &Fragment,
    full_match: &[u8],
    secret: &[u8],
    current_line: &'a [u8],
    allowlists: &'a [CompiledAllowlist],
    line_cache: &mut Vec<Option<LineRegexResult<'a>>>,
) -> bool {
    allowlists.iter().enumerate().any(|(index, allowlist)| {
        let regex = match allowlist.regex_target {
            RegexTarget::Secret | RegexTarget::Unknown(_) => allowlist.regex_allowed(secret),
            RegexTarget::Match => allowlist.regex_allowed(full_match),
            RegexTarget::Line => {
                line_regex_allowed(allowlist, current_line, index, allowlists.len(), line_cache)
            }
        };
        let stopword = allowlist.contains_stop_word(secret);
        match allowlist.condition {
            Condition::Or => regex || stopword,
            Condition::And => {
                let commit = allowlist.commit_allowed(fragment.commit().as_bytes());
                let path = allowlist.path_allowed(fragment.file_path().as_bytes())
                    || (!fragment.windows_file_path().is_empty()
                        && allowlist.path_allowed(fragment.windows_file_path().as_bytes()));
                (!allowlist.commits.is_empty())
                    .then_some(commit)
                    .into_iter()
                    .chain((!allowlist.paths.is_empty()).then_some(path))
                    .chain((!allowlist.regexes.is_empty()).then_some(regex))
                    .chain((!allowlist.stop_words.is_empty()).then_some(stopword))
                    .all(|check| check)
            }
            Condition::Unknown(_) => false,
        }
    })
}

fn line_regex_allowed<'a>(
    allowlist: &'a CompiledAllowlist,
    line: &'a [u8],
    index: usize,
    slots: usize,
    cache: &mut Vec<Option<LineRegexResult<'a>>>,
) -> bool {
    if line.is_empty() || allowlist.regex_matcher.is_none() {
        return false;
    }
    if cache.is_empty() {
        cache.resize(slots, None);
    }
    let slot = &mut cache[index];
    if let Some(previous) = slot
        && std::ptr::eq(previous.allowlist, allowlist)
        && std::ptr::eq(previous.line, line)
    {
        return previous.matched;
    }
    // Preserve this exact slice as the regex haystack, including its anchors
    // and invalid-byte normalization. No secret-dependent predicate is cached.
    let matched = allowlist.regex_allowed(line);
    *slot = Some(LineRegexResult {
        allowlist,
        line,
        matched,
    });
    matched
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
    options: &ScanOptions,
    usage: ScanUsage,
    termination: ScanTermination,
) -> ScanOutcome {
    // Completed rules are finalized even when the signal remains set. This is
    // the atomic cleanup needed to avoid exposing unsuppressed/unredacted raw
    // candidates as partial findings. `max_finding_records` bounds this phase
    // when callers require a hard cardinality ceiling.
    ScanOutcome::partial(
        filter_findings(findings, options.redaction_percent()),
        usage,
        termination,
    )
}

fn finish_complete(
    findings: Vec<Finding>,
    options: &ScanOptions,
    context: &ScanContext<'_>,
) -> ScanOutcome {
    let (findings, termination) =
        filter_findings_cancellable(findings, options.redaction_percent(), context.control);
    match termination {
        Some(termination) => ScanOutcome::partial(findings, context.usage, termination),
        None => ScanOutcome::complete(findings, context.usage),
    }
}

fn filter_findings_cancellable(
    findings: Vec<Finding>,
    redact: usize,
    control: ScanControl<'_>,
) -> (Vec<Finding>, Option<ScanTermination>) {
    let suppression = GenericSuppression::new(&findings);
    let mut include = Vec::with_capacity(findings.len());
    for index in 0..findings.len() {
        if control.is_cancelled() {
            return (
                apply_finding_filter(findings, include, redact),
                Some(ScanTermination::Cancelled),
            );
        }
        if !suppression.is_generic(index) {
            include.push(true);
            continue;
        }
        let suppressor = suppression.first_suppressor(index);
        // A caller's signal can count its polls. Keep one poll per finding that
        // the linear comparison visits, through the first suppressor.
        if control.cancellation.is_some() {
            let visited = suppressor.map_or(findings.len(), |other| other + 1);
            for _ in 0..visited {
                if control.is_cancelled() {
                    return (
                        apply_finding_filter(findings, include, redact),
                        Some(ScanTermination::Cancelled),
                    );
                }
            }
        }
        include.push(suppressor.is_none());
    }
    (apply_finding_filter(findings, include, redact), None)
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
        let mut generic = Vec::with_capacity(findings.len());
        // Findings arrive grouped by rule; the flag depends only on the ID bytes.
        let mut previous = None;
        for finding in findings {
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
                if !generic[index] {
                    specific_by_line_and_commit
                        .entry((finding.location().start_line(), finding.commit().as_bytes()))
                        .or_default()
                        .push(index);
                }
            }
        }
        Self {
            findings,
            generic,
            specific_by_line_and_commit,
        }
    }

    fn is_generic(&self, index: usize) -> bool {
        self.generic[index]
    }

    /// Returns the lowest list index that suppresses the generic finding.
    fn first_suppressor(&self, index: usize) -> Option<usize> {
        let finding = &self.findings[index];
        self.specific_by_line_and_commit
            .get(&(finding.location().start_line(), finding.commit().as_bytes()))?
            .iter()
            .copied()
            .find(|&candidate| {
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

fn filter_findings(findings: Vec<Finding>, redact: usize) -> Vec<Finding> {
    let suppression = GenericSuppression::new(&findings);
    let include = (0..findings.len())
        .map(|index| {
            !suppression.is_generic(index) || suppression.first_suppressor(index).is_none()
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
        let prefilter = if keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .build(&keywords)
                    .map_err(|error| ScanError::Prefilter {
                        message: error.to_string(),
                    })?,
            )
        };
        Ok(Engine {
            config: self.config,
            prefilter,
            keyword_count,
            rule_keyword_indexes,
        })
    }
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
        // For an empty match on a newline, the old loop set the end column
        // on the preceding iteration, then overwrote its end line and index
        // when assigning the start. Preserve that assignment order exactly.
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

fn extract_secret<'a>(
    regex: &GoRegex,
    matched: &'a [u8],
    secret_group: i64,
    scratch: &mut Option<CaptureScratch>,
) -> Option<ExtractedSecret<'a>> {
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
        return Some(whole_match());
    }
    let scratch = scratch.get_or_insert_with(|| regex.capture_scratch());
    let Some(spans) = regex.captures_into(matched, scratch) else {
        // Trimming leading/trailing newlines can make an anchored full-match
        // expression stop matching. Go leaves the already-trimmed secret
        // unchanged when FindStringSubmatch consequently returns nil.
        return Some(whole_match());
    };
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
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    use base64::Engine as _;
    use serde_json::Value;

    use super::*;
    use crate::config::ConfigLoader;

    fn engine(config: &str) -> Engine {
        Engine::builder(ConfigLoader::new().load_toml(config).unwrap())
            .build()
            .unwrap()
    }

    fn upstream_location(
        newlines: &[usize],
        raw: &[u8],
        start: usize,
        end: usize,
    ) -> SourceLocation {
        super::upstream_location(newlines, raw, start, end, &Cell::new(None))
    }

    // Frozen capture-first extraction, retained only as differential evidence.
    // The explicit table below states the expected results independently.
    fn frozen_extract_secret<'a>(
        regex: &GoRegex,
        matched: &'a [u8],
        secret_group: i64,
    ) -> Option<ExtractedSecret<'a>> {
        let Some(captures) = regex.captures(matched) else {
            return Some(ExtractedSecret {
                bytes: matched,
                span: Some(ByteSpan {
                    start: 0,
                    end: matched.len(),
                }),
            });
        };
        if captures.spans().len() < 2 {
            return Some(ExtractedSecret {
                bytes: matched,
                span: Some(ByteSpan {
                    start: 0,
                    end: matched.len(),
                }),
            });
        }
        if secret_group > 0 {
            let index = usize::try_from(secret_group).ok()?;
            let span = captures.spans().get(index)?;
            return match span {
                Some(span) => Some(ExtractedSecret {
                    bytes: matched.get(span.start..span.end)?,
                    span: Some(*span),
                }),
                None => Some(ExtractedSecret {
                    bytes: matched.get(..0)?,
                    span: None,
                }),
            };
        }
        let span = captures
            .spans()
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
    }

    type ExtractedView<'a> = Option<(&'a [u8], Option<(usize, usize)>)>;

    fn extracted_view(extracted: Option<ExtractedSecret<'_>>) -> ExtractedView<'_> {
        extracted.map(|secret| (secret.bytes, secret.span.map(|span| (span.start, span.end))))
    }

    #[test]
    fn extract_secret_preserves_every_group_and_search_branch() {
        const WHOLE_ABC: ExtractedView<'static> = Some((b"abc", Some((0, 3))));
        const INNER_B: ExtractedView<'static> = Some((b"b", Some((1, 2))));
        let cases: &[(&str, &[u8], i64, ExtractedView<'static>)] = &[
            // Without a group, a hit and a miss both yield the whole slice and
            // no secret-group value is consulted.
            ("abc", b"abc", 0, WHOLE_ABC),
            ("abc", b"abc", 1, WHOLE_ABC),
            ("abc", b"abc", 99, WHOLE_ABC),
            ("abc", b"abc", -1, WHOLE_ABC),
            ("^zzz$", b"abc", 0, WHOLE_ABC),
            ("^zzz$", b"abc", 1, WHOLE_ABC),
            ("(?:a)(?:b)c", b"abc", 1, WHOLE_ABC),
            (".", b"\xff\xfe", 0, Some((b"\xff\xfe", Some((0, 2))))),
            ("", b"", 0, Some((b"", Some((0, 0))))),
            ("^x$", b"", 3, Some((b"", Some((0, 0))))),
            // A group makes the search and every secret-group branch reachable.
            ("a(b)c", b"abc", 0, INNER_B),
            ("a(b)c", b"abc", 1, INNER_B),
            ("a(b)c", b"abc", -1, INNER_B),
            ("a(b)c", b"abc", 2, None),
            // A failed search returns before the secret group is validated.
            ("^(a)$", b"abc", 0, WHOLE_ABC),
            ("^(a)$", b"abc", 7, WHOLE_ABC),
            // Nonparticipating groups are empty without a span.
            ("a(b)?c", b"ac", 1, Some((b"", None))),
            ("a(b)?c", b"ac", 0, Some((b"ac", Some((0, 2))))),
            // Empty participating groups keep their span, and are skipped by
            // the first-nonempty fallback.
            ("a()c", b"ac", 1, Some((b"", Some((1, 1))))),
            ("a()c", b"ac", 0, Some((b"ac", Some((0, 2))))),
            ("(x?)(y)", b"y", 1, Some((b"", Some((0, 0))))),
            ("(x?)(y)", b"y", 0, Some((b"y", Some((0, 1))))),
            ("(x?)(y)", b"y", 2, Some((b"y", Some((0, 1))))),
            // Offsets are reported in the original source bytes.
            ("(.)x", b"\xffx", 1, Some((b"\xff", Some((0, 1))))),
            ("(.)x", b"\xc3\xa9x", 1, Some((b"\xc3\xa9", Some((0, 2))))),
        ];
        // A scratch is reused only by repeated searches of one expression.
        let regexes = cases
            .iter()
            .map(|(pattern, ..)| (*pattern, GoRegex::compile(pattern).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let mut scratches = BTreeMap::<&str, Option<CaptureScratch>>::new();
        for &(pattern, matched, secret_group, expected) in cases.iter().chain(cases.iter().rev()) {
            let regex = &regexes[pattern];
            let label = format!("{pattern} on {matched:?}, group {secret_group}");
            assert_eq!(
                extracted_view(frozen_extract_secret(regex, matched, secret_group)),
                expected,
                "frozen {label}",
            );
            assert_eq!(
                extracted_view(extract_secret(regex, matched, secret_group, &mut None)),
                expected,
                "fresh {label}",
            );
            let shared = scratches.entry(pattern).or_default();
            for attempt in ["first", "repeated"] {
                assert_eq!(
                    extracted_view(extract_secret(regex, matched, secret_group, shared)),
                    expected,
                    "{attempt} shared {label}",
                );
            }
        }
    }

    #[test]
    fn groupless_extraction_does_not_allocate_capture_scratch() {
        let groupless = GoRegex::compile("(?:a)bc").unwrap();
        let mut scratch = None;
        assert!(extract_secret(&groupless, b"abc", 1, &mut scratch).is_some());
        assert!(scratch.is_none());
        let grouped = GoRegex::compile("a(b)c").unwrap();
        assert!(extract_secret(&grouped, b"abc", 1, &mut scratch).is_some());
        assert!(scratch.is_some());
    }

    #[test]
    fn candidates_in_one_rule_pass_do_not_share_capture_results() {
        let detector = engine(
            r#"
[[rules]]
id = "probe"
regex = "(a)|(b)"
secretGroup = 2
"#,
        );
        let outcome = detector.scan_fragment(&Fragment::new(b"a b a"), &ScanOptions::default());
        assert!(outcome.is_complete());
        let observed = outcome
            .findings()
            .iter()
            .map(|finding| {
                (
                    finding.match_text().as_bytes(),
                    finding.secret().as_bytes(),
                    finding.secret_range(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            [
                (b"a".as_slice(), b"".as_slice(), FindingRange::Unavailable),
                (
                    b"b".as_slice(),
                    b"b".as_slice(),
                    FindingRange::Exact(ByteRange::new(2, 3).unwrap()),
                ),
                (b"a".as_slice(), b"".as_slice(), FindingRange::Unavailable),
            ]
        );
    }

    #[test]
    fn groupless_rules_keep_trimmed_whole_match_secrets_and_ranges() {
        let detector = engine(
            r"
[[rules]]
id = 'probe'
regex = '''(?s)\A\nZX9\n\z'''
",
        );
        let outcome = detector.scan_fragment(&Fragment::new(b"\nZX9\n"), &ScanOptions::default());
        assert!(outcome.is_complete());
        let [finding] = outcome.findings() else {
            panic!("expected one finding, got {}", outcome.findings().len());
        };
        // The search over the trimmed slice misses; the secret stays trimmed.
        assert_eq!(finding.secret().as_bytes(), b"ZX9");
        assert_eq!(
            finding.secret_range(),
            FindingRange::Exact(ByteRange::new(1, 4).unwrap())
        );
        assert_eq!(
            finding.match_range(),
            FindingRange::Exact(ByteRange::new(1, 4).unwrap())
        );
    }

    // Frozen per-rule map lookup, retained only as differential evidence.
    fn frozen_keyword_gate_open(
        rule: &CompiledRule,
        keyword_ids: &BTreeMap<String, usize>,
        matched_keywords: &[bool],
    ) -> bool {
        rule.keywords.is_empty()
            || rule.keywords.iter().any(|keyword| {
                keyword_ids
                    .get(keyword)
                    .is_some_and(|index| matched_keywords[*index])
            })
    }

    fn prefilter_keyword_ids(config: &CompiledConfig) -> BTreeMap<String, usize> {
        config
            .keywords
            .iter()
            .filter(|keyword| !keyword.is_empty())
            .cloned()
            .enumerate()
            .map(|(index, keyword)| (keyword, index))
            .collect()
    }

    #[test]
    fn keyword_indexes_match_the_frozen_lookup_for_every_matched_subset() {
        let detector = engine(
            r#"
[[rules]]
id = "a-two"
regex = "A"
keywords = ["Alpha", "beta"]
[[rules]]
id = "b-repeated"
regex = "B"
keywords = ["beta", "beta"]
[[rules]]
id = "c-none"
regex = "C"
[[rules]]
id = "d-empty"
regex = "D"
keywords = [""]
[[rules]]
id = "e-empty-and-real"
regex = "E"
keywords = ["", "gamma"]
[[rules]]
id = "f-go-lowercase"
regex = "F"
keywords = ["\U0000212Aey", "\U00000130x"]
"#,
        );
        let keyword_ids = prefilter_keyword_ids(&detector.config);
        assert_eq!(
            keyword_ids.keys().map(String::as_str).collect::<Vec<_>>(),
            ["alpha", "beta", "gamma", "ix", "key"]
        );
        assert_eq!(detector.keyword_count, keyword_ids.len());
        assert_eq!(
            detector.rule_keyword_indexes.len(),
            detector.config.rules.len()
        );
        for mask in 0_u32..(1 << keyword_ids.len()) {
            let matched = (0..keyword_ids.len())
                .map(|index| mask & (1 << index) != 0)
                .collect::<Vec<_>>();
            for (rule, indexes) in detector
                .config
                .rules
                .values()
                .zip(&detector.rule_keyword_indexes)
            {
                assert_eq!(
                    keyword_gate_open(rule, indexes, &matched),
                    frozen_keyword_gate_open(rule, &keyword_ids, &matched),
                    "rule {}, mask {mask:b}",
                    rule.id,
                );
            }
        }
        // Stated independently of both implementations.
        let rules = &detector.config.rules;
        let indexes = |id: &str| {
            let ordinal = rules.keys().position(|rule| rule == id).unwrap();
            &*detector.rule_keyword_indexes[ordinal]
        };
        assert_eq!(indexes("a-two"), [0, 1]);
        assert_eq!(indexes("b-repeated"), [1, 1]);
        assert!(indexes("c-none").is_empty());
        assert!(indexes("d-empty").is_empty());
        assert_eq!(indexes("e-empty-and-real"), [2]);
        assert_eq!(indexes("f-go-lowercase"), [4, 3]);
        let none = [false; 5];
        assert!(keyword_gate_open(
            &rules["c-none"],
            indexes("c-none"),
            &none
        ));
        assert!(!keyword_gate_open(
            &rules["d-empty"],
            indexes("d-empty"),
            &[true; 5]
        ));
    }

    #[test]
    fn default_rule_keyword_indexes_match_the_frozen_lookup() {
        let detector = Engine::builder(ConfigLoader::new().load_default().unwrap())
            .build()
            .unwrap();
        let keyword_ids = prefilter_keyword_ids(&detector.config);
        assert_eq!(detector.keyword_count, keyword_ids.len());
        assert_eq!(
            detector.rule_keyword_indexes.len(),
            detector.config.rules.len()
        );
        for (rule, indexes) in detector
            .config
            .rules
            .values()
            .zip(&detector.rule_keyword_indexes)
        {
            let expected = rule
                .keywords
                .iter()
                .filter_map(|keyword| keyword_ids.get(keyword).copied())
                .collect::<Vec<_>>();
            assert_eq!(&**indexes, expected.as_slice(), "rule {}", rule.id);
        }
    }

    fn explained_keyword_events(
        detector: &Engine,
        fragment: &Fragment,
        options: &ScanOptions,
    ) -> (ScanOutcome, Vec<(Option<usize>, usize, ExplanationReason)>) {
        let (outcome, log) = detector.scan_fragment_explained(
            fragment,
            options,
            &ScanControl::unlimited(),
            ExplanationOptions::bounded(ExplanationOptions::MAX_RECORDS),
            false,
        );
        assert!(!log.is_truncated());
        let events = log
            .events()
            .iter()
            .filter(|event| {
                matches!(
                    event.reason(),
                    ExplanationReason::RuleSelected
                        | ExplanationReason::KeywordMatched
                        | ExplanationReason::KeywordMissed
                        | ExplanationReason::KeywordNotRequired
                )
            })
            .map(|event| (event.rule_ordinal(), event.decoded_pass(), event.reason()))
            .collect();
        (outcome, events)
    }

    #[test]
    fn keyword_gate_explanations_and_work_units_are_pinned() {
        use ExplanationReason::{KeywordMatched, KeywordMissed, KeywordNotRequired, RuleSelected};

        let detector = engine(
            r#"
[[rules]]
id = "a-two"
regex = "TOK"
keywords = ["alpha", "beta"]
[[rules]]
id = "b-one"
regex = "TOK"
keywords = ["beta"]
[[rules]]
id = "c-none"
regex = "TOK"
[[rules]]
id = "d-empty"
regex = "TOK"
keywords = [""]
[[rules]]
id = "e-miss"
regex = "TOK"
keywords = ["gamma"]
"#,
        );
        let (outcome, events) = explained_keyword_events(
            &detector,
            &Fragment::new(b"beta TOK"),
            &ScanOptions::default(),
        );
        assert!(outcome.is_complete());
        assert_eq!(
            events,
            [
                (Some(0), 0, RuleSelected),
                (Some(0), 0, KeywordMatched),
                (Some(1), 0, RuleSelected),
                (Some(1), 0, KeywordMatched),
                (Some(2), 0, RuleSelected),
                (Some(2), 0, KeywordNotRequired),
                (Some(3), 0, RuleSelected),
                (Some(3), 0, KeywordMissed),
                (Some(4), 0, RuleSelected),
                (Some(4), 0, KeywordMissed),
            ]
        );
        assert_eq!(
            outcome
                .findings()
                .iter()
                .map(|finding| finding.rule_id().as_bytes())
                .collect::<Vec<_>>(),
            [
                b"a-two".as_slice(),
                b"b-one".as_slice(),
                b"c-none".as_slice()
            ]
        );
        // One pass start, one emitted keyword, three admitted rules, and one
        // content match for each admitted rule.
        assert_eq!(outcome.usage().work_units(), 1 + 1 + 3 + 3);
    }

    #[test]
    fn keyword_flags_from_one_pass_do_not_admit_a_later_decoded_pass() {
        use ExplanationReason::{KeywordMatched, KeywordMissed, KeywordNotRequired, RuleSelected};

        // The keyword exists only in the encoded spelling, so it is absent from
        // the decoded pass where the rule's expression would otherwise match.
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello world, hello");
        assert!(encoded.to_ascii_lowercase().contains("agvsbg8g"));
        let detector = engine(
            r#"
[[rules]]
id = "control"
regex = "hello"
[[rules]]
id = "encoded-keyword"
regex = "hello"
keywords = ["agvsbg8g"]
"#,
        );
        let options = ScanOptions::builder().max_decode_depth(1).build();
        let (outcome, events) =
            explained_keyword_events(&detector, &Fragment::new(encoded.as_bytes()), &options);
        assert!(outcome.is_complete());
        assert_eq!(
            events,
            [
                (Some(0), 0, RuleSelected),
                (Some(0), 0, KeywordNotRequired),
                (Some(1), 0, RuleSelected),
                (Some(1), 0, KeywordMatched),
                (Some(0), 1, RuleSelected),
                (Some(0), 1, KeywordNotRequired),
                (Some(1), 1, RuleSelected),
                (Some(1), 1, KeywordMissed),
            ]
        );
        assert_eq!(outcome.findings().len(), 2);
        for finding in outcome.findings() {
            assert_eq!(finding.rule_id().as_bytes(), b"control");
        }
    }

    // Frozen ordered-map computation, retained only as differential evidence.
    fn frozen_shannon_entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = BTreeMap::<char, usize>::new();
        for character in go_chars(bytes) {
            *counts.entry(character).or_default() += 1;
        }
        let inverse_length = 1.0 / usize_to_f64(bytes.len());
        counts.values().fold(0.0, |entropy, count| {
            let frequency = usize_to_f64(*count) * inverse_length;
            entropy - frequency * frequency.log2()
        })
    }

    /// The defining sum over counts given in ascending symbol order.
    fn entropy_of_ordered_counts(counts: &[usize], byte_length: usize) -> f64 {
        let inverse_length = 1.0 / usize_to_f64(byte_length);
        counts.iter().fold(0.0, |entropy, count| {
            let frequency = usize_to_f64(*count) * inverse_length;
            entropy - frequency * frequency.log2()
        })
    }

    #[test]
    fn entropy_values_are_specified_by_exact_bits() {
        for (input, expected_bits) in [
            // Empty, and every single-symbol input, has zero entropy.
            (b"".as_slice(), 0_u64),
            (b"a".as_slice(), 0),
            (b"aaaa".as_slice(), 0),
            (b"\x00".as_slice(), 0),
            (b"\x7f\x7f".as_slice(), 0),
            // Equal frequencies with exact powers of two.
            (b"ab".as_slice(), 1.0_f64.to_bits()),
            (b"abcd".as_slice(), 2.0_f64.to_bits()),
            (b"\x00\x7f".as_slice(), 1.0_f64.to_bits()),
            // Non-ASCII input divides by byte length, not symbol count.
            ("\u{e9}".as_bytes(), 0.5_f64.to_bits()),
            // Each invalid byte is one replacement symbol.
            (b"\xff\xfe".as_slice(), 0),
            (b"\xffa".as_slice(), 1.0_f64.to_bits()),
        ] {
            let actual = shannon_entropy(input);
            assert_eq!(actual.to_bits(), expected_bits, "{input:?}");
            assert_eq!(frozen_shannon_entropy(input).to_bits(), expected_bits);
        }
        let every_ascii = (0_u8..128).collect::<Vec<_>>();
        assert_eq!(
            shannon_entropy(&every_ascii).to_bits(),
            7.0_f64.to_bits(),
            "all 128 ASCII symbols with equal frequency",
        );
    }

    #[test]
    fn ascii_entropy_sums_counts_in_ascending_symbol_order() {
        // The input lists the most frequent symbol first. These counts make
        // the sum depend on its order, so the expected bits take the counts
        // in ascending symbol order, independent of how the input is arranged.
        let counts = [1, 3, 5_usize];
        let mut input = Vec::new();
        for (symbol, count) in (b'a'..=b'c').zip(&counts).rev() {
            input.extend(std::iter::repeat_n(symbol, *count));
        }
        let expected = entropy_of_ordered_counts(&counts, input.len());
        assert_eq!(shannon_entropy(&input).to_bits(), expected.to_bits());
        assert_eq!(frozen_shannon_entropy(&input).to_bits(), expected.to_bits());
    }

    #[test]
    fn entropy_histogram_is_bit_identical_to_the_frozen_map() {
        let check = |input: &[u8]| {
            assert_eq!(
                shannon_entropy(input).to_bits(),
                frozen_shannon_entropy(input).to_bits(),
                "{input:?}",
            );
        };
        check(b"");
        for first in 0_u8..=255 {
            check(&[first]);
            for second in 0_u8..=255 {
                check(&[first, second]);
            }
        }
        for prefix in [b"".as_slice(), "\u{212a}".as_bytes(), "\u{130}".as_bytes()] {
            for tail in [b"".as_slice(), b"a", b"\xff", b"\xe2\x82"] {
                let mut input = prefix.to_vec();
                input.extend_from_slice(tail);
                check(&input);
            }
        }
        // Deterministic ASCII inputs over several alphabet and length sizes.
        let mut state = 0x9e37_79b9_u32;
        for alphabet in [1_u32, 2, 8, 64, 128] {
            for length in [1_usize, 2, 7, 31, 32, 33, 128, 1024] {
                for _ in 0..4 {
                    let input = (0..length)
                        .map(|_| {
                            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                            u8::try_from((state >> 8) % alphabet).unwrap()
                        })
                        .collect::<Vec<_>>();
                    check(&input);
                }
            }
        }
    }

    #[test]
    fn deferred_entropy_keeps_decisions_explanations_and_finding_values() {
        use ExplanationReason::{
            AllowlistMatched, AllowlistNotMatched, CandidateAccepted, EntropyAccepted,
            EntropyNotRequired, EntropyRejected, KeywordNotRequired, PatternMatched, RuleSelected,
        };

        let detector = engine(
            r#"
[[rules]]
id = "threshold"
regex = "x(ab)x|y(abc)y"
entropy = 1.0
[[rules]]
id = "zero"
regex = "abcd"
[[rules]]
id = "zero-allowed"
regex = "abcd"
[[rules.allowlists]]
stopwords = ["abcd"]
"#,
        );
        let (outcome, log) = detector.scan_fragment_explained(
            &Fragment::new(b"xabx yabcy abcd"),
            &ScanOptions::default(),
            &ScanControl::unlimited(),
            ExplanationOptions::bounded(ExplanationOptions::MAX_RECORDS),
            false,
        );
        assert!(outcome.is_complete());
        let reasons = |ordinal: usize| {
            log.events()
                .iter()
                .filter(|event| event.rule_ordinal() == Some(ordinal))
                .map(|event| event.reason())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            reasons(0),
            [
                RuleSelected,
                KeywordNotRequired,
                AllowlistNotMatched,
                PatternMatched,
                EntropyRejected,
                PatternMatched,
                EntropyAccepted,
                AllowlistNotMatched,
                CandidateAccepted,
            ]
        );
        assert_eq!(
            reasons(1),
            [
                RuleSelected,
                KeywordNotRequired,
                AllowlistNotMatched,
                PatternMatched,
                EntropyNotRequired,
                AllowlistNotMatched,
                CandidateAccepted,
            ]
        );
        assert_eq!(
            reasons(2),
            [
                RuleSelected,
                KeywordNotRequired,
                AllowlistNotMatched,
                PatternMatched,
                EntropyNotRequired,
                AllowlistMatched,
            ]
        );

        let findings = outcome
            .findings()
            .iter()
            .map(|finding| {
                (
                    finding.rule_id().as_bytes().to_vec(),
                    finding.secret().as_bytes().to_vec(),
                    finding.entropy().to_bits(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            findings,
            [
                (
                    b"threshold".to_vec(),
                    b"abc".to_vec(),
                    entropy_to_f32(frozen_shannon_entropy(b"abc")).to_bits(),
                ),
                (b"zero".to_vec(), b"abcd".to_vec(), 2.0_f32.to_bits()),
            ]
        );
    }

    #[test]
    fn canonical_entropy_is_one_proven_go_admissible_value() {
        let mut bytes = Vec::new();
        for (index, byte) in (b'a'..=b'j').enumerate() {
            bytes.extend(std::iter::repeat_n(byte, index + 1));
        }
        let entropy = shannon_entropy(&bytes);
        assert_eq!(entropy.to_bits(), 0x4008_d443_070e_ac15);
        assert_eq!(entropy_to_f32(entropy).to_bits(), 0x4046_a218);
        assert!(entropy <= f64::from_bits(0x4008_d443_070e_ac15));
    }

    #[test]
    fn upstream_location_matches_pinned_helper_assertions() {
        let raw = vec![b'x'; 57];
        let first = upstream_location(&[0, 40, 56], &raw, 35, 38);
        assert_eq!(
            (
                first.start_line,
                first.start_column,
                first.end_line,
                first.end_column,
                first.start_line_index,
                first.end_line_index,
            ),
            (1, 36, 1, 38, 0, 40)
        );
        let second = upstream_location(&[0, 40, 56], &raw, 40, 44);
        assert_eq!(
            (
                second.start_line,
                second.start_column,
                second.end_line,
                second.end_column,
                second.start_line_index,
                second.end_line_index,
            ),
            (2, 1, 2, 4, 40, 56)
        );
    }

    #[test]
    fn upstream_location_preserves_newline_and_empty_span_edges() {
        let raw = b"a\nbc\nd\r";
        for (start, end, expected) in [
            (0, 0, (0, 0, 1, 0, 0, 1)),
            (0, 1, (0, 0, 1, 1, 0, 1)),
            (1, 1, (1, 1, 1, 1, 1, 4)),
            (1, 4, (1, 1, 1, 3, 1, 4)),
            (4, 4, (2, 2, 1, 0, 0, 4)),
            (4, 5, (2, 2, 1, 1, 0, 6)),
            (5, 6, (2, 2, 2, 2, 0, 6)),
            (0, 6, (0, 0, 1, 0, 0, 6)),
        ] {
            let location = upstream_location(&[1, 4], raw, start, end);
            assert_eq!(
                (
                    location.start_line,
                    location.end_line,
                    location.start_column,
                    location.end_column,
                    location.start_line_index,
                    location.end_line_index
                ),
                expected,
                "span {start}..{end}",
            );
        }
        assert_eq!(
            upstream_location(&[], b"", 0, 0),
            SourceLocation {
                start_line: 1,
                end_line: 1,
                start_column: 1,
                end_column: 0,
                start_line_index: 0,
                end_line_index: 0,
            }
        );
        assert_eq!(
            upstream_location(&[], b"ab", 0, 0),
            SourceLocation {
                start_line: 0,
                end_line: 0,
                start_column: 1,
                end_column: 0,
                start_line_index: 0,
                end_line_index: 2,
            }
        );
        assert_eq!(
            upstream_location(&[], b"ab", 2, 2),
            SourceLocation {
                start_line: 1,
                end_line: 1,
                start_column: 1,
                end_column: 0,
                start_line_index: 0,
                end_line_index: 2,
            }
        );
    }

    #[test]
    fn indexed_location_matches_the_previous_loop_for_all_small_spans() {
        for length in 0..=8 {
            for mask in 0..(1 << length) {
                let raw = (0..length)
                    .map(|index| {
                        if mask & (1 << index) == 0 {
                            b'x'
                        } else {
                            b'\n'
                        }
                    })
                    .collect::<Vec<_>>();
                let newlines = raw
                    .iter()
                    .enumerate()
                    .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
                    .collect::<Vec<_>>();
                for start in 0..=length {
                    for end in start..=length {
                        assert_eq!(
                            upstream_location(&newlines, &raw, start, end),
                            linear_upstream_location(&newlines, &raw, start, end),
                            "length {length}, newline mask {mask}, span {start}..{end}"
                        );
                    }
                }
            }
        }
    }

    // Frozen previous helper used only as differential evidence. The explicit
    // edge cases above specify expected results independently of this loop.
    fn linear_upstream_location(
        newlines: &[usize],
        raw: &[u8],
        start: usize,
        end: usize,
    ) -> SourceLocation {
        let fallback;
        let newlines = if newlines.is_empty() {
            fallback = [raw.len()];
            &fallback[..]
        } else {
            newlines
        };
        let mut previous = 0;
        let mut location = SourceLocation {
            start_line: 0,
            end_line: 0,
            start_column: 0,
            end_column: 0,
            start_line_index: 0,
            end_line_index: 0,
        };
        let mut line_set = false;
        let mut last_line = 0;
        for (line_number, &newline) in newlines.iter().enumerate() {
            last_line = line_number;
            if previous <= start && start < newline {
                line_set = true;
                location.start_line = line_number;
                location.end_line = line_number;
                location.start_column = start - previous + 1;
                location.start_line_index = previous;
                location.end_line_index = newline;
            }
            if previous < end && end <= newline {
                location.end_line = line_number;
                location.end_column = end - previous;
                location.end_line_index = newline;
            }
            previous = newline;
        }
        if !line_set {
            location.start_column = start - previous + 1;
            location.end_column = end - previous;
            location.start_line = last_line + 1;
            location.end_line = last_line + 1;
            location.end_line_index = raw[end..]
                .iter()
                .position(|byte| matches!(byte, b'\n' | b'\r'))
                .map_or(raw.len(), |distance| end + distance);
        }
        if end > location.end_line_index {
            location.end_line_index = end;
        }
        location
    }

    #[test]
    fn cached_marker_results_use_exact_original_source_bounds() {
        let context = OriginalFragmentContext::default();
        let raw = b"Xrustleaks:allowY\nZgitleaks:allowQ\r\n\xff";
        for (start, end, expected) in [(1, 16, true), (1, 15, false), (2, 16, false), (0, 0, false)]
        {
            assert_eq!(
                context.has_allow_marker(&raw[start..end], start, end),
                expected
            );
        }
        for start in (0..=raw.len()).rev() {
            for end in start..=raw.len() {
                let line = &raw[start..end];
                let expected = contains_bytes(line, RUSTLEAKS_ALLOW_SIGNATURE)
                    || contains_bytes(line, ALLOW_SIGNATURE);
                assert_eq!(context.has_allow_marker(line, start, end), expected);
                assert_eq!(context.has_allow_marker(line, start, end), expected);
            }
        }
    }

    #[test]
    fn tail_search_reuses_only_its_inclusive_covered_interval() {
        let raw = b"\nAB\rCD\rEF";
        let cache = Cell::new(None);
        for (from, expected, interval) in [
            (1, 3, (1, 3)),
            (2, 3, (1, 3)),
            (3, 3, (1, 3)),
            (4, 6, (4, 6)),
            (6, 6, (4, 6)),
            (7, 9, (7, 9)),
            (9, 9, (7, 9)),
            (2, 3, (2, 3)),
            (0, 0, (0, 0)),
            (5, 6, (5, 6)),
        ] {
            assert_eq!(next_line_break(raw, from, &cache), expected);
            assert_eq!(cache.get(), Some(interval));
        }
    }

    #[test]
    fn cached_locations_match_pinned_loop_for_reordered_crlf_and_empty_spans() {
        for raw in [b"".as_slice(), b"abc\rdef", b"\nAB\rCD\rEF", b"a\r\nb\nc\r"] {
            let newlines = raw
                .iter()
                .enumerate()
                .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
                .collect::<Vec<_>>();
            let spans = (0..=raw.len())
                .flat_map(|start| (start..=raw.len()).map(move |end| (start, end)))
                .collect::<Vec<_>>();
            let cache = Cell::new(None);
            for &(start, end) in spans.iter().chain(spans.iter().rev()) {
                assert_eq!(
                    super::upstream_location(&newlines, raw, start, end, &cache),
                    linear_upstream_location(&newlines, raw, start, end),
                    "raw {raw:?}, span {start}..{end}",
                );
            }
        }
    }

    #[test]
    fn marker_cache_retains_pinned_prefix_and_disabled_option_behavior() {
        let detector = engine("[[rules]]\nid = 'probe'\nregex = 'ZX9'\n");
        let disabled = ScanOptions::builder().honor_allow_markers(false).build();
        for (raw, suppressed_count, offsets) in [
            (b"ZX9 rustleaks:allow ZX9".as_slice(), 0, vec![0, 20]),
            (b"rustleaks:allow\nZX9".as_slice(), 0, vec![16]),
            (b"rustleaks:allow\nZX9\n".as_slice(), 1, vec![16]),
        ] {
            let fragment = Fragment::new(raw);
            let honored = detector.scan_fragment(&fragment, &ScanOptions::default());
            assert!(honored.is_complete());
            assert_eq!(honored.findings().len(), suppressed_count);
            assert_eq!(honored.usage().finding_records(), suppressed_count);
            assert_eq!(honored.usage().work_units(), offsets.len() + 2);
            let ignored = detector.scan_fragment(&fragment, &disabled);
            assert!(ignored.is_complete());
            assert_eq!(ignored.usage().work_units(), offsets.len() + 2);
            assert_eq!(ignored.usage().finding_records(), offsets.len());
            for (finding, start) in ignored.findings().iter().zip(offsets) {
                assert_eq!(
                    finding.match_range().exact().unwrap().as_range(),
                    start..start + 3
                );
            }
        }
    }

    #[test]
    fn line_regex_memo_preserves_slice_length_invalid_bytes_and_multiline_anchors() {
        let detector = engine(
            r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[allowlists]]
regexTarget = "line"
regexes = ['''^\x{FFFD}x$''', '''(?s)^A\nB\r\n$''']
"#,
        );
        let allowlist = &detector.config.allowlists[0];
        let malformed = b"\xffxx";
        let multiline = b"A\nB\r\n";
        let mut cache = Vec::new();
        for (line, expected) in [
            (&malformed[..2], true),
            (&malformed[..], false),
            (&multiline[..], true),
            (&multiline[..4], false),
            (&malformed[..2], true),
            (b"\xffx".as_slice(), true),
        ] {
            assert_eq!(
                line_regex_allowed(allowlist, line, 0, 1, &mut cache),
                expected
            );
            assert_eq!(allowlist.regex_allowed(line), expected);
            assert!(std::ptr::eq(cache[0].unwrap().line, line));
        }
        let mut empty = Vec::new();
        assert!(!line_regex_allowed(allowlist, b"", 0, 1, &mut empty));
        assert!(empty.is_empty());
    }

    #[test]
    fn line_regex_memo_keeps_global_and_rule_predicates_and_conditions_separate() {
        let detector = engine(
            r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[rules.allowlists]]
condition = "AND"
regexTarget = "line"
regexes = ['''RULE$''']
stopwords = ["accepted"]
commits = ["abc"]
paths = ['''^ok$''']
[[allowlists]]
condition = "OR"
regexTarget = "line"
regexes = ['''GLOBAL$''']
stopwords = ["override"]
"#,
        );
        let global = &detector.config.allowlists;
        let rule = &detector.config.rules["probe"].allowlists;
        let good = Fragment::builder(b"").file_path("ok").commit("ABC").build();
        let bad_path = Fragment::builder(b"")
            .file_path("other")
            .commit("ABC")
            .build();
        let bad_commit = Fragment::builder(b"")
            .file_path("ok")
            .commit("other")
            .build();
        let mut memo = LineAllowlistMemo::default();
        for (fragment, secret, line, expected) in [
            (
                &good,
                b"accepted".as_slice(),
                b"RULE".as_slice(),
                (false, true),
            ),
            (
                &good,
                b"other".as_slice(),
                b"RULE".as_slice(),
                (false, false),
            ),
            (
                &bad_path,
                b"accepted".as_slice(),
                b"RULE".as_slice(),
                (false, false),
            ),
            (
                &bad_commit,
                b"accepted".as_slice(),
                b"RULE".as_slice(),
                (false, false),
            ),
            (
                &good,
                b"override".as_slice(),
                b"RULE".as_slice(),
                (true, false),
            ),
            (
                &good,
                b"other".as_slice(),
                b"GLOBAL".as_slice(),
                (true, false),
            ),
            (
                &good,
                b"other".as_slice(),
                b"none".as_slice(),
                (false, false),
            ),
            (
                &good,
                b"accepted".as_slice(),
                b"RULE".as_slice(),
                (false, true),
            ),
        ] {
            let global_result =
                finding_allowed(fragment, b"ZX9", secret, line, global, &mut memo.global);
            let rule_result = finding_allowed(fragment, b"ZX9", secret, line, rule, &mut memo.rule);
            assert_eq!((global_result, rule_result), expected);
            assert_eq!(
                global_result,
                uncached_finding_allowed(fragment, b"ZX9", secret, line, global)
            );
            assert_eq!(
                rule_result,
                uncached_finding_allowed(fragment, b"ZX9", secret, line, rule)
            );
        }
        assert_eq!(memo.global.len(), 1);
        assert_eq!(memo.rule.len(), 1);
        assert!(!std::ptr::eq(
            memo.global[0].unwrap().allowlist,
            memo.rule[0].unwrap().allowlist
        ));
    }

    #[test]
    fn non_line_allowlists_do_not_allocate_line_memo_slots() {
        let detector = engine(
            r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[allowlists]]
regexTarget = "match"
regexes = ['''ZX9''']
"#,
        );
        let mut cache = Vec::new();
        assert!(finding_allowed(
            &Fragment::new(b""),
            b"ZX9",
            b"ZX9",
            b"line",
            &detector.config.allowlists,
            &mut cache,
        ));
        assert!(cache.is_empty());
    }

    #[test]
    fn decoded_line_memo_uses_decoded_slices_and_does_not_escape_a_scan() {
        let config = r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[allowlists]]
regexTarget = "line"
regexes = ['''^ZX9(?: ZX9){3}$''']
"#;
        let detector = engine(config);
        let decoded = b"ZX9 ZX9 ZX9 ZX9";
        let encoded = base64::engine::general_purpose::STANDARD.encode(decoded);
        let fragment = Fragment::new(encoded.as_bytes());
        let options = ScanOptions::builder().max_decode_depth(1).build();
        let suppressed = detector.scan_fragment(&fragment, &options);
        assert!(suppressed.is_complete());
        assert!(suppressed.findings().is_empty());
        assert_eq!(suppressed.usage().finding_records(), 0);
        assert_eq!(suppressed.usage().decoded_bytes(), decoded.len());
        let negative = engine(&config.replace("^ZX9(?: ZX9){3}$", "^ABSENT$"));
        let visible = negative.scan_fragment(&fragment, &options);
        assert!(visible.is_complete());
        assert_eq!(visible.findings().len(), 4);
        assert_eq!(visible.usage().finding_records(), 4);
        for finding in visible.findings() {
            assert_eq!(finding.match_text().as_bytes(), b"ZX9");
            assert_eq!(finding.secret().as_bytes(), b"ZX9");
            assert_eq!(finding.match_range(), FindingRange::Unavailable);
            assert_eq!(finding.secret_range(), FindingRange::Unavailable);
        }
        let next = detector.scan_fragment(&Fragment::new(b"ZX9"), &ScanOptions::default());
        assert!(next.is_complete());
        assert_eq!(next.findings().len(), 1);
    }

    // Frozen uncached predicate used only for comparison with the local memo.
    fn uncached_finding_allowed(
        fragment: &Fragment,
        full_match: &[u8],
        secret: &[u8],
        current_line: &[u8],
        allowlists: &[CompiledAllowlist],
    ) -> bool {
        allowlists.iter().any(|allowlist| {
            let target = match allowlist.regex_target {
                RegexTarget::Secret | RegexTarget::Unknown(_) => secret,
                RegexTarget::Match => full_match,
                RegexTarget::Line => current_line,
            };
            let regex = allowlist.regex_allowed(target);
            let stopword = allowlist.contains_stop_word(secret);
            match allowlist.condition {
                Condition::Or => regex || stopword,
                Condition::And => {
                    let commit = allowlist.commit_allowed(fragment.commit().as_bytes());
                    let path = allowlist.path_allowed(fragment.file_path().as_bytes())
                        || (!fragment.windows_file_path().is_empty()
                            && allowlist.path_allowed(fragment.windows_file_path().as_bytes()));
                    (!allowlist.commits.is_empty())
                        .then_some(commit)
                        .into_iter()
                        .chain((!allowlist.paths.is_empty()).then_some(path))
                        .chain((!allowlist.regexes.is_empty()).then_some(regex))
                        .chain((!allowlist.stop_words.is_empty()).then_some(stopword))
                        .all(|check| check)
                }
                Condition::Unknown(_) => false,
            }
        })
    }

    #[test]
    fn joined_allowlist_flags_and_stopword_match_geometry_match_go() {
        let config = ConfigLoader::new()
            .load_toml(
                r#"
[[rules]]
id = "probe"
regex = '''.+'''

[[allowlists]]
paths = ['''(?i)foo''', '''BAR''']
regexes = ['''(?i)foo''', '''BAR''']
stopwords = ["he", "she", "FaKe", "ÉCOLE", "�"]
"#,
            )
            .unwrap();
        let allowlist = &config.allowlists[0];
        assert!(allowlist.path_allowed(b"bar"));
        assert!(allowlist.regex_allowed(b"bar"));
        assert_eq!(allowlist.matched_stop_word(b"she"), Some(b"she".to_vec()));
        assert_eq!(
            allowlist.matched_stop_word(b"prefix FAKE suffix"),
            Some(b"fake".to_vec())
        );
        assert_eq!(
            allowlist.matched_stop_word("prefix ÉCOLE suffix".as_bytes()),
            Some("école".as_bytes().to_vec())
        );
        assert_eq!(
            allowlist.matched_stop_word(b"\xff"),
            Some("�".as_bytes().to_vec())
        );
        assert_eq!(allowlist.matched_stop_word(b"real"), None);

        let empty = ConfigLoader::new()
            .load_toml(
                r#"
[[rules]]
id = "probe"
regex = '''.+'''

[[allowlists]]
stopwords = [""]
"#,
            )
            .unwrap();
        assert_eq!(empty.allowlists[0].matched_stop_word(b"nonempty"), None);
    }

    #[test]
    fn allowlist_phases_path_only_bypass_and_windows_guard_are_explicit() {
        let path_only = engine(
            r#"
[[rules]]
id = "path-only"
path = '''secret\.txt$'''

[[rules.allowlists]]
regexes = ['''.*''']
"#,
        );
        assert_eq!(
            path_only
                .scan_fragment(
                    &Fragment::builder(b"ignored".to_vec())
                        .file_path("secret.txt")
                        .build(),
                    &ScanOptions::default(),
                )
                .findings()
                .len(),
            1
        );

        let path_and_stopword = engine(
            r#"
[[rules]]
id = "path-only"
path = '''secret\.txt$'''

[[rules.allowlists]]
condition = "AND"
paths = ['''secret\.txt$''']
stopwords = ["ignored"]
"#,
        );
        assert_eq!(
            path_and_stopword
                .scan_fragment(
                    &Fragment::builder(b"ignored".to_vec())
                        .file_path("secret.txt")
                        .build(),
                    &ScanOptions::default(),
                )
                .findings()
                .len(),
            1
        );

        let path_early = engine(
            r#"
[[rules]]
id = "path-only"
path = '''secret\.txt$'''

[[rules.allowlists]]
condition = "AND"
paths = ['''secret\.txt$''']
"#,
        );
        assert!(
            path_early
                .scan_fragment(
                    &Fragment::builder(b"ignored".to_vec())
                        .file_path("secret.txt")
                        .build(),
                    &ScanOptions::default(),
                )
                .findings()
                .is_empty()
        );

        let windows_guard = engine(
            r#"
[[rules]]
id = "content"
regex = '''TOKEN'''

[[allowlists]]
paths = ['''C:\\secret\.txt$''']
"#,
        );
        let windows_only = Fragment::builder(b"TOKEN".to_vec())
            .windows_file_path(r"C:\secret.txt")
            .build();
        assert_eq!(
            windows_guard
                .scan_fragment(&windows_only, &ScanOptions::default())
                .findings()
                .len(),
            1
        );
        let dual = Fragment::builder(b"TOKEN".to_vec())
            .file_path("secret.txt")
            .windows_file_path(r"C:\secret.txt")
            .build();
        assert!(
            windows_guard
                .scan_fragment(&dual, &ScanOptions::default())
                .findings()
                .is_empty()
        );
    }

    #[test]
    fn generic_filter_ignores_file_columns_and_end_geometry() {
        let generic = Finding::builder()
            .rule_id("preGeNeRiCpost")
            .location(Location::new(7, 7, 90, 99).unwrap())
            .file("generic.txt")
            .commit("same")
            .match_text("abc")
            .secret("abc")
            .build()
            .unwrap();
        let specific = Finding::builder()
            .rule_id("specific")
            .location(Location::new(7, 8, 1, 1).unwrap())
            .file("specific.txt")
            .commit("same")
            .match_text("xxabcxx")
            .secret("xxabcxx")
            .build()
            .unwrap();

        let filtered = filter_findings(vec![generic, specific], 100);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id().as_bytes(), b"specific");
        assert_eq!(filtered[0].secret().as_bytes(), b"REDACTED");
    }

    // Frozen quadratic filters, retained only as differential evidence. The
    // explicit cases below state the expected results independently.
    fn frozen_filter_findings(findings: Vec<Finding>, redact: usize) -> Vec<Finding> {
        let include = findings
            .iter()
            .map(|finding| {
                if !contains_bytes(
                    &go_lowercase_bytes(finding.rule_id().as_bytes()),
                    b"generic",
                ) {
                    return true;
                }
                !findings.iter().any(|other| {
                    finding.location().start_line() == other.location().start_line()
                        && finding.commit() == other.commit()
                        && finding.rule_id() != other.rule_id()
                        && contains_bytes(other.secret().as_bytes(), finding.secret().as_bytes())
                        && !contains_bytes(
                            &go_lowercase_bytes(other.rule_id().as_bytes()),
                            b"generic",
                        )
                })
            })
            .collect::<Vec<_>>();
        apply_finding_filter(findings, include, redact)
    }

    fn frozen_filter_findings_cancellable(
        findings: Vec<Finding>,
        redact: usize,
        control: ScanControl<'_>,
    ) -> (Vec<Finding>, Option<ScanTermination>) {
        let mut include = Vec::with_capacity(findings.len());
        for finding in &findings {
            if control.is_cancelled() {
                return (
                    apply_finding_filter(findings, include, redact),
                    Some(ScanTermination::Cancelled),
                );
            }
            if !contains_bytes(
                &go_lowercase_bytes(finding.rule_id().as_bytes()),
                b"generic",
            ) {
                include.push(true);
                continue;
            }
            let mut retained = true;
            for other in &findings {
                if control.is_cancelled() {
                    return (
                        apply_finding_filter(findings, include, redact),
                        Some(ScanTermination::Cancelled),
                    );
                }
                if finding.location().start_line() == other.location().start_line()
                    && finding.commit() == other.commit()
                    && finding.rule_id() != other.rule_id()
                    && contains_bytes(other.secret().as_bytes(), finding.secret().as_bytes())
                    && !contains_bytes(&go_lowercase_bytes(other.rule_id().as_bytes()), b"generic")
                {
                    retained = false;
                    break;
                }
            }
            include.push(retained);
        }
        (apply_finding_filter(findings, include, redact), None)
    }

    fn filter_probe(rule_id: &[u8], start_line: usize, commit: &[u8], secret: &[u8]) -> Finding {
        Finding::builder()
            .rule_id(rule_id)
            .location(Location::new(start_line, start_line, 1, 1).unwrap())
            .commit(commit)
            .match_text(secret)
            .secret(secret)
            .build()
            .unwrap()
    }

    fn generic_filter_prototypes() -> Vec<Finding> {
        vec![
            filter_probe(b"generic-a", 1, b"c", b"ab"),
            filter_probe(b"GENERIC-Upper", 1, b"c", b"ab"),
            // U+0130 lowercases to one ASCII i under Go's simple mapping.
            filter_probe("gener\u{130}c-dot".as_bytes(), 1, b"c", b"xaby"),
            // Invalid rule-ID bytes still lowercase around their replacement.
            filter_probe(b"\xffGeneric", 1, b"c", b""),
            filter_probe(b"specific-1", 1, b"c", b"xaby"),
            filter_probe(b"specific-2", 1, b"c", b"ab"),
            filter_probe(b"specific-line", 2, b"c", b"xaby"),
            filter_probe(b"specific-commit", 1, b"d", b"xaby"),
            filter_probe(b"specific-miss", 1, b"c", b"zz"),
        ]
    }

    fn assert_generic_filters_match_frozen(findings: &[Finding]) {
        for redact in [0, 100] {
            assert_eq!(
                filter_findings(findings.to_vec(), redact),
                frozen_filter_findings(findings.to_vec(), redact),
                "{findings:?}",
            );
        }
        assert_eq!(
            filter_findings_cancellable(findings.to_vec(), 0, ScanControl::unlimited()),
            frozen_filter_findings_cancellable(findings.to_vec(), 0, ScanControl::unlimited()),
            "{findings:?}",
        );
        let run = |limit: usize, frozen: bool| {
            let polls = AtomicUsize::new(0);
            let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= limit;
            let control = ScanControl::cancellable(&cancel);
            let outcome = if frozen {
                frozen_filter_findings_cancellable(findings.to_vec(), 0, control)
            } else {
                filter_findings_cancellable(findings.to_vec(), 0, control)
            };
            (outcome, polls.load(Ordering::SeqCst))
        };
        let (complete, total) = run(usize::MAX, true);
        assert_eq!(complete.1, None);
        for limit in (0..=total + 1).chain([usize::MAX]) {
            assert_eq!(
                run(limit, false),
                run(limit, true),
                "limit {limit}, {findings:?}"
            );
        }
    }

    #[test]
    fn generic_buckets_match_the_frozen_quadratic_filter_exhaustively() {
        let prototypes = generic_filter_prototypes();
        assert_generic_filters_match_frozen(&[]);
        for first in &prototypes {
            assert_generic_filters_match_frozen(std::slice::from_ref(first));
            for second in &prototypes {
                assert_generic_filters_match_frozen(&[first.clone(), second.clone()]);
                for third in &prototypes {
                    assert_generic_filters_match_frozen(&[
                        first.clone(),
                        second.clone(),
                        third.clone(),
                    ]);
                }
            }
        }
        // Deterministic longer lists exercise bucket order across repeated keys.
        let mut state = 0x2545_f491_u32;
        for _ in 0..32 {
            let list = (0..6)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    let choice = usize::try_from(state >> 24).unwrap() % prototypes.len();
                    prototypes[choice].clone()
                })
                .collect::<Vec<_>>();
            assert_generic_filters_match_frozen(&list);
        }
    }

    #[test]
    fn generic_suppression_outcomes_and_poll_counts_are_explicit() {
        let generic = || filter_probe(b"generic-a", 7, b"same", b"abc");
        let specific = || filter_probe(b"specific", 7, b"same", b"xxabcxx");
        let other_line = || filter_probe(b"specific", 8, b"same", b"xxabcxx");
        let other_commit = || filter_probe(b"specific", 7, b"other", b"xxabcxx");
        let another_generic = || filter_probe(b"GENERIC-b", 7, b"same", b"xxabcxx");
        let empty_secret = || filter_probe(b"generic-empty", 7, b"same", b"");

        let ids = |findings: &[Finding]| {
            findings
                .iter()
                .map(|finding| finding.rule_id().as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        // Findings, retained rule IDs, and polls with a counting signal.
        type Case = (Vec<Finding>, Vec<&'static [u8]>, usize);
        let cases: Vec<Case> = vec![
            // Suppressor after the generic finding: 1 outer + 2 compared + 1 outer.
            (vec![generic(), specific()], vec![b"specific".as_slice()], 4),
            // Suppressor before the generic finding: 1 outer + 1 outer + 1 compared.
            (vec![specific(), generic()], vec![b"specific".as_slice()], 3),
            // No suppressor: every finding is compared.
            (
                vec![generic(), other_line(), other_commit()],
                vec![
                    b"generic-a".as_slice(),
                    b"specific".as_slice(),
                    b"specific".as_slice(),
                ],
                6,
            ),
            // Generic findings do not suppress each other, by either direction.
            (
                vec![generic(), another_generic()],
                vec![b"generic-a".as_slice(), b"GENERIC-b".as_slice()],
                6,
            ),
            // An empty generic secret is contained in every other secret.
            (
                vec![empty_secret(), specific()],
                vec![b"specific".as_slice()],
                4,
            ),
        ];
        for (findings, retained, expected_polls) in cases {
            let polls = AtomicUsize::new(0);
            let count = || {
                polls.fetch_add(1, Ordering::SeqCst);
                false
            };
            let (filtered, termination) =
                filter_findings_cancellable(findings.clone(), 0, ScanControl::cancellable(&count));
            assert_eq!(termination, None);
            assert_eq!(polls.load(Ordering::SeqCst), expected_polls, "{findings:?}");
            assert_eq!(ids(&filtered), retained, "{findings:?}");
            assert_eq!(ids(&filter_findings(findings, 0)), retained);
        }

        // Polls are numbered from zero: 0 and 1 are the outer checks for the
        // first two findings, 2 through 4 visit findings 0 through 2 for the
        // generic comparison, and 5 is the outer check for the last finding.
        let findings = vec![filter_probe(b"plain", 1, b"", b"p"), generic(), specific()];
        let plain = vec![b"plain".to_vec()];
        for (limit, expected) in [
            (0, Vec::new()),
            (1, plain.clone()),
            (2, plain.clone()),
            (3, plain.clone()),
            (4, plain.clone()),
            // The generic finding is finalized as suppressed; the specific one
            // is not yet finalized, so it is outside the returned prefix.
            (5, plain.clone()),
        ] {
            let polls = AtomicUsize::new(0);
            let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= limit;
            let (filtered, termination) =
                filter_findings_cancellable(findings.clone(), 0, ScanControl::cancellable(&cancel));
            assert_eq!(
                termination,
                Some(ScanTermination::Cancelled),
                "limit {limit}"
            );
            assert_eq!(ids(&filtered), expected, "limit {limit}");
        }
        let polls = AtomicUsize::new(0);
        let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= 6;
        let (filtered, termination) =
            filter_findings_cancellable(findings, 0, ScanControl::cancellable(&cancel));
        assert_eq!(termination, None);
        assert_eq!(ids(&filtered), [b"plain".to_vec(), b"specific".to_vec()]);
    }

    #[test]
    fn private_filter_replays_the_frozen_oracle_adapter() {
        let corpus =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/composite-corpus");
        let requests = json_lines(&corpus.join("requests-v1.jsonl"))
            .into_iter()
            .filter(|value| string(value, "operation") == "filter_probe")
            .collect::<Vec<_>>();
        let responses = json_lines(&corpus.join("outcomes-v1.jsonl"))
            .into_iter()
            .map(|value| (string(&value, "id").to_owned(), value))
            .collect::<BTreeMap<_, _>>();
        assert!(!requests.is_empty());
        for request in requests {
            let id = string(&request, "id");
            let response = responses.get(id).unwrap_or_else(|| panic!("missing {id}"));
            let inputs = request["filter_inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(finding_from_json)
                .collect();
            let redact = usize::try_from(request["redact_percent"].as_u64().unwrap()).unwrap();
            let actual = filter_findings(inputs, redact);
            let expected = response["findings"].as_array().unwrap();
            assert_eq!(actual.len(), expected.len(), "{id}");
            for (finding, value) in actual.iter().zip(expected) {
                assert_finding_matches_json(finding, value);
            }
        }
    }

    fn finding_from_json(value: &Value) -> Finding {
        let mut builder = Finding::builder()
            .rule_id(string(value, "rule_id"))
            .description(decode(string(value, "description_base64")))
            .location(
                Location::new(
                    integer(value, "start_line"),
                    integer(value, "end_line"),
                    integer(value, "start_column"),
                    integer(value, "end_column"),
                )
                .unwrap(),
            )
            .line(decode(string(value, "line_base64")))
            .match_text(decode(string(value, "match_base64")))
            .secret(decode(string(value, "secret_base64")))
            .file(decode(string(value, "file_base64")))
            .symlink_file(decode(string(value, "symlink_file_base64")))
            .commit(decode(string(value, "commit_base64")))
            .link(decode(string(value, "link_base64")))
            .entropy(f32::from_bits(
                u32::try_from(value["entropy_bits"].as_u64().unwrap()).unwrap(),
            ))
            .author(decode(string(value, "author_base64")))
            .email(decode(string(value, "email_base64")))
            .date(decode(string(value, "date_base64")))
            .message(decode(string(value, "message_base64")))
            .tags(
                value["tags_base64"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|tag| decode(tag.as_str().unwrap())),
            )
            .fingerprint(decode(string(value, "fingerprint_base64")));
        if let Some(required_findings) = value["required_findings"].as_array() {
            builder = builder.required_findings(required_findings.iter().map(|required| {
                RequiredFinding::builder()
                    .rule_id(string(required, "rule_id"))
                    .location(
                        Location::new(
                            integer(required, "start_line"),
                            integer(required, "end_line"),
                            integer(required, "start_column"),
                            integer(required, "end_column"),
                        )
                        .unwrap(),
                    )
                    .line(decode(string(required, "line_base64")))
                    .match_text(decode(string(required, "match_base64")))
                    .secret(decode(string(required, "secret_base64")))
                    .build()
                    .unwrap()
            }));
        }
        builder.build().unwrap()
    }

    fn assert_finding_matches_json(finding: &Finding, value: &Value) {
        assert_eq!(
            finding.rule_id().as_bytes(),
            string(value, "rule_id").as_bytes()
        );
        for (actual, key) in [
            (finding.description().as_bytes(), "description_base64"),
            (finding.line().as_bytes(), "line_base64"),
            (finding.match_text().as_bytes(), "match_base64"),
            (finding.secret().as_bytes(), "secret_base64"),
            (finding.file().as_bytes(), "file_base64"),
            (finding.symlink_file().as_bytes(), "symlink_file_base64"),
            (finding.commit().as_bytes(), "commit_base64"),
            (finding.link().as_bytes(), "link_base64"),
            (finding.author().as_bytes(), "author_base64"),
            (finding.email().as_bytes(), "email_base64"),
            (finding.date().as_bytes(), "date_base64"),
            (finding.message().as_bytes(), "message_base64"),
            (finding.fingerprint().as_bytes(), "fingerprint_base64"),
        ] {
            assert_eq!(actual, decode(string(value, key)));
        }
        assert_eq!(
            finding.location().start_line(),
            integer(value, "start_line")
        );
        assert_eq!(finding.location().end_line(), integer(value, "end_line"));
        assert_eq!(
            finding.location().start_column(),
            integer(value, "start_column")
        );
        assert_eq!(
            finding.location().end_column(),
            integer(value, "end_column")
        );
        assert_eq!(
            finding.entropy().to_bits(),
            u32::try_from(value["entropy_bits"].as_u64().unwrap()).unwrap()
        );
        assert_eq!(
            finding
                .tags()
                .iter()
                .map(crate::model::ByteText::as_bytes)
                .collect::<Vec<_>>(),
            value["tags_base64"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tag| decode(tag.as_str().unwrap()))
                .collect::<Vec<_>>()
        );
        assert!(finding.fragment().is_none());
        let expected_required = value["required_findings"].as_array().unwrap();
        assert_eq!(finding.required_findings().len(), expected_required.len());
        for (required, expected) in finding.required_findings().iter().zip(expected_required) {
            assert_eq!(
                required.rule_id().as_bytes(),
                string(expected, "rule_id").as_bytes()
            );
            assert_eq!(
                required.location().start_line(),
                integer(expected, "start_line")
            );
            assert_eq!(
                required.location().end_line(),
                integer(expected, "end_line")
            );
            assert_eq!(
                required.location().start_column(),
                integer(expected, "start_column")
            );
            assert_eq!(
                required.location().end_column(),
                integer(expected, "end_column")
            );
            for (actual, key) in [
                (required.line().as_bytes(), "line_base64"),
                (required.match_text().as_bytes(), "match_base64"),
                (required.secret().as_bytes(), "secret_base64"),
            ] {
                assert_eq!(actual, decode(string(expected, key)));
            }
        }
    }

    fn json_lines(path: &std::path::Path) -> Vec<Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn string<'a>(value: &'a Value, key: &str) -> &'a str {
        value[key].as_str().unwrap()
    }

    fn integer(value: &Value, key: &str) -> usize {
        usize::try_from(value[key].as_i64().unwrap()).unwrap()
    }

    fn decode(encoded: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
    }
}
