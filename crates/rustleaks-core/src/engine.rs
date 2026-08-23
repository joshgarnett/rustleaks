//! Immutable raw-fragment detection engine.

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
use crate::go_unicode::{chars as go_chars, lowercase_bytes as go_lowercase_bytes};
use crate::model::{Finding, Fragment, Location, RequiredFinding, ScanOptions};
use crate::regex::{ByteSpan, GoRegex};

const ALLOW_SIGNATURE: &[u8] = b"gitleaks:allow";
const RUSTLEAKS_ALLOW_SIGNATURE: &[u8] = b"rustleaks:allow";

/// A synchronous, runtime-independent cancellation signal for one scan.
///
/// The engine polls this signal between bounded units of owned work. A regular
/// expression backend evaluation and one individual encoding transform are
/// indivisible; decoder candidate loops are checkpointed between transforms.
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
    keyword_ids: BTreeMap<String, usize>,
}

#[derive(Clone, Copy)]
struct DetectionPass<'a> {
    current_raw: &'a [u8],
    encoded_segments: &'a [EncodedSegment],
    original_newlines: &'a [usize],
}

#[derive(Clone, Copy)]
struct RulePass<'a> {
    current_raw: &'a [u8],
    encoded_segments: &'a [EncodedSegment],
    inherited_from_finding: bool,
}

struct ScanContext<'a> {
    control: ScanControl<'a>,
    usage: ScanUsage,
}

impl<'a> ScanContext<'a> {
    const fn new(control: ScanControl<'a>) -> Self {
        Self {
            control,
            usage: ScanUsage {
                decoded_bytes: 0,
                work_units: 0,
                finding_records: 0,
            },
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
    /// loops. One regex backend evaluation, one individual encoding transform,
    /// finding construction, and redaction of one finding are indivisible.
    #[must_use]
    pub fn scan_fragment_controlled(
        &self,
        fragment: &Fragment,
        options: &ScanOptions,
        control: &ScanControl<'_>,
    ) -> ScanOutcome {
        let mut context = ScanContext::new(*control);
        if let Err(termination) = context.check_cancelled() {
            return ScanOutcome::partial(Vec::new(), context.usage, termination);
        }
        if commit_or_path_allowed(fragment, &self.config.allowlists) {
            return ScanOutcome::complete(Vec::new(), context.usage);
        }

        let mut findings = Vec::new();
        let mut current_raw = fragment.content().as_bytes().to_vec();
        let mut encoded_segments = Vec::new();
        let mut decoder = Decoder::new();
        let mut decode_depth = 0;
        loop {
            if let Err(termination) = context.work() {
                return finish_partial(findings, options, context.usage, termination);
            }
            let normalized = go_lowercase_bytes(&current_raw);
            let mut matched_keywords = vec![false; self.keyword_ids.len()];
            if let Some(prefilter) = &self.prefilter {
                for found in prefilter.find_overlapping_iter(&normalized) {
                    if let Err(termination) = context.work() {
                        return finish_partial(findings, options, context.usage, termination);
                    }
                    matched_keywords[found.pattern().as_usize()] = true;
                }
            }

            for rule in self.config.rules.values() {
                if !rule.keywords.is_empty()
                    && !rule.keywords.iter().any(|keyword| {
                        self.keyword_ids
                            .get(keyword)
                            .is_some_and(|index| matched_keywords[*index])
                    })
                {
                    continue;
                }
                let detected = self.detect_rule(
                    fragment,
                    options,
                    rule,
                    RulePass {
                        current_raw: &current_raw,
                        encoded_segments: &encoded_segments,
                        inherited_from_finding: fragment.inherited_from_finding(),
                    },
                    &mut context,
                );
                match detected {
                    Ok(detected) => findings.extend(detected),
                    Err(termination) => {
                        return finish_partial(findings, options, context.usage, termination);
                    }
                }
            }

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
            current_raw = decoded_output;
            encoded_segments = segments;
        }
        finish_complete(findings, options, &context)
    }

    fn detect_rule(
        &self,
        fragment: &Fragment,
        options: &ScanOptions,
        rule: &CompiledRule,
        rule_pass: RulePass<'_>,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<Finding>, ScanTermination> {
        context.work()?;
        if rule.skip_report && !rule_pass.inherited_from_finding {
            return Ok(Vec::new());
        }
        if commit_or_path_allowed(fragment, &rule.allowlists) {
            return Ok(Vec::new());
        }

        if let Some(path) = &rule.path_matcher {
            let path_matches = path.is_match(fragment.file_path().as_bytes())
                || (!fragment.windows_file_path().is_empty()
                    && path.is_match(fragment.windows_file_path().as_bytes()));
            if rule.regex_matcher.is_none() {
                let finding = (rule_pass.encoded_segments.is_empty() && path_matches)
                    .then(|| path_finding(fragment, rule))
                    .flatten()
                    .into_iter()
                    .collect::<Vec<_>>();
                if !finding.is_empty() {
                    context.finding_record()?;
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
            return Ok(Vec::new());
        }

        let original_raw = fragment.content().as_bytes();
        let newlines = original_raw
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
            .collect::<Vec<_>>();
        let pass = DetectionPass {
            current_raw: rule_pass.current_raw,
            encoded_segments: rule_pass.encoded_segments,
            original_newlines: &newlines,
        };
        let mut findings = Vec::new();
        for span in regex.find_all(rule_pass.current_raw) {
            context.work()?;
            if let Some(finding) = Self::content_finding(
                fragment,
                options,
                rule,
                regex,
                &self.config.allowlists,
                pass,
                span,
            ) {
                context.finding_record()?;
                findings.push(finding);
            }
        }
        if rule_pass.inherited_from_finding || rule.required.is_empty() || findings.is_empty() {
            return Ok(findings);
        }

        self.project_required_findings(fragment, options, rule, rule_pass, findings, context)
    }

    fn project_required_findings(
        &self,
        fragment: &Fragment,
        options: &ScanOptions,
        primary_rule: &CompiledRule,
        rule_pass: RulePass<'_>,
        primary_findings: Vec<Finding>,
        context: &mut ScanContext<'_>,
    ) -> Result<Vec<Finding>, ScanTermination> {
        let mut required_by_id = BTreeMap::<&str, Vec<Finding>>::new();
        for required in &primary_rule.required {
            context.work()?;
            let Some(rule) = self.config.rules.get(&required.id) else {
                continue;
            };
            let findings = self.detect_rule(
                fragment,
                options,
                rule,
                RulePass {
                    inherited_from_finding: true,
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
                continue;
            }
            primary.add_required_findings(projected);
            completed.push(primary);
        }
        Ok(completed)
    }

    fn content_finding(
        fragment: &Fragment,
        options: &ScanOptions,
        rule: &CompiledRule,
        regex: &GoRegex,
        global_allowlists: &[CompiledAllowlist],
        pass: DetectionPass<'_>,
        whole: ByteSpan,
    ) -> Option<Finding> {
        let original_raw = fragment.content().as_bytes();
        let matched = pass.current_raw.get(whole.start..whole.end)?;
        let trimmed = trim_newlines(matched);
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
        let source = upstream_location(
            pass.original_newlines,
            original_raw,
            adjusted_start,
            adjusted_end,
        );
        let line = original_raw.get(source.start_line_index..source.end_line_index)?;
        if options.honor_allow_markers()
            && (contains_bytes(line, RUSTLEAKS_ALLOW_SIGNATURE)
                || contains_bytes(line, ALLOW_SIGNATURE))
        {
            return None;
        }

        let secret = extract_secret(regex, trimmed, rule.secret_group)?;
        let entropy = shannon_entropy(secret);
        if rule.entropy != 0.0 && entropy <= rule.entropy {
            return None;
        }
        let allowlist_line = decoded_line.filter(|line| !line.is_empty()).unwrap_or(line);
        if finding_allowed(fragment, trimmed, secret, allowlist_line, global_allowlists)
            || finding_allowed(fragment, trimmed, secret, allowlist_line, &rule.allowlists)
        {
            return None;
        }

        let location = Location::from_upstream(
            fragment.start_line().saturating_add(source.start_line),
            fragment.start_line().saturating_add(source.end_line),
            source.start_column,
            source.end_column,
        );
        let mut finding_tags = rule.tags.clone();
        finding_tags.extend(meta_tags);
        let mut builder = Finding::builder()
            .rule_id(rule.id.as_str())
            .description(rule.description.as_str())
            .location(location)
            .line(line)
            .match_text(trimmed)
            .secret(secret)
            .file(fragment.file_path().as_bytes())
            .symlink_file(fragment.symlink_file().as_bytes())
            .commit(fragment.commit().as_bytes())
            .entropy(entropy_to_f32(entropy))
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

fn finding_allowed(
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
                    && !contains_bytes(&go_lowercase_bytes(other.rule_id().as_bytes()), b"generic")
            })
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
            .map(|(index, keyword)| (keyword.clone(), index))
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
            keyword_ids,
        })
    }
}

/// Result of one stateless fragment scan.
///
/// Equality is structural: findings, measured usage, and termination must all
/// match. This prevents a partial scan from comparing equal to a complete scan
/// that happened to retain the same findings.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanOutcome {
    findings: Vec<Finding>,
    usage: ScanUsage,
    termination: Option<ScanTermination>,
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

#[derive(Clone, Copy, Debug)]
struct SourceLocation {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    start_line_index: usize,
    end_line_index: usize,
}

fn upstream_location(newlines: &[usize], raw: &[u8], start: usize, end: usize) -> SourceLocation {
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

fn trim_newlines(mut bytes: &[u8]) -> &[u8] {
    while bytes.first() == Some(&b'\n') {
        bytes = &bytes[1..];
    }
    while bytes.last() == Some(&b'\n') {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn extract_secret<'a>(regex: &GoRegex, matched: &'a [u8], secret_group: i64) -> Option<&'a [u8]> {
    let Some(captures) = regex.captures_all(matched).into_iter().next() else {
        // Trimming leading/trailing newlines can make an anchored full-match
        // expression stop matching. Go leaves the already-trimmed secret
        // unchanged when FindStringSubmatch consequently returns nil.
        return Some(matched);
    };
    if captures.spans().len() < 2 {
        return Some(matched);
    }
    if secret_group > 0 {
        let index = usize::try_from(secret_group).ok()?;
        let span = captures.spans().get(index)?;
        return match span {
            Some(span) => matched.get(span.start..span.end),
            // FindStringSubmatch represents a nonparticipating group as an
            // empty string, which is observably different from an invalid
            // group index (the latter suppresses the finding).
            None => matched.get(..0),
        };
    }
    captures
        .spans()
        .iter()
        .skip(1)
        .flatten()
        .find(|span| span.start != span.end)
        .and_then(|span| matched.get(span.start..span.end))
        .or(Some(matched))
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
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

    use base64::Engine as _;
    use serde_json::Value;

    use super::*;
    use crate::config::ConfigLoader;

    fn engine(config: &str) -> Engine {
        Engine::builder(ConfigLoader::new().load_toml(config).unwrap())
            .build()
            .unwrap()
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
