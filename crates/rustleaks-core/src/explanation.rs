//! Bounded source-omitting diagnostic records for explicitly selected native scans.
//!
//! Records contain only engine ordinals and finite reason codes. Ordinals are
//! local to a scan and are not persistent occurrence identifiers. The log may
//! include rejected candidates and unfinished rules; it is not a finding list.
//! Rule ordinals index the effective configuration's lexicographically ordered
//! rule map. No input, path, rule text, token, or provider response is retained.

use serde::Serialize;

use crate::validation::OfflineCheck;

/// Retention controls for native explanation metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExplanationOptions {
    maximum: usize,
}

impl ExplanationOptions {
    /// Absolute maximum retained records per fragment.
    pub const MAX_RECORDS: usize = 65_536;

    /// Disables explanation retention and offline annotation work.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { maximum: 0 }
    }

    /// Sets the record ceiling, clamped to [`Self::MAX_RECORDS`].
    ///
    /// Zero disables the channel. Exhaustion truncates diagnostics only; it
    /// never changes detection, finding order, or scan completion.
    #[must_use]
    pub const fn bounded(maximum: usize) -> Self {
        Self {
            maximum: if maximum > Self::MAX_RECORDS {
                Self::MAX_RECORDS
            } else {
                maximum
            },
        }
    }

    /// Returns the effective retained-record ceiling.
    #[must_use]
    pub const fn record_limit(self) -> usize {
        self.maximum
    }
}

/// Offline structural assessment, never a statement about credential activity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationState {
    /// The specifically documented structural check succeeded.
    Valid,
    /// The specifically documented structural check failed.
    Invalid,
    /// The input or available specification does not support a decision.
    Unknown,
}

/// Reason for an offline structural assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationReason {
    /// Prefix, length and alphabet match the historical layout only.
    HistoricalLayoutMatched,
    /// Exact historical prefix/length contain bytes outside its alphabet.
    HistoricalAlphabetMismatch,
    /// The input is outside the precisely supported historical layout.
    UnsupportedFormat,
    /// Issuer documentation does not specify enough checksum parameters.
    UnspecifiedChecksumContract,
    /// A candidate may be part of a longer token, or its source span is unknown.
    AmbiguousBoundary,
}

/// Deterministic engine decisions. Codes carry no source-derived strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExplanationReason {
    /// A configured top-level or auxiliary rule was considered.
    RuleSelected,
    /// A rule is configured not to report independently.
    RuleReportSkipped,
    /// A configured keyword was present in this pass.
    KeywordMatched,
    /// No configured keyword was present in this pass.
    KeywordMissed,
    /// This rule has no keyword requirement.
    KeywordNotRequired,
    /// The path expression matched.
    PathMatched,
    /// The path expression did not match.
    PathMissed,
    /// A content expression matched one candidate.
    PatternMatched,
    /// No content candidate matched this rule in this pass.
    PatternMissed,
    /// Secret extraction did not yield a supported capture.
    SecretGroupUnavailable,
    /// A decoded candidate did not map to an encoded segment.
    DecodedMappingUnavailable,
    /// A candidate exceeded the configured entropy threshold.
    EntropyAccepted,
    /// A candidate did not exceed the configured entropy threshold.
    EntropyRejected,
    /// No entropy threshold is configured.
    EntropyNotRequired,
    /// A global or rule allowlist accepted the path, commit, or candidate.
    AllowlistMatched,
    /// The applicable allowlist phase did not accept the input.
    AllowlistNotMatched,
    /// An inline allow marker suppressed this candidate.
    AllowMarkerMatched,
    /// All required auxiliary rules supplied a nearby finding.
    RequiredRulesMatched,
    /// At least one required auxiliary rule lacked a nearby finding.
    RequiredRulesMissing,
    /// The compatibility per-target byte gate skipped a content rule.
    TargetByteLimit,
    /// The candidate passed this rule's local gates, before final filtering.
    CandidateAccepted,
    /// The caller cancelled the scan.
    ScanCancelled,
    /// The scan stopped at its decoded-byte budget.
    DecodedByteBudgetExceeded,
    /// The scan stopped at its work-unit budget.
    WorkBudgetExceeded,
    /// The scan stopped at its finding-record budget.
    FindingBudgetExceeded,
    /// An explicitly selected offline check annotated a candidate.
    OfflineValidation {
        /// The exact check; layout is distinct from checksum validity.
        check: OfflineCheck,
        /// Structural assessment only.
        state: ValidationState,
        /// Scope or limitation of that assessment.
        reason: ValidationReason,
    },
}

/// One source-omitting decision at a scan-local engine location.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ExplanationEvent {
    rule_ordinal: Option<usize>,
    decoded_pass: usize,
    candidate_ordinal: Option<usize>,
    reason: ExplanationReason,
}

impl ExplanationEvent {
    /// Index into the effective config's ordered rule map, or a scan-wide event.
    #[must_use]
    pub const fn rule_ordinal(self) -> Option<usize> {
        self.rule_ordinal
    }

    /// Zero for raw input; positive values identify subsequent decoded passes.
    #[must_use]
    pub const fn decoded_pass(self) -> usize {
        self.decoded_pass
    }

    /// Regex match ordinal within this evaluation, including rejected matches.
    #[must_use]
    pub const fn candidate_ordinal(self) -> Option<usize> {
        self.candidate_ordinal
    }

    /// Returns the finite decision code.
    #[must_use]
    pub const fn reason(self) -> ExplanationReason {
        self.reason
    }
}

/// Bounded metadata suitable for deliberate diagnostic projection.
///
/// Even source-omitting counts and decisions reveal scan activity. A log is
/// never proof that an input is safe, and a truncated log is not exhaustive.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ExplanationLog {
    enabled: bool,
    events: Vec<ExplanationEvent>,
    truncated: bool,
}

impl ExplanationLog {
    /// Whether a nonzero record budget enabled this diagnostic channel.
    /// Disabled logs are empty and are not represented as completed validation.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns retained records in engine execution order.
    #[must_use]
    pub fn events(&self) -> &[ExplanationEvent] {
        &self.events
    }

    /// Whether enabled diagnostics were omitted due to a limit or allocation.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

pub(crate) struct ExplanationCollector {
    options: ExplanationOptions,
    pub(crate) log: ExplanationLog,
    pub(crate) github_classic: bool,
}

impl ExplanationCollector {
    pub(crate) fn new(options: ExplanationOptions, github_classic: bool) -> Self {
        Self {
            options,
            log: ExplanationLog {
                enabled: options.maximum != 0,
                ..ExplanationLog::default()
            },
            github_classic,
        }
    }

    pub(crate) fn has_room(&self) -> bool {
        !self.log.truncated
            && self.options.maximum != 0
            && self.log.events.len() < self.options.maximum
    }

    pub(crate) fn record(
        &mut self,
        rule_ordinal: Option<usize>,
        decoded_pass: usize,
        candidate_ordinal: Option<usize>,
        reason: ExplanationReason,
    ) {
        if self.options.maximum == 0 {
            return;
        }
        if self.log.truncated
            || self.log.events.len() == self.options.maximum
            || self.log.events.try_reserve(1).is_err()
        {
            self.log.truncated = true;
            return;
        }
        self.log.events.push(ExplanationEvent {
            rule_ordinal,
            decoded_pass,
            candidate_ordinal,
            reason,
        });
    }
}
