//! Opt-in review state and occurrence-preserving presentation.
//!
//! Acknowledgement is a workflow decision, never a statement that a credential
//! is safe. This module does not filter findings or change legacy baselines.
//! Persisted records contain caller-supplied identifiers, rule IDs and numeric
//! locations, but never copy secrets, source text, paths or configuration.
//! Identifiers must be non-sensitive references from the caller's trusted
//! store. Do not use an unsalted hash of a credential as an identifier.
//!
//! Compile once and reuse an immutable engine on caller-managed threads. The
//! application supplies the worker count, budgets and source-reference store.
//! Diagnostic tuples below omit every source-derived string. A partial scan
//! always carries its completion state even when no finding was returned.
//!
//! ```
//! use rustleaks_core::explanation::ExplanationOptions;
//! use rustleaks_core::model::{Fragment, ScanOptions};
//! use rustleaks_core::native::NativePolicy;
//! use rustleaks_core::triage::{ReviewPolicy, ReviewSource};
//! use rustleaks_core::{ScanBudget, ScanControl};
//!
//! let engine = NativePolicy::builder().build()?;
//! let policy = ReviewPolicy::for_builtin(engine.identity())?;
//! let fragments = [Fragment::new(b"synthetic input"), Fragment::new(b"other input")];
//! let inputs = [
//!     ReviewSource::caller_bound("snapshot-001")?,
//!     ReviewSource::caller_bound("snapshot-002")?,
//! ];
//! std::thread::scope(|scope| {
//!     let handles = fragments.iter().zip(&inputs).map(|(fragment, source)| {
//!         let engine = &engine;
//!         let policy = &policy;
//!         scope.spawn(move || {
//!             let control = ScanControl::unlimited().with_budget(
//!                 ScanBudget::unlimited().max_work_units(10_000)
//!                     .max_decoded_bytes(1_024).max_finding_records(32),
//!             );
//!             let scan = engine.scan_fragment_controlled(
//!                 fragment, &ScanOptions::default(), &control,
//!                 ExplanationOptions::bounded(64),
//!             );
//!             let review = policy.review(&scan, source, &[], 1_700_000_000)?;
//!             let diagnostics = review.occurrences().iter()
//!                 .zip(review.classifications())
//!                 .map(|(occurrence, state)| (occurrence.index(), occurrence.location(), *state))
//!                 .collect::<Vec<_>>();
//!             Ok::<_, rustleaks_core::triage::ReviewError>((
//!                 review.is_complete(), scan.scan().termination().cloned(), diagnostics,
//!             ))
//!         })
//!     }).collect::<Vec<_>>();
//!     for handle in handles {
//!         let (complete, termination, diagnostics) = handle.join().expect("worker panicked")?;
//!         if !complete {
//!             // Retain partial status and decide whether to retry outside core.
//!             assert!(termination.is_some());
//!         }
//!         // Only numeric locations and finite workflow states may be logged.
//!         let _ = diagnostics;
//!     }
//!     Ok::<_, rustleaks_core::triage::ReviewError>(())
//! })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Review an actual partial outcome without treating missing findings as clean.
//!
//! ```
//! use rustleaks_core::explanation::ExplanationOptions;
//! use rustleaks_core::model::{Fragment, ScanOptions};
//! use rustleaks_core::native::NativePolicy;
//! use rustleaks_core::triage::{ReviewPolicy, ReviewSource};
//! use rustleaks_core::{ScanBudget, ScanControl};
//! let engine = NativePolicy::builder().build()?;
//! let scan = engine.scan_fragment_controlled(
//!     &Fragment::new(b"synthetic input"), &ScanOptions::default(),
//!     &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0)),
//!     ExplanationOptions::disabled(),
//! );
//! let policy = ReviewPolicy::for_builtin(engine.identity())?;
//! let source = ReviewSource::caller_bound("snapshot-003")?;
//! let review = policy.review(&scan, &source, &[], 1_700_000_000)?;
//! assert!(!review.is_complete());
//! assert!(scan.scan().termination().is_some());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::model::{Finding, FindingRange, Location, ScanOptions};
use crate::native::{NativePolicyIdentity, NativeScanOutcome};
use crate::{ScanOutcome, ScanTermination};

/// Review-record schema version, independent of detection-policy versions.
pub const REVIEW_SCHEMA_VERSION: u32 = 1;
/// Hard ceiling on records in one review operation or serialized artifact.
pub const MAX_REVIEW_RECORDS: usize = 4_096;
/// Hard ceiling on findings projected or grouped in one operation.
pub const MAX_TRIAGE_FINDINGS: usize = 100_000;
/// Maximum bytes in an externally bound policy reference.
pub const MAX_POLICY_REFERENCE_BYTES: usize = 1_024;
/// Maximum bytes in a source reference.
pub const MAX_SOURCE_REFERENCE_BYTES: usize = 256;
/// Maximum bytes in a persisted rule ID.
pub const MAX_REVIEW_RULE_BYTES: usize = 128;

/// An immutable source-snapshot reference from a caller-controlled store.
///
/// The caller must bind this reference to exact source bytes, source metadata
/// and scan options, including decode/redaction options. Reusing it for changed
/// input can incorrectly acknowledge a new credential at an old location.
/// Use a new reference when any of these change. The engine cannot verify an
/// external store across restarts. References are retained in review artifacts;
/// keep them non-sensitive and access-control the store and artifacts.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReviewSource(String);

impl ReviewSource {
    /// Explicitly binds an opaque reference to an immutable scan input.
    ///
    /// # Errors
    /// Returns an error for an empty, oversized or non-identifier reference.
    pub fn caller_bound(reference: &str) -> Result<Self, ReviewError> {
        validate_reference(reference, MAX_SOURCE_REFERENCE_BYTES)?;
        Ok(Self(reference.to_owned()))
    }

    /// Returns the caller-bound reference; no source path is inferred.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.0
    }
}

/// A persistent policy reference bound to an exact native identity in memory.
///
/// Custom bindings require a trusted registry or a caller-owned cryptographic
/// construction covering every exact identity byte. A human pack name/version
/// alone is insufficient. Policy references are retained in review artifacts.
#[derive(Clone, Debug)]
pub struct ReviewPolicy {
    identity: NativePolicyIdentity,
    reference: String,
}

impl ReviewPolicy {
    /// Uses the checked immutable built-in configuration references.
    ///
    /// # Errors
    /// Returns `CustomPolicyBindingRequired` for arbitrary custom packs.
    pub fn for_builtin(identity: &NativePolicyIdentity) -> Result<Self, ReviewError> {
        let reference = identity
            .builtin_review_reference()
            .ok_or(ReviewError::CustomPolicyBindingRequired)?;
        Self::caller_bound(identity, reference)
    }

    /// Explicitly binds a non-sensitive persistent ID to this exact identity.
    ///
    /// The caller must never reassign this ID to different identity bytes.
    /// Repeating a name or version without an exact immutable binding is not
    /// sufficient. Complete configuration bytes are retained only in memory,
    /// inside the opaque native identity, and are never copied into records.
    ///
    /// # Errors
    /// Returns an error for an empty, oversized or non-identifier reference.
    pub fn caller_bound(
        identity: &NativePolicyIdentity,
        reference: &str,
    ) -> Result<Self, ReviewError> {
        validate_reference(reference, MAX_POLICY_REFERENCE_BYTES)?;
        Ok(Self {
            identity: identity.clone(),
            reference: reference.to_owned(),
        })
    }

    /// Returns the persistent reference, excluding exact configuration bytes.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Classifies all current occurrences and every prior record deterministically.
    ///
    /// `now` is caller-supplied Unix time in seconds; no clock is read. Expiry is
    /// exclusive: a record expires when `now >= expires_at`. Results retain a
    /// borrowed reference to every original finding, including acknowledged
    /// occurrences. Records absent from a partial scan are reported as unobserved,
    /// not resolved. No result is labelled safe.
    ///
    /// # Errors
    /// Rejects an exact policy mismatch, exceeded hard ceilings, unsupported rule
    /// identifiers or duplicate records for the same policy and occurrence.
    pub fn review<'a>(
        &self,
        scan: &'a NativeScanOutcome,
        source: &ReviewSource,
        records: &[ReviewRecord],
        now: u64,
    ) -> Result<ReviewResult<'a>, ReviewError> {
        if scan.identity() != &self.identity {
            return Err(ReviewError::PolicyMismatch);
        }
        validate_records(records)?;
        let findings = scan.scan().findings();
        check_findings(findings.len())?;
        let occurrences = findings
            .iter()
            .enumerate()
            .map(|(index, finding)| ReviewOccurrence::from_finding(source.clone(), finding, index))
            .collect::<Result<Vec<_>, _>>()?;
        let lookup = occurrences
            .iter()
            .enumerate()
            .map(|(index, occurrence)| (occurrence, index))
            .collect::<BTreeMap<_, _>>();
        let mut classifications = vec![ReviewClassification::New; findings.len()];
        let record_states = records
            .iter()
            .enumerate()
            .map(|(record_index, record)| {
                if record.policy_reference != self.reference {
                    RecordState::StalePolicy
                } else if record.options != scan.options() {
                    RecordState::StaleOptions
                } else if record.occurrence.source != *source {
                    RecordState::StaleSource
                } else if now >= record.expires_at {
                    RecordState::Expired
                } else if let Some(&finding_index) = lookup.get(&record.occurrence) {
                    classifications[finding_index] =
                        ReviewClassification::Acknowledged { record_index };
                    RecordState::Active { finding_index }
                } else if scan.scan().is_complete() {
                    RecordState::StaleOccurrence
                } else {
                    RecordState::UnobservedInPartialScan
                }
            })
            .collect();
        Ok(ReviewResult {
            findings,
            occurrences,
            classifications,
            record_states,
            complete: scan.scan().is_complete(),
        })
    }
}

/// The exact observable occurrence within an immutable caller-bound input.
///
/// The index distinguishes duplicate and decoded findings even when their
/// report locations coincide. Line shifts do not silently retain review state:
/// changed source input requires a new source reference. Exact byte ranges stay
/// unavailable for decoded findings, matching the underlying finding contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReviewOccurrence {
    source: ReviewSource,
    rule_id: String,
    location: [usize; 4],
    match_range: Option<[usize; 2]>,
    secret_range: Option<[usize; 2]>,
    index: usize,
}

impl ReviewOccurrence {
    /// Constructs an occurrence without reading source text or credentials.
    ///
    /// # Errors
    /// Rejects rule IDs outside the bounded ASCII identifier contract or an
    /// index at or above the finding ceiling.
    pub fn from_finding(
        source: ReviewSource,
        finding: &Finding,
        index: usize,
    ) -> Result<Self, ReviewError> {
        let rule_id = finding
            .rule_id()
            .as_str()
            .map_err(|_| ReviewError::InvalidReference)?;
        Self::new(
            source,
            rule_id,
            finding.location(),
            finding.match_range(),
            finding.secret_range(),
            index,
        )
    }

    /// Restores a record occurrence from validated numeric metadata.
    ///
    /// # Errors
    /// Rejects oversized or invalid rule identifiers and finding indices.
    pub fn new(
        source: ReviewSource,
        rule_id: &str,
        location: Location,
        match_range: FindingRange,
        secret_range: FindingRange,
        index: usize,
    ) -> Result<Self, ReviewError> {
        validate_reference(rule_id, MAX_REVIEW_RULE_BYTES)?;
        if index >= MAX_TRIAGE_FINDINGS {
            return Err(ReviewError::LimitExceeded);
        }
        Ok(Self {
            source,
            rule_id: rule_id.to_owned(),
            location: [
                location.start_line(),
                location.end_line(),
                location.start_column(),
                location.end_column(),
            ],
            match_range: range_array(match_range),
            secret_range: range_array(secret_range),
            index,
        })
    }

    /// Returns the immutable source reference.
    #[must_use]
    pub const fn source(&self) -> &ReviewSource {
        &self.source
    }
    /// Returns the retained rule ID, never a pattern or credential.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }
    /// Returns start/end lines and start/end columns, in that order.
    #[must_use]
    pub const fn location(&self) -> [usize; 4] {
        self.location
    }
    /// Returns the exact half-open match range, if available.
    #[must_use]
    pub const fn match_range(&self) -> Option<[usize; 2]> {
        self.match_range
    }
    /// Returns the exact half-open secret range, if available.
    #[must_use]
    pub const fn secret_range(&self) -> Option<[usize; 2]> {
        self.secret_range
    }
    /// Returns the original position in the scan's finding slice.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }
}

fn range_array(range: FindingRange) -> Option<[usize; 2]> {
    range.exact().map(|range| [range.start(), range.end()])
}

/// Bounded acknowledgement reasons. None asserts that a credential is safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReviewReason {
    /// A reviewer identified a deliberately synthetic fixture.
    SyntheticFixture,
    /// A reviewer accepted the exposure under their external policy.
    AcceptedRisk,
    /// Remediation is tracked outside the scanner.
    RemediationScheduled,
}

/// A versioned, expiring acknowledgement that contains no copied source text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRecord {
    policy_reference: String,
    options: ScanOptions,
    occurrence: ReviewOccurrence,
    reason: ReviewReason,
    expires_at: u64,
}

impl ReviewRecord {
    /// Creates an acknowledgement from validated metadata.
    ///
    /// `policy_reference` must come from the exact bound [`ReviewPolicy`]. This
    /// constructor also permits restoring historical records for stale reporting.
    /// Free-form notes are deliberately excluded; keep them in a controlled
    /// external review system. `expires_at` is Unix seconds, supplied by caller.
    ///
    /// # Errors
    /// Rejects an empty, invalid or oversized persistent policy reference.
    pub fn new(
        policy_reference: &str,
        options: ScanOptions,
        occurrence: ReviewOccurrence,
        reason: ReviewReason,
        expires_at: u64,
    ) -> Result<Self, ReviewError> {
        validate_reference(policy_reference, MAX_POLICY_REFERENCE_BYTES)?;
        Ok(Self {
            policy_reference: policy_reference.to_owned(),
            options,
            occurrence,
            reason,
            expires_at,
        })
    }

    /// Returns the bound policy reference, never exact configuration bytes.
    #[must_use]
    pub fn policy_reference(&self) -> &str {
        &self.policy_reference
    }
    /// Returns the actual scan options whose findings were acknowledged.
    #[must_use]
    pub const fn options(&self) -> ScanOptions {
        self.options
    }
    /// Returns the exact occurrence metadata.
    #[must_use]
    pub const fn occurrence(&self) -> &ReviewOccurrence {
        &self.occurrence
    }
    /// Returns the explicit acknowledgement reason.
    #[must_use]
    pub const fn reason(&self) -> ReviewReason {
        self.reason
    }
    /// Returns the exclusive expiry in Unix seconds.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Current workflow state. Neither state makes a safety assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewClassification {
    /// No current, unexpired acknowledgement applies.
    New,
    /// A current acknowledgement applies; the finding remains available.
    Acknowledged {
        /// Index in the reviewed record slice.
        record_index: usize,
    },
}

/// The applicability of a prior record, including stale suppression decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecordState {
    /// The record currently acknowledges exactly one finding.
    Active {
        /// Index in the original finding slice.
        finding_index: usize,
    },
    /// The bound native configuration or extension identity changed.
    StalePolicy,
    /// Decode, size, redaction or inline-allow options changed.
    StaleOptions,
    /// The immutable source-snapshot reference changed.
    StaleSource,
    /// The exclusive caller-supplied expiry has been reached.
    Expired,
    /// A completed scan did not produce this exact occurrence.
    StaleOccurrence,
    /// An incomplete scan did not observe this occurrence; absence is inconclusive.
    UnobservedInPartialScan,
}

/// Review projections with all original findings still accessible.
///
/// Debug output omits findings and source metadata. The findings accessor is
/// sensitive; use classification and numeric occurrence projections for logs.
pub struct ReviewResult<'a> {
    findings: &'a [Finding],
    occurrences: Vec<ReviewOccurrence>,
    classifications: Vec<ReviewClassification>,
    record_states: Vec<RecordState>,
    complete: bool,
}

impl fmt::Debug for ReviewResult<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewResult")
            .field("finding_count", &self.findings.len())
            .field("record_count", &self.record_states.len())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl ReviewResult<'_> {
    /// Returns all sensitive original findings in their original order.
    #[must_use]
    pub const fn findings(&self) -> &[Finding] {
        self.findings
    }
    /// Returns metadata for every original occurrence in the same order.
    #[must_use]
    pub fn occurrences(&self) -> &[ReviewOccurrence] {
        &self.occurrences
    }
    /// Returns the workflow classification of every original finding.
    #[must_use]
    pub fn classifications(&self) -> &[ReviewClassification] {
        &self.classifications
    }
    /// Returns the applicability of every input record in its original order.
    #[must_use]
    pub fn record_states(&self) -> &[RecordState] {
        &self.record_states
    }
    /// Reports whether detection completed; review never upgrades a partial scan.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Presentation-only grouping of exact raw occurrences within a single scan.
///
/// Equal secret bytes and equal exact secret spans can group related provider
/// and generic detections. Keys exist only during construction, in memory.
/// No hash, credential or stable secret-derived ID is emitted. Decoded findings
/// with unavailable exact byte ranges remain singleton groups. Group numbers
/// are local to this result and must not be used as durable review identities.
pub struct PresentationGroups<'a> {
    scan: &'a ScanOutcome,
    groups: Vec<Vec<usize>>,
}

impl fmt::Debug for PresentationGroups<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentationGroups")
            .field("finding_count", &self.scan.findings().len())
            .field("group_count", &self.groups.len())
            .field("complete", &self.scan.is_complete())
            .finish_non_exhaustive()
    }
}

impl<'a> PresentationGroups<'a> {
    /// Groups a single scan's occurrences while preserving all original indices.
    ///
    /// The first occurrence establishes group order. This API accepts one scan,
    /// so ranges from different fragments are never treated as one occurrence.
    ///
    /// # Errors
    /// Returns `LimitExceeded` above the hard finding ceiling.
    pub fn for_scan(scan: &'a ScanOutcome) -> Result<Self, ReviewError> {
        let findings = scan.findings();
        check_findings(findings.len())?;
        let mut groups: Vec<Vec<usize>> = Vec::new();
        let mut keys: BTreeMap<(usize, usize, &[u8]), usize> = BTreeMap::new();
        for (index, finding) in findings.iter().enumerate() {
            let key = finding
                .secret_range()
                .exact()
                .filter(|range| !range.is_empty())
                .map(|range| (range.start(), range.end(), finding.secret().as_bytes()));
            if let Some(key) = key {
                if let Some(&group_index) = keys.get(&key) {
                    groups[group_index].push(index);
                    continue;
                }
                keys.insert(key, groups.len());
            }
            groups.push(vec![index]);
        }
        Ok(Self { scan, groups })
    }

    /// Returns every original sensitive finding, including duplicates.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        self.scan.findings()
    }
    /// Returns presentation groups of original indices, each appearing once.
    #[must_use]
    pub fn groups(&self) -> &[Vec<usize>] {
        &self.groups
    }
    /// Reports whether the original scan completed, even for empty groups.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.scan.is_complete()
    }
    /// Returns the original scan's termination; no completion state is inferred.
    #[must_use]
    pub const fn termination(&self) -> Option<&ScanTermination> {
        self.scan.termination()
    }
}

/// Validates the hard record ceiling and rejects ambiguous duplicate decisions.
///
/// # Errors
/// Returns `LimitExceeded` or `DuplicateRecord` without partial acceptance.
pub fn validate_records(records: &[ReviewRecord]) -> Result<(), ReviewError> {
    if records.len() > MAX_REVIEW_RECORDS {
        return Err(ReviewError::LimitExceeded);
    }
    let mut seen = BTreeSet::new();
    for record in records {
        let options = record.options;
        let options_key = (
            options.max_decode_depth(),
            options.max_target_bytes(),
            options.redaction_percent(),
            options.honor_allow_markers(),
        );
        if !seen.insert((&record.policy_reference, options_key, &record.occurrence)) {
            return Err(ReviewError::DuplicateRecord);
        }
    }
    Ok(())
}

fn check_findings(count: usize) -> Result<(), ReviewError> {
    if count > MAX_TRIAGE_FINDINGS {
        Err(ReviewError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_reference(reference: &str, max_bytes: usize) -> Result<(), ReviewError> {
    if reference.is_empty()
        || reference.len() > max_bytes
        || !reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/+=;|".contains(&byte))
    {
        Err(ReviewError::InvalidReference)
    } else {
        Ok(())
    }
}

/// Bounded triage validation errors. Diagnostics never contain input values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ReviewError {
    /// A custom configuration lacks an explicitly bound persistent identity.
    #[error("custom native policy requires an exact caller-bound review reference")]
    CustomPolicyBindingRequired,
    /// The scan's exact identity differs from the bound policy.
    #[error("review policy does not match the scan's exact native identity")]
    PolicyMismatch,
    /// An identifier is empty, oversized or contains unsupported bytes.
    #[error("invalid bounded review identifier")]
    InvalidReference,
    /// A record or finding hard ceiling was exceeded.
    #[error("review resource limit exceeded")]
    LimitExceeded,
    /// More than one record addresses the same policy and occurrence.
    #[error("duplicate review record")]
    DuplicateRecord,
}
