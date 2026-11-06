//! Bounded JSON for opt-in review artifacts and numeric diagnostic projections.
//!
//! Review artifacts retain caller-supplied policy/source references and rule
//! IDs. Those metadata must be non-sensitive and artifacts access-controlled.
//! No finding text, path, credential, configuration or secret hash is copied.
//! Diagnostic projections omit even those caller-supplied strings.

use std::io::Write;

use rustleaks_core::model::{ByteRange, FindingRange, Location, ScanOptions};
use rustleaks_core::triage::{
    MAX_REVIEW_RECORDS, REVIEW_SCHEMA_VERSION, RecordState, ReviewClassification, ReviewError,
    ReviewOccurrence, ReviewReason, ReviewRecord, ReviewResult, ReviewSource, validate_records,
};
use serde_json::{Map, Value, json};

/// Hard byte ceiling for reading or writing one review JSON artifact.
pub const MAX_REVIEW_JSON_BYTES: usize = 8 * 1_024 * 1_024;

/// Writes bounded, versioned acknowledgement records without finding payloads.
///
/// The artifact retains metadata described in this module's data contract.
/// Destination failures can leave a partial artifact; replace persisted files
/// atomically in the caller's storage layer.
///
/// # Errors
/// Rejects duplicate or oversized records, byte-limit excess and output errors.
pub fn write_review_records(
    writer: &mut dyn Write,
    records: &[ReviewRecord],
) -> Result<(), TriageReportError> {
    validate_records(records)?;
    let records = records.iter().map(record_value).collect::<Vec<_>>();
    write_bounded(
        writer,
        &json!({"schema_version": REVIEW_SCHEMA_VERSION, "records": records}),
    )
}

fn record_value(record: &ReviewRecord) -> Value {
    let occurrence = record.occurrence();
    let options = record.options();
    json!({
        "policy_reference": record.policy_reference(),
        "options": {
            "max_decode_depth": options.max_decode_depth(),
            "max_target_bytes": options.max_target_bytes(),
            "redaction_percent": options.redaction_percent(),
            "honor_allow_markers": options.honor_allow_markers(),
        },
        "source_reference": occurrence.source().reference(),
        "rule_id": occurrence.rule_id(),
        "location": occurrence.location(),
        "match_range": occurrence.match_range(),
        "secret_range": occurrence.secret_range(),
        "finding_index": occurrence.index(),
        "reason": reason_name(record.reason()),
        "expires_at": record.expires_at(),
    })
}

fn reason_name(reason: ReviewReason) -> &'static str {
    match reason {
        ReviewReason::SyntheticFixture => "synthetic_fixture",
        ReviewReason::AcceptedRisk => "accepted_risk",
        ReviewReason::RemediationScheduled => "remediation_scheduled",
        _ => "unsupported",
    }
}

/// Restores bounded version-one records; does not apply or trust a policy ID.
///
/// The caller must rebind current exact policy and immutable source identity
/// before classifying findings. Expiry is checked by core review against the
/// caller's clock. Unknown schema versions, fields and reason codes fail closed.
///
/// # Errors
/// Rejects malformed/oversized artifacts, unknown versions, invalid metadata
/// and duplicate records. Errors do not contain input text.
pub fn read_review_records(bytes: &[u8]) -> Result<Vec<ReviewRecord>, TriageReportError> {
    if bytes.len() > MAX_REVIEW_JSON_BYTES {
        return Err(TriageReportError::LimitExceeded);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| TriageReportError::InvalidArtifact)?;
    let root = object(&value, &["schema_version", "records"])?;
    if root["schema_version"].as_u64() != Some(u64::from(REVIEW_SCHEMA_VERSION)) {
        return Err(TriageReportError::UnsupportedVersion);
    }
    let values = root["records"]
        .as_array()
        .ok_or(TriageReportError::InvalidArtifact)?;
    if values.len() > MAX_REVIEW_RECORDS {
        return Err(TriageReportError::LimitExceeded);
    }
    let records = values
        .iter()
        .map(parse_record)
        .collect::<Result<Vec<_>, _>>()?;
    validate_records(&records)?;
    Ok(records)
}

fn parse_record(value: &Value) -> Result<ReviewRecord, TriageReportError> {
    let record = object(
        value,
        &[
            "policy_reference",
            "options",
            "source_reference",
            "rule_id",
            "location",
            "match_range",
            "secret_range",
            "finding_index",
            "reason",
            "expires_at",
        ],
    )?;
    let options = object(
        &record["options"],
        &[
            "max_decode_depth",
            "max_target_bytes",
            "redaction_percent",
            "honor_allow_markers",
        ],
    )?;
    let options = ScanOptions::builder()
        .max_decode_depth(number(&options["max_decode_depth"])?)
        .max_target_bytes(optional_number(&options["max_target_bytes"])?)
        .redaction_percent(number(&options["redaction_percent"])?)
        .honor_allow_markers(
            options["honor_allow_markers"]
                .as_bool()
                .ok_or(TriageReportError::InvalidArtifact)?,
        )
        .build();
    let location = numbers::<4>(&record["location"])?;
    let location = Location::new(location[0], location[1], location[2], location[3])
        .map_err(|_| TriageReportError::InvalidArtifact)?;
    let occurrence = ReviewOccurrence::new(
        ReviewSource::caller_bound(string(&record["source_reference"])?)?,
        string(&record["rule_id"])?,
        location,
        parse_range(&record["match_range"])?,
        parse_range(&record["secret_range"])?,
        number(&record["finding_index"])?,
    )?;
    let reason = match string(&record["reason"])? {
        "synthetic_fixture" => ReviewReason::SyntheticFixture,
        "accepted_risk" => ReviewReason::AcceptedRisk,
        "remediation_scheduled" => ReviewReason::RemediationScheduled,
        _ => return Err(TriageReportError::InvalidArtifact),
    };
    Ok(ReviewRecord::new(
        string(&record["policy_reference"])?,
        options,
        occurrence,
        reason,
        record["expires_at"]
            .as_u64()
            .ok_or(TriageReportError::InvalidArtifact)?,
    )?)
}

fn object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, TriageReportError> {
    let object = value
        .as_object()
        .ok_or(TriageReportError::InvalidArtifact)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(TriageReportError::InvalidArtifact);
    }
    Ok(object)
}

fn string(value: &Value) -> Result<&str, TriageReportError> {
    value.as_str().ok_or(TriageReportError::InvalidArtifact)
}

fn number(value: &Value) -> Result<usize, TriageReportError> {
    value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(TriageReportError::InvalidArtifact)
}

fn optional_number(value: &Value) -> Result<Option<usize>, TriageReportError> {
    if value.is_null() {
        Ok(None)
    } else {
        number(value).map(Some)
    }
}

fn numbers<const N: usize>(value: &Value) -> Result<[usize; N], TriageReportError> {
    let values = value.as_array().ok_or(TriageReportError::InvalidArtifact)?;
    if values.len() != N {
        return Err(TriageReportError::InvalidArtifact);
    }
    let mut result = [0; N];
    for (destination, value) in result.iter_mut().zip(values) {
        *destination = number(value)?;
    }
    Ok(result)
}

fn parse_range(value: &Value) -> Result<FindingRange, TriageReportError> {
    if value.is_null() {
        return Ok(FindingRange::Unavailable);
    }
    let [start, end] = numbers::<2>(value)?;
    Ok(FindingRange::Exact(
        ByteRange::new(start, end).map_err(|_| TriageReportError::InvalidArtifact)?,
    ))
}

/// Writes numeric occurrence projections and finite workflow status codes.
///
/// Paths, IDs, source text, credentials, configurations and free-form reasons
/// are omitted. Original indices let a trusted caller join with sensitive data
/// separately. An incomplete scan always retains `complete: false`.
///
/// # Errors
/// Returns a byte-limit or destination error without silently truncating data.
pub fn write_review_projection(
    writer: &mut dyn Write,
    result: &ReviewResult<'_>,
) -> Result<(), TriageReportError> {
    let occurrences = result
        .occurrences()
        .iter()
        .zip(result.classifications())
        .map(|(occurrence, classification)| {
            let (state, record_index) = match classification {
                ReviewClassification::New => ("new", None),
                ReviewClassification::Acknowledged { record_index } => {
                    ("acknowledged", Some(*record_index))
                }
            };
            json!({
                "finding_index": occurrence.index(), "location": occurrence.location(),
                "match_range": occurrence.match_range(), "secret_range": occurrence.secret_range(),
                "state": state, "record_index": record_index,
            })
        })
        .collect::<Vec<_>>();
    let records = result
        .record_states()
        .iter()
        .enumerate()
        .map(|(index, state)| {
            let (state, finding_index) = match state {
                RecordState::Active { finding_index } => ("active", Some(*finding_index)),
                RecordState::StalePolicy => ("stale_policy", None),
                RecordState::StaleOptions => ("stale_options", None),
                RecordState::StaleSource => ("stale_source", None),
                RecordState::Expired => ("expired", None),
                RecordState::StaleOccurrence => ("stale_occurrence", None),
                RecordState::UnobservedInPartialScan => ("unobserved_in_partial_scan", None),
                _ => ("unsupported", None),
            };
            json!({"record_index": index, "state": state, "finding_index": finding_index})
        })
        .collect::<Vec<_>>();
    write_bounded(
        writer,
        &json!({
            "schema_version": REVIEW_SCHEMA_VERSION, "complete": result.is_complete(),
            "occurrences": occurrences, "records": records,
        }),
    )
}

fn write_bounded(writer: &mut dyn Write, value: &Value) -> Result<(), TriageReportError> {
    let bytes = serde_json::to_vec(value).map_err(|_| TriageReportError::InvalidArtifact)?;
    if bytes.len() >= MAX_REVIEW_JSON_BYTES {
        return Err(TriageReportError::LimitExceeded);
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Review artifact errors with no copied source or configuration text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TriageReportError {
    /// A bounded identifier or duplicate record was rejected by core.
    #[error(transparent)]
    Review(#[from] ReviewError),
    /// A JSON byte or record ceiling was exceeded.
    #[error("review JSON resource limit exceeded")]
    LimitExceeded,
    /// The artifact has an unsupported schema version.
    #[error("unsupported review schema version")]
    UnsupportedVersion,
    /// A malformed, unknown or invalid metadata field was encountered.
    #[error("invalid review JSON artifact")]
    InvalidArtifact,
    /// The destination rejected serialized bytes.
    #[error("could not write review JSON: {0}")]
    Io(#[from] std::io::Error),
}
