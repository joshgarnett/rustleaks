//! Session response envelopes, counts, hashes, and complete projections.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::controls;
use super::spec::{CONFIG_SHA256, PROTOCOL_VERSION, REQUEST_COUNT, REVISION};
use crate::tooling::support::sha256_bytes;

const FINDING_KEYS: &[&str] = &[
    "author_base64",
    "commit_base64",
    "date_base64",
    "description_base64",
    "email_base64",
    "end_column",
    "end_line",
    "entropy_bits",
    "file_base64",
    "fingerprint_base64",
    "fragment",
    "line_base64",
    "link_base64",
    "match_base64",
    "message_base64",
    "required_findings",
    "rule_id",
    "secret_base64",
    "start_column",
    "start_line",
    "symlink_file_base64",
    "tags_base64",
];

pub(super) fn validate_envelope(
    request: &Value,
    outcome: &Value,
    go_version: &str,
) -> Result<(), String> {
    let id = required_str(request, "id", "request")?;
    if required_str(outcome, "id", id)? != id
        || required_u64(outcome, "protocol_version", id)? != PROTOCOL_VERSION
        || required_str(outcome, "oracle_mode", id)? != "session"
        || required_str(outcome, "upstream_revision", id)? != REVISION
        || required_str(outcome, "default_config_sha256", id)? != CONFIG_SHA256
        || required_str(outcome, "go_version", id)? != go_version
        || required_str(outcome, "operation", id)? != "session"
    {
        return Err(format!("{id}: session oracle envelope changed"));
    }
    for field in ["behavior_ids", "test_case_ids"] {
        if request.get(field) != outcome.get(field) {
            return Err(format!("{id}: {field} changed in oracle response"));
        }
    }
    for field in [
        "input_findings",
        "decisions",
        "collected_findings",
        "canonical_findings",
    ] {
        if !outcome.get(field).is_some_and(Value::is_array) {
            return Err(format!("{id}: {field} is not an array"));
        }
    }
    if !outcome
        .pointer("/baseline/findings")
        .is_some_and(Value::is_array)
    {
        return Err(format!("{id}: baseline findings are not an array"));
    }
    Ok(())
}

pub(super) fn validate_all(
    requests: &[Value],
    outcomes: &[Value],
    outcome_bytes: &[u8],
    coverage: &Value,
    negative: &Value,
    manifest: &Value,
) -> Result<(), String> {
    if requests.len() != REQUEST_COUNT || requests.len() != outcomes.len() {
        return Err("session request/outcome count mismatch".into());
    }
    let by_id = outcomes
        .iter()
        .map(|outcome| required_str(outcome, "id", "outcome").map(|id| (id, outcome)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if by_id.len() != REQUEST_COUNT {
        return Err("session outcomes contain duplicate ids".into());
    }
    for (request, outcome) in requests.iter().zip(outcomes) {
        let id = required_str(request, "id", "request")?;
        if required_str(outcome, "id", "outcome")? != id {
            return Err(format!("{id}: outcome order changed"));
        }
    }
    validate_errors(outcomes)?;
    validate_projection(outcomes)?;
    controls::validate(&by_id, coverage, negative)?;
    validate_counts(outcomes, manifest)?;
    let outcome_entry = &required_object(manifest, "files", "manifest")?["outcomes-v1.jsonl"];
    if required_str(outcome_entry, "sha256", "outcomes")? != sha256_bytes(outcome_bytes)
        || required_u64(outcome_entry, "records", "outcomes")? != REQUEST_COUNT as u64
    {
        return Err("fresh session outcomes differ from the committed manifest".into());
    }
    Ok(())
}

fn validate_errors(outcomes: &[Value]) -> Result<(), String> {
    let expected = BTreeMap::from([
        (
            "ignore-missing",
            ("ignore-open", "could not open .gitleaksignore"),
        ),
        (
            "baseline-invalid-csv",
            (
                "baseline-format",
                "the format of the file baseline.csv is not supported",
            ),
        ),
        (
            "baseline-invalid-sarif",
            (
                "baseline-format",
                "the format of the file baseline.sarif is not supported",
            ),
        ),
        (
            "baseline-float32-overflow",
            (
                "baseline-format",
                "the format of the file baseline.json is not supported",
            ),
        ),
        (
            "baseline-missing",
            ("baseline-open", "could not open notfound.json"),
        ),
    ]);
    for outcome in outcomes {
        let id = required_str(outcome, "id", "outcome")?;
        match expected.get(id) {
            Some((class, message)) => {
                if outcome.pointer("/error/class").and_then(Value::as_str) != Some(class)
                    || outcome.pointer("/error/message").and_then(Value::as_str) != Some(message)
                {
                    return Err(format!("{id}: structured error changed"));
                }
            }
            None if !outcome.get("error").is_some_and(Value::is_null) => {
                return Err(format!("{id}: unexpected session error"));
            }
            None => {}
        }
    }
    Ok(())
}

fn validate_projection(outcomes: &[Value]) -> Result<(), String> {
    let expected = FINDING_KEYS.iter().copied().collect::<BTreeSet<_>>();
    for outcome in outcomes {
        let id = required_str(outcome, "id", "outcome")?;
        for field in ["input_findings", "collected_findings", "canonical_findings"] {
            for finding in required_array(outcome, field, id)? {
                let keys = finding
                    .as_object()
                    .ok_or_else(|| format!("{id}: {field} contains a non-object"))?
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                if keys != expected {
                    return Err(format!("{id}: complete finding projection changed"));
                }
            }
        }
    }
    Ok(())
}

fn validate_counts(outcomes: &[Value], manifest: &Value) -> Result<(), String> {
    let sum = |pointer: &str| -> Result<u64, String> {
        outcomes
            .iter()
            .map(|outcome| {
                outcome
                    .pointer(pointer)
                    .and_then(Value::as_array)
                    .map(|items| items.len() as u64)
                    .ok_or_else(|| format!("outcome is missing {pointer}"))
            })
            .sum()
    };
    for (field, actual) in [
        ("request_count", REQUEST_COUNT as u64),
        ("outcome_count", outcomes.len() as u64),
        ("input_finding_count", sum("/input_findings")?),
        ("collected_finding_count", sum("/collected_findings")?),
        ("baseline_finding_count", sum("/baseline/findings")?),
        ("behavior_count", 10),
        ("upstream_identity_count", 10),
        ("material_assertion_count", 33),
    ] {
        if required_u64(manifest, field, "manifest")? != actual {
            return Err(format!("session manifest {field} changed"));
        }
    }
    Ok(())
}

pub(super) fn render_manifest(
    legacy: &[u8],
    manifest: &Value,
    readme: &[u8],
) -> Result<Vec<u8>, String> {
    let old = required_str(
        &required_object(manifest, "files", "manifest")?["README.md"],
        "sha256",
        "README",
    )?;
    let new = sha256_bytes(readme);
    replace_once(legacy, old.as_bytes(), new.as_bytes(), "README digest")
}

fn replace_once(bytes: &[u8], old: &[u8], new: &[u8], label: &str) -> Result<Vec<u8>, String> {
    if old.len() != new.len() {
        return Err(format!("cannot replace {label} without changing layout"));
    }
    let matches = bytes
        .windows(old.len())
        .enumerate()
        .filter(|(_, window)| *window == old)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!("expected one {label}, found {}", matches.len()));
    }
    let mut rendered = bytes.to_vec();
    rendered[matches[0]..matches[0] + old.len()].copy_from_slice(new);
    Ok(rendered)
}

pub(super) fn required_object<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label}: {field} must be an object"))
}

pub(super) fn required_array<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Vec<Value>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: {field} must be an array"))
}

pub(super) fn required_str<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: {field} must be a string"))
}

pub(super) fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label}: {field} must be a nonnegative integer"))
}

pub(super) fn strings<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<Vec<&'a str>, String> {
    required_array(value, field, label)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("{label}: {field} contains a non-string"))
        })
        .collect()
}

pub(super) fn outcome_for<'a>(
    outcomes: &'a BTreeMap<&str, &Value>,
    id: &str,
) -> Result<&'a Value, String> {
    outcomes
        .get(id)
        .copied()
        .ok_or_else(|| format!("missing session outcome {id}"))
}

#[cfg(test)]
mod tests {
    use super::replace_once;

    #[test]
    fn provenance_replacement_is_exact_and_unique() {
        assert_eq!(
            replace_once(b"before-old-after", b"old", b"new", "test").unwrap(),
            b"before-new-after"
        );
        assert!(replace_once(b"old-old", b"old", b"new", "test").is_err());
        assert!(replace_once(b"missing", b"old", b"new", "test").is_err());
    }
}
