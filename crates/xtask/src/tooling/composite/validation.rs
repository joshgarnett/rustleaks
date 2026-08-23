//! Schema, count, negative-control, and semantic checks for fresh outcomes.

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use super::process::Observed;
use super::spec::{Canonical, DEFAULT_SHA256, OUTCOMES_SHA256, REVISION};
use crate::tooling::support::sha256_bytes;

const RESPONSE_KEYS: &[&str] = &[
    "behavior_ids",
    "config_sha256",
    "default_config_sha256",
    "error",
    "findings",
    "go_version",
    "id",
    "input_sha256",
    "mask_secret_base64",
    "operation",
    "oracle_mode",
    "original",
    "protocol_version",
    "redact_percent",
    "redacted",
    "test_case_ids",
    "upstream_revision",
];
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
const REQUIRED_KEYS: &[&str] = &[
    "end_column",
    "end_line",
    "line_base64",
    "match_base64",
    "rule_id",
    "secret_base64",
    "start_column",
    "start_line",
];

pub(super) struct Summary {
    pub(super) requests: usize,
    pub(super) findings: usize,
    pub(super) required_findings: usize,
    pub(super) outcomes_sha256: String,
}

pub(super) fn validate(canonical: &Canonical, observed: &Observed) -> Result<Summary, String> {
    let outcomes = records(&observed.outcomes)?;
    if outcomes.len() != 182 || outcomes.len() != canonical.request_values.len() {
        return Err(format!(
            "fresh composite outcome count changed: {}",
            outcomes.len()
        ));
    }
    let response_keys = set(RESPONSE_KEYS);
    let finding_keys = set(FINDING_KEYS);
    let required_keys = set(REQUIRED_KEYS);
    let mut by_id = BTreeMap::new();
    let mut finding_count = 0;
    let mut required_count = 0;
    let mut errors = BTreeMap::new();
    for (request, outcome) in canonical.request_values.iter().zip(&outcomes) {
        let id = text(request, "id", "request")?;
        require_keys(outcome, &response_keys, id)?;
        if outcome["protocol_version"] != 1
            || outcome["oracle_mode"] != "composite"
            || outcome["id"] != id
            || outcome["behavior_ids"] != request["behavior_ids"]
            || outcome["test_case_ids"] != request["test_case_ids"]
            || outcome["operation"] != request["operation"]
            || outcome["upstream_revision"] != REVISION
            || outcome["default_config_sha256"] != DEFAULT_SHA256
        {
            return Err(format!("{id}: fresh composite response envelope changed"));
        }
        if !outcome["go_version"]
            .as_str()
            .is_some_and(|version| version.starts_with("go1.25."))
        {
            return Err(format!("{id}: fresh composite Go version changed"));
        }
        let findings = outcome["findings"]
            .as_array()
            .ok_or_else(|| format!("{id}: findings is not an array"))?;
        finding_count += findings.len();
        for finding in findings {
            require_keys(finding, &finding_keys, id)?;
            let required = finding["required_findings"]
                .as_array()
                .ok_or_else(|| format!("{id}: required_findings is not an array"))?;
            required_count += required.len();
            for attachment in required {
                require_keys(attachment, &required_keys, id)?;
            }
        }
        if let Some(error) = outcome["error"].as_object() {
            errors.insert(
                id.to_owned(),
                error
                    .get("class")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{id}: error class is missing"))?
                    .to_owned(),
            );
        }
        if by_id.insert(id.to_owned(), outcome).is_some() {
            return Err(format!("duplicate fresh composite outcome {id}"));
        }
    }
    if finding_count != 275 || required_count != 1623 {
        return Err(format!(
            "composite finding totals changed: {finding_count} findings, {required_count} attachments"
        ));
    }
    if errors
        != BTreeMap::from([
            ("required-config-empty-id".into(), "config".into()),
            ("required-config-missing-id".into(), "config".into()),
        ])
    {
        return Err(format!("composite error identity set changed: {errors:?}"));
    }
    validate_controls(&by_id)?;
    validate_negative_pairs(canonical, &by_id)?;
    let outcomes_sha256 = sha256_bytes(&observed.outcomes);
    if outcomes_sha256 != OUTCOMES_SHA256 {
        return Err(format!(
            "fresh composite outcomes SHA-256 changed: expected {OUTCOMES_SHA256}, got {outcomes_sha256}"
        ));
    }
    Ok(Summary {
        requests: outcomes.len(),
        findings: finding_count,
        required_findings: required_count,
        outcomes_sha256,
    })
}

fn validate_controls(by_id: &BTreeMap<String, &Value>) -> Result<(), String> {
    let extension = get(by_id, "required-extension-disabled-dependency-fail-closed")?;
    if extension["config_sha256"]
        != "50cbe78501cf4585751b8364e6c462c65023c865bfb3e1e674325367366bc3a8"
        || !extension["error"].is_null()
        || count(extension)? != 0
    {
        return Err("extension dangling-required control changed".into());
    }
    let tm = &get(by_id, "upstream-tm-0084-fragment-level-composite")?["findings"][0];
    if values(
        tm,
        &[
            "rule_id",
            "start_line",
            "end_line",
            "start_column",
            "end_column",
        ],
    ) != vec![
        Value::from("primary-rule"),
        5.into(),
        5.into(),
        5.into(),
        26.into(),
    ] || tm["required_findings"][0]["rule_id"] != "username-rule"
        || decode(
            &tm["required_findings"][0]["secret_base64"],
            "TM-0084 secret",
        )? != b"admin"
    {
        return Err("TM-0084 composite geometry/projection changed".into());
    }
    let duplicate = get(by_id, "required-duplicate-specs")?["findings"][0]["required_findings"]
        .as_array()
        .ok_or("duplicate required vector missing")?
        .iter()
        .map(|finding| decode(&finding["secret_base64"], "duplicate secret"))
        .collect::<Result<Vec<_>, _>>()?;
    if duplicate != [b"one", b"two", b"one", b"two"] {
        return Err("duplicate required attachment order changed".into());
    }
    for (id, expected) in [
        ("upstream-tm-0246-high-masking", b"s...".as_slice()),
        ("upstream-tm-0247-invalid-masking", b"...".as_slice()),
        ("upstream-tm-0248-low-masking", b"secre...".as_slice()),
        ("upstream-tm-0249-normal-masking", b"se...".as_slice()),
    ] {
        if decode(&get(by_id, id)?["mask_secret_base64"], id)? != expected {
            return Err(format!("{id}: private mask changed"));
        }
    }
    if count(get(by_id, "resource-primary-aux-duplicate-cartesian")?)? != 16
        || count(get(by_id, "resource-many-generics")?)? != 128
        || count(get(by_id, "resource-deep-required-cycle")?)? != 1
    {
        return Err("bounded resource controls changed".into());
    }
    let adapter = &get(by_id, "generic-filter-adapter-ignores-file-column-end")?["findings"];
    if adapter.as_array().map(Vec::len) != Some(1)
        || adapter[0]["rule_id"] != "specific-adapter"
        || decode(&adapter[0]["file_base64"], "filter adapter file")? != b"specific.go"
    {
        return Err("private final-filter adapter predicate changed".into());
    }
    let direct_zero = decode(
        &get(by_id, "redact-direct-zero")?["redacted"]["secret_base64"],
        "direct zero",
    )?;
    let detector_zero = decode(
        &get(by_id, "redact-detector-option-zero")?["findings"][0]["secret_base64"],
        "detector zero",
    )?;
    if direct_zero != b"secret..." || detector_zero != b"VALUE" {
        return Err("redaction zero boundary changed".into());
    }
    Ok(())
}

fn validate_negative_pairs(
    canonical: &Canonical,
    by_id: &BTreeMap<String, &Value>,
) -> Result<(), String> {
    let controls: Value = serde_json::from_slice(&canonical.negative_controls)
        .map_err(|error| format!("invalid canonical negative controls: {error}"))?;
    for pair in controls["same_count_substitutions"]
        .as_array()
        .ok_or("negative-control pairs missing")?
    {
        let positive = text(pair, "positive", "negative control")?;
        let negative = text(pair, "negative", "negative control")?;
        if count(get(by_id, positive)?)? <= count(get(by_id, negative)?)? {
            return Err(format!(
                "negative-control discrimination changed: {positive} vs {negative}"
            ));
        }
    }
    Ok(())
}

fn records(bytes: &[u8]) -> Result<Vec<Value>, String> {
    if !bytes.ends_with(b"\n") {
        return Err("fresh composite outcomes lack final newline".into());
    }
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .map(|(index, line)| {
            if line == b"\n" {
                return Err(format!(
                    "fresh composite outcome line {} is blank",
                    index + 1
                ));
            }
            serde_json::from_slice(line).map_err(|error| {
                format!(
                    "fresh composite outcome line {} is invalid: {error}",
                    index + 1
                )
            })
        })
        .collect()
}

fn require_keys(value: &Value, expected: &BTreeSet<String>, id: &str) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| format!("{id}: expected JSON object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if &actual != expected {
        return Err(format!(
            "{id}: schema keys changed: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn get<'a>(values: &'a BTreeMap<String, &Value>, id: &str) -> Result<&'a Value, String> {
    values
        .get(id)
        .copied()
        .ok_or_else(|| format!("missing composite control {id}"))
}

fn count(value: &Value) -> Result<usize, String> {
    value["findings"]
        .as_array()
        .map(Vec::len)
        .ok_or("findings is not an array".into())
}

fn text<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{label}: {field} is not a string"))
}

fn decode(value: &Value, label: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(
            value
                .as_str()
                .ok_or_else(|| format!("{label} is not a string"))?,
        )
        .map_err(|error| format!("{label} is invalid base64: {error}"))
}

fn values(value: &Value, fields: &[&str]) -> Vec<Value> {
    fields.iter().map(|field| value[*field].clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::{FINDING_KEYS, REQUIRED_KEYS, RESPONSE_KEYS, set};

    #[test]
    fn schema_key_inventories_are_unique() {
        assert_eq!(set(RESPONSE_KEYS).len(), RESPONSE_KEYS.len());
        assert_eq!(set(FINDING_KEYS).len(), FINDING_KEYS.len());
        assert_eq!(set(REQUIRED_KEYS).len(), REQUIRED_KEYS.len());
    }
}
