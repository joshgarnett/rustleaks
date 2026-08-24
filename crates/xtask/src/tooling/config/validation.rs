//! Semantic and byte-level validation of fresh configuration observations.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::process::Observed;
use super::spec::{CONFIG_SHA256, Canonical, OUTCOMES_SHA256, REVISION};
use crate::tooling::support::sha256_bytes;

const ERROR_IDENTITIES_SHA256: &str =
    "769fe05a9f51f40c51a37261a35ec4057139b676c6f65856db65ee326b385e01";

pub(super) struct Summary {
    pub(super) case_count: usize,
    pub(super) success_count: usize,
    pub(super) error_count: usize,
    pub(super) outcomes_sha256: String,
}

pub(super) fn validate_all(canonical: &Canonical, observed: &Observed) -> Result<Summary, String> {
    require_hash(
        "fresh default configuration",
        &observed.default_config,
        CONFIG_SHA256,
    )?;
    if observed.default_config != canonical.committed_default {
        return Err("fresh default configuration differs from committed canonical bytes".into());
    }
    let outcomes = jsonl(&observed.outcomes, "fresh config outcomes")?;
    if outcomes.len() != canonical.request_values.len() || outcomes.len() != 112 {
        return Err(format!(
            "fresh config outcome count changed: expected 112, got {}",
            outcomes.len()
        ));
    }
    let response_fields = canonical.schema_value()?["response"]
        .as_array()
        .ok_or("config schema response is not an array")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "config schema response field is not a string".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut by_id = BTreeMap::new();
    let mut errors = Vec::new();
    let mut success_count = 0;
    for (request, outcome) in canonical.request_values.iter().zip(&outcomes) {
        validate_envelope(request, outcome, &response_fields)?;
        let id = required_str(outcome, "id", "config outcome")?;
        if by_id.insert(id.to_owned(), outcome).is_some() {
            return Err(format!("duplicate fresh config outcome ID {id}"));
        }
        if outcome["error"].is_null() {
            success_count += 1;
            if !outcome["effective"].is_object() {
                return Err(format!("{id}: successful outcome has no effective config"));
            }
        } else {
            errors.push(format!("{id}\n"));
            if !outcome["error"].is_object() || !outcome["effective"].is_null() {
                return Err(format!("{id}: error/effective exclusivity changed"));
            }
        }
    }
    let error_count = outcomes.len() - success_count;
    if success_count != 75 || error_count != 37 {
        return Err(format!(
            "config success/error totals changed: {success_count} successful, {error_count} errors"
        ));
    }
    errors.sort();
    require_hash(
        "config error identity set",
        errors.concat().as_bytes(),
        ERROR_IDENTITIES_SHA256,
    )?;
    validate_semantic_controls(&by_id)?;
    let outcomes_sha256 = sha256_bytes(&observed.outcomes);
    if outcomes_sha256 != OUTCOMES_SHA256 {
        return Err(format!(
            "fresh config outcomes SHA-256 changed: expected {OUTCOMES_SHA256}, got {outcomes_sha256}"
        ));
    }
    Ok(Summary {
        case_count: outcomes.len(),
        success_count,
        error_count,
        outcomes_sha256,
    })
}

fn validate_envelope(
    request: &Value,
    outcome: &Value,
    response_fields: &BTreeSet<String>,
) -> Result<(), String> {
    let object = outcome
        .as_object()
        .ok_or("fresh config outcome is not an object")?;
    let actual_fields = object.keys().cloned().collect::<BTreeSet<_>>();
    if &actual_fields != response_fields {
        return Err(format!(
            "config response fields changed: expected {response_fields:?}, got {actual_fields:?}"
        ));
    }
    let id = required_str(request, "id", "config request")?;
    if outcome["protocol_version"] != 1
        || outcome["oracle_mode"] != "config"
        || outcome["id"] != id
        || outcome["upstream_revision"] != REVISION
        || outcome["default_config_sha256"] != CONFIG_SHA256
        || outcome["config_sha256"] != request["input_sha256"]
    {
        return Err(format!("{id}: fresh config outcome envelope changed"));
    }
    let version = required_str(outcome, "go_version", id)?;
    if !version.starts_with("go1.26.") {
        return Err(format!("{id}: unsupported Go version {version}"));
    }
    if !outcome["source"].is_object() || !outcome["diagnostics"].is_array() {
        return Err(format!(
            "{id}: source or diagnostics response shape changed"
        ));
    }
    Ok(())
}

fn validate_semantic_controls(by_id: &BTreeMap<String, &Value>) -> Result<(), String> {
    let default = outcome(by_id, "default/pinned")?;
    require_effective_counts(default, "default/pinned", 222, 222, 0)?;
    let simple = outcome(by_id, "fixture/simple")?;
    require_effective_counts(simple, "fixture/simple", 36, 37, 1)?;

    let depth = outcome(by_id, "focused/depth-limit")?;
    let depth_ids = effective(depth, "focused/depth-limit")?["rules"]
        .as_array()
        .ok_or("focused/depth-limit: effective rules is not an array")?
        .iter()
        .map(|rule| required_str(rule, "id", "focused/depth-limit rule"))
        .collect::<Result<Vec<_>, _>>()?;
    if depth_ids != ["depth-1", "depth-2", "depth-root"] {
        return Err(format!("extension depth semantics changed: {depth_ids:?}"));
    }

    let mut first = outcome(by_id, "focused/reentrant-a")?.clone();
    let mut second = outcome(by_id, "focused/reentrant-b")?.clone();
    remove_id(&mut first)?;
    remove_id(&mut second)?;
    if first != second {
        return Err("fresh-process reentrant outcomes differ".into());
    }
    Ok(())
}

fn require_effective_counts(
    value: &Value,
    id: &str,
    rules: usize,
    ordered: usize,
    duplicates: usize,
) -> Result<(), String> {
    if !value["error"].is_null() {
        return Err(format!("{id}: expected successful config"));
    }
    let effective = effective(value, id)?;
    let actual = (
        array_len(effective, "rules", id)?,
        array_len(effective, "ordered_rule_ids", id)?,
        array_len(effective, "duplicate_rule_ids", id)?,
    );
    if actual != (rules, ordered, duplicates) {
        return Err(format!(
            "{id}: rule bookkeeping changed: expected ({rules}, {ordered}, {duplicates}), got {actual:?}"
        ));
    }
    Ok(())
}

fn outcome<'a>(by_id: &'a BTreeMap<String, &Value>, id: &str) -> Result<&'a Value, String> {
    by_id
        .get(id)
        .copied()
        .ok_or_else(|| format!("missing semantic control outcome {id}"))
}

fn effective<'a>(value: &'a Value, id: &str) -> Result<&'a Map<String, Value>, String> {
    value["effective"]
        .as_object()
        .ok_or_else(|| format!("{id}: effective config is not an object"))
}

fn array_len(value: &Map<String, Value>, field: &str, id: &str) -> Result<usize, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| format!("{id}: effective {field} is not an array"))
}

fn remove_id(value: &mut Value) -> Result<(), String> {
    value
        .as_object_mut()
        .ok_or("reentrant outcome is not an object")?
        .remove("id")
        .ok_or("reentrant outcome has no ID")?;
    Ok(())
}

fn jsonl(bytes: &[u8], label: &str) -> Result<Vec<Value>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} lacks a final newline"));
    }
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .map(|(index, line)| {
            if line == b"\n" {
                return Err(format!("{label} line {} is blank", index + 1));
            }
            serde_json::from_slice(line)
                .map_err(|error| format!("{label} line {} is invalid JSON: {error}", index + 1))
        })
        .collect()
}

fn required_str<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: {field} is not a string"))
}

fn require_hash(label: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let actual = sha256_bytes(bytes);
    if actual != expected {
        return Err(format!(
            "{label} SHA-256 changed: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::validate_envelope;

    #[test]
    fn envelope_rejects_wrong_revision_and_extra_fields() {
        let request = json!({"id":"case","input_sha256":"input"});
        let outcome = json!({
            "protocol_version":1, "oracle_mode":"config", "id":"case",
            "upstream_revision":"wrong", "default_config_sha256":"wrong",
            "go_version":"go1.26.0", "source":{}, "config_sha256":"input",
            "effective":{}, "diagnostics":[], "error":null
        });
        let fields = outcome
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(validate_envelope(&request, &outcome, &fields).is_err());
        let mut fields_with_extra = fields;
        fields_with_extra.insert("extra".into());
        assert!(validate_envelope(&request, &outcome, &fields_with_extra).is_err());
    }
}
