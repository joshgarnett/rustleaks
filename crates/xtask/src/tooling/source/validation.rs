//! Source response envelopes, hashes, counts, and complete projections.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value, json};

use super::spec::{CONFIG_SHA256, PROTOCOL_VERSION, REQUEST_COUNT, REVISION};
use super::{controls, controls_archive};
use crate::tooling::{
    artifacts::{OutcomeBaseline, compare_json_outcomes},
    support::sha256_bytes,
};

const FRAGMENT_KEYS: &[&str] = &[
    "bytes_base64",
    "bytes_nil",
    "commit_base64",
    "file_base64",
    "inherited_from_finding",
    "raw_base64",
    "start_line",
    "symlink_file_base64",
    "windows_file_base64",
];

pub(super) fn validate_envelope(
    request: &Value,
    outcome: &Value,
    go_version: &str,
    platform: &str,
) -> Result<(), String> {
    let id = required_str(request, "id", "request")?;
    if required_str(outcome, "id", id)? != id
        || required_u64(outcome, "protocol_version", id)? != PROTOCOL_VERSION
        || required_str(outcome, "oracle_mode", id)? != "source"
        || required_str(outcome, "upstream_revision", id)? != REVISION
        || required_str(outcome, "default_config_sha256", id)? != CONFIG_SHA256
        || required_str(outcome, "go_version", id)? != go_version
        || required_str(outcome, "platform", id)? != platform
        || request.get("operation") != outcome.get("operation")
    {
        return Err(format!("{id}: source oracle envelope changed"));
    }
    for field in ["behavior_ids", "test_case_ids"] {
        if request.get(field) != outcome.get(field) {
            return Err(format!("{id}: {field} changed in oracle response"));
        }
    }
    for field in ["fragments", "canonical_fragments", "findings", "issues"] {
        if !outcome.get(field).is_some_and(Value::is_array) {
            return Err(format!("{id}: {field} is not an array"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct ValidationMetadata<'a> {
    pub(super) coverage: &'a Value,
    pub(super) negative: &'a Value,
    pub(super) native_windows: &'a Value,
    pub(super) manifest: &'a Value,
}

pub(super) fn validate_all(
    root: &Path,
    requests: &[Value],
    observed: OutcomeBaseline<'_>,
    committed: OutcomeBaseline<'_>,
    metadata: ValidationMetadata<'_>,
) -> Result<(), String> {
    let ValidationMetadata {
        coverage,
        negative,
        native_windows,
        manifest,
    } = metadata;
    let outcomes = observed.values;
    if requests.len() != REQUEST_COUNT || requests.len() != outcomes.len() {
        return Err("source request/outcome count mismatch".into());
    }
    let by_id = outcomes
        .iter()
        .map(|outcome| required_str(outcome, "id", "outcome").map(|id| (id, outcome)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if by_id.len() != REQUEST_COUNT {
        return Err("source outcomes contain duplicate ids".into());
    }
    for (request, outcome) in requests.iter().zip(outcomes) {
        let id = required_str(request, "id", "request")?;
        if required_str(outcome, "id", "outcome")? != id {
            return Err(format!("{id}: outcome order changed"));
        }
    }
    let committed_go = required_str(manifest, "go_version", "manifest")?;
    let committed_platform = required_str(manifest, "platform", "manifest")?;
    for (request, outcome) in requests.iter().zip(committed.values) {
        validate_envelope(request, outcome, committed_go, committed_platform)?;
    }
    validate_projection(outcomes)?;
    controls::validate(&by_id, outcomes, negative)?;
    controls_archive::validate(root, &by_id)?;
    validate_counts(
        outcomes,
        coverage,
        manifest,
        !uniform_string(outcomes, "platform", "frozen source")?.starts_with("windows/"),
    )?;
    let entry = &required_object(manifest, "files", "manifest")?["outcomes-v1.jsonl"];
    if required_str(entry, "sha256", "outcomes")? != sha256_bytes(committed.bytes)
        || required_u64(entry, "records", "outcomes")? != REQUEST_COUNT as u64
    {
        return Err("committed source outcomes differ from their manifest".into());
    }
    validate_native_windows_ledger(committed, observed, native_windows)?;
    if !uniform_string(observed.values, "platform", "frozen source")?.starts_with("windows/") {
        // The committed platform remains pinned provenance. Non-Windows
        // cross-host replays may differ only in that envelope field.
        compare_json_outcomes(committed.values, outcomes, &["platform"], "source")?;
    }
    Ok(())
}

fn validate_native_windows_ledger(
    committed: OutcomeBaseline<'_>,
    observed: OutcomeBaseline<'_>,
    ledger: &Value,
) -> Result<(), String> {
    if required_u64(ledger, "schema_version", "native Windows ledger")? != 1
        || required_u64(ledger, "protocol_version", "native Windows ledger")? != PROTOCOL_VERSION
        || required_str(ledger, "oracle_mode", "native Windows ledger")? != "source"
        || required_str(ledger, "upstream_revision", "native Windows ledger")? != REVISION
        || required_str(ledger, "default_config_sha256", "native Windows ledger")? != CONFIG_SHA256
        || required_u64(ledger, "record_count", "native Windows ledger")? != REQUEST_COUNT as u64
    {
        return Err("native Windows source ledger provenance changed".into());
    }
    let committed_platform = uniform_string(committed.values, "platform", "committed source")?;
    let committed_go = uniform_string(committed.values, "go_version", "committed source")?;
    if required_str(ledger, "baseline_platform", "native Windows ledger")? != committed_platform
        || required_str(ledger, "go_version", "native Windows ledger")? != committed_go
    {
        return Err("native Windows source ledger baseline changed".into());
    }

    let (_, committed_semantic_bytes) = semantic_outcomes(committed.values)?;
    if required_str(
        ledger,
        "baseline_semantic_outcomes_sha256",
        "native Windows ledger",
    )? != sha256_bytes(&committed_semantic_bytes)
    {
        return Err("native Windows source ledger baseline hash changed".into());
    }
    let platforms = required_object(ledger, "platforms", "native Windows ledger")?;
    let expected_platforms = ["windows/amd64", "windows/arm64"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if platforms
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_platforms
    {
        return Err("native Windows source ledger platform set changed".into());
    }
    for platform in &expected_platforms {
        validate_sha256(
            required_str(&platforms[*platform], "outcomes_sha256", platform)?,
            platform,
        )?;
    }
    validate_sha256(
        required_str(ledger, "semantic_outcomes_sha256", "native Windows ledger")?,
        "native Windows semantic outcomes",
    )?;

    if !uniform_string(observed.values, "platform", "frozen source")?.starts_with("windows/") {
        return Ok(());
    }

    let observed_platform = uniform_string(observed.values, "platform", "observed source")?;
    let expected_raw = required_str(
        &platforms[observed_platform],
        "outcomes_sha256",
        observed_platform,
    )?;
    if sha256_bytes(observed.bytes) != expected_raw {
        return Err(format!(
            "native Windows source outcomes changed for {observed_platform}"
        ));
    }
    let (observed_semantic, observed_semantic_bytes) = semantic_outcomes(observed.values)?;
    if sha256_bytes(&observed_semantic_bytes)
        != required_str(ledger, "semantic_outcomes_sha256", "native Windows ledger")?
    {
        return Err("native Windows source semantic outcomes changed".into());
    }
    let (committed_semantic, _) = semantic_outcomes(committed.values)?;
    if committed_semantic.len() != observed_semantic.len() {
        return Err("native Windows source semantic outcome count changed".into());
    }
    let mut difference_ids = Vec::new();
    let mut structural = Vec::new();
    for (baseline, windows) in committed_semantic.iter().zip(&observed_semantic) {
        let baseline_id = required_str(baseline, "id", "source baseline")?;
        if required_str(windows, "id", "Windows source outcome")? != baseline_id {
            return Err("native Windows source outcome order changed".into());
        }
        if baseline != windows {
            difference_ids.push(Value::String(baseline_id.to_owned()));
        }
        let baseline_structure = outcome_structure(baseline, baseline_id)?;
        let windows_structure = outcome_structure(windows, baseline_id)?;
        if baseline_structure != windows_structure {
            structural.push(json!({
                "id": baseline_id,
                "baseline": baseline_structure,
                "windows": windows_structure,
            }));
        }
    }
    if required_array(ledger, "semantic_difference_ids", "native Windows ledger")?
        != &difference_ids
        || required_array(ledger, "structural_differences", "native Windows ledger")? != &structural
    {
        return Err("native Windows source difference ledger changed".into());
    }
    Ok(())
}

fn semantic_outcomes(outcomes: &[Value]) -> Result<(Vec<Value>, Vec<u8>), String> {
    let mut values = Vec::with_capacity(outcomes.len());
    let mut bytes = Vec::new();
    for outcome in outcomes {
        let id = required_str(outcome, "id", "source outcome")?;
        let mut semantic = outcome.clone();
        let platform = semantic
            .as_object_mut()
            .ok_or_else(|| format!("source outcome {id} is not an object"))?
            .remove("platform")
            .ok_or_else(|| format!("source outcome {id} has no platform"))?;
        if !platform.is_string() {
            return Err(format!("source outcome {id} platform is not a string"));
        }
        bytes.extend_from_slice(
            &serde_json::to_vec(&semantic)
                .map_err(|error| format!("cannot render source outcome {id}: {error}"))?,
        );
        bytes.push(b'\n');
        values.push(semantic);
    }
    Ok((values, bytes))
}

fn outcome_structure(outcome: &Value, id: &str) -> Result<Value, String> {
    Ok(json!({
        "fragments": required_array(outcome, "fragments", id)?.len(),
        "canonical_fragments": required_array(outcome, "canonical_fragments", id)?.len(),
        "findings": required_array(outcome, "findings", id)?.len(),
        "issues": required_array(outcome, "issues", id)?.len(),
        "has_error": !outcome.get("error").is_some_and(Value::is_null),
    }))
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} SHA-256 is invalid"));
    }
    Ok(())
}

fn validate_projection(outcomes: &[Value]) -> Result<(), String> {
    let expected = FRAGMENT_KEYS.iter().copied().collect::<BTreeSet<_>>();
    for outcome in outcomes {
        let id = required_str(outcome, "id", "outcome")?;
        for field in ["fragments", "canonical_fragments"] {
            for fragment in required_array(outcome, field, id)? {
                let object = fragment
                    .as_object()
                    .ok_or_else(|| format!("{id}: {field} contains a non-object"))?;
                let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
                if keys != expected {
                    return Err(format!("{id}: complete fragment projection changed"));
                }
                for key in [
                    "raw_base64",
                    "bytes_base64",
                    "file_base64",
                    "windows_file_base64",
                    "symlink_file_base64",
                    "commit_base64",
                ] {
                    decode(fragment, key, id)?;
                }
                if !fragment["bytes_nil"].is_boolean()
                    || !fragment["inherited_from_finding"].is_boolean()
                    || !fragment["start_line"].is_u64()
                {
                    return Err(format!("{id}: fragment scalar projection changed"));
                }
            }
        }
    }
    Ok(())
}

fn validate_counts(
    outcomes: &[Value],
    coverage: &Value,
    manifest: &Value,
    require_baseline_structure: bool,
) -> Result<(), String> {
    let sum = |field: &str| -> Result<u64, String> {
        outcomes
            .iter()
            .map(|outcome| {
                required_array(outcome, field, "outcome").map(|items| items.len() as u64)
            })
            .sum()
    };
    let material = required_array(coverage, "behavior_ids", "coverage")?
        .iter()
        .map(|row| required_array(row, "material_assertions", "behavior").map(Vec::len))
        .sum::<Result<usize, _>>()? as u64;
    let invariant_counts = [
        ("request_count", REQUEST_COUNT as u64),
        ("outcome_count", outcomes.len() as u64),
        (
            "behavior_count",
            required_array(coverage, "behavior_ids", "coverage")?.len() as u64,
        ),
        (
            "upstream_identity_count",
            required_array(coverage, "upstream", "coverage")?.len() as u64,
        ),
        ("material_assertion_count", material),
    ];
    for (field, actual) in invariant_counts {
        if required_u64(manifest, field, "manifest")? != actual {
            return Err(format!("source manifest {field} changed"));
        }
    }
    if require_baseline_structure {
        for (field, actual) in [
            ("fragment_count", sum("fragments")?),
            ("finding_count", sum("findings")?),
            ("issue_count", sum("issues")?),
        ] {
            if required_u64(manifest, field, "manifest")? != actual {
                return Err(format!("source manifest {field} changed"));
            }
        }
    }
    Ok(())
}

pub(super) fn outcome_for<'a>(
    outcomes: &'a BTreeMap<&str, &Value>,
    id: &str,
) -> Result<&'a Value, String> {
    outcomes
        .get(id)
        .copied()
        .ok_or_else(|| format!("missing source outcome {id}"))
}

pub(super) fn required_array<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Vec<Value>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: {field} is not an array"))
}

pub(super) fn required_object<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label}: {field} is not an object"))
}

pub(super) fn required_str<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: {field} is not a string"))
}

pub(super) fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label}: {field} is not an unsigned integer"))
}

pub(super) fn strings(value: &Value, field: &str, label: &str) -> Result<Vec<String>, String> {
    required_array(value, field, label)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{label}: {field} contains a non-string"))
        })
        .collect()
}

pub(super) fn decode(value: &Value, field: &str, label: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(required_str(value, field, label)?)
        .map_err(|error| format!("{label}: invalid {field}: {error}"))
}

pub(super) fn fragment_values(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
    field: &str,
) -> Result<Vec<Vec<u8>>, String> {
    required_array(outcome_for(outcomes, id)?, "fragments", id)?
        .iter()
        .map(|fragment| decode(fragment, field, id))
        .collect()
}

pub(super) fn finding_files(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
) -> Result<Vec<Vec<u8>>, String> {
    required_array(outcome_for(outcomes, id)?, "findings", id)?
        .iter()
        .map(|finding| decode(finding, "file_base64", id))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate_counts;
    use crate::tooling::source::spec::REQUEST_COUNT;

    #[test]
    fn windows_counts_defer_platform_structure_to_the_native_ledger() {
        let outcomes = vec![
            json!({
                "fragments": [],
                "findings": [],
                "issues": [],
            });
            REQUEST_COUNT
        ];
        let coverage = json!({
            "behavior_ids": [{"material_assertions": []}],
            "upstream": [],
        });
        let manifest = json!({
            "request_count": REQUEST_COUNT,
            "outcome_count": REQUEST_COUNT,
            "fragment_count": 1,
            "finding_count": 1,
            "issue_count": 1,
            "behavior_count": 1,
            "upstream_identity_count": 0,
            "material_assertion_count": 0,
        });

        validate_counts(&outcomes, &coverage, &manifest, false).unwrap();
        assert!(validate_counts(&outcomes, &coverage, &manifest, true).is_err());
    }
}
