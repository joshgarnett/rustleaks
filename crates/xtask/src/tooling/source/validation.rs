//! Source response envelopes, hashes, counts, and complete projections.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value};

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

pub(super) fn validate_all(
    root: &Path,
    requests: &[Value],
    outcomes: &[Value],
    committed: OutcomeBaseline<'_>,
    coverage: &Value,
    negative: &Value,
    manifest: &Value,
) -> Result<(), String> {
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
    validate_counts(outcomes, coverage, manifest)?;
    let entry = &required_object(manifest, "files", "manifest")?["outcomes-v1.jsonl"];
    if required_str(entry, "sha256", "outcomes")? != sha256_bytes(committed.bytes)
        || required_u64(entry, "records", "outcomes")? != REQUEST_COUNT as u64
    {
        return Err("committed source outcomes differ from their manifest".into());
    }
    // The committed platform remains pinned provenance. Cross-host replays may
    // differ only in that envelope field; all semantic fields stay exact.
    compare_json_outcomes(committed.values, outcomes, &["platform"], "source")?;
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

fn validate_counts(outcomes: &[Value], coverage: &Value, manifest: &Value) -> Result<(), String> {
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
    for (field, actual) in [
        ("request_count", REQUEST_COUNT as u64),
        ("outcome_count", outcomes.len() as u64),
        ("fragment_count", sum("fragments")?),
        ("finding_count", sum("findings")?),
        ("issue_count", sum("issues")?),
        (
            "behavior_count",
            required_array(coverage, "behavior_ids", "coverage")?.len() as u64,
        ),
        (
            "upstream_identity_count",
            required_array(coverage, "upstream", "coverage")?.len() as u64,
        ),
        ("material_assertion_count", material),
    ] {
        if required_u64(manifest, field, "manifest")? != actual {
            return Err(format!("source manifest {field} changed"));
        }
    }
    Ok(())
}

pub(super) fn render_manifest(
    legacy: &[u8],
    manifest: &Value,
    readme: &[u8],
    coverage: &[u8],
    outcome_bytes: &[u8],
    outcomes: &[Value],
) -> Result<Vec<u8>, String> {
    let old_platform = required_str(manifest, "platform", "manifest")?;
    let new_platform = uniform_string(outcomes, "platform", "source")?;
    let old = format!("\"platform\": \"{old_platform}\"");
    let new = format!("\"platform\": \"{new_platform}\"");
    let rendered = replace_once(
        legacy,
        old.as_bytes(),
        new.as_bytes(),
        "platform provenance",
    )?;
    let old = required_str(
        &required_object(manifest, "files", "manifest")?["outcomes-v1.jsonl"],
        "sha256",
        "outcomes",
    )?;
    let rendered = replace_once(
        &rendered,
        old.as_bytes(),
        sha256_bytes(outcome_bytes).as_bytes(),
        "outcome digest",
    )?;
    let old = required_str(
        &required_object(manifest, "files", "manifest")?["coverage-v1.json"],
        "sha256",
        "coverage",
    )?;
    let rendered = replace_once(
        &rendered,
        old.as_bytes(),
        sha256_bytes(coverage).as_bytes(),
        "coverage digest",
    )?;
    let old = required_str(
        &required_object(manifest, "files", "manifest")?["README.md"],
        "sha256",
        "README",
    )?;
    replace_once(
        &rendered,
        old.as_bytes(),
        sha256_bytes(readme).as_bytes(),
        "README digest",
    )
}

fn uniform_string<'a>(outcomes: &'a [Value], field: &str, label: &str) -> Result<&'a str, String> {
    let first = outcomes
        .first()
        .ok_or_else(|| format!("{label} outcomes are empty"))?;
    let expected = required_str(first, field, label)?;
    if outcomes
        .iter()
        .any(|outcome| outcome.get(field).and_then(Value::as_str) != Some(expected))
    {
        return Err(format!(
            "generated {label} {field} provenance is inconsistent"
        ));
    }
    Ok(expected)
}

fn replace_once(bytes: &[u8], old: &[u8], new: &[u8], label: &str) -> Result<Vec<u8>, String> {
    let positions = bytes
        .windows(old.len())
        .enumerate()
        .filter_map(|(index, window)| (window == old).then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(format!(
            "expected exactly one {label}, found {}",
            positions.len()
        ));
    }
    let position = positions[0];
    let mut rendered = Vec::with_capacity(bytes.len() - old.len() + new.len());
    rendered.extend_from_slice(&bytes[..position]);
    rendered.extend_from_slice(new);
    rendered.extend_from_slice(&bytes[position + old.len()..]);
    Ok(rendered)
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

    use super::{render_manifest, replace_once};
    use crate::tooling::support::sha256_bytes;

    #[test]
    fn manifest_replacement_fails_closed() {
        assert_eq!(
            replace_once(b"old", b"old", b"new", "test").unwrap(),
            b"new"
        );
        assert_eq!(
            replace_once(b"a darwin/arm64 z", b"darwin/arm64", b"linux/amd64", "test").unwrap(),
            b"a linux/amd64 z"
        );
        assert!(replace_once(b"old old", b"old", b"new", "test").is_err());
        assert!(replace_once(b"none", b"old", b"new", "test").is_err());
    }

    #[test]
    fn rendered_manifest_tracks_generated_platform_and_outcomes() {
        let manifest = json!({
            "platform": "darwin/arm64",
            "files": {
                "outcomes-v1.jsonl": {"sha256": "old-outcomes"},
                "coverage-v1.json": {"sha256": "old-coverage"},
                "README.md": {"sha256": "old-readme"}
            }
        });
        let legacy = br#"{
  "platform": "darwin/arm64",
  "outcomes": "old-outcomes",
  "coverage": "old-coverage",
  "readme": "old-readme"
}"#;
        let outcomes = [json!({"platform": "linux/amd64"})];
        let rendered = render_manifest(
            legacy,
            &manifest,
            b"readme",
            b"coverage",
            b"outcomes",
            &outcomes,
        )
        .unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("\"platform\": \"linux/amd64\""));
        assert!(rendered.contains(&sha256_bytes(b"outcomes")));
        assert!(rendered.contains(&sha256_bytes(b"coverage")));
        assert!(rendered.contains(&sha256_bytes(b"readme")));
    }
}
