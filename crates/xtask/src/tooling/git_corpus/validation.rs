//! Git response envelopes, hashes, projections, and manifest rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value};

use super::controls;
use super::spec::{CONFIG_SHA256, PROTOCOL_VERSION, REQUEST_COUNT, REVISION};
use crate::tooling::{
    artifacts::{OutcomeBaseline, compare_json_outcomes},
    support::sha256_bytes,
};

const FRAGMENT_KEYS: &[&str] = &[
    "bytes_base64",
    "bytes_nil",
    "commit_base64",
    "commit_info",
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
        || required_str(outcome, "oracle_mode", id)? != "git"
        || required_str(outcome, "upstream_revision", id)? != REVISION
        || required_str(outcome, "default_config_sha256", id)? != CONFIG_SHA256
        || required_str(outcome, "go_version", id)? != go_version
        || required_str(outcome, "platform", id)? != platform
        || request.get("operation") != outcome.get("operation")
    {
        return Err(format!("{id}: Git oracle envelope changed"));
    }
    for field in ["behavior_ids", "test_case_ids"] {
        if request.get(field) != outcome.get(field) {
            return Err(format!("{id}: {field} changed in oracle response"));
        }
    }
    for field in [
        "arguments_base64",
        "fragments",
        "canonical_fragments",
        "findings",
        "issues",
    ] {
        if !outcome.get(field).is_some_and(Value::is_array) {
            return Err(format!("{id}: {field} is not an array"));
        }
    }
    for argument in required_array(outcome, "arguments_base64", id)? {
        decode_str(
            argument
                .as_str()
                .ok_or_else(|| format!("{id}: argument is not a string"))?,
            id,
        )?;
    }
    decode(outcome, "command_base64", id)?;
    decode(outcome, "git_version_base64", id)?;
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
        return Err("Git request/outcome count mismatch".into());
    }
    let by_id = outcomes
        .iter()
        .map(|outcome| required_str(outcome, "id", "outcome").map(|id| (id, outcome)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if by_id.len() != REQUEST_COUNT {
        return Err("Git outcomes contain duplicate ids".into());
    }
    for (request, outcome) in requests.iter().zip(outcomes) {
        let id = required_str(request, "id", "request")?;
        if required_str(outcome, "id", "outcome")? != id {
            return Err(format!("{id}: outcome order changed"));
        }
    }
    let committed_go = uniform_string(committed.values, "go_version", "Git")?;
    let committed_platform = uniform_string(committed.values, "platform", "Git")?;
    let _committed_git = uniform_string(committed.values, "git_version_base64", "Git")?;
    let _observed_git = uniform_string(outcomes, "git_version_base64", "Git")?;
    for (request, outcome) in requests.iter().zip(committed.values) {
        validate_envelope(request, outcome, committed_go, committed_platform)?;
    }
    if outcomes
        .iter()
        .any(|outcome| outcome.get("go_version").and_then(Value::as_str) != Some(committed_go))
    {
        return Err(format!(
            "selected Go version differs from committed Git provenance {committed_go}"
        ));
    }
    validate_projection(outcomes)?;
    controls::validate(root, requests, &by_id, coverage, negative)?;
    let entry = &required_object(manifest, "files", "manifest")?["outcomes-v1.jsonl"];
    if required_str(entry, "sha256", "outcomes")? != sha256_bytes(committed.bytes)
        || required_u64(entry, "bytes", "outcomes")? != committed.bytes.len() as u64
    {
        return Err("committed Git outcomes differ from their manifest".into());
    }
    // The committed platform and host Git version remain pinned provenance.
    // Cross-host replays may differ only in those fields.
    compare_json_outcomes(
        committed.values,
        outcomes,
        &["platform", "git_version_base64"],
        "Git",
    )?;
    Ok(())
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
            "committed {label} {field} provenance is inconsistent"
        ));
    }
    Ok(expected)
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
                if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
                    return Err(format!("{id}: complete Git fragment projection changed"));
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
                    || !(fragment["commit_info"].is_object() || fragment["commit_info"].is_null())
                {
                    return Err(format!("{id}: Git fragment scalar projection changed"));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn render_manifest(
    legacy: &[u8],
    manifest: &Value,
    legacy_readme_len: usize,
    readme: &[u8],
    outcome_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let outcome_entry = &required_object(manifest, "files", "manifest")?["outcomes-v1.jsonl"];
    let old_outcome_hash = required_str(outcome_entry, "sha256", "outcomes")?;
    let old_outcome_bytes = required_u64(outcome_entry, "bytes", "outcomes")?;
    let old = format!(
        "\"outcomes-v1.jsonl\": {{\n      \"sha256\": \"{old_outcome_hash}\",\n      \"bytes\": {old_outcome_bytes}\n    }}"
    );
    let new = format!(
        "\"outcomes-v1.jsonl\": {{\n      \"sha256\": \"{}\",\n      \"bytes\": {}\n    }}",
        sha256_bytes(outcome_bytes),
        outcome_bytes.len()
    );
    let rendered = replace_once(
        legacy,
        old.as_bytes(),
        new.as_bytes(),
        "outcomes manifest entry",
    )?;
    let old_hash = required_str(
        &required_object(manifest, "files", "manifest")?["README.md"],
        "sha256",
        "README",
    )?;
    let old = format!(
        "\"README.md\": {{\n      \"sha256\": \"{old_hash}\",\n      \"bytes\": {legacy_readme_len}\n    }}"
    );
    let new = format!(
        "\"README.md\": {{\n      \"sha256\": \"{}\",\n      \"bytes\": {}\n    }}",
        sha256_bytes(readme),
        readme.len()
    );
    replace_once(
        &rendered,
        old.as_bytes(),
        new.as_bytes(),
        "README manifest entry",
    )
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
        .ok_or_else(|| format!("missing Git outcome {id}"))
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
    decode_str(required_str(value, field, label)?, label)
}

pub(super) fn decode_str(value: &str, label: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(value)
        .map_err(|error| format!("{label}: invalid base64: {error}"))
}

pub(super) fn fragment_bytes(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
) -> Result<Vec<Vec<u8>>, String> {
    required_array(outcome_for(outcomes, id)?, "fragments", id)?
        .iter()
        .map(|fragment| decode(fragment, "raw_base64", id))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{render_manifest, replace_once};
    use crate::tooling::support::sha256_bytes;

    #[test]
    fn manifest_replacement_supports_length_changes() {
        assert_eq!(
            replace_once(b"a old z", b"old", b"newer", "test").unwrap(),
            b"a newer z"
        );
        assert!(replace_once(b"old old", b"old", b"new", "test").is_err());
    }

    #[test]
    fn rendered_manifest_tracks_generated_outcome_bytes() {
        let manifest = json!({
            "files": {
                "outcomes-v1.jsonl": {"sha256": "old-outcomes", "bytes": 3},
                "README.md": {"sha256": "old-readme", "bytes": 3}
            }
        });
        let legacy = br#"{
    "outcomes-v1.jsonl": {
      "sha256": "old-outcomes",
      "bytes": 3
    },
    "README.md": {
      "sha256": "old-readme",
      "bytes": 3
    }
}"#;
        let rendered = render_manifest(legacy, &manifest, 3, b"readme", b"outcomes").unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains(&sha256_bytes(b"outcomes")));
        assert!(rendered.contains("\"bytes\": 8"));
        assert!(rendered.contains(&sha256_bytes(b"readme")));
        assert!(rendered.contains("\"bytes\": 6"));
    }
}
