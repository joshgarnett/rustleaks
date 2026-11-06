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
    validate_native_windows_ledger(committed, observed, native_windows)?;
    if !uniform_string(observed.values, "platform", "frozen Git")?.starts_with("windows/") {
        // The committed platform and host Git version remain pinned provenance.
        // Non-Windows cross-host replays may differ only in those fields.
        compare_json_outcomes(
            committed.values,
            outcomes,
            &["platform", "git_version_base64"],
            "Git",
        )?;
    }
    Ok(())
}

struct NativeWindowsMetadata<'a> {
    committed_semantic: Vec<Value>,
    platforms: &'a Map<String, Value>,
    semantic_hash: &'a str,
    portable_hash: &'a str,
    expected_difference_ids: &'a Vec<Value>,
    expected_windows_counts: &'a Map<String, Value>,
}

fn validate_native_windows_ledger(
    committed: OutcomeBaseline<'_>,
    observed: OutcomeBaseline<'_>,
    ledger: &Value,
) -> Result<(), String> {
    let metadata = validate_native_windows_metadata(committed, ledger)?;
    if !uniform_string(observed.values, "platform", "frozen Git")?.starts_with("windows/") {
        return Ok(());
    }
    validate_native_windows_observations(observed.values, metadata)
}

fn validate_native_windows_observations(
    observed: &[Value],
    metadata: NativeWindowsMetadata<'_>,
) -> Result<(), String> {
    let NativeWindowsMetadata {
        committed_semantic,
        platforms,
        semantic_hash,
        portable_hash,
        expected_difference_ids,
        expected_windows_counts,
    } = metadata;

    let observed_platform = uniform_string(observed, "platform", "observed Git")?;
    if !platforms.contains_key(observed_platform) {
        return Err(format!(
            "native Windows Git platform is not recorded: {observed_platform}"
        ));
    }
    // Raw hashes retain the original observations. Replays allow only the same
    // platform and Git-version provenance differences as non-Windows hosts.
    let (observed_semantic, observed_semantic_bytes) = semantic_outcomes(observed)?;
    if sha256_bytes(&observed_semantic_bytes) != semantic_hash {
        return Err("native Windows Git semantic outcomes changed".into());
    }
    let mut portable = observed_semantic.clone();
    let mut counts = Map::new();
    let mut difference_ids = Vec::new();
    for ((baseline, windows), portable) in committed_semantic
        .iter()
        .zip(&observed_semantic)
        .zip(&mut portable)
    {
        let id = required_str(baseline, "id", "committed Git outcome")?;
        if required_str(windows, "id", "native Windows Git outcome")? != id
            || required_str(portable, "id", "portable Git outcome")? != id
        {
            return Err("native Windows Git outcome order changed".into());
        }
        if baseline != windows {
            difference_ids.push(Value::String(id.to_owned()));
        }
        let count = validate_and_clear_windows_paths(portable, id)?;
        if count != 0 {
            counts.insert(id.to_owned(), Value::from(count as u64));
        }
    }
    if &difference_ids != expected_difference_ids || &counts != expected_windows_counts {
        return Err("native Windows Git difference ledger changed".into());
    }
    let portable_bytes = render_outcomes(&portable, "portable Git")?;
    if sha256_bytes(&portable_bytes) != portable_hash || portable != committed_semantic {
        return Err("native Windows Git portable outcomes changed".into());
    }
    Ok(())
}

fn validate_native_windows_metadata<'a>(
    committed: OutcomeBaseline<'_>,
    ledger: &'a Value,
) -> Result<NativeWindowsMetadata<'a>, String> {
    if required_u64(ledger, "schema_version", "native Windows Git ledger")? != 1
        || required_u64(ledger, "protocol_version", "native Windows Git ledger")?
            != PROTOCOL_VERSION
        || required_str(ledger, "oracle_mode", "native Windows Git ledger")? != "git"
        || required_str(ledger, "upstream_revision", "native Windows Git ledger")? != REVISION
        || required_str(ledger, "default_config_sha256", "native Windows Git ledger")?
            != CONFIG_SHA256
        || required_u64(ledger, "record_count", "native Windows Git ledger")?
            != REQUEST_COUNT as u64
    {
        return Err("native Windows Git ledger provenance changed".into());
    }
    let committed_platform = uniform_string(committed.values, "platform", "committed Git")?;
    let committed_go = uniform_string(committed.values, "go_version", "committed Git")?;
    if required_str(ledger, "baseline_platform", "native Windows Git ledger")? != committed_platform
        || required_str(ledger, "go_version", "native Windows Git ledger")? != committed_go
    {
        return Err("native Windows Git ledger baseline changed".into());
    }
    let (committed_semantic, committed_semantic_bytes) = semantic_outcomes(committed.values)?;
    let baseline_hash = sha256_bytes(&committed_semantic_bytes);
    let portable_hash = required_str(
        ledger,
        "portable_outcomes_sha256",
        "native Windows Git ledger",
    )?;
    if required_str(
        ledger,
        "baseline_semantic_outcomes_sha256",
        "native Windows Git ledger",
    )? != baseline_hash
        || portable_hash != baseline_hash
    {
        return Err("native Windows Git ledger baseline hash changed".into());
    }
    let platforms = required_object(ledger, "platforms", "native Windows Git ledger")?;
    let expected_platforms = ["windows/amd64", "windows/arm64"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if platforms
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_platforms
    {
        return Err("native Windows Git ledger platform set changed".into());
    }
    for platform in &expected_platforms {
        validate_sha256(
            required_str(&platforms[*platform], "outcomes_sha256", platform)?,
            platform,
        )?;
    }
    let semantic_hash = required_str(
        ledger,
        "semantic_outcomes_sha256",
        "native Windows Git ledger",
    )?;
    validate_sha256(semantic_hash, "native Windows Git semantic outcomes")?;
    let expected_difference_ids = required_array(
        ledger,
        "semantic_difference_ids",
        "native Windows Git ledger",
    )?;
    let expected_windows_counts =
        required_object(ledger, "windows_file_counts", "native Windows Git ledger")?;
    if expected_difference_ids
        .iter()
        .any(|value| !value.is_string())
        || expected_windows_counts
            .values()
            .any(|value| !value.is_u64())
    {
        return Err("native Windows Git difference ledger changed".into());
    }

    Ok(NativeWindowsMetadata {
        committed_semantic,
        platforms,
        semantic_hash,
        portable_hash,
        expected_difference_ids,
        expected_windows_counts,
    })
}

fn semantic_outcomes(outcomes: &[Value]) -> Result<(Vec<Value>, Vec<u8>), String> {
    let mut values = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        let id = required_str(outcome, "id", "Git outcome")?;
        values.push(super::semantic_outcome(outcome, id)?);
    }
    let bytes = render_outcomes(&values, "semantic Git")?;
    Ok((values, bytes))
}

fn render_outcomes(outcomes: &[Value], label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for outcome in outcomes {
        let id = required_str(outcome, "id", label)?;
        bytes.extend_from_slice(
            &serde_json::to_vec(outcome)
                .map_err(|error| format!("cannot render {label} outcome {id}: {error}"))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn validate_and_clear_windows_paths(value: &mut Value, id: &str) -> Result<usize, String> {
    match value {
        Value::Array(values) => values
            .iter_mut()
            .map(|value| validate_and_clear_windows_paths(value, id))
            .sum(),
        Value::Object(values) => {
            let mut count = 0;
            if let Some(windows_value) = values.get("windows_file_base64") {
                let windows = windows_value
                    .as_str()
                    .ok_or_else(|| format!("{id}: Windows path projection is not a string"))?;
                if !windows.is_empty() {
                    let file = values
                        .get("file_base64")
                        .and_then(Value::as_str)
                        .ok_or_else(|| format!("{id}: Windows path projection has no file path"))?;
                    let mut windows = decode_str(windows, id)?;
                    let file = decode_str(file, id)?;
                    for byte in &mut windows {
                        if *byte == b'\\' {
                            *byte = b'/';
                        }
                    }
                    if windows != file {
                        return Err(format!(
                            "{id}: Windows path does not match its slash-normalized path"
                        ));
                    }
                    count += 1;
                }
            }
            for (key, value) in values.iter_mut() {
                if key != "windows_file_base64" {
                    count += validate_and_clear_windows_paths(value, id)?;
                }
            }
            if let Some(value) = values.get_mut("windows_file_base64") {
                *value = Value::String(String::new());
            }
            Ok(count)
        }
        _ => Ok(0),
    }
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} SHA-256 is invalid"));
    }
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

    use super::{
        NativeWindowsMetadata, semantic_outcomes, validate_and_clear_windows_paths,
        validate_native_windows_observations,
    };
    use crate::tooling::support::sha256_bytes;

    #[test]
    fn native_windows_paths_require_exact_slash_normalization() {
        let mut matching = json!({
            "file_base64": "bmVzdGVkLnRhci5neiFmaWxlcy9hcGkuZ28=",
            "windows_file_base64": "bmVzdGVkLnRhci5neiFmaWxlc1xhcGkuZ28="
        });
        assert_eq!(
            validate_and_clear_windows_paths(&mut matching, "archive").unwrap(),
            1
        );
        assert_eq!(matching["windows_file_base64"], "");

        let mut mismatch = json!({
            "file_base64": "ZmlsZXMvYXBpLmdv",
            "windows_file_base64": "ZmlsZXNcb3RoZXIuZ28="
        });
        assert!(validate_and_clear_windows_paths(&mut mismatch, "archive").is_err());
    }

    #[test]
    fn native_windows_replay_allows_git_version_but_rejects_semantic_drift() {
        let baseline = json!({
            "id": "case", "platform": "darwin/arm64", "git_version_base64": "b2xk",
            "go_version": "go1.26.7", "fragments": [], "findings": [], "error": null
        });
        let (committed_semantic, bytes) =
            semantic_outcomes(std::slice::from_ref(&baseline)).unwrap();
        let hash = sha256_bytes(&bytes);
        let platforms = json!({"windows/amd64": {}, "windows/arm64": {}});
        let counts = serde_json::Map::new();
        let differences = Vec::new();
        let check = |value| {
            validate_native_windows_observations(
                &[value],
                NativeWindowsMetadata {
                    committed_semantic: committed_semantic.clone(),
                    platforms: platforms.as_object().unwrap(),
                    semantic_hash: &hash,
                    portable_hash: &hash,
                    expected_difference_ids: &differences,
                    expected_windows_counts: &counts,
                },
            )
        };
        let mut observed = baseline;
        observed["platform"] = json!("windows/amd64");
        observed["git_version_base64"] = json!("bmV3");
        check(observed.clone()).unwrap();
        observed["platform"] = json!("windows/arm64");
        check(observed.clone()).unwrap();
        observed["findings"] = json!([{"changed": true}]);
        assert!(check(observed.clone()).is_err());
        observed["findings"] = json!([]);
        observed["platform"] = json!("windows/unsupported");
        assert!(check(observed).is_err());
    }
}
