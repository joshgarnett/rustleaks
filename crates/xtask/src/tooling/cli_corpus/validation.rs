//! Fresh outcome validation, provenance rendering, and traceability baselines.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use super::spec::{
    BUILD_VERSION, CASE_COUNT, DECLARED_TRANSITIONS, LEGACY_BUILD_VERSION, VARIANT_COUNT,
};
use super::{newline_records, read};
use crate::tooling::support::sha256_bytes;

const DECLARED_OUTCOME_TRANSITION: (&str, &str) = (
    "2d1f1f679ca552f7563e4c3313e4215c0d7e89317304db723a4c6d2321b2a791",
    "525fa0bc43e6603b15cdbc5c6078a3063dfa2c36162ce2e847561ed0eda36df4",
);

pub(super) fn validate_outcomes(bytes: &[u8], manifest: &Value) -> Result<(), String> {
    let lines = newline_records(bytes, "CLI outcomes")?;
    if lines.len() != CASE_COUNT {
        return Err(format!("fresh CLI outcomes contain {} cases", lines.len()));
    }
    let mut variants = 0;
    let mut paired = 0;
    let mut followups = 0;
    for (number, line) in (1..=CASE_COUNT).zip(lines) {
        let row: Value = serde_json::from_slice(line)
            .map_err(|e| format!("invalid CLI outcome {number}: {e}"))?;
        let id = format!("CLI-BB-{number:03}");
        if required_u64(&row, "protocol_version", &id)? != 1 || required_str(&row, "id", &id)? != id
        {
            return Err(format!("{id}: outcome envelope changed"));
        }
        let rows = required_array(&row, "variants", &id)?;
        variants += rows.len();
        for variant in rows {
            if variant.get("status").and_then(Value::as_str) == Some("native-runtime-followup") {
                followups += 1;
                continue;
            }
            paired += 1;
            for implementation in ["go", "rust"] {
                let observation = variant
                    .get(implementation)
                    .ok_or_else(|| format!("{id}: missing {implementation} observation"))?;
                for field in ["stdout_base64", "stdout_sha256"] {
                    required_str(observation, field, &id)?;
                }
                required_array(observation, "stderr_events", &id)?;
                if !(observation["report"].is_null() || observation["report"].is_object())
                    || !(observation["findings"].is_null() || observation["findings"].is_array())
                {
                    return Err(format!("{id}: incomplete {implementation} observation"));
                }
            }
            let comparison = variant
                .get("comparison")
                .ok_or_else(|| format!("{id}: comparison missing"))?;
            let axes = required_object(comparison, "axes", &id)?;
            if axes.keys().map(String::as_str).collect::<BTreeSet<_>>()
                != [
                    "child_cleanup",
                    "exit",
                    "findings",
                    "report",
                    "stderr_events",
                    "stderr_usage",
                    "stdout",
                ]
                .into_iter()
                .collect()
            {
                return Err(format!("{id}: comparison axes changed"));
            }
        }
    }
    if variants != VARIANT_COUNT || paired != 119 || followups != 0 {
        return Err("fresh CLI variant/process accounting changed".into());
    }
    let expected = required_str(manifest, "outcomes_sha256", "manifest")?;
    let actual = sha256_bytes(bytes);
    if expected != actual && (expected, actual.as_str()) != DECLARED_OUTCOME_TRANSITION {
        return Err(format!(
            "fresh CLI outcomes differ from committed manifest: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

pub(super) fn render_manifest(
    legacy: &[u8],
    manifest: &Value,
    generator_hash: &str,
    native_linux_hash: &str,
    unix_path_hash: &str,
) -> Result<Vec<u8>, String> {
    let old = required_str(manifest, "generator_sha256", "manifest")?;
    let mut rendered = legacy.to_vec();
    for field in ["go_runtime_tree_sha256", "rust_runtime_tree_sha256"] {
        rendered = remove_flat_object_field(&rendered, field)?;
    }
    rendered = replace_once(
        &rendered,
        old.as_bytes(),
        generator_hash.as_bytes(),
        "generator provenance",
    )?;
    rendered = replace_declared_transition(
        &rendered,
        LEGACY_BUILD_VERSION.as_bytes(),
        BUILD_VERSION.as_bytes(),
        "CLI build version transition",
    )?;
    for (path, expected, actual) in DECLARED_TRANSITIONS {
        rendered = replace_declared_transition(
            &rendered,
            expected.as_bytes(),
            actual.as_bytes(),
            &format!("{path} transition"),
        )?;
    }
    rendered = replace_declared_transition(
        &rendered,
        DECLARED_OUTCOME_TRANSITION.0.as_bytes(),
        DECLARED_OUTCOME_TRANSITION.1.as_bytes(),
        "CLI outcomes transition",
    )?;
    for (old, new, label) in [
        (
            "  \"paired_observation_pair_count\": 118,\n",
            "  \"paired_observation_pair_count\": 119,\n",
            "paired observation count",
        ),
        (
            "  \"paired_observation_process_count\": 236,\n",
            "  \"paired_observation_process_count\": 238,\n",
            "observation process count",
        ),
        (
            "  \"fresh_cli_process_count\": 240,\n",
            "  \"fresh_cli_process_count\": 242,\n",
            "fresh process count",
        ),
        (
            "  \"exact_variant_count\": 100,\n",
            "  \"exact_variant_count\": 101,\n",
            "exact variant count",
        ),
        (
            "  \"versioned_disposition_variant_count\": 19,\n",
            "  \"versioned_disposition_variant_count\": 18,\n",
            "disposition variant count",
        ),
        (
            "  \"complete_duplicate_preserving_finding_count_both_implementations\": 100,\n",
            "  \"complete_duplicate_preserving_finding_count_both_implementations\": 102,\n",
            "finding count",
        ),
        (
            "  \"raw_report_byte_count_both_implementations\": 48732,\n",
            "  \"raw_report_byte_count_both_implementations\": 49540,\n",
            "report byte count",
        ),
        (
            "  \"stderr_event_count_both_implementations\": 884,\n",
            "  \"stderr_event_count_both_implementations\": 888,\n",
            "stderr event count",
        ),
    ] {
        rendered = replace_text_transition(&rendered, old, new, label)?;
    }
    rendered = replace_text_transition(
        &rendered,
        "    \"FOLLOWUP-NATIVE-M11-001\": 1,\n",
        "",
        "native follow-up disposition count",
    )?;
    rendered = replace_text_transition(
        &rendered,
        "    \"REPORT-SAFE-001\": \"Rust uses the reviewed deterministic capability-free safe-template profile; Go helpers outside that profile are not reproduced.\",\n    \"FOLLOWUP-NATIVE-M11-001\": \"Native Linux and Windows runtime replay is unavailable and nonblocking; cross-compilation is not runtime evidence.\"\n",
        "    \"REPORT-SAFE-001\": \"Rust uses the reviewed deterministic capability-free safe-template profile; Go helpers outside that profile are not reproduced.\"\n",
        "native follow-up disposition description",
    )?;
    rendered = replace_text_transition(
        &rendered,
        "  \"runtime_provenance_policy\": \"independently-validated-then-omitted\",\n",
        "  \"runtime_provenance_policy\": \"independently-validated-with-native-linux-record\",\n",
        "runtime provenance policy",
    )?;
    rendered = replace_text_transition(
        &rendered,
        "  \"native_runtime_evidence\": {\n    \"generation_host\": \"validated-but-omitted\",\n    \"linux\": \"FOLLOWUP-NATIVE-M11-001\",\n    \"windows\": \"FOLLOWUP-NATIVE-M11-001\"\n  }\n",
        "  \"native_runtime_evidence\": {\n    \"generation_host\": \"validated-and-recorded\",\n    \"linux\": \"native-linux-v1.json exact replay plus native Bazel tests\",\n    \"windows\": \"pinned oracle replay plus native Bazel tests\"\n  }\n",
        "native runtime evidence",
    )?;
    let field = format!("  \"native_linux_outcome_sha256\": \"{native_linux_hash}\",\n");
    if let Some(current) = manifest
        .get("native_linux_outcome_sha256")
        .and_then(Value::as_str)
    {
        if current != native_linux_hash {
            return Err("native Linux evidence hash differs from manifest".into());
        }
    } else {
        rendered = insert_after_once(
            &rendered,
            b"  \"negative_controls_sha256\": \"fd24952e9e8e28dae4f8a581ae6bbb20bfa720ac75e2028a717850cc9ac6f152\",\n",
            field.as_bytes(),
            "native Linux evidence provenance",
        )?;
    }
    let field = format!("  \"unix_path_outcome_sha256\": \"{unix_path_hash}\",\n");
    if let Some(current) = manifest
        .get("unix_path_outcome_sha256")
        .and_then(Value::as_str)
    {
        if current != unix_path_hash {
            return Err("Unix path evidence hash differs from manifest".into());
        }
    } else {
        rendered = insert_after_once(
            &rendered,
            b"  \"negative_controls_sha256\": \"fd24952e9e8e28dae4f8a581ae6bbb20bfa720ac75e2028a717850cc9ac6f152\",\n",
            field.as_bytes(),
            "Unix path evidence provenance",
        )?;
    }
    Ok(rendered)
}

fn replace_text_transition(
    bytes: &[u8],
    old: &str,
    new: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let old_count = bytes
        .windows(old.len())
        .filter(|value| *value == old.as_bytes())
        .count();
    let new_count = if new.is_empty() {
        usize::from(old_count == 0)
    } else {
        bytes
            .windows(new.len())
            .filter(|value| *value == new.as_bytes())
            .count()
    };
    match (old_count, new_count) {
        (1, 0) => {
            let start = bytes
                .windows(old.len())
                .position(|value| value == old.as_bytes())
                .unwrap();
            let mut result = Vec::with_capacity(bytes.len() - old.len() + new.len());
            result.extend_from_slice(&bytes[..start]);
            result.extend_from_slice(new.as_bytes());
            result.extend_from_slice(&bytes[start + old.len()..]);
            Ok(result)
        }
        (0, 1) => Ok(bytes.to_vec()),
        _ => Err(format!(
            "expected exactly one old or current {label}, found {old_count}/{new_count}"
        )),
    }
}

fn insert_after_once(
    bytes: &[u8],
    marker: &[u8],
    insertion: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let positions = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, value)| (value == marker).then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(format!(
            "expected one {label} marker, found {}",
            positions.len()
        ));
    }
    let end = positions[0] + marker.len();
    let mut result = Vec::with_capacity(bytes.len() + insertion.len());
    result.extend_from_slice(&bytes[..end]);
    result.extend_from_slice(insertion);
    result.extend_from_slice(&bytes[end..]);
    Ok(result)
}

fn remove_flat_object_field(bytes: &[u8], field: &str) -> Result<Vec<u8>, String> {
    let prefix = format!("  \"{field}\": {{\n");
    let positions = bytes
        .windows(prefix.len())
        .enumerate()
        .filter_map(|(index, window)| (window == prefix.as_bytes()).then_some(index))
        .collect::<Vec<_>>();
    if positions.is_empty() {
        return Ok(bytes.to_vec());
    }
    if positions.len() != 1 {
        return Err(format!(
            "expected at most one {field} object, found {}",
            positions.len()
        ));
    }
    let start = positions[0];
    let body = &bytes[start + prefix.len()..];
    let suffix = b"\n  },\n";
    let relative_end = body
        .windows(suffix.len())
        .position(|window| window == suffix)
        .ok_or_else(|| format!("{field} object is not a flat generated object"))?;
    let end = start + prefix.len() + relative_end + suffix.len();
    let mut rendered = Vec::with_capacity(bytes.len() - (end - start));
    rendered.extend_from_slice(&bytes[..start]);
    rendered.extend_from_slice(&bytes[end..]);
    Ok(rendered)
}

fn replace_declared_transition(
    bytes: &[u8],
    old: &[u8],
    new: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let old_count = bytes
        .windows(old.len())
        .filter(|value| *value == old)
        .count();
    let new_count = bytes
        .windows(new.len())
        .filter(|value| *value == new)
        .count();
    match (old_count, new_count) {
        (1, 0) => replace_once(bytes, old, new, label),
        (0, 1) => Ok(bytes.to_vec()),
        _ => Err(format!(
            "expected exactly one old or current {label}, found {old_count}/{new_count}"
        )),
    }
}

fn replace_once(bytes: &[u8], old: &[u8], new: &[u8], label: &str) -> Result<Vec<u8>, String> {
    if old.len() != new.len() {
        return Err(format!("{label} digest length changed"));
    }
    let positions = bytes
        .windows(old.len())
        .enumerate()
        .filter_map(|(i, w)| (w == old).then_some(i))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(format!("expected one {label}, found {}", positions.len()));
    }
    let mut result = bytes.to_vec();
    result[positions[0]..positions[0] + old.len()].copy_from_slice(new);
    Ok(result)
}

pub(crate) fn validate_cli_manifest_baselines(root: &Path, text: &str) -> Result<(), String> {
    let corpus = root.join("compat/cli-corpus");
    let manifest_bytes = read(&corpus.join("manifest-v1.json"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("invalid CLI manifest: {e}"))?;
    let required = [
        format!(
            "cli_generator_sha256 = \"{}\"",
            required_str(&manifest, "generator_sha256", "manifest")?
        ),
        format!(
            "cli_requests_sha256 = \"{}\"",
            required_str(&manifest, "requests_sha256", "manifest")?
        ),
        format!(
            "cli_outcomes_sha256 = \"{}\"",
            required_str(&manifest, "outcomes_sha256", "manifest")?
        ),
        format!(
            "cli_negative_controls_sha256 = \"{}\"",
            required_str(&manifest, "negative_controls_sha256", "manifest")?
        ),
        format!(
            "cli_manifest_sha256 = \"{}\"",
            sha256_bytes(&manifest_bytes)
        ),
        format!(
            "cli_readme_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("README.md"))?)
        ),
        format!(
            "cli_native_linux_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("native-linux-v1.json"))?)
        ),
        format!(
            "cli_unix_path_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("unix-path-v1.json"))?)
        ),
        "cli_cases = 34".into(),
        "cli_variants = 119".into(),
        "cli_fresh_processes = 242".into(),
        "cli_exact_variants = 101".into(),
        "cli_disposition_variants = 18".into(),
        "cli_findings_both = 102".into(),
        "cli_report_bytes_both = 49540".into(),
        "cli_parser_usage_bytes_both = 19508".into(),
        "cli_stderr_events_both = 888".into(),
        "cli_mutation_controls = 20".into(),
    ];
    for baseline in required {
        if !text.contains(&baseline) {
            return Err(format!("test manifest is missing CLI baseline {baseline}"));
        }
    }
    Ok(())
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
        .ok_or_else(|| format!("{label}: {field} is not unsigned"))
}

#[cfg(test)]
mod tests {
    use super::{remove_flat_object_field, replace_declared_transition, replace_once};

    #[test]
    fn flat_generated_object_removal_is_idempotent_and_fails_closed() {
        let input =
            b"{\n  \"keep\": 1,\n  \"tree\": {\n    \"path\": \"hash\"\n  },\n  \"tail\": 2\n}\n";
        let expected = b"{\n  \"keep\": 1,\n  \"tail\": 2\n}\n";
        assert_eq!(remove_flat_object_field(input, "tree").unwrap(), expected);
        assert_eq!(
            remove_flat_object_field(expected, "tree").unwrap(),
            expected
        );
        assert!(remove_flat_object_field(b"  \"tree\": {\n  \"tree\": {\n", "tree").is_err());
    }

    #[test]
    fn provenance_replacement_fails_closed() {
        assert_eq!(
            replace_once(b"old", b"old", b"new", "test").unwrap(),
            b"new"
        );
        assert!(replace_once(b"old old", b"old", b"new", "test").is_err());
        assert_eq!(
            replace_declared_transition(b"new", b"old", b"new", "test").unwrap(),
            b"new"
        );
        assert!(replace_declared_transition(b"old new", b"old", b"new", "test").is_err());
    }
}
