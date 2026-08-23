//! Fresh outcome validation, provenance rendering, and traceability baselines.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use super::spec::{CASE_COUNT, VARIANT_COUNT};
use super::{newline_records, read};
use crate::tooling::support::sha256_bytes;

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
    if variants != VARIANT_COUNT || paired != 118 || followups != 1 {
        return Err("fresh CLI variant/process accounting changed".into());
    }
    if required_str(manifest, "outcomes_sha256", "manifest")? != sha256_bytes(bytes) {
        return Err("fresh CLI outcomes differ from committed manifest".into());
    }
    Ok(())
}

pub(super) fn render_manifest(
    legacy: &[u8],
    manifest: &Value,
    generator_hash: &str,
) -> Result<Vec<u8>, String> {
    let old = required_str(manifest, "generator_sha256", "manifest")?;
    let rendered = replace_once(
        legacy,
        old.as_bytes(),
        generator_hash.as_bytes(),
        "generator provenance",
    )?;
    let rendered = replace_declared_transition(
        &rendered,
        b"c27f70ea157cdacf5f493de0a68a30e737f44b1d7051bdf53a07a4ea440ad008",
        b"8b3054f67f1b52a8bda4ffab8f5ce9a961c091d924f5b75880624bbd125ae567",
        "Cargo.lock transition",
    )?;
    replace_declared_transition(
        &rendered,
        b"f35c35413025ee78af5ca9a0a8227e723f3572a1a7092f80989153f49b7d0891",
        b"9d1d5883df0730eae8cdbc7008257083a6e8fc7521d3a313f8674cab2a9959a8",
        "rustleaks-core transition",
    )
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
        "cli_cases = 34".into(),
        "cli_variants = 119".into(),
        "cli_fresh_processes = 240".into(),
        "cli_exact_variants = 100".into(),
        "cli_disposition_variants = 19".into(),
        "cli_findings_both = 100".into(),
        "cli_report_bytes_both = 48732".into(),
        "cli_parser_usage_bytes_both = 19508".into(),
        "cli_stderr_events_both = 884".into(),
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
    use super::{replace_declared_transition, replace_once};
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
