//! Offline integrity of frozen git observations.
mod controls;
mod spec;
mod validation;
use super::artifacts::OutcomeBaseline;
use serde_json::Value;
use std::fs;
use std::path::Path;
pub(crate) fn check_git_corpus(root: &Path) -> Result<(), String> {
    let corpus = root.join("compat/git-corpus");
    let requests = read(&corpus.join("requests-v1.jsonl"))?;
    let coverage = read(&corpus.join("coverage-v1.json"))?;
    let negative = read(&corpus.join("negative-controls-v1.json"))?;
    let native_windows = read(&corpus.join("native-windows-v1.json"))?;
    let legacy_readme = read(&corpus.join("README.md"))?;
    let legacy_manifest = read(&corpus.join("manifest-v1.json"))?;
    let legacy_outcomes = read(&corpus.join("outcomes-v1.jsonl"))?;
    let coverage_value = parse_json(&coverage, "Git coverage")?;
    let negative_value = parse_json(&negative, "Git negative controls")?;
    let native_windows_value = parse_json(&native_windows, "native Windows Git ledger")?;
    let manifest_value = parse_json(&legacy_manifest, "Git manifest")?;
    let legacy_outcome_values = parse_jsonl(&legacy_outcomes, "committed Git outcomes")?;
    let request_values = spec::validate_inputs(
        &requests,
        spec::InputMetadata {
            coverage_bytes: &coverage,
            coverage: &coverage_value,
            negative_bytes: &negative,
            negative: &negative_value,
            native_windows: &native_windows,
            readme: &legacy_readme,
            manifest: &manifest_value,
        },
    )?;

    spec::validate_local(root, &coverage_value)?;
    for (request, outcome) in request_values.iter().zip(&legacy_outcome_values) {
        validation::validate_envelope(
            request,
            outcome,
            validation::required_str(outcome, "go_version", "frozen outcome")?,
            validation::required_str(outcome, "platform", "frozen outcome")?,
        )?;
    }
    let frozen = OutcomeBaseline {
        values: &legacy_outcome_values,
        bytes: &legacy_outcomes,
    };
    validation::validate_all(
        root,
        &request_values,
        frozen,
        frozen,
        validation::ValidationMetadata {
            coverage: &coverage_value,
            negative: &negative_value,
            native_windows: &native_windows_value,
            manifest: &manifest_value,
        },
    )?;
    println!("frozen git integrity: {} requests", request_values.len());
    Ok(())
}

fn semantic_outcome(value: &Value, id: &str) -> Result<Value, String> {
    let mut semantic = value.clone();
    let object = semantic
        .as_object_mut()
        .ok_or_else(|| format!("Git outcome {id} is not an object"))?;
    for field in ["platform", "git_version_base64"] {
        if !object.remove(field).is_some_and(|value| value.is_string()) {
            return Err(format!("Git outcome {id} has no string {field}"));
        }
    }
    Ok(semantic)
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn parse_jsonl(bytes: &[u8], label: &str) -> Result<Vec<Value>, String> {
    newline_records(bytes, label)?
        .iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_slice(line)
                .map_err(|error| format!("invalid {label} record {}: {error}", index + 1))
        })
        .collect()
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn newline_records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} JSONL lacks a final newline"));
    }
    let mut records = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            if index == start {
                return Err(format!("{label} JSONL contains a blank line"));
            }
            records.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    Ok(records)
}
