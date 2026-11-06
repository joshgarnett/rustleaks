//! Offline integrity of frozen report observations.
mod controls;
mod spec;
mod validation;
use super::artifacts::OutcomeBaseline;
use serde_json::Value;
use std::fs;
use std::path::Path;
pub(crate) fn check_report_corpus(root: &Path) -> Result<(), String> {
    let canonical_root = root.join("compat/report-corpus");
    let requests = read(&canonical_root.join("requests-v1.jsonl"))?;
    let committed_outcomes = read(&canonical_root.join("outcomes-v1.jsonl"))?;
    let committed_values = parse_outcomes(&committed_outcomes)?;
    let native_windows = read(&canonical_root.join("native-windows-v1.json"))?;
    let native_windows_value: Value = serde_json::from_slice(&native_windows)
        .map_err(|error| format!("invalid native Windows report ledger JSON: {error}"))?;
    let coverage = read(&canonical_root.join("coverage-v1.json"))?;
    let coverage_value: Value = serde_json::from_slice(&coverage)
        .map_err(|error| format!("invalid report coverage JSON: {error}"))?;
    let request_values = spec::validate_inputs(&requests, &coverage_value)?;

    for (request, outcome) in request_values.iter().zip(&committed_values) {
        validation::validate_envelope(request, outcome)?;
    }
    let frozen = OutcomeBaseline {
        values: &committed_values,
        bytes: &committed_outcomes,
    };
    validation::validate_native_windows_ledger(
        frozen,
        frozen,
        "darwin/arm64",
        &native_windows_value,
    )?;
    validation::validate_all(
        &root.join("compat/fixtures/upstream"),
        &request_values,
        &committed_values,
        &committed_outcomes,
        &coverage_value,
    )?;
    println!("frozen report integrity: {} requests", request_values.len());
    Ok(())
}

fn parse_outcomes(bytes: &[u8]) -> Result<Vec<Value>, String> {
    newline_records(bytes, "committed report outcomes")?
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_slice(line).map_err(|error| {
                format!(
                    "committed report outcome {} is invalid JSON: {error}",
                    index + 1
                )
            })
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
