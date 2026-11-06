//! Offline integrity of the frozen session corpus.
mod controls;
mod spec;
mod validation;
use serde_json::Value;
use std::fs;
use std::path::Path;
pub(crate) fn check_session_corpus(root: &Path) -> Result<(), String> {
    let corpus = root.join("compat/session-corpus");
    let requests = read(&corpus.join("requests-v1.jsonl"))?;
    let committed_outcomes = read(&corpus.join("outcomes-v1.jsonl"))?;
    let coverage = read(&corpus.join("coverage-v1.json"))?;
    let negative = read(&corpus.join("negative-controls-v1.json"))?;
    let legacy_readme = read(&corpus.join("README.md"))?;
    let legacy_manifest = read(&corpus.join("manifest-v1.json"))?;
    let coverage_value = parse_json(&coverage, "session coverage")?;
    let negative_value = parse_json(&negative, "session negative controls")?;
    let manifest_value = parse_json(&legacy_manifest, "session manifest")?;
    let request_values = spec::validate_inputs(
        &requests,
        &coverage,
        &coverage_value,
        &negative,
        &negative_value,
        &legacy_readme,
        &manifest_value,
    )?;

    spec::validate_local(root, &coverage_value)?;
    let values = newline_records(&committed_outcomes, "frozen session outcomes")?
        .into_iter()
        .map(|line| serde_json::from_slice(line).map_err(|error| error.to_string()))
        .collect::<Result<Vec<Value>, String>>()?;
    for (request, outcome) in request_values.iter().zip(&values) {
        validation::validate_envelope(
            request,
            outcome,
            validation::required_str(outcome, "go_version", "session outcome")?,
        )?;
    }
    validation::validate_all(
        &request_values,
        &values,
        &committed_outcomes,
        &coverage_value,
        &negative_value,
        &manifest_value,
    )?;
    println!(
        "frozen session integrity: {} requests",
        request_values.len()
    );
    Ok(())
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
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

#[cfg(test)]
mod tests {
    use super::newline_records;

    #[test]
    fn jsonl_boundaries_fail_closed() {
        assert!(newline_records(b"{}", "test").is_err());
        assert!(newline_records(b"{}\n\n", "test").is_err());
        assert_eq!(newline_records(b"{}\n[]\n", "test").unwrap().len(), 2);
    }
}
