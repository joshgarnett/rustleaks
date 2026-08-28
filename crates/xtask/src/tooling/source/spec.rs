//! Immutable source schema, provenance, and declarative-input checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use super::process;
use super::validation::{required_array, required_object, required_str, required_u64, strings};
use super::{TempDir, newline_records, read};
use crate::tooling::support::sha256_bytes;

pub(super) const PROTOCOL_VERSION: u64 = 1;
pub(super) const REQUEST_COUNT: usize = 124;
pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";

const SOURCE_HASH_COUNT: usize = 10;
const FIXTURE_HASH_COUNT: usize = 32;
const LEGACY_COVERAGE_SHA256: &str =
    "271080c50356b0a108f22f454a5bfdf63c30f450a8ab5836c1687980842c11cb";

pub(super) fn validate_inputs(
    requests: &[u8],
    coverage_bytes: &[u8],
    coverage: &Value,
    negative_bytes: &[u8],
    negative: &Value,
    readme: &[u8],
    manifest: &Value,
) -> Result<Vec<Value>, String> {
    validate_provenance(coverage, manifest)?;
    validate_manifest_inputs(requests, coverage_bytes, negative_bytes, readme, manifest)?;
    validate_negative_metadata(negative)?;
    let lines = newline_records(requests, "source requests")?;
    if lines.len() != REQUEST_COUNT {
        return Err(format!(
            "source corpus has {} requests, expected {REQUEST_COUNT}",
            lines.len()
        ));
    }
    let mut values = Vec::with_capacity(lines.len());
    let mut ids = BTreeSet::new();
    let mut behavior_requests: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut test_requests: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        let request: Value = serde_json::from_slice(line)
            .map_err(|error| format!("invalid source request {}: {error}", index + 1))?;
        let id = required_str(&request, "id", "request")?.to_owned();
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate source request id {id}"));
        }
        if required_u64(&request, "protocol_version", &id)? != PROTOCOL_VERSION
            || !["boundary", "reader", "file", "files"].contains(&required_str(
                &request,
                "operation",
                &id,
            )?)
        {
            return Err(format!("{id}: source request envelope changed"));
        }
        for behavior in strings(&request, "behavior_ids", &id)? {
            if !valid_behavior(&behavior) {
                return Err(format!("{id}: unknown behavior id {behavior}"));
            }
            behavior_requests
                .entry(behavior)
                .or_default()
                .push(id.clone());
        }
        for test in strings(&request, "test_case_ids", &id)? {
            test_requests.entry(test).or_default().push(id.clone());
        }
        values.push(request);
    }
    validate_coverage(coverage, &behavior_requests, &test_requests)?;
    Ok(values)
}

fn validate_provenance(coverage: &Value, manifest: &Value) -> Result<(), String> {
    for value in [coverage, manifest] {
        if required_u64(value, "schema_version", "source metadata")? != 1
            || required_u64(value, "protocol_version", "source metadata")? != PROTOCOL_VERSION
            || required_str(value, "upstream_revision", "source metadata")? != REVISION
            || required_str(value, "default_config_sha256", "source metadata")? != CONFIG_SHA256
        {
            return Err("source metadata provenance changed".into());
        }
    }
    if required_str(manifest, "oracle_mode", "manifest")? != "source"
        || manifest.get("fresh_process_per_request") != Some(&Value::Bool(true))
        || required_u64(manifest, "deadline_seconds", "manifest")? != 15
        || required_u64(manifest, "stream_limit_bytes", "manifest")? != 8 * 1024 * 1024
    {
        return Err("source manifest execution contract changed".into());
    }
    Ok(())
}

fn validate_manifest_inputs(
    requests: &[u8],
    coverage: &[u8],
    negative: &[u8],
    readme: &[u8],
    manifest: &Value,
) -> Result<(), String> {
    let files = required_object(manifest, "files", "manifest")?;
    for (name, bytes, records) in [
        ("requests-v1.jsonl", requests, Some(REQUEST_COUNT as u64)),
        ("coverage-v1.json", coverage, None),
        ("negative-controls-v1.json", negative, None),
        ("README.md", readme, None),
    ] {
        let entry = files
            .get(name)
            .ok_or_else(|| format!("manifest is missing {name}"))?;
        let expected = required_str(entry, "sha256", name)?;
        let actual = sha256_bytes(bytes);
        let declared_coverage_transition =
            name == "coverage-v1.json" && expected == LEGACY_COVERAGE_SHA256 && actual != expected;
        if expected != actual && !declared_coverage_transition {
            return Err(format!("source {name} hash differs from manifest"));
        }
        if records.is_some_and(|count| entry.get("records").and_then(Value::as_u64) != Some(count))
        {
            return Err(format!("manifest record count changed for {name}"));
        }
    }
    Ok(())
}

fn validate_coverage(
    coverage: &Value,
    behaviors: &BTreeMap<String, Vec<String>>,
    tests: &BTreeMap<String, Vec<String>>,
) -> Result<(), String> {
    let rows = required_array(coverage, "behavior_ids", "coverage")?;
    if rows.len() != 30 {
        return Err("source behavior count changed".into());
    }
    let mut assertion_count = 0;
    for (number, row) in (1..=30).zip(rows) {
        let id = format!("SRC-{number:03}");
        if required_str(row, "id", "behavior")? != id
            || required_str(row, "definition", &id)?.is_empty()
            || strings(row, "request_ids", &id)? != behaviors.get(&id).cloned().unwrap_or_default()
        {
            return Err(format!("{id}: coverage mapping or definition changed"));
        }
        let assertions = strings(row, "material_assertions", &id)?;
        if assertions.is_empty() || assertions.iter().any(String::is_empty) {
            return Err(format!("{id}: material assertions are incomplete"));
        }
        assertion_count += assertions.len();
    }
    if assertion_count != 56 || behaviors.len() != 30 {
        return Err("source material behavior inventory changed".into());
    }
    let upstream = required_array(coverage, "upstream", "coverage")?;
    if upstream.len() != 34 {
        return Err("source upstream identity count changed".into());
    }
    for row in upstream {
        let id = required_str(row, "test_case_id", "upstream")?;
        if required_str(row, "go_name", id)?.is_empty()
            || !["aggregator", "leaf"].contains(&required_str(row, "classification", id)?)
            || strings(row, "request_ids", id)? != tests.get(id).cloned().unwrap_or_default()
        {
            return Err(format!("{id}: upstream identity mapping changed"));
        }
    }
    if tests
        .keys()
        .any(|id| !upstream.iter().any(|row| row["test_case_id"] == **id))
    {
        return Err("a source request names an unknown upstream identity".into());
    }
    let gaps = required_object(coverage, "known_gaps", "coverage")?;
    if gaps.len() != 11 || gaps.values().any(|value| !value.is_string()) {
        return Err("source known-gap inventory changed".into());
    }
    if strings(coverage, "excluded", "coverage")?
        != [
            "Git source semantics",
            "Rust implementation",
            "metadata TOCTOU fault injection",
        ]
    {
        return Err("source exclusions changed".into());
    }
    Ok(())
}

fn validate_negative_metadata(negative: &Value) -> Result<(), String> {
    let expected = json!({"pairs":[
        {"positive":"detect-reader-eof","negative":"stream-error","dimension":"EOF-versus-error"},
        {"positive":"files-size-boundary/equal","negative":"files-size-boundary/over","dimension":"strict-size-limit"},
        {"positive":"files-symlink-enabled","negative":"files-symlink-disabled","dimension":"follow-symlinks"},
        {"positive":"nested-depth-8","negative":"nested-depth-1","dimension":"archive-depth"},
        {"positive":"files-prune-directory/keep","negative":"files-prune-directory/skip","dimension":"directory-pruning"}
    ]});
    if negative != &expected {
        return Err("source negative-control metadata changed".into());
    }
    Ok(())
}

pub(super) fn validate_upstream(
    root: &Path,
    upstream: &Path,
    coverage: &Value,
    temporary: &TempDir,
) -> Result<(), String> {
    let mut command = Command::new("git");
    command.current_dir(upstream).args(["rev-parse", "HEAD"]);
    let revision = process::capture(
        &mut command,
        temporary,
        "upstream-revision",
        Duration::from_secs(30),
    )?;
    if trim(&revision) != REVISION.as_bytes() {
        return Err("pinned upstream revision changed".into());
    }
    verify_hash(upstream, "config/gitleaks.toml", CONFIG_SHA256)?;
    let sources = required_object(coverage, "source_hashes", "coverage")?;
    if sources.len() != SOURCE_HASH_COUNT {
        return Err("source hash inventory changed".into());
    }
    for (path, hash) in sources {
        verify_hash(upstream, path, hash.as_str().ok_or("invalid source hash")?)?;
    }
    let fixtures = required_object(coverage, "fixture_hashes", "coverage")?;
    if fixtures.len() != FIXTURE_HASH_COUNT {
        return Err("archive fixture hash inventory changed".into());
    }
    for (path, hash) in fixtures {
        let relative = if path.starts_with("testdata/archives/") {
            PathBuf::from("compat/fixtures/upstream").join(path)
        } else {
            PathBuf::from("compat/fixtures/oracle").join(path)
        };
        verify_hash(root, relative, hash.as_str().ok_or("invalid fixture hash")?)?;
    }
    validate_test_manifest(root, coverage)
}

fn validate_test_manifest(root: &Path, coverage: &Value) -> Result<(), String> {
    let bytes = read(&root.join("compat/test-manifest.toml"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("test manifest is not UTF-8: {error}"))?;
    for row in required_array(coverage, "upstream", "coverage")? {
        let id = required_str(row, "test_case_id", "upstream")?;
        let name = required_str(row, "go_name", id)?;
        let matched = text.split("[[case]]").any(|block| {
            block.lines().any(|line| line == format!("id = \"{id}\""))
                && block
                    .lines()
                    .any(|line| line == format!("go_name = \"{name}\""))
        });
        if !matched {
            return Err(format!("manifest identity changed for {id}:{name}"));
        }
    }
    Ok(())
}

fn verify_hash(root: &Path, relative: impl AsRef<Path>, expected: &str) -> Result<(), String> {
    let relative = relative.as_ref();
    if sha256_bytes(&read(&root.join(relative))?) != expected {
        return Err(format!("pinned source file {} changed", relative.display()));
    }
    Ok(())
}

fn valid_behavior(id: &str) -> bool {
    id.strip_prefix("SRC-")
        .and_then(|number| number.parse::<u8>().ok())
        .is_some_and(|number| (1..=30).contains(&number))
        && id.len() == 7
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::valid_behavior;

    #[test]
    fn behavior_ids_are_exactly_bounded() {
        assert!(valid_behavior("SRC-001"));
        assert!(valid_behavior("SRC-030"));
        assert!(!valid_behavior("SRC-000"));
        assert!(!valid_behavior("SRC-031"));
        assert!(!valid_behavior("SRC-1"));
    }
}
