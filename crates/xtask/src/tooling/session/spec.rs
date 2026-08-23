//! Immutable session schema, provenance, and declarative-input checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use super::process;
use super::validation::{required_array, required_object, required_str, required_u64, strings};
use super::{TempDir, newline_records, read};
use crate::tooling::support::sha256_bytes;

pub(super) const PROTOCOL_VERSION: u64 = 1;
pub(super) const REQUEST_COUNT: usize = 45;
pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";

const SOURCE_HASHES: &[(&str, &str)] = &[
    (
        "detect/baseline.go",
        "23d043ab3bf70d0a4ff560598a22b8507f38054b038acd3e6e684abf5c663e93",
    ),
    (
        "detect/detect.go",
        "2bac563a09f22ff76c56b200c3b9b5dc865c1de699eb0ba2a27cca741fa9bd13",
    ),
    (
        "report/finding.go",
        "a1ecd3837f6d89b8ddf95f2b0a6c301103b8d3e67f84e1b3520ffc6f7d7751a6",
    ),
    (
        "detect/baseline_test.go",
        "4e6e40bae1d71f14acf66f8ebeb1f328607e1ca01b675c28a8447284f5068895",
    ),
    (
        "detect/detect_test.go",
        "191e7178827d790ae7c72f7b17824e3d368fe66b263fb12a9b8f3ede225124d3",
    ),
    (
        "report/finding_test.go",
        "60f6950823fd227c77d65c630b540fdb3dba46b947bda5bf98f5a72d9d513874",
    ),
];

const IDENTITIES: &[(&str, &str, &str)] = &[
    ("TM-0127", "TestFileLoadBaseline", "aggregator"),
    ("TM-0139", "TestIgnoreIssuesInBaseline", "aggregator"),
    ("TM-0140", "TestIsNew", "aggregator"),
    (
        "TM-0141",
        "TestIsNew/new_-_commit_doesn't_match_baseline",
        "leaf",
    ),
    (
        "TM-0142",
        "TestIsNew/new_-_redacted,_different_baseline",
        "leaf",
    ),
    (
        "TM-0143",
        "TestIsNew/not_new_-_commit+author_matches",
        "leaf",
    ),
    (
        "TM-0144",
        "TestIsNew/not_new_-_commit+author_matches,_tags_ignored",
        "leaf",
    ),
    (
        "TM-0145",
        "TestIsNew/not_new_-_redacted,_everything_else_matches",
        "leaf",
    ),
    ("TM-0146", "TestNormalizeGitleaksIgnorePaths", "leaf"),
    ("TM-0250", "TestRedact", "aggregator"),
];

const COMPARED: &[&str] = &[
    "rule-id",
    "description",
    "start-line",
    "end-line",
    "start-column",
    "end-column",
    "match",
    "secret",
    "file",
    "commit",
    "author",
    "email",
    "date",
    "message",
    "entropy",
];
const IGNORED: &[&str] = &[
    "line",
    "symlink",
    "link",
    "tags",
    "fingerprint",
    "fragment",
    "required-findings",
];

pub(super) fn validate_inputs(
    request_bytes: &[u8],
    coverage_bytes: &[u8],
    coverage: &Value,
    negative_bytes: &[u8],
    negative: &Value,
    readme: &[u8],
    manifest: &Value,
) -> Result<Vec<Value>, String> {
    validate_provenance(coverage, manifest)?;
    validate_manifest_inputs(
        request_bytes,
        coverage_bytes,
        negative_bytes,
        readme,
        manifest,
    )?;
    if strings(coverage, "baseline_compared_fields", "coverage")? != COMPARED
        || strings(coverage, "baseline_ignored_fields", "coverage")? != IGNORED
    {
        return Err("session baseline field inventory changed".into());
    }
    validate_negative_metadata(negative)?;

    let lines = newline_records(request_bytes, "session requests")?;
    if lines.len() != REQUEST_COUNT {
        return Err(format!(
            "session corpus has {} requests, expected {REQUEST_COUNT}",
            lines.len()
        ));
    }
    let mut values = Vec::with_capacity(lines.len());
    let mut ids = BTreeSet::new();
    let mut behavior_requests: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut test_requests: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        let request: Value = serde_json::from_slice(line)
            .map_err(|error| format!("invalid session request {}: {error}", index + 1))?;
        let id = required_str(&request, "id", "request")?.to_owned();
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate session request id {id}"));
        }
        if required_u64(&request, "protocol_version", &id)? != PROTOCOL_VERSION
            || required_str(&request, "operation", &id)? != "session"
            || !request.get("findings").is_some_and(Value::is_array)
        {
            return Err(format!("{id}: session request envelope changed"));
        }
        for behavior in strings(&request, "behavior_ids", &id)? {
            if !("SESSION-001"..="SESSION-010").contains(&behavior) {
                return Err(format!("{id}: unknown behavior id {behavior}"));
            }
            behavior_requests
                .entry(behavior.to_owned())
                .or_default()
                .push(id.clone());
        }
        for test in strings(&request, "test_case_ids", &id)? {
            if !IDENTITIES.iter().any(|(expected, _, _)| *expected == test) {
                return Err(format!("{id}: unknown upstream identity {test}"));
            }
            test_requests
                .entry(test.to_owned())
                .or_default()
                .push(id.clone());
        }
        values.push(request);
    }
    validate_coverage_mappings(coverage, &behavior_requests, &test_requests)?;
    Ok(values)
}

fn validate_provenance(coverage: &Value, manifest: &Value) -> Result<(), String> {
    for value in [coverage, manifest] {
        if required_u64(value, "protocol_version", "session metadata")? != PROTOCOL_VERSION
            || required_str(value, "upstream_revision", "session metadata")? != REVISION
            || required_str(value, "default_config_sha256", "session metadata")? != CONFIG_SHA256
        {
            return Err("session metadata provenance changed".into());
        }
    }
    if required_u64(coverage, "schema_version", "coverage")? != 1
        || required_u64(manifest, "schema_version", "manifest")? != 1
        || required_str(manifest, "oracle_mode", "manifest")? != "session"
        || manifest.get("fresh_process_per_request") != Some(&Value::Bool(true))
        || required_u64(manifest, "deadline_seconds", "manifest")? != 10
        || required_u64(manifest, "stream_limit_bytes", "manifest")? != 4 * 1024 * 1024
    {
        return Err("session manifest execution contract changed".into());
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
        if required_str(entry, "sha256", name)? != sha256_bytes(bytes) {
            return Err(format!("session {name} hash differs from manifest"));
        }
        if records.is_some_and(|count| entry.get("records").and_then(Value::as_u64) != Some(count))
        {
            return Err(format!("manifest record count changed for {name}"));
        }
    }
    Ok(())
}

fn validate_coverage_mappings(
    coverage: &Value,
    behaviors: &BTreeMap<String, Vec<String>>,
    tests: &BTreeMap<String, Vec<String>>,
) -> Result<(), String> {
    let rows = required_array(coverage, "behavior_ids", "coverage")?;
    if rows.len() != 10 {
        return Err("session behavior count changed".into());
    }
    for (number, row) in (1..=10).zip(rows) {
        let id = format!("SESSION-{number:03}");
        if required_str(row, "id", "behavior")? != id
            || strings(row, "request_ids", &id)? != behaviors.get(&id).cloned().unwrap_or_default()
        {
            return Err(format!("{id}: coverage request mapping changed"));
        }
    }
    let rows = required_array(coverage, "upstream", "coverage")?;
    if rows.len() != IDENTITIES.len() {
        return Err("session upstream identity count changed".into());
    }
    for (row, (id, name, classification)) in rows.iter().zip(IDENTITIES) {
        if required_str(row, "test_case_id", "upstream")? != *id
            || required_str(row, "go_name", id)? != *name
            || required_str(row, "classification", id)? != *classification
            || strings(row, "request_ids", id)? != tests.get(*id).cloned().unwrap_or_default()
        {
            return Err(format!("{id}: upstream identity mapping changed"));
        }
    }
    Ok(())
}

fn validate_negative_metadata(negative: &Value) -> Result<(), String> {
    let expected = json!({"pairs":[
        {"positive":"ignore-slash-positive-backslash-negative[0]","negative":"ignore-slash-positive-backslash-negative[1]"},
        {"positive":"ignore-commit-exact-and-near-misses[0]","negative":"ignore-commit-exact-and-near-misses[2]"},
        {"positive":"baseline-redaction-enabled","negative":"baseline-redaction-disabled-near-negative"},
        {"positive":"baseline-equal","negative":"baseline-compared-description"}
    ]});
    if negative != &expected {
        return Err("session negative-control metadata changed".into());
    }
    Ok(())
}

pub(super) fn validate_upstream(
    root: &Path,
    upstream: &Path,
    coverage: &Value,
    temporary: &TempDir,
) -> Result<(), String> {
    let mut revision_command = Command::new("git");
    revision_command
        .current_dir(upstream)
        .args(["rev-parse", "HEAD"]);
    if trim(&process::capture(
        &mut revision_command,
        temporary,
        "upstream-revision",
        Duration::from_secs(30),
    )?) != REVISION.as_bytes()
    {
        return Err("pinned upstream revision changed".into());
    }
    verify_hash(upstream, "config/gitleaks.toml", CONFIG_SHA256)?;
    let hashes = required_object(coverage, "source_hashes", "coverage")?;
    if hashes.len() != SOURCE_HASHES.len() {
        return Err("session source hash inventory changed".into());
    }
    for (path, expected) in SOURCE_HASHES {
        if hashes.get(*path).and_then(Value::as_str) != Some(*expected) {
            return Err(format!("coverage source hash changed for {path}"));
        }
        verify_hash(upstream, path, expected)?;
    }
    verify_hash(
        upstream,
        "testdata/gitleaksignore/.windowspaths",
        "5426aeccb90cd6495f01a2ff078a008108615697f2fe5ff98d0baa1a1738add3",
    )?;
    verify_hash(
        upstream,
        "testdata/baseline/baseline.json",
        "02b42cf04e716d178e4fc2c98783646e3133a5b14a47f15f7305074b376676f7",
    )?;
    validate_test_manifest(&read(&root.join("compat/test-manifest.toml"))?)
}

fn validate_test_manifest(bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("test manifest is not UTF-8: {error}"))?;
    for (id, name, _) in IDENTITIES {
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

fn verify_hash(root: &Path, relative: &str, expected: &str) -> Result<(), String> {
    if sha256_bytes(&read(&root.join(relative))?) != expected {
        return Err(format!("pinned upstream file {relative} changed"));
    }
    Ok(())
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
