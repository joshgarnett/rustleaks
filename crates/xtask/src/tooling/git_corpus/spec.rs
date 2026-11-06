//! Immutable Git corpus schema, provenance, and fixture checks.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use super::validation::{required_array, required_object, required_str, required_u64, strings};
use super::{newline_records, read};
use crate::tooling::support::sha256_bytes;

pub(super) const PROTOCOL_VERSION: u64 = 1;
pub(super) const REQUEST_COUNT: usize = 34;
pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";

const BEHAVIORS: &[&str] = &[
    "GIT-001", "GIT-002", "GIT-003", "GIT-004", "GIT-005", "GIT-006", "GIT-007", "GIT-008",
    "GIT-009", "GIT-010", "GIT-011", "GIT-013", "GIT-014", "GIT-015", "GIT-016", "GIT-017",
    "GIT-018", "GIT-019", "GIT-023",
];
const INDEX_HASHES: &[(&str, &str)] = &[
    (
        "small",
        "0225d0ccae1b6703377c9485a0a8f465188a35a1339a2bdb1d40742168f05ac2",
    ),
    (
        "staged",
        "c81406d3e48089b14a5efaaed17ebba84bd7ffadd5fbad6819194a6946fc3c36",
    ),
    (
        "archives",
        "ddc2d463377afd84c184a1ba581ddec81d6f89569fecff178718cd9e0fa3dc77",
    ),
];
const TESTS: &[(&str, &str)] = &[
    (
        "TM-0134",
        "TestFromGit/archives/../testdata/repos/archives/",
    ),
    ("TM-0135", "TestFromGit/simple/../testdata/repos/small/"),
    (
        "TM-0136",
        "TestFromGit/simple/../testdata/repos/small/--all_foo...",
    ),
    ("TM-0137", "TestFromGitStaged"),
];

#[derive(Clone, Copy)]
pub(super) struct InputMetadata<'a> {
    pub(super) coverage_bytes: &'a [u8],
    pub(super) coverage: &'a Value,
    pub(super) negative_bytes: &'a [u8],
    pub(super) negative: &'a Value,
    pub(super) native_windows: &'a [u8],
    pub(super) readme: &'a [u8],
    pub(super) manifest: &'a Value,
}

pub(super) fn validate_inputs(
    requests: &[u8],
    metadata: InputMetadata<'_>,
) -> Result<Vec<Value>, String> {
    let InputMetadata {
        coverage_bytes,
        coverage,
        negative_bytes,
        negative,
        native_windows,
        readme,
        manifest,
    } = metadata;
    validate_provenance(coverage, manifest)?;
    validate_manifest_inputs(
        requests,
        coverage_bytes,
        negative_bytes,
        native_windows,
        readme,
        manifest,
    )?;
    validate_negative(negative)?;
    let lines = newline_records(requests, "Git requests")?;
    if lines.len() != REQUEST_COUNT {
        return Err(format!(
            "Git corpus has {} requests, expected {REQUEST_COUNT}",
            lines.len()
        ));
    }
    let mut ids = BTreeSet::new();
    let mut behaviors = BTreeSet::new();
    let mut intentions = BTreeSet::new();
    let mut tests = BTreeSet::new();
    let mut values = Vec::with_capacity(lines.len());
    for (index, line) in lines.iter().enumerate() {
        let request: Value = serde_json::from_slice(line)
            .map_err(|error| format!("invalid Git request {}: {error}", index + 1))?;
        let id = required_str(&request, "id", "request")?.to_owned();
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate Git request id {id}"));
        }
        if required_u64(&request, "protocol_version", &id)? != PROTOCOL_VERSION
            || !["log", "diff", "remote"].contains(&required_str(&request, "operation", &id)?)
            || !["small", "staged", "archives", "empty"].contains(&required_str(
                &request,
                "repository",
                &id,
            )?)
        {
            return Err(format!("{id}: Git request envelope changed"));
        }
        for behavior in strings(&request, "behavior_ids", &id)? {
            if !BEHAVIORS.contains(&behavior.as_str()) {
                return Err(format!("{id}: unknown behavior {behavior}"));
            }
            behaviors.insert(behavior);
        }
        for intention in strings(&request, "git_intention_ids", &id)? {
            intentions.insert(intention);
        }
        for test in strings(&request, "test_case_ids", &id)? {
            if !TESTS.iter().any(|(expected, _)| *expected == test) {
                return Err(format!("{id}: unknown upstream test {test}"));
            }
            tests.insert(test);
        }
        values.push(request);
    }
    if behaviors != BEHAVIORS.iter().map(|value| (*value).to_owned()).collect()
        || intentions
            != (1..=7)
                .map(|number| format!("GIT-INT-{number:03}"))
                .collect()
        || tests != TESTS.iter().map(|(id, _)| (*id).to_owned()).collect()
    {
        return Err("Git behavior, intention, or test coverage is incomplete".into());
    }
    validate_coverage(coverage, &values)?;
    Ok(values)
}

fn validate_provenance(coverage: &Value, manifest: &Value) -> Result<(), String> {
    for value in [coverage, manifest] {
        if required_u64(value, "protocol_version", "Git metadata")? != PROTOCOL_VERSION
            || required_str(value, "upstream_revision", "Git metadata")? != REVISION
        {
            return Err("Git metadata provenance changed".into());
        }
    }
    if required_str(manifest, "default_config_sha256", "manifest")? != CONFIG_SHA256
        || required_u64(manifest, "request_count", "manifest")? != REQUEST_COUNT as u64
        || required_u64(manifest, "outcome_count", "manifest")? != REQUEST_COUNT as u64
    {
        return Err("Git manifest contract changed".into());
    }
    Ok(())
}

fn validate_manifest_inputs(
    requests: &[u8],
    coverage: &[u8],
    negative: &[u8],
    native_windows: &[u8],
    readme: &[u8],
    manifest: &Value,
) -> Result<(), String> {
    let files = required_object(manifest, "files", "manifest")?;
    for (name, bytes) in [
        ("README.md", readme),
        ("requests-v1.jsonl", requests),
        ("coverage-v1.json", coverage),
        ("negative-controls-v1.json", negative),
    ] {
        let entry = files
            .get(name)
            .ok_or_else(|| format!("manifest is missing {name}"))?;
        if required_str(entry, "sha256", name)? != sha256_bytes(bytes)
            || required_u64(entry, "bytes", name)? != bytes.len() as u64
        {
            return Err(format!("Git {name} bytes differ from manifest"));
        }
    }
    if let Some(entry) = files.get("native-windows-v1.json")
        && (required_str(entry, "sha256", "native-windows-v1.json")?
            != sha256_bytes(native_windows)
            || required_u64(entry, "bytes", "native-windows-v1.json")?
                != native_windows.len() as u64)
    {
        return Err("Git native-windows-v1.json bytes differ from manifest".into());
    }
    Ok(())
}

fn validate_coverage(coverage: &Value, requests: &[Value]) -> Result<(), String> {
    if strings(coverage, "behavior_ids", "coverage")? != BEHAVIORS
        || strings(coverage, "git_intention_ids", "coverage")?
            != (1..=7)
                .map(|number| format!("GIT-INT-{number:03}"))
                .collect::<Vec<_>>()
    {
        return Err("Git coverage inventory changed".into());
    }
    let definitions = required_object(coverage, "behavior_definitions", "coverage")?;
    if definitions.len() != BEHAVIORS.len()
        || BEHAVIORS.iter().any(|id| {
            definitions
                .get(*id)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err("Git behavior definitions changed".into());
    }
    let cases = required_array(coverage, "cases", "coverage")?;
    if cases.len() != requests.len() {
        return Err("Git coverage case count changed".into());
    }
    for (case, request) in cases.iter().zip(requests) {
        let id = required_str(request, "id", "request")?;
        if required_str(case, "id", "coverage case")? != id
            || case.get("behavior_ids") != request.get("behavior_ids")
            || case.get("git_intention_ids") != request.get("git_intention_ids")
        {
            return Err(format!("{id}: coverage mapping changed"));
        }
    }
    if required_array(coverage, "gaps", "coverage")?.len() != 7 {
        return Err("Git gap inventory changed".into());
    }
    Ok(())
}

fn validate_negative(negative: &Value) -> Result<(), String> {
    if required_u64(negative, "protocol_version", "negative controls")? != PROTOCOL_VERSION {
        return Err("Git negative-control protocol changed".into());
    }
    let expected = [
        "shared-fixture-mutation",
        "shell-log-options",
        "native-git-reimplementation",
        "silent-stderr-normalization",
        "force-stale-default-golden",
        "force-stale-foo-golden",
        "force-stale-archive-count",
    ];
    let controls = required_array(negative, "controls", "negative controls")?;
    for (control, id) in controls.iter().zip(expected) {
        if required_str(control, "id", "negative control")? != id
            || control.get("rejected") != Some(&Value::Bool(true))
            || required_str(control, "reason", id)?.is_empty()
        {
            return Err(format!("negative control {id} changed"));
        }
    }
    if controls.len() != expected.len() {
        return Err("Git negative-control count changed".into());
    }
    Ok(())
}

pub(super) fn validate_local(root: &Path, _coverage: &Value) -> Result<(), String> {
    for (repository, hash) in INDEX_HASHES {
        let relative = format!("testdata/repos/{repository}/dotGit/index");
        verify_hash(&root.join("compat/fixtures/upstream"), &relative, hash)?;
    }
    validate_test_manifest(root)
}

fn validate_test_manifest(root: &Path) -> Result<(), String> {
    let text = String::from_utf8(read(&root.join("compat/test-manifest.toml"))?)
        .map_err(|error| format!("test manifest is not UTF-8: {error}"))?;
    for (id, name) in TESTS {
        if !text.split("[[case]]").any(|block| {
            block.lines().any(|line| line == format!("id = \"{id}\""))
                && block
                    .lines()
                    .any(|line| line == format!("go_name = \"{name}\""))
        }) {
            return Err(format!("manifest identity changed for {id}:{name}"));
        }
    }
    Ok(())
}

fn verify_hash(root: &Path, relative: &str, expected: &str) -> Result<(), String> {
    if sha256_bytes(&read(&root.join(relative))?) != expected {
        return Err(format!("pinned Git source {relative} changed"));
    }
    Ok(())
}
