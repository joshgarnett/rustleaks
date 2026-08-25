//! Canonical request, coverage, negative-control, and pin validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::identities::validate_test_manifest;
use crate::tooling::support::sha256_bytes;

pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const DEFAULT_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
pub(super) const OUTCOMES_SHA256: &str =
    "380b8636b47bb4c099f7d238a5fa37703442e3e071d4947f178f7214500e40ad";
const README_SHA256: &str = "b65d60fa4c5d96e8e55c81d14dc171174211a9424cfd94cf360d1497d5b5b2c9";
const COVERAGE_SHA256: &str = "e0d3b738854524c3b9ce620022c286728c08d807a9ff1e4a11f30401a99c2149";
const MANIFEST_SHA256: &str = "ca66155a14984575f1dfa059c40199681af1100d57c0e6416f30ca56f4362712";
const NEGATIVE_SHA256: &str = "69dc393a8dea2fec2b88211e5bdcd4dcfb0e916eb4a05647dc47fac690fba0da";
const REQUESTS_SHA256: &str = "be01978f45cbeb6b180e4a28b3fa909c672f2690c8a3861e5088b4b09b5a531f";
const REQUEST_IDENTITIES_SHA256: &str =
    "dbb0f2e790d598cd32fa32fec859964b07dd8bcba5b66c1675159b2921ad5152";
const BEHAVIOR_IDENTITIES_SHA256: &str =
    "bc76f555aef6e9275826dfa9d9b436410193a48f41288d7d33e5bbf423157dc4";
const TEST_IDENTITIES_SHA256: &str =
    "67b808a4264df3d3d8c27072325b8248368511ea5a890719a4d84fda8ad68dd8";
// The executable oracle produces the corpus. Its tests are validation, not corpus provenance.
const ORACLE_MAIN_SHA256: &str = "8e2482a757fe49eece06694c1c8300c09b5752b9625ece8eee9fac18d39c1266";
const DETECT_SOURCE_SHA256: &str =
    "2bac563a09f22ff76c56b200c3b9b5dc865c1de699eb0ba2a27cca741fa9bd13";
const FINDING_SOURCE_SHA256: &str =
    "a1ecd3837f6d89b8ddf95f2b0a6c301103b8d3e67f84e1b3520ffc6f7d7751a6";

const FILES: &[&str] = &[
    "README.md",
    "coverage-v1.json",
    "manifest-v1.json",
    "negative-controls-v1.json",
    "outcomes-v1.jsonl",
    "requests-v1.jsonl",
];

pub(super) struct ResourceContract {
    pub(super) timeout_seconds: u64,
    pub(super) output_bytes: u64,
    pub(super) allocation_bytes: u64,
}

pub(super) struct Canonical {
    pub(super) readme: Vec<u8>,
    pub(super) coverage: Vec<u8>,
    pub(super) manifest: Vec<u8>,
    pub(super) negative_controls: Vec<u8>,
    pub(super) requests: Vec<u8>,
    pub(super) request_lines: Vec<Vec<u8>>,
    pub(super) request_values: Vec<Value>,
    pub(super) resources: BTreeMap<String, ResourceContract>,
}

struct RequestSet {
    lines: Vec<Vec<u8>>,
    values: Vec<Value>,
    ids: BTreeSet<String>,
}

pub(super) fn load(root: &Path) -> Result<Canonical, String> {
    let corpus = root.join("compat/composite-corpus");
    exact_file_set(&corpus)?;
    let readme = read(&corpus.join("README.md"))?;
    let coverage = read(&corpus.join("coverage-v1.json"))?;
    let manifest = read(&corpus.join("manifest-v1.json"))?;
    let negative_controls = read(&corpus.join("negative-controls-v1.json"))?;
    let outcomes = read(&corpus.join("outcomes-v1.jsonl"))?;
    let requests = read(&corpus.join("requests-v1.jsonl"))?;
    for (label, bytes, hash) in [
        ("README", readme.as_slice(), README_SHA256),
        ("coverage", coverage.as_slice(), COVERAGE_SHA256),
        ("manifest", manifest.as_slice(), MANIFEST_SHA256),
        (
            "negative controls",
            negative_controls.as_slice(),
            NEGATIVE_SHA256,
        ),
        ("requests", requests.as_slice(), REQUESTS_SHA256),
        ("committed outcomes", outcomes.as_slice(), OUTCOMES_SHA256),
    ] {
        require_hash(label, bytes, hash)?;
    }
    validate_sources(root)?;
    validate_manifest(&manifest)?;
    let request_set = validate_requests(&requests)?;
    let resources = validate_coverage(&coverage, &request_set.ids)?;
    validate_negative_controls(&negative_controls, &request_set.ids)?;
    Ok(Canonical {
        readme,
        coverage,
        manifest,
        negative_controls,
        requests,
        request_lines: request_set.lines,
        request_values: request_set.values,
        resources,
    })
}

pub(super) fn rust_readme(canonical: &[u8]) -> Result<Vec<u8>, String> {
    let source = std::str::from_utf8(canonical)
        .map_err(|error| format!("composite README is not UTF-8: {error}"))?;
    let provenance = "cargo xtask generate composite\ncargo xtask generate composite --check";
    if source.matches(provenance).count() == 1 {
        return Ok(canonical.to_vec());
    }
    Err("composite README regeneration provenance changed".into())
}

pub(super) fn rust_manifest(canonical: &[u8], readme: &[u8]) -> Result<Vec<u8>, String> {
    let source = std::str::from_utf8(canonical)
        .map_err(|error| format!("composite manifest is not UTF-8: {error}"))?;
    let expected = sha256_bytes(readme);
    if source.matches(&expected).count() == 1 {
        return Ok(canonical.to_vec());
    }
    Err("composite manifest README pin changed".into())
}

fn validate_manifest(bytes: &[u8]) -> Result<(), String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid composite manifest: {error}"))?;
    pins(&value, "composite manifest")?;
    for (field, expected) in [
        ("request_count", 182),
        ("outcome_count", 182),
        ("finding_count", 275),
        ("required_finding_count", 1623),
        ("behavior_count", 12),
        ("leaf_identity_count", 9),
        ("aggregator_identity_count", 2),
    ] {
        if value[field].as_u64() != Some(expected) {
            return Err(format!("composite manifest {field} changed"));
        }
    }
    let files = value["files"]
        .as_object()
        .ok_or("composite manifest files is not an object")?;
    for (name, expected) in [
        ("README.md", README_SHA256),
        ("coverage-v1.json", COVERAGE_SHA256),
        ("negative-controls-v1.json", NEGATIVE_SHA256),
        ("outcomes-v1.jsonl", OUTCOMES_SHA256),
        ("requests-v1.jsonl", REQUESTS_SHA256),
    ] {
        if files.get(name).and_then(Value::as_str) != Some(expected) {
            return Err(format!("composite manifest file pin changed for {name}"));
        }
    }
    Ok(())
}

fn validate_requests(bytes: &[u8]) -> Result<RequestSet, String> {
    let lines = records(bytes, "composite requests")?;
    if lines.len() != 182 {
        return Err(format!(
            "expected 182 composite requests, got {}",
            lines.len()
        ));
    }
    let mut values = Vec::new();
    let mut ids = BTreeSet::new();
    let mut identity = String::new();
    let mut operations = BTreeMap::<String, usize>::new();
    let mut behaviors = BTreeSet::new();
    let mut tests = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let value: Value = serde_json::from_slice(line)
            .map_err(|error| format!("composite request line {} is invalid: {error}", index + 1))?;
        if value["protocol_version"] != 1 {
            return Err(format!(
                "composite request line {} has wrong protocol",
                index + 1
            ));
        }
        let id = string(&value, "id", "composite request")?;
        if !ids.insert(id.to_owned()) {
            return Err(format!("duplicate composite request {id}"));
        }
        let operation = string(&value, "operation", id)?;
        identity.push_str(id);
        identity.push('\t');
        identity.push_str(operation);
        identity.push('\n');
        *operations.entry(operation.to_owned()).or_default() += 1;
        collect_strings(&value["behavior_ids"], id, &mut behaviors)?;
        collect_strings(&value["test_case_ids"], id, &mut tests)?;
        values.push(value);
    }
    if operations
        != BTreeMap::from([
            ("detect".into(), 143),
            ("filter_probe".into(), 5),
            ("mask_secret".into(), 4),
            ("probe_missing_required".into(), 1),
            ("redact".into(), 29),
        ])
    {
        return Err(format!(
            "composite operation inventory changed: {operations:?}"
        ));
    }
    require_hash(
        "composite request identities",
        identity.as_bytes(),
        REQUEST_IDENTITIES_SHA256,
    )?;
    require_set_hash(
        "composite behavior identities",
        &behaviors,
        BEHAVIOR_IDENTITIES_SHA256,
    )?;
    require_set_hash("composite test identities", &tests, TEST_IDENTITIES_SHA256)?;
    Ok(RequestSet { lines, values, ids })
}

fn validate_coverage(
    bytes: &[u8],
    ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, ResourceContract>, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid composite coverage: {error}"))?;
    pins(&value, "composite coverage")?;
    let request_ids = strings(&value["request_ids"], "coverage request_ids")?;
    if request_ids.iter().cloned().collect::<BTreeSet<_>>() != *ids || request_ids.len() != 182 {
        return Err("composite coverage request identity inventory changed".into());
    }
    validate_numbered_refs(&value["mandatory_cases"], "request_ids", 58, ids)?;
    let assertions = value["material_assertions"]
        .as_array()
        .ok_or("coverage material_assertions is not an array")?;
    if assertions.len() != 38
        || assertions
            .iter()
            .any(|row| row["assertion_ids"].as_array().is_none_or(Vec::is_empty))
    {
        return Err("composite material assertion inventory changed".into());
    }
    let source = &value["source_order_evidence"][0];
    if source["source_sha256"] != DETECT_SOURCE_SHA256
        || source["entropy_line"] != 543
        || source["global_allowlist_line"] != 557
        || source["rule_allowlist_line"] != 563
    {
        return Err("composite source-order evidence changed".into());
    }
    let mut resources = BTreeMap::new();
    for row in value["resource_contracts"]
        .as_array()
        .ok_or("coverage resource_contracts is not an array")?
    {
        let id = string(row, "request_id", "resource contract")?;
        if !ids.contains(id)
            || resources
                .insert(
                    id.to_owned(),
                    ResourceContract {
                        timeout_seconds: unsigned(row, "deadline_seconds", id)?,
                        output_bytes: unsigned(row, "output_bytes", id)?,
                        allocation_bytes: unsigned(row, "allocation_bytes", id)?,
                    },
                )
                .is_some()
        {
            return Err(format!("invalid or duplicate resource contract {id}"));
        }
    }
    if resources.len() != 6 {
        return Err(format!(
            "expected 6 resource contracts, got {}",
            resources.len()
        ));
    }
    Ok(resources)
}

fn validate_negative_controls(bytes: &[u8], ids: &BTreeSet<String>) -> Result<(), String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid composite negative controls: {error}"))?;
    let pairs = value["same_count_substitutions"]
        .as_array()
        .ok_or("same_count_substitutions is not an array")?;
    if pairs.len() != 5 {
        return Err("composite negative-control pair count changed".into());
    }
    for pair in pairs {
        for field in ["positive", "negative"] {
            let id = string(pair, field, "negative control")?;
            if !ids.contains(id) {
                return Err(format!("negative control references missing request {id}"));
            }
        }
    }
    Ok(())
}

fn validate_sources(root: &Path) -> Result<(), String> {
    for (path, expected) in [
        (
            root.join("crates/rustleaks-compat/oracle/main.go"),
            ORACLE_MAIN_SHA256,
        ),
        (
            root.parent()
                .ok_or("repository has no parent")?
                .join("gitleaks/detect/detect.go"),
            DETECT_SOURCE_SHA256,
        ),
        (
            root.parent()
                .ok_or("repository has no parent")?
                .join("gitleaks/report/finding.go"),
            FINDING_SOURCE_SHA256,
        ),
    ] {
        require_hash(&path.display().to_string(), &read(&path)?, expected)?;
    }
    validate_test_manifest(&read(&root.join("compat/test-manifest.toml"))?)?;
    Ok(())
}

fn exact_file_set(root: &Path) -> Result<(), String> {
    let expected = FILES.iter().map(PathBuf::from).collect::<BTreeSet<_>>();
    let actual = fs::read_dir(root)
        .map_err(|error| format!("cannot read {}: {error}", root.display()))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("cannot read composite entry: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_file()
            {
                return Err(format!(
                    "non-file composite artifact: {}",
                    entry.path().display()
                ));
            }
            Ok(PathBuf::from(entry.file_name()))
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    if actual != expected {
        return Err(format!(
            "composite artifact set changed: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn validate_numbered_refs(
    value: &Value,
    field: &str,
    count: usize,
    ids: &BTreeSet<String>,
) -> Result<(), String> {
    let rows = value
        .as_array()
        .ok_or("numbered coverage rows is not an array")?;
    if rows.len() != count {
        return Err(format!(
            "expected {count} numbered coverage rows, got {}",
            rows.len()
        ));
    }
    for (index, row) in rows.iter().enumerate() {
        if row["number"].as_u64() != Some((index + 1) as u64) {
            return Err("composite mandatory numbering changed".into());
        }
        for id in strings(&row[field], "numbered coverage references")? {
            if !ids.contains(&id) {
                return Err(format!("coverage references missing request {id}"));
            }
        }
    }
    Ok(())
}

fn records(bytes: &[u8], label: &str) -> Result<Vec<Vec<u8>>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} lacks final newline"));
    }
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .map(|(index, line)| {
            if line == b"\n" {
                Err(format!("{label} line {} is blank", index + 1))
            } else {
                Ok(line.to_vec())
            }
        })
        .collect()
}

fn pins(value: &Value, label: &str) -> Result<(), String> {
    if value["protocol_version"] != 1
        || value["upstream_revision"] != REVISION
        || value["default_config_sha256"] != DEFAULT_SHA256
    {
        return Err(format!("{label} pins changed"));
    }
    Ok(())
}

fn collect_strings(
    value: &Value,
    label: &str,
    output: &mut BTreeSet<String>,
) -> Result<(), String> {
    output.extend(strings(value, label)?);
    Ok(())
}

fn strings(value: &Value, label: &str) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{label} is not an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{label} contains a non-string"))
        })
        .collect()
}

fn string<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{label}: {field} is not a string"))
}

fn unsigned(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("{label}: {field} is not unsigned"))
}

fn require_set_hash(label: &str, values: &BTreeSet<String>, expected: &str) -> Result<(), String> {
    let mut bytes = String::new();
    for value in values {
        bytes.push_str(value);
        bytes.push('\n');
    }
    require_hash(label, bytes.as_bytes(), expected)
}

fn require_hash(label: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let actual = sha256_bytes(bytes);
    if actual != expected {
        return Err(format!(
            "{label} SHA-256 changed: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::rust_manifest;

    #[test]
    fn manifest_replacement_requires_exact_pin() {
        assert!(rust_manifest(b"{}\n", b"readme\n").is_err());
    }
}
