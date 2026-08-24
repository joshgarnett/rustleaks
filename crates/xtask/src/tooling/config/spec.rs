//! Validation of canonical declarative configuration inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use super::filetree::recursive_files;
use super::metadata::{validate_manifest, validate_schema};
use crate::tooling::support::sha256_bytes;

pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
pub(super) const OUTCOMES_SHA256: &str =
    "6a82a1466c54421b9997d07243fdbbc2b6cee7273fcf172090d8aa9e14be578a";
pub(super) const INPUTS_SHA256: &str =
    "8c187d3d7942cf2ac11c1d27043c44b7923f6f311c2008c7dade62f559e5da7a";
pub(super) const REQUESTS_SHA256: &str =
    "91efa888f8fb2a875892f61629b561ceeb52c82bd503fdf6d25de59b5b6373bb";
pub(super) const SCHEMA_SHA256: &str =
    "8fe48dbcc0e67b94c06437ce2e4cc29322c28355cd810f22ef1901ed60b194f1";
const MANIFEST_SHA256: &str = "ee1896d06dd855d1c0711a8b4d3e52ad3866b05f3cbe17e60043e21867800307";
pub(super) const ORACLE_MAIN_SHA256: &str =
    "8e2482a757fe49eece06694c1c8300c09b5752b9625ece8eee9fac18d39c1266";
pub(super) const ORACLE_TEST_SHA256: &str =
    "a878d3766980e6f4095a38ce727d324bf929b3f03b8ed500ab16c841b14483ef";
pub(super) const FIXTURE_TREE_SHA256: &str =
    "bd9ce06e8db1d3c7711529b53c9dc339b1603e6c7f085e64256db73cb3407dab";
const INPUT_IDENTITIES_SHA256: &str =
    "4b81ba286ce7afdb590f65a32ee01644caa472fe054f0af36363411db5c92e80";
const REQUEST_IDENTITIES_SHA256: &str =
    "3c9601fe0fb3aee559303e48c127426eff3d1dfa6b17637ab815f2e696e48593";
const MANIFEST_IDENTITIES_SHA256: &str =
    "eab7f3458c93d728fe04c75ed2cdc419320e292a12806f3d6e85a5c62b0ef191";

const ARTIFACTS: &[&str] = &[
    "README.md",
    "default-gitleaks.toml",
    "inputs-v1.jsonl",
    "manifest-v1.json",
    "outcomes-v1.jsonl",
    "requests-v1.jsonl",
    "schema-v1.json",
];

#[derive(Clone)]
pub(super) struct Fixture {
    pub(super) path: PathBuf,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct Canonical {
    pub(super) schema: Vec<u8>,
    pub(super) manifest: Vec<u8>,
    pub(super) inputs: Vec<u8>,
    pub(super) requests: Vec<u8>,
    pub(super) committed_default: Vec<u8>,
    pub(super) request_values: Vec<Value>,
    pub(super) fixtures: Vec<Fixture>,
}

impl Canonical {
    pub(super) fn schema_value(&self) -> Result<Value, String> {
        serde_json::from_slice(&self.schema)
            .map_err(|error| format!("invalid canonical config schema: {error}"))
    }
}

pub(super) fn load(root: &Path) -> Result<Canonical, String> {
    let corpus = root.join("compat/config-corpus");
    validate_file_set(&corpus)?;
    let schema = read(&corpus.join("schema-v1.json"))?;
    let manifest = read(&corpus.join("manifest-v1.json"))?;
    let inputs = read(&corpus.join("inputs-v1.jsonl"))?;
    let requests = read(&corpus.join("requests-v1.jsonl"))?;
    let outcomes = read(&corpus.join("outcomes-v1.jsonl"))?;
    let committed_default = read(&corpus.join("default-gitleaks.toml"))?;
    require_hash("schema", &schema, SCHEMA_SHA256)?;
    require_hash("manifest", &manifest, MANIFEST_SHA256)?;
    require_hash("inputs", &inputs, INPUTS_SHA256)?;
    require_hash("requests", &requests, REQUESTS_SHA256)?;
    require_hash("committed outcomes", &outcomes, OUTCOMES_SHA256)?;
    require_hash(
        "committed default configuration",
        &committed_default,
        CONFIG_SHA256,
    )?;

    validate_schema(&schema)?;
    validate_manifest(root, &manifest)?;
    let fixtures = validate_inputs(root, &inputs)?;
    let request_values = validate_requests(&requests, &fixtures, &committed_default)?;
    Ok(Canonical {
        schema,
        manifest,
        inputs,
        requests,
        committed_default,
        request_values,
        fixtures,
    })
}

fn validate_file_set(root: &Path) -> Result<(), String> {
    let expected = ARTIFACTS.iter().map(PathBuf::from).collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("cannot read config corpus {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot read config corpus entry: {error}"))?;
        if !entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?
            .is_file()
        {
            return Err(format!(
                "config corpus contains a non-file artifact: {}",
                entry.path().display()
            ));
        }
        actual.insert(PathBuf::from(entry.file_name()));
    }
    if expected != actual {
        return Err(format!(
            "config corpus file set differs: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn validate_inputs(root: &Path, bytes: &[u8]) -> Result<Vec<Fixture>, String> {
    let values = jsonl(bytes, "config inputs")?;
    if values.len() != 66 {
        return Err(format!("expected 66 config inputs, got {}", values.len()));
    }
    let mut identities = Vec::new();
    let mut fixtures = Vec::new();
    let mut kinds = BTreeMap::<String, usize>::new();
    let mut upstream_paths = BTreeSet::new();
    let fixture_root = root.join("compat/fixtures/upstream/testdata/config");
    for value in values {
        let kind = required_str(&value, "kind", "config input")?;
        let path = required_str(&value, "path", "config input")?;
        validate_relative(Path::new(path))?;
        let decoded = BASE64
            .decode(required_str(&value, "config_base64", path)?)
            .map_err(|error| format!("{path}: invalid config_base64: {error}"))?;
        require_exact(&value, "sha256", &sha256_bytes(&decoded), path)?;
        identities.push(format!("{kind}\t{path}\n"));
        *kinds.entry(kind.to_owned()).or_default() += 1;
        if kind == "upstream-fixture" {
            let copied = read(&fixture_root.join(path))?;
            if copied != decoded {
                return Err(format!(
                    "copied config fixture {path} differs from canonical input"
                ));
            }
            upstream_paths.insert(PathBuf::from(path));
        } else if kind != "focused-auxiliary" {
            return Err(format!("unknown config input kind {kind}"));
        }
        fixtures.push(Fixture {
            path: PathBuf::from(path),
            bytes: decoded,
        });
    }
    if kinds.get("upstream-fixture") != Some(&50) || kinds.get("focused-auxiliary") != Some(&16) {
        return Err(format!("config input kind counts changed: {kinds:?}"));
    }
    let actual_upstream_paths = recursive_files(&fixture_root)?;
    if upstream_paths != actual_upstream_paths {
        return Err(format!(
            "copied config fixture file set changed: expected {upstream_paths:?}, got {actual_upstream_paths:?}"
        ));
    }
    identities.sort();
    require_hash(
        "config input identity set",
        identities.concat().as_bytes(),
        INPUT_IDENTITIES_SHA256,
    )?;
    let mut fixture_records = fixtures
        .iter()
        .filter(|fixture| fixture_root.join(&fixture.path).is_file())
        .map(|fixture| {
            format!(
                "{}\t{}\n",
                fixture.path.display(),
                sha256_bytes(&fixture.bytes)
            )
        })
        .collect::<Vec<_>>();
    fixture_records.sort();
    require_hash(
        "copied config fixture tree",
        fixture_records.concat().as_bytes(),
        FIXTURE_TREE_SHA256,
    )?;
    Ok(fixtures)
}

fn validate_requests(
    bytes: &[u8],
    fixtures: &[Fixture],
    default_config: &[u8],
) -> Result<Vec<Value>, String> {
    let values = jsonl(bytes, "config requests")?;
    if values.len() != 112 {
        return Err(format!(
            "expected 112 config requests, got {}",
            values.len()
        ));
    }
    let fixture_by_path = fixtures
        .iter()
        .map(|fixture| (fixture.path.to_string_lossy().into_owned(), fixture))
        .collect::<BTreeMap<_, _>>();
    let mut previous = None;
    let mut identities = Vec::new();
    let mut categories = BTreeMap::<String, usize>::new();
    let mut manifest_ids = BTreeSet::new();
    for value in &values {
        if value["protocol_version"] != 1 {
            return Err("config request protocol version changed".into());
        }
        let id = required_str(value, "id", "config request")?;
        if previous.is_some_and(|prior| prior >= id) {
            return Err(format!(
                "config request IDs are duplicated or unsorted at {id}"
            ));
        }
        previous = Some(id);
        identities.push(format!("{id}\n"));
        let category = required_str(value, "category", id)?;
        *categories.entry(category.to_owned()).or_default() += 1;
        for manifest_id in value["manifest_ids"]
            .as_array()
            .ok_or_else(|| format!("{id}: manifest_ids is not an array"))?
        {
            manifest_ids.insert(
                manifest_id
                    .as_str()
                    .ok_or_else(|| format!("{id}: manifest ID is not a string"))?
                    .to_owned(),
            );
        }
        validate_request_source(value, id, &fixture_by_path, default_config)?;
    }
    let expected_categories = BTreeMap::from([
        ("default".to_owned(), 1),
        ("extension-focused".to_owned(), 6),
        ("extension-reentrant".to_owned(), 2),
        ("focused".to_owned(), 53),
        ("upstream-fixture".to_owned(), 50),
    ]);
    if categories != expected_categories {
        return Err(format!(
            "config request category counts changed: {categories:?}"
        ));
    }
    require_hash(
        "config request identity set",
        identities.concat().as_bytes(),
        REQUEST_IDENTITIES_SHA256,
    )?;
    let mut manifest_identity_bytes = String::new();
    for id in manifest_ids {
        manifest_identity_bytes.push_str(&id);
        manifest_identity_bytes.push('\n');
    }
    require_hash(
        "config manifest identity set",
        manifest_identity_bytes.as_bytes(),
        MANIFEST_IDENTITIES_SHA256,
    )?;
    Ok(values)
}

fn validate_request_source(
    request: &Value,
    id: &str,
    fixtures: &BTreeMap<String, &Fixture>,
    default_config: &[u8],
) -> Result<(), String> {
    let source = request["source"]
        .as_object()
        .ok_or_else(|| format!("{id}: source is not an object"))?;
    let kind = source
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{id}: source kind is missing"))?;
    let decoded = BASE64
        .decode(
            source
                .get("config_base64")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{id}: config_base64 is missing"))?,
        )
        .map_err(|error| format!("{id}: invalid source config_base64: {error}"))?;
    require_exact(request, "input_sha256", &sha256_bytes(&decoded), id)?;
    match kind {
        "default" if decoded == default_config => {}
        "path" => {
            let path = source
                .get("path")
                .and_then(Value::as_str)
                .and_then(|path| path.strip_prefix("../testdata/config/"))
                .ok_or_else(|| format!("{id}: path source is outside the fixture tree"))?;
            let fixture = fixtures
                .get(path)
                .ok_or_else(|| format!("{id}: path source has no canonical input {path}"))?;
            if fixture.bytes != decoded {
                return Err(format!("{id}: path source bytes differ from {path}"));
            }
        }
        "inline" => {}
        "origin" if source.get("origin").and_then(Value::as_str) == Some("virtual/config.toml") => {
        }
        _ => return Err(format!("{id}: invalid source kind or metadata {kind}")),
    }
    Ok(())
}

fn jsonl(bytes: &[u8], label: &str) -> Result<Vec<Value>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} lacks a final newline"));
    }
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .map(|(index, line)| {
            if line == b"\n" {
                return Err(format!("{label} line {} is blank", index + 1));
            }
            serde_json::from_slice(line)
                .map_err(|error| format!("{label} line {} is invalid JSON: {error}", index + 1))
        })
        .collect()
}

fn validate_relative(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe config input path: {}", path.display()));
    }
    Ok(())
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

fn require_exact(value: &Value, field: &str, expected: &str, label: &str) -> Result<(), String> {
    if value.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(format!("{label}: {field} changed"));
    }
    Ok(())
}

fn required_str<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: {field} is not a string"))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::validate_relative;
    use std::path::Path;

    #[test]
    fn input_paths_accept_spaces_and_unicode_but_reject_escape() {
        assert!(validate_relative(Path::new("focused dir ü/input.toml")).is_ok());
        assert!(validate_relative(Path::new("../escape.toml")).is_err());
        assert!(validate_relative(Path::new("/absolute.toml")).is_err());
    }
}
