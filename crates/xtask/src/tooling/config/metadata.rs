//! Schema, manifest, source-pin, and coverage validation.

use std::fs;
use std::path::Path;

use serde_json::Value;

use super::spec::{
    CONFIG_SHA256, FIXTURE_TREE_SHA256, INPUTS_SHA256, ORACLE_MAIN_SHA256, OUTCOMES_SHA256,
    REQUESTS_SHA256, REVISION, SCHEMA_SHA256,
};
use crate::tooling::support::sha256_bytes;

pub(super) fn validate_schema(bytes: &[u8]) -> Result<(), String> {
    let schema: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid config schema JSON: {error}"))?;
    if require_u64(&schema, "schema_version", "schema")? != 1 {
        return Err("config schema version is not 1".into());
    }
    require_string_array(&schema, "request", "schema", 6)?;
    require_string_array(&schema, "source_kinds", "schema", 4)?;
    require_string_array(&schema, "response", "schema", 11)?;
    let canonicalization = schema["canonicalization"]
        .as_object()
        .ok_or("config schema canonicalization is not an object")?;
    if canonicalization.len() != 5 || canonicalization.values().any(|value| !value.is_string()) {
        return Err("config schema canonicalization contract changed".into());
    }
    Ok(())
}

pub(super) fn validate_manifest(root: &Path, bytes: &[u8]) -> Result<(), String> {
    let manifest: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid config manifest JSON: {error}"))?;
    require_exact(&manifest, "upstream_revision", REVISION)?;
    if require_u64(&manifest, "schema_version", "manifest")? != 1
        || require_u64(&manifest, "protocol_version", "manifest")? != 1
    {
        return Err("config manifest schema/protocol version changed".into());
    }
    for (field, expected) in [
        ("default_config_sha256", CONFIG_SHA256),
        ("schema_sha256", SCHEMA_SHA256),
        ("oracle_main_sha256", ORACLE_MAIN_SHA256),
        ("copied_config_tree_sha256", FIXTURE_TREE_SHA256),
        ("inputs_sha256", INPUTS_SHA256),
        ("requests_sha256", REQUESTS_SHA256),
        ("outcomes_sha256", OUTCOMES_SHA256),
    ] {
        require_exact(&manifest, field, expected)?;
    }
    let oracle = root.join("crates/rustleaks-compat/oracle");
    require_file_hash(&oracle.join("main.go"), ORACLE_MAIN_SHA256)?;
    let totals = manifest["case_totals"]
        .as_object()
        .ok_or("config manifest case_totals is not an object")?;
    for (field, expected) in [
        ("all", 112),
        ("upstream_fixtures", 50),
        ("default", 1),
        ("focused", 61),
        ("successful", 75),
        ("errors", 37),
    ] {
        if totals.get(field).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("config manifest {field} total changed"));
        }
    }
    if manifest["fresh_process_per_case"] != true
        || manifest["isolated_fixture_tree_per_case"] != true
    {
        return Err("config manifest isolation contract changed".into());
    }
    let covered = string_array(&manifest, "covered_manifest_ids", "manifest")?;
    let expected = (29..=31)
        .chain(34..=72)
        .map(|number| format!("TM-{number:04}"))
        .collect::<Vec<_>>();
    if covered != expected
        || manifest["deferred_manifest_ids"] != serde_json::json!(["TM-0028", "TM-0032", "TM-0033"])
    {
        return Err("config manifest covered/deferred identities changed".into());
    }
    Ok(())
}

fn require_file_hash(path: &Path, expected: &str) -> Result<(), String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let actual = sha256_bytes(&bytes);
    if actual != expected {
        return Err(format!(
            "{} SHA-256 changed: expected {expected}, got {actual}",
            path.display()
        ));
    }
    Ok(())
}

fn require_exact(value: &Value, field: &str, expected: &str) -> Result<(), String> {
    if value.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(format!("manifest: {field} changed"));
    }
    Ok(())
}

fn require_u64(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label}: {field} is not an unsigned integer"))
}

fn require_string_array(
    value: &Value,
    field: &str,
    label: &str,
    count: usize,
) -> Result<(), String> {
    let values = string_array(value, field, label)?;
    if values.len() != count {
        return Err(format!("{label}: {field} contract changed"));
    }
    Ok(())
}

fn string_array(value: &Value, field: &str, label: &str) -> Result<Vec<String>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: {field} is not an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{label}: {field} contains a non-string"))
        })
        .collect()
}
