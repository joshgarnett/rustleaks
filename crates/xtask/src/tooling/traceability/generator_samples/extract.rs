//! Read-only archive instrumentation and observation normalization.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

use super::{CONFIG_SHA256, REVISION, json as corpus_json, observer, process};
use crate::tooling::support::TempDir;

pub(super) fn observations(upstream: &Path, inventory: &[Value]) -> Result<Vec<Value>, String> {
    let by_name: BTreeMap<String, &Value> = inventory
        .iter()
        .map(|row| Ok((corpus_json::string(row, "constructor")?.to_owned(), row)))
        .collect::<Result<_, String>>()?;
    let temporary = TempDir::new("generator-corpus")?;
    archive(upstream, &temporary.path)?;
    let validate = temporary.path.join("cmd/generate/config/utils/validate.go");
    fs::write(&validate, observer::VALIDATE_GO)
        .map_err(|error| format!("cannot write {}: {error}", validate.display()))?;
    observer::instrument_helpers(&temporary.path.join("cmd/generate/config/utils/generate.go"))?;
    observer::instrument_secret(&temporary.path.join("cmd/generate/secrets/regen.go"))?;

    let log = temporary.path.join("observations.jsonl");
    let generated = temporary.path.join("generated.toml");
    let go_cache = std::env::var_os("GOCACHE").map_or_else(
        || std::env::temp_dir().join("rustleaks-go-cache"),
        Into::into,
    );
    let module_cache = std::env::var_os("GOMODCACHE").map_or_else(
        || std::env::temp_dir().join("rustleaks-go-mod-cache"),
        Into::into,
    );
    let mut go = Command::new("go");
    go.current_dir(temporary.path.join("cmd/generate/config"))
        .args(["run", "."])
        .arg(&generated)
        .env("GOCACHE", go_cache)
        .env("GOMODCACHE", module_cache)
        .env("RUSTLEAKS_GENERATOR_SAMPLE_LOG", &log);
    process::status(&mut go, "instrumented generator", Duration::from_secs(600))?;
    let digest = crate::tooling::support::sha256_file(&generated)?;
    if digest != CONFIG_SHA256 {
        return Err(format!(
            "instrumentation changed generated config: {digest}"
        ));
    }
    let raw = corpus_json::read_jsonl(&log)?;
    normalize(&raw, &by_name)
}

fn archive(upstream: &Path, destination: &Path) -> Result<(), String> {
    let archive = destination.join("upstream.tar");
    let mut git = Command::new("git");
    git.arg("-C")
        .arg(upstream)
        .args(["archive", "--format=tar", "--output"])
        .arg(&archive)
        .arg(REVISION);
    process::status(&mut git, "git archive", Duration::from_secs(120))?;
    let mut tar = Command::new("tar");
    tar.args(["-xf"])
        .arg(&archive)
        .args(["-C"])
        .arg(destination);
    process::status(&mut tar, "git archive extraction", Duration::from_secs(120))
}

fn normalize(raw: &[Value], inventory: &BTreeMap<String, &Value>) -> Result<Vec<Value>, String> {
    let mut rows = raw
        .iter()
        .map(|record| normalize_one(record, inventory))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|left, right| {
        corpus_json::string(left, "case_id")
            .unwrap_or_default()
            .cmp(corpus_json::string(right, "case_id").unwrap_or_default())
    });
    let mut duplicates = HashMap::<String, u64>::new();
    for row in &mut rows {
        let key = serde_json::to_string(&json!([
            corpus_json::required(row, "rule_id")?,
            corpus_json::required(row, "polarity")?,
            corpus_json::required(row, "path_present")?,
            corpus_json::required(row, "path_base64")?,
            corpus_json::required(row, "input_base64")?
        ]))
        .map_err(|error| error.to_string())?;
        let ordinal = duplicates.entry(key).or_default();
        set(row, "duplicate_ordinal", Value::from(*ordinal))?;
        *ordinal += 1;
        let identity = corpus_json::identity_bytes(row)?;
        set(
            row,
            "identity_sha256",
            Value::String(crate::tooling::support::sha256_bytes(&identity)),
        )?;
    }
    Ok(rows)
}

fn normalize_one(raw: &Value, inventory: &BTreeMap<String, &Value>) -> Result<Value, String> {
    let name = corpus_json::string(raw, "constructor")?;
    let constructor = inventory
        .get(name)
        .ok_or_else(|| format!("observer emitted unknown constructor {name}"))?;
    if !boolean(constructor, "selected_default")? {
        return Err(format!("observer emitted unselected constructor {name}"));
    }
    for (raw_field, source_field, label) in [
        ("rule_id", "rule_id", "RuleID"),
        ("helper", "helper", "helper"),
        ("helper_source_file", "source_file", "helper source"),
        ("helper_line", "helper_line", "helper line"),
    ] {
        if corpus_json::required(raw, raw_field)?
            != corpus_json::required(constructor, source_field)?
        {
            return Err(format!("observer {label} mismatch for {name}"));
        }
    }
    let polarity = corpus_json::string(raw, "polarity")?;
    let ordinal = unsigned(raw, "ordinal")?;
    let helper_line = unsigned(constructor, "helper_line")?;
    let source_file = corpus_json::string(constructor, "source_file")?;
    let case_id = format!("GEN/{name}/{polarity}/{ordinal:04}");
    let occurrence = format!("{source_file}:{helper_line}:{polarity}:{ordinal:04}");
    let input_base64 = corpus_json::string(raw, "input_base64")?;
    let input = decode(input_base64, "observer input")?;
    let path_encoded = corpus_json::required(raw, "path_base64")?.clone();
    let path_sha = match path_encoded.as_str() {
        Some(value) => Value::String(crate::tooling::support::sha256_bytes(&decode(
            value,
            "observer path",
        )?)),
        None if path_encoded.is_null() => Value::Null,
        None => return Err("observer path_base64 must be a string or null".into()),
    };
    let findings = corpus_json::required(raw, "findings")?
        .as_array()
        .ok_or("observer findings must be an array")?;
    let contract = corpus_json::string(raw, "contract")?;
    let expected = match contract {
        "at_least_one" => Value::Null,
        "exactly_one" => Value::from(1),
        "zero" => Value::from(0),
        _ => return Err("unknown observer contract".into()),
    };
    Ok(json!({
        "schema_version": 1, "record_type": "generator_sample", "upstream_revision": REVISION,
        "case_id": case_id, "constructor": name, "rule_id": corpus_json::required(constructor, "rule_id")?.clone(),
        "selected_default": true, "helper": corpus_json::required(raw, "helper")?.clone(),
        "polarity": polarity, "ordinal": ordinal, "contract": contract,
        "source_file": source_file, "constructor_line": corpus_json::required(constructor, "constructor_line")?.clone(),
        "helper_line": helper_line, "source_occurrence": occurrence,
        "constructor_source_sha256": corpus_json::required(constructor, "constructor_source_sha256")?.clone(),
        "origin_kind": corpus_json::required(raw, "origin_kind")?.clone(),
        "origin_source_file": corpus_json::required(raw, "origin_source_file")?.clone(),
        "origin_line": corpus_json::required(raw, "origin_line")?.clone(), "template_key": corpus_json::required(raw, "template_key")?.clone(),
        "duplicate_ordinal": Value::Null, "input_base64": input_base64,
        "input_sha256": crate::tooling::support::sha256_bytes(&input),
        "path_present": corpus_json::required(raw, "path_present")?.clone(), "path_base64": path_encoded,
        "path_sha256": path_sha, "upstream_expected_count": expected,
        "oracle_observed_count": findings.len(), "findings": findings,
        "dependencies": corpus_json::required(raw, "dependencies")?.clone()
    }))
}

fn set(row: &mut Value, field: &str, value: Value) -> Result<(), String> {
    row.as_object_mut()
        .ok_or("sample row is not an object")?
        .insert(field.into(), value);
    Ok(())
}

fn boolean(row: &Value, field: &str) -> Result<bool, String> {
    corpus_json::required(row, field)?
        .as_bool()
        .ok_or_else(|| format!("{field} must be boolean"))
}

fn unsigned(row: &Value, field: &str) -> Result<u64, String> {
    corpus_json::required(row, field)?
        .as_u64()
        .ok_or_else(|| format!("{field} must be unsigned"))
}

fn decode(value: &str, label: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| format!("invalid {label} base64: {error}"))
}
