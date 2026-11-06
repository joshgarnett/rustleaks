//! Immutable CLI request and historical provenance contracts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::newline_records;
use super::validation::{required_array, required_object, required_str, required_u64};
use crate::tooling::support::sha256_bytes;

pub(super) const CASE_COUNT: usize = 34;
pub(super) const VARIANT_COUNT: usize = 119;
pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
pub(super) const BUILD_VERSION: &str = "0.1.0-alpha.5";

pub(super) fn validate_inputs(
    requests: &[u8],
    negative: &[u8],
    negative_value: &Value,
    manifest: &Value,
) -> Result<Vec<Value>, String> {
    if required_str(manifest, "corpus_version", "manifest")? != "rustleaks-cli-corpus-v1"
        || required_u64(manifest, "protocol_version", "manifest")? != 1
        || required_str(manifest, "upstream_revision", "manifest")? != REVISION
        || required_str(manifest, "default_config_sha256", "manifest")? != CONFIG_SHA256
        || required_str(manifest, "build_version", "manifest")? != BUILD_VERSION
        || required_u64(manifest, "case_count", "manifest")? != CASE_COUNT as u64
        || required_u64(manifest, "variant_count", "manifest")? != VARIANT_COUNT as u64
        || required_str(manifest, "requests_sha256", "manifest")? != sha256_bytes(requests)
        || required_str(manifest, "negative_controls_sha256", "manifest")? != sha256_bytes(negative)
    {
        return Err("CLI manifest provenance or canonical hashes changed".into());
    }
    validate_accounting(manifest)?;
    validate_negative(negative_value)?;
    let lines = newline_records(requests, "CLI requests")?;
    if lines.len() != CASE_COUNT {
        return Err(format!("CLI case count changed to {}", lines.len()));
    }
    let mut rows = Vec::with_capacity(lines.len());
    let mut variant_count = 0;
    let mut dispositions = BTreeMap::<String, usize>::new();
    for (number, line) in (1..=CASE_COUNT).zip(lines) {
        let row: Value = serde_json::from_slice(line)
            .map_err(|e| format!("invalid CLI request {number}: {e}"))?;
        let expected_id = format!("CLI-BB-{number:03}");
        if required_u64(&row, "protocol_version", &expected_id)? != 1
            || required_str(&row, "id", "CLI request")? != expected_id
            || required_str(&row, "title", &expected_id)?.is_empty()
        {
            return Err(format!("{expected_id}: request envelope changed"));
        }
        let variants = required_array(&row, "variants", &expected_id)?;
        let mut ids = BTreeSet::new();
        for variant in variants {
            let id = required_str(variant, "id", &expected_id)?;
            if !ids.insert(id) {
                return Err(format!("{expected_id}: duplicate variant {id}"));
            }
            validate_variant(variant, &expected_id)?;
            if let Some(disposition) = variant.get("disposition").and_then(Value::as_str) {
                *dispositions.entry(disposition.into()).or_default() += 1;
            }
        }
        variant_count += variants.len();
        rows.push(row);
    }
    if variant_count != VARIANT_COUNT {
        return Err(format!("CLI variant count changed to {variant_count}"));
    }
    let manifest_dispositions = required_object(manifest, "disposition_counts", "manifest")?;
    for (id, count) in dispositions {
        if manifest_dispositions.get(&id).and_then(Value::as_u64) != Some(count as u64) {
            return Err(format!("CLI disposition count changed for {id}"));
        }
    }
    Ok(rows)
}

fn validate_variant(value: &Value, label: &str) -> Result<(), String> {
    for field in ["id", "setup", "stdin_base64"] {
        required_str(value, field, label)?;
    }
    if !value.get("args").is_some_and(Value::is_array)
        || !value.get("env").is_some_and(Value::is_object)
        || !value.get("expectation").is_some_and(Value::is_object)
        || !(value["report_path"].is_string() || value["report_path"].is_null())
        || !(value["disposition"].is_string() || value["disposition"].is_null())
        || !(value["finding_source"].is_string() || value["finding_source"].is_null())
        || !(value["prepare"].is_string() || value["prepare"].is_null())
    {
        return Err(format!("{label}: variant shape changed"));
    }
    Ok(())
}

fn validate_accounting(manifest: &Value) -> Result<(), String> {
    for (field, value) in [
        ("paired_observation_pair_count", 119),
        ("paired_observation_process_count", 238),
        ("auxiliary_cli_process_count", 4),
        ("fresh_cli_process_count", 242),
        ("exact_variant_count", 101),
        ("versioned_disposition_variant_count", 18),
        (
            "complete_duplicate_preserving_finding_count_both_implementations",
            102,
        ),
        ("raw_report_byte_count_both_implementations", 49_540),
        ("parser_usage_byte_count_both_implementations", 19_508),
        ("stderr_event_count_both_implementations", 888),
        ("mutation_control_count", 20),
    ] {
        if required_u64(manifest, field, "manifest")? != value {
            return Err(format!("CLI manifest {field} changed"));
        }
    }
    if ![
        "independently-validated-then-omitted",
        "independently-validated-with-native-linux-record",
    ]
    .contains(&required_str(
        manifest,
        "runtime_provenance_policy",
        "manifest",
    )?) {
        return Err("CLI runtime provenance policy changed".into());
    }
    Ok(())
}

fn validate_negative(negative: &Value) -> Result<(), String> {
    let controls = required_array(negative, "controls", "negative controls")?;
    if controls.len() != 20 {
        return Err("CLI mutation-control count changed".into());
    }
    let mut ids = BTreeSet::new();
    for control in controls {
        let id = required_str(control, "id", "negative control")?;
        if !ids.insert(id) || !id.starts_with("MUT-CLI-") {
            return Err(format!("invalid CLI mutation control {id}"));
        }
        for field in [
            "case_id",
            "variant_id",
            "expected_failure_class",
            "observed_rejection_sha256",
        ] {
            if required_str(control, field, id)?.is_empty() {
                return Err(format!("{id}: incomplete mutation control"));
            }
        }
    }
    Ok(())
}
