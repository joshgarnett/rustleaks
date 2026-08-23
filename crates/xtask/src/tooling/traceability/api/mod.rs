//! Frozen Go API-disposition generation, checking, mutation controls, and summaries.

mod inventory;
mod model;
mod rules;
mod validation;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde_json::Value;

use self::inventory::validate_inventory;
use self::model::{Row, jsonl};
use self::validation::{load_rows, validate_rows};

pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const IDENTITY_COUNT: usize = 607;
pub(super) const IDENTITY_SHA256: &str =
    "de2e917190f3fdcc24c3db77e3e0a5c7fdd09aff97805b066273f4a7b6e96e6b";
pub(super) const DISPOSITIONS_SHA256: &str =
    "aafe70e228d5cc740b42b8c6dad5ea353aec1052a7d8e8152b0ea731bd41eb56";

/// Recreate the pinned disposition artifact and return Ruby-compatible summary output.
pub(crate) fn write_api_dispositions(root: &Path, output: &Path) -> Result<String, String> {
    let (inventory, rows, bytes) = expected(root)?;
    validate_rows(root, &inventory, &rows, &rows, true)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::write(output, &bytes)
        .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
    render_summary(&rows, SummaryMode::Plain)
}

/// Check a candidate artifact byte-for-byte and return Ruby-compatible check output.
pub(crate) fn check_api_dispositions(root: &Path, candidate: &Path) -> Result<String, String> {
    validate_candidate(root, candidate).and_then(|rows| render_summary(&rows, SummaryMode::Check))
}

/// Run all same-count mutation controls against a checked candidate.
pub(crate) fn self_test_api_dispositions(root: &Path, candidate: &Path) -> Result<String, String> {
    let (inventory, expected, expected_bytes) = expected(root)?;
    let bytes = fs::read(candidate)
        .map_err(|error| format!("cannot read {}: {error}", candidate.display()))?;
    let rows = load_rows(&bytes, &candidate.display().to_string())?;
    if bytes != expected_bytes {
        return Err(format!(
            "API disposition artifact differs: {}",
            candidate.display()
        ));
    }
    validate_rows(root, &inventory, &rows, &expected, true)?;
    prove_mutations(root, &inventory, &rows, &expected)?;
    render_summary(&rows, SummaryMode::SelfTest)
}

/// Validate a candidate and return the Ruby `summary` mode output.
pub(crate) fn summarize_api_dispositions(root: &Path, candidate: &Path) -> Result<String, String> {
    validate_candidate(root, candidate).and_then(|rows| render_summary(&rows, SummaryMode::Plain))
}

fn validate_candidate(root: &Path, candidate: &Path) -> Result<Vec<Value>, String> {
    let (inventory, expected, expected_bytes) = expected(root)?;
    let bytes = fs::read(candidate)
        .map_err(|error| format!("cannot read {}: {error}", candidate.display()))?;
    if bytes != expected_bytes {
        return Err(format!(
            "API disposition artifact differs: {}",
            candidate.display()
        ));
    }
    let rows = load_rows(&bytes, &candidate.display().to_string())?;
    validate_rows(root, &inventory, &rows, &expected, true)?;
    Ok(rows)
}

fn expected(root: &Path) -> Result<(inventory::Inventory, Vec<Value>, Vec<u8>), String> {
    let inventory = validate_inventory(root)?;
    let mut rows = Vec::with_capacity(inventory.records.len());
    for record in inventory.records.values() {
        rows.push(Row::new(record, rules::annotation(record, &inventory)?));
    }
    let bytes = jsonl(&rows)?;
    let digest = crate::tooling::support::sha256_bytes(&bytes);
    if digest != DISPOSITIONS_SHA256 {
        return Err(format!(
            "derived API dispositions digest mismatch: {digest} != {DISPOSITIONS_SHA256}"
        ));
    }
    let parsed = load_rows(&bytes, "derived API dispositions")?;
    Ok((inventory, parsed, bytes))
}

fn prove_mutations(
    root: &Path,
    inventory: &inventory::Inventory,
    rows: &[Value],
    expected: &[Value],
) -> Result<(), String> {
    let mut key_mutation = rows.to_vec();
    let key = required_string_mut(&mut key_mutation[0], "source_key")?;
    key.push_str("#substituted");
    reject_mutation(
        root,
        inventory,
        &key_mutation,
        expected,
        "same-count key substitution",
    )?;

    let mut disposition_mutation = rows.to_vec();
    let current = disposition_mutation[0]["disposition"]
        .as_str()
        .ok_or_else(|| "first row lacks disposition".to_owned())?;
    let replacement = validation::DISPOSITIONS
        .iter()
        .find(|candidate| **candidate != current)
        .ok_or_else(|| "no alternate disposition".to_owned())?;
    disposition_mutation[0]["disposition"] = Value::String((*replacement).to_owned());
    reject_mutation(
        root,
        inventory,
        &disposition_mutation,
        expected,
        "same-count disposition substitution",
    )?;

    let mut status_mutation = rows.to_vec();
    status_mutation[0]["implementation_status"] = Value::String("partial".to_owned());
    reject_mutation(
        root,
        inventory,
        &status_mutation,
        expected,
        "unfinished implementation status",
    )
}

fn required_string_mut<'a>(row: &'a mut Value, field: &str) -> Result<&'a mut String, String> {
    match row.get_mut(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(format!("mutation row lacks {field}")),
    }
}

fn reject_mutation(
    root: &Path,
    inventory: &inventory::Inventory,
    rows: &[Value],
    expected: &[Value],
    label: &str,
) -> Result<(), String> {
    if rows.len() != expected.len() {
        return Err(format!("{label} changed count"));
    }
    if validate_rows(root, inventory, rows, expected, false).is_ok() {
        return Err(format!("{label} was accepted"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SummaryMode {
    Plain,
    Check,
    SelfTest,
}

fn render_summary(rows: &[Value], mode: SummaryMode) -> Result<String, String> {
    let mut dispositions = BTreeMap::<String, usize>::new();
    let mut clusters = BTreeMap::<String, usize>::new();
    for row in rows {
        *dispositions
            .entry(required(row, "disposition")?.to_owned())
            .or_default() += 1;
        *clusters
            .entry(required(row, "disposition_cluster")?.to_owned())
            .or_default() += 1;
    }
    let mut output = String::from("{\n");
    string_field(&mut output, 2, "upstream_revision", REVISION, true)?;
    string_field(
        &mut output,
        2,
        "inventory_identity_set_sha256",
        IDENTITY_SHA256,
        true,
    )?;
    string_field(
        &mut output,
        2,
        "dispositions_sha256",
        DISPOSITIONS_SHA256,
        true,
    )?;
    writeln!(&mut output, "  \"rows\": {},", rows.len()).expect("writing to String cannot fail");
    map_field(&mut output, "by_disposition", &dispositions, true)?;
    let extra = !matches!(mode, SummaryMode::Plain);
    map_field(&mut output, "by_cluster", &clusters, extra)?;
    match mode {
        SummaryMode::Plain => {}
        SummaryMode::Check => string_field(&mut output, 2, "status", "ok", false)?,
        SummaryMode::SelfTest => {
            string_field(&mut output, 2, "status", "ok", true)?;
            string_field(
                &mut output,
                2,
                "same_count_key_substitution",
                "rejected",
                true,
            )?;
            string_field(
                &mut output,
                2,
                "same_count_disposition_substitution",
                "rejected",
                true,
            )?;
            string_field(
                &mut output,
                2,
                "unfinished_status_substitution",
                "rejected",
                false,
            )?;
        }
    }
    output.push_str("}\n");
    Ok(output)
}

fn map_field(
    output: &mut String,
    name: &str,
    values: &BTreeMap<String, usize>,
    comma: bool,
) -> Result<(), String> {
    writeln!(output, "  {}: {{", quote(name)?).expect("writing to String cannot fail");
    for (index, (key, value)) in values.iter().enumerate() {
        let suffix = if index + 1 == values.len() { "" } else { "," };
        writeln!(output, "    {}: {value}{suffix}", quote(key)?)
            .expect("writing to String cannot fail");
    }
    output.push_str(if comma { "  },\n" } else { "  }\n" });
    Ok(())
}

fn string_field(
    output: &mut String,
    indent: usize,
    name: &str,
    value: &str,
    comma: bool,
) -> Result<(), String> {
    let suffix = if comma { "," } else { "" };
    writeln!(
        output,
        "{}{}: {}{suffix}",
        " ".repeat(indent),
        quote(name)?,
        quote(value)?
    )
    .expect("writing to String cannot fail");
    Ok(())
}

fn quote(value: &str) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("cannot quote summary string: {error}"))
}

fn required<'a>(row: &'a Value, field: &str) -> Result<&'a str, String> {
    row.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("summary row lacks {field}"))
}
