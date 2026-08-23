//! Structural, cardinality, cryptographic, and semantic identity checks.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::Engine as _;
use serde_json::Value;

use super::{REVISION, json};

const TOTALS: [(&str, usize); 4] = [
    ("ordinary_true", 6_368),
    ("ordinary_false", 342),
    ("path_true", 28),
    ("path_false", 32),
];
const EXCLUSIONS: [(&str, &str); 3] = [
    (
        "GCPServiceAccount",
        "excluded-default; helper fails: escaped keyword does not occur in positive sample",
    ),
    (
        "SquareSecret",
        "excluded-default; helper passes when invoked independently",
    ),
    (
        "TrelloAccessToken",
        "excluded-default; helper passes when invoked independently",
    ),
];
const GAPS: [(&str, &str); 2] = [
    (
        "DropBoxLongLivedAPIToken",
        "selected-default; validate TODO returns rule without helper",
    ),
    (
        "DropBoxShortLivedAPIToken",
        "selected-default; validate TODO returns rule without helper",
    ),
];

pub(super) fn inventory(rows: &[Value]) -> Result<(), String> {
    if rows.len() != 225 {
        return Err(format!(
            "expected 225 constructor records, got {}",
            rows.len()
        ));
    }
    unique_strings(rows, "constructor", "constructor identities")?;
    unique_strings(rows, "rule_id", "constructor RuleIDs")?;
    for row in rows {
        if unsigned(row, "schema_version")? != 1
            || string(row, "record_type")? != "generator_constructor"
        {
            return Err("invalid constructor schema".into());
        }
        if string(row, "upstream_revision")? != REVISION {
            return Err("constructor revision mismatch".into());
        }
        let digest = string(row, "constructor_source_sha256")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("invalid constructor source digest".into());
        }
    }
    let selected: Vec<_> = rows
        .iter()
        .filter(|row| boolean(row, "selected_default").unwrap_or(false))
        .collect();
    let covered: Vec<_> = rows
        .iter()
        .filter(|row| boolean(row, "helper_covered").unwrap_or(false))
        .collect();
    if selected.len() != 222 {
        return Err(format!(
            "expected 222 selected constructors, got {}",
            selected.len()
        ));
    }
    if covered.len() != 220 {
        return Err(format!(
            "expected 220 helper-covered selected constructors, got {}",
            covered.len()
        ));
    }
    let mut helpers = BTreeMap::new();
    for row in selected {
        *helpers.entry(string(row, "helper")?).or_insert(0) += 1;
    }
    if helpers != BTreeMap::from([("none", 2), ("validate", 215), ("validate_with_paths", 5)]) {
        return Err(format!("selected helper split mismatch: {helpers:?}"));
    }
    disposition_set(rows, "selected_gap", &GAPS, "gap")?;
    disposition_set(rows, "excluded_default", &EXCLUSIONS, "excluded")?;
    let unexpected: Vec<_> = rows
        .iter()
        .filter(|row| string(row, "disposition") == Ok("unexpected_exclusion"))
        .collect();
    if !unexpected.is_empty() {
        return Err("unexpected excluded constructors".into());
    }
    Ok(())
}

pub(super) fn samples(rows: &[Value], constructors: &[Value]) -> Result<(), String> {
    if rows.len() != 6_770 {
        return Err(format!("expected 6770 sample records, got {}", rows.len()));
    }
    unique_strings(rows, "case_id", "sample case IDs")?;
    let mut totals = BTreeMap::new();
    for row in rows {
        *totals.entry(string(row, "polarity")?).or_insert(0) += 1;
    }
    if totals != BTreeMap::from(TOTALS) {
        return Err(format!("sample polarity totals mismatch: {totals:?}"));
    }
    let by_name: BTreeMap<_, _> = constructors
        .iter()
        .map(|row| Ok((string(row, "constructor")?, row)))
        .collect::<Result<_, String>>()?;
    for row in rows {
        sample(row, &by_name)?;
    }
    contiguous(rows)?;
    let covered: BTreeSet<_> = constructors
        .iter()
        .filter(|row| boolean(row, "helper_covered").unwrap_or(false))
        .map(|row| string(row, "constructor").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    let observed: BTreeSet<_> = rows
        .iter()
        .map(|row| string(row, "constructor").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    if observed != covered {
        return Err("helper-covered/sample constructor set mismatch".into());
    }
    duplicate_ordinals(rows)
}

fn sample(row: &Value, constructors: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let id = string(row, "case_id")?;
    if unsigned(row, "schema_version")? != 1 || string(row, "record_type")? != "generator_sample" {
        return Err(format!("{id}: invalid schema"));
    }
    if string(row, "upstream_revision")? != REVISION {
        return Err(format!("{id}: revision mismatch"));
    }
    let name = string(row, "constructor")?;
    let constructor = constructors
        .get(name)
        .ok_or_else(|| format!("{id}: unknown constructor"))?;
    if !boolean(constructor, "selected_default")? || !boolean(constructor, "helper_covered")? {
        return Err(format!("{id}: constructor is not selected/helper-covered"));
    }
    equal_field(row, constructor, "rule_id", id, "RuleID")?;
    equal_field(row, constructor, "helper", id, "helper")?;
    equal_field(
        row,
        constructor,
        "constructor_source_sha256",
        id,
        "source digest",
    )?;
    let polarity = string(row, "polarity")?;
    let ordinal = unsigned(row, "ordinal")?;
    let expected_id = format!("GEN/{name}/{polarity}/{ordinal:04}");
    if id != expected_id {
        return Err(format!("{id}: ID is not derived from source occurrence"));
    }
    let occurrence = format!(
        "{}:{}:{polarity}:{ordinal:04}",
        string(row, "source_file")?,
        unsigned(row, "helper_line")?
    );
    if string(row, "source_occurrence")? != occurrence {
        return Err(format!("{id}: source occurrence mismatch"));
    }
    let input = strict_base64(string(row, "input_base64")?, &format!("{id} input"))?;
    if string(row, "input_sha256")? != crate::tooling::support::sha256_bytes(&input) {
        return Err(format!("{id}: input digest mismatch"));
    }
    validate_path(row, id)?;
    validate_findings(row, id)?;
    validate_contract(row, id)?;
    validate_shape(row, id)?;
    validate_dependencies(row, id)?;
    let identity = crate::tooling::support::sha256_bytes(&json::identity_bytes(row)?);
    if string(row, "identity_sha256")? != identity {
        return Err(format!("{id}: identity digest mismatch"));
    }
    Ok(())
}

fn validate_path(row: &Value, id: &str) -> Result<(), String> {
    if boolean(row, "path_present")? {
        let path = strict_base64(string(row, "path_base64")?, &format!("{id} path"))?;
        if string(row, "path_sha256")? != crate::tooling::support::sha256_bytes(&path) {
            return Err(format!("{id}: path digest mismatch"));
        }
    } else if !json::required(row, "path_base64")?.is_null()
        || !json::required(row, "path_sha256")?.is_null()
    {
        return Err(format!("{id}: absent path must be JSON null"));
    }
    Ok(())
}

fn validate_findings(row: &Value, id: &str) -> Result<(), String> {
    let findings = json::required(row, "findings")?
        .as_array()
        .ok_or_else(|| format!("{id}: findings must be an array"))?;
    for (index, finding) in findings.iter().enumerate() {
        strict_base64(
            string(finding, "match_base64")?,
            &format!("{id} finding {index} match"),
        )?;
        strict_base64(
            string(finding, "secret_base64")?,
            &format!("{id} finding {index} secret"),
        )?;
    }
    if unsigned(row, "oracle_observed_count")? != u64::try_from(findings.len()).unwrap_or(u64::MAX)
    {
        return Err(format!("{id}: observed count mismatch"));
    }
    Ok(())
}

fn validate_contract(row: &Value, id: &str) -> Result<(), String> {
    let count = unsigned(row, "oracle_observed_count")?;
    match string(row, "contract")? {
        "at_least_one"
            if json::required(row, "upstream_expected_count")?.is_null() && count >= 1 =>
        {
            Ok(())
        }
        "exactly_one" if unsigned(row, "upstream_expected_count")? == 1 && count == 1 => Ok(()),
        "zero" if unsigned(row, "upstream_expected_count")? == 0 && count == 0 => Ok(()),
        "at_least_one" => Err(format!("{id}: at-least-one contract mismatch")),
        "exactly_one" => Err(format!("{id}: exactly-one contract mismatch")),
        "zero" => Err(format!("{id}: zero contract mismatch")),
        _ => Err(format!("{id}: unknown helper contract")),
    }
}

fn validate_shape(row: &Value, id: &str) -> Result<(), String> {
    let polarity = string(row, "polarity")?;
    let helper = string(row, "helper")?;
    let path = boolean(row, "path_present")?;
    if polarity.starts_with("ordinary_") && helper == "validate" && !path
        || polarity.starts_with("path_") && helper == "validate_with_paths" && path
    {
        return Ok(());
    }
    Err(format!("{id}: helper/path shape mismatch"))
}

fn validate_dependencies(row: &Value, id: &str) -> Result<(), String> {
    let dependencies = json::required(row, "dependencies")?;
    if !boolean(dependencies, "global_allowlist")? {
        return Err(format!("{id}: global allowlist dependency missing"));
    }
    let keywords = json::required(dependencies, "keyword_base64")?
        .as_array()
        .ok_or_else(|| format!("{id}: keywords must be an array"))?;
    for (index, keyword) in keywords.iter().enumerate() {
        strict_base64(
            keyword
                .as_str()
                .ok_or_else(|| format!("{id}: keyword {index} must be a string"))?,
            &format!("{id} keyword {index}"),
        )?;
    }
    unsigned(dependencies, "rule_allowlist_count")?;
    if boolean(dependencies, "has_path")? != boolean(row, "path_present")?
        && string(row, "helper")? != "validate"
    {
        return Err(format!("{id}: helper/path dependency mismatch"));
    }
    match string(row, "origin_kind")? {
        "generated_template"
            if string(row, "template_key").is_ok_and(|value| !value.is_empty()) =>
        {
            Ok(())
        }
        "direct" if json::required(row, "template_key")?.is_null() => Ok(()),
        "generated_template" => Err(format!("{id}: generated sample lacks template key")),
        "direct" => Err(format!("{id}: direct sample has template key")),
        _ => Err(format!("{id}: invalid origin kind")),
    }
}

fn contiguous(rows: &[Value]) -> Result<(), String> {
    let mut groups = BTreeMap::<(&str, &str), Vec<u64>>::new();
    for row in rows {
        groups
            .entry((string(row, "constructor")?, string(row, "polarity")?))
            .or_default()
            .push(unsigned(row, "ordinal")?);
    }
    for ((constructor, polarity), mut values) in groups {
        values.sort_unstable();
        if values.iter().copied().ne(0..values.len() as u64) {
            return Err(format!(
                "{constructor}/{polarity}: non-contiguous source ordinals"
            ));
        }
    }
    Ok(())
}

fn duplicate_ordinals(rows: &[Value]) -> Result<(), String> {
    let mut sorted: Vec<_> = rows.iter().collect();
    sorted.sort_by_key(|row| string(row, "case_id").unwrap_or_default());
    let mut seen = HashMap::<String, u64>::new();
    for row in sorted {
        let key = [
            "rule_id",
            "polarity",
            "path_present",
            "path_base64",
            "input_base64",
        ]
        .iter()
        .map(|field| {
            serde_json::to_string(json::required(row, field).unwrap_or(&Value::Null))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("|");
        let expected = seen.entry(key).or_default();
        if unsigned(row, "duplicate_ordinal")? != *expected {
            return Err(format!(
                "{}: duplicate ordinal mismatch",
                string(row, "case_id")?
            ));
        }
        *expected += 1;
    }
    Ok(())
}

pub(super) fn same_identities(expected: &[Value], actual: &[Value]) -> Result<(), String> {
    let expected = projected(expected)?;
    let actual = projected(actual)?;
    if expected == actual {
        return Ok(());
    }
    let missing = expected
        .keys()
        .find(|key| !actual.contains_key(*key))
        .map_or("<none>", String::as_str);
    let extra = actual
        .keys()
        .find(|key| !expected.contains_key(*key))
        .map_or("<none>", String::as_str);
    let changed = expected
        .iter()
        .find(|(key, value)| actual.get(*key).is_some_and(|actual| actual != *value))
        .map_or("<none>", |(key, _)| key);
    Err(format!(
        "stable generator identity drift: missing={missing}; extra={extra}; changed={changed}"
    ))
}

pub(super) fn negative_identity_control(rows: &[Value]) -> Result<(), String> {
    let mut changed = rows.to_vec();
    let id = changed
        .first_mut()
        .and_then(Value::as_object_mut)
        .and_then(|row| row.get_mut("case_id"))
        .and_then(|value| value.as_str())
        .ok_or("first sample lacks case_id")?
        .to_owned();
    changed[0]["case_id"] = Value::String(format!("{id}-SUBSTITUTED"));
    if same_identities(rows, &changed).is_ok() {
        return Err(
            "same-count identity-substitution negative self-test unexpectedly passed".into(),
        );
    }
    Ok(())
}

pub(super) fn changed_observations(expected: &[Value], actual: &[Value]) -> Result<usize, String> {
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|row| Ok((string(row, "case_id")?, row)))
        .collect::<Result<_, String>>()?;
    actual
        .iter()
        .map(|row| {
            let frozen = expected
                .get(string(row, "case_id")?)
                .ok_or("fresh sample absent from frozen set")?;
            Ok(usize::from(
                ["input_base64", "path_base64", "findings"]
                    .iter()
                    .any(|field| {
                        json::required(row, field).ok() != json::required(frozen, field).ok()
                    }),
            ))
        })
        .sum()
}

fn projected(rows: &[Value]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    rows.iter()
        .map(|row| {
            Ok((
                string(row, "case_id")?.to_owned(),
                json::identity_bytes(row)?,
            ))
        })
        .collect()
}

fn disposition_set(
    rows: &[Value],
    disposition: &str,
    expected: &[(&str, &str)],
    label: &str,
) -> Result<(), String> {
    let actual: BTreeMap<_, _> = rows
        .iter()
        .filter(|row| string(row, "disposition") == Ok(disposition))
        .map(|row| Ok((string(row, "constructor")?, string(row, "exception")?)))
        .collect::<Result<_, String>>()?;
    if actual != expected.iter().copied().collect() {
        return Err(format!("{label} constructor set mismatch"));
    }
    Ok(())
}

fn unique_strings(rows: &[Value], field: &str, label: &str) -> Result<(), String> {
    let values: BTreeSet<_> = rows
        .iter()
        .map(|row| string(row, field))
        .collect::<Result<_, _>>()?;
    if values.len() != rows.len() {
        return Err(format!("{label} are not unique"));
    }
    Ok(())
}

fn equal_field(
    left: &Value,
    right: &Value,
    field: &str,
    id: &str,
    label: &str,
) -> Result<(), String> {
    if json::required(left, field)? != json::required(right, field)? {
        return Err(format!("{id}: {label} mismatch"));
    }
    Ok(())
}

fn strict_base64(value: &str, label: &str) -> Result<Vec<u8>, String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{label} is invalid base64"))?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(format!("{label} is not canonical base64"));
    }
    Ok(decoded)
}

fn string<'a>(row: &'a Value, field: &str) -> Result<&'a str, String> {
    json::string(row, field)
}
fn unsigned(row: &Value, field: &str) -> Result<u64, String> {
    json::required(row, field)?
        .as_u64()
        .ok_or_else(|| format!("{field} must be a nonnegative integer"))
}
fn boolean(row: &Value, field: &str) -> Result<bool, String> {
    json::required(row, field)?
        .as_bool()
        .ok_or_else(|| format!("{field} must be boolean"))
}
