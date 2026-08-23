//! Validation of the frozen 607-identity API inventory and constructor manifest join.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::tooling::support::sha256_bytes;

use super::{IDENTITY_COUNT, IDENTITY_SHA256, REVISION};

pub(super) struct Inventory {
    pub(super) keys: BTreeSet<String>,
    pub(super) records: BTreeMap<String, Record>,
    pub(super) generator_ids: BTreeMap<String, String>,
}

#[derive(Clone)]
pub(super) struct Record {
    pub(super) key: String,
    pub(super) identity: String,
    pub(super) identity_sha256: String,
    pub(super) package: String,
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) owner: String,
}

pub(super) fn validate_inventory(root: &Path) -> Result<Inventory, String> {
    let path = root.join("compat/api-inventory-v1.json");
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid API inventory {}: {error}", path.display()))?;
    expect_string(
        &document,
        "upstream_revision",
        REVISION,
        "inventory revision mismatch",
    )?;
    expect_usize(
        &document,
        "identity_count",
        IDENTITY_COUNT,
        "inventory identity count mismatch",
    )?;
    expect_string(
        &document,
        "identity_set_sha256",
        IDENTITY_SHA256,
        "inventory identity SHA mismatch",
    )?;

    let records = document
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| "inventory lacks records".to_owned())?;
    let identities = document
        .get("identities")
        .and_then(Value::as_array)
        .ok_or_else(|| "inventory lacks identities".to_owned())?;
    if records.len() != IDENTITY_COUNT {
        return Err("inventory record count mismatch".into());
    }
    if identities.len() != IDENTITY_COUNT {
        return Err("inventory identity count mismatch".into());
    }

    let mut record_map = BTreeMap::new();
    for record in records {
        let key = field(record, "key")?.to_owned();
        let provenance = Record {
            key: key.clone(),
            identity: field(record, "identity")?.to_owned(),
            identity_sha256: field(record, "identity_sha256")?.to_owned(),
            package: field(record, "package")?.to_owned(),
            kind: field(record, "kind")?.to_owned(),
            name: field(record, "name")?.to_owned(),
            owner: record
                .get("owner")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        };
        if record_map.insert(key, provenance).is_some() {
            return Err("duplicate inventory key".into());
        }
    }
    let keys = record_map.keys().cloned().collect();
    let identity_set = collect_unique(
        identities.iter().map(|identity| {
            identity
                .as_str()
                .ok_or_else(|| "non-string inventory identity".to_owned())
        }),
        "inventory identity",
    )?;
    let mut identity_stream = identity_set.iter().cloned().collect::<Vec<_>>();
    identity_stream.sort();
    let stream = identity_stream
        .into_iter()
        .fold(String::new(), |mut output, identity| {
            writeln!(&mut output, "{identity}").expect("writing to String cannot fail");
            output
        });
    if sha256_bytes(stream.as_bytes()) != IDENTITY_SHA256 {
        return Err("inventory identity stream digest mismatch".into());
    }
    let generator_ids = validate_constructor_manifest(root, records)?;
    Ok(Inventory {
        keys,
        records: record_map,
        generator_ids,
    })
}

fn validate_constructor_manifest(
    root: &Path,
    records: &[Value],
) -> Result<BTreeMap<String, String>, String> {
    let mut constructors = records
        .iter()
        .filter(|record| {
            field(record, "package")
                .is_ok_and(|package| package.ends_with("/cmd/generate/config/rules"))
                && field(record, "kind").is_ok_and(|kind| kind == "func")
        })
        .map(|record| field(record, "name").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    constructors.sort();
    if constructors.len() != 225 {
        return Err("expected 225 rule constructors".into());
    }
    let expected = constructors
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name, format!("GEN-{:04}", index + 1)))
        .collect::<BTreeMap<_, _>>();

    let path = root.join("compat/test-manifest.toml");
    let manifest = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut actual = BTreeMap::new();
    for block in manifest.split("[[generator_constructor]]").skip(1) {
        let body = block.split("[[").next().unwrap_or(block);
        let id = assignment(body, "id")
            .ok_or_else(|| "malformed generator_constructor manifest block".to_owned())?;
        let name = assignment(body, "name")
            .ok_or_else(|| "malformed generator_constructor manifest block".to_owned())?;
        if actual.insert(name, id).is_some() {
            return Err("duplicate generator manifest constructor".into());
        }
    }
    if actual.len() != 225 {
        return Err("generator manifest constructor count mismatch".into());
    }
    if actual != expected {
        return Err("generator manifest IDs differ from API constructor set".into());
    }
    Ok(actual)
}

fn assignment(block: &str, field_name: &str) -> Option<String> {
    let prefix = format!("{field_name} = \"");
    block.lines().find_map(|line| {
        line.strip_prefix(&prefix)?
            .strip_suffix('"')
            .map(str::to_owned)
    })
}

fn collect_unique<'a>(
    values: impl Iterator<Item = Result<&'a str, String>>,
    label: &str,
) -> Result<BTreeSet<String>, String> {
    let mut output = BTreeSet::new();
    for value in values {
        if !output.insert(value?.to_owned()) {
            return Err(format!("duplicate {label}"));
        }
    }
    Ok(output)
}

fn expect_string(
    document: &Value,
    field_name: &str,
    expected: &str,
    error: &str,
) -> Result<(), String> {
    if field(document, field_name)? != expected {
        return Err(error.to_owned());
    }
    Ok(())
}

fn expect_usize(
    document: &Value,
    field_name: &str,
    expected: usize,
    error: &str,
) -> Result<(), String> {
    if document.get(field_name).and_then(Value::as_u64) != Some(expected as u64) {
        return Err(error.to_owned());
    }
    Ok(())
}

fn field<'a>(value: &'a Value, field_name: &str) -> Result<&'a str, String> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("inventory record lacks {field_name}"))
}
