//! Fail-closed validation of API-disposition JSONL and repository evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::inventory::Inventory;
use super::{IDENTITY_COUNT, IDENTITY_SHA256, REVISION};

pub(super) const DISPOSITIONS: &[&str] = &[
    "equivalent-public-api",
    "idiomatic-public-replacement",
    "compatibility-shim",
    "compatibility-tooling-private-implementation",
    "out-of-public-product-scope",
];
const PUBLICITIES: &[&str] = &[
    "public",
    "compatibility-public",
    "crate-private",
    "binary-private",
    "tooling-private",
    "none",
];
const REQUIRED_FIELDS: &[&str] = &[
    "schema_version",
    "upstream_revision",
    "inventory_identity_set_sha256",
    "source_key",
    "source_identity",
    "source_identity_sha256",
    "source_package",
    "source_kind",
    "disposition",
    "disposition_cluster",
    "rust_crate",
    "rust_module",
    "rust_path",
    "rust_publicity",
    "contract_justification",
    "behavior_links",
    "manifest_links",
    "implementation_status",
    "test_status",
    "evidence_status",
    "implementation_evidence",
    "design_evidence",
];
const NONEMPTY_FIELDS: &[&str] = &[
    "source_key",
    "source_identity",
    "source_identity_sha256",
    "source_package",
    "source_kind",
    "disposition_cluster",
    "rust_crate",
    "rust_module",
    "rust_path",
    "contract_justification",
    "implementation_evidence",
    "design_evidence",
];

pub(super) fn load_rows(bytes: &[u8], label: &str) -> Result<Vec<Value>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} lacks terminal newline"));
    }
    bytes
        .split(|byte| *byte == b'\n')
        .take_while(|line| !line.is_empty())
        .enumerate()
        .map(|(index, line)| {
            if line.iter().all(u8::is_ascii_whitespace) {
                return Err(format!("blank JSONL line {}", index + 1));
            }
            serde_json::from_slice(line)
                .map_err(|error| format!("invalid JSONL line {}: {error}", index + 1))
        })
        .collect()
}

pub(super) fn validate_rows(
    root: &Path,
    inventory: &Inventory,
    rows: &[Value],
    expected: &[Value],
    _check_digest: bool,
) -> Result<(), String> {
    if rows.len() != IDENTITY_COUNT {
        return Err("disposition row count mismatch".into());
    }
    let mut keys = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        validate_row(index + 1, row)?;
        keys.push(required(row, "source_key")?.to_owned());
    }
    if !keys.windows(2).all(|pair| pair[0] <= pair[1]) {
        return Err("disposition keys are not sorted".into());
    }
    if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
        return Err("duplicate disposition key".into());
    }
    if keys.iter().cloned().collect::<BTreeSet<_>>() != inventory.keys {
        return Err("disposition key-set differs from inventory".into());
    }
    validate_inventory_join(rows, inventory)?;
    validate_expected(rows, expected)?;
    validate_source_paths(root, rows)?;
    Ok(())
}

fn validate_inventory_join(rows: &[Value], inventory: &Inventory) -> Result<(), String> {
    for row in rows {
        let key = required(row, "source_key")?;
        let record = inventory
            .records
            .get(key)
            .ok_or_else(|| format!("missing inventory record for {key}"))?;
        for (field, actual, expected) in [
            (
                "source_identity",
                required(row, "source_identity")?,
                record.identity.as_str(),
            ),
            (
                "source_identity_sha256",
                required(row, "source_identity_sha256")?,
                record.identity_sha256.as_str(),
            ),
            (
                "source_package",
                required(row, "source_package")?,
                record.package.as_str(),
            ),
            (
                "source_kind",
                required(row, "source_kind")?,
                record.kind.as_str(),
            ),
        ] {
            if actual != expected {
                return Err(format!("disposition {field} differs for {key}"));
            }
        }
    }
    Ok(())
}

fn validate_row(index: usize, row: &Value) -> Result<(), String> {
    let object = row
        .as_object()
        .ok_or_else(|| format!("row {index} is not an object"))?;
    validate_fields(index, object)?;
    if row["schema_version"].as_u64() != Some(1) {
        return Err(format!("row {index} bad schema"));
    }
    expect(index, row, "upstream_revision", REVISION, "revision")?;
    expect(
        index,
        row,
        "inventory_identity_set_sha256",
        IDENTITY_SHA256,
        "inventory digest",
    )?;
    member(index, row, "disposition", DISPOSITIONS)?;
    member(index, row, "rust_publicity", PUBLICITIES)?;
    member(
        index,
        row,
        "implementation_status",
        &["implemented", "not-applicable"],
    )?;
    member(index, row, "test_status", &["passing", "not-applicable"])?;
    member(
        index,
        row,
        "evidence_status",
        &["rust-tested", "go-inventoried"],
    )?;
    validate_final_status(index, row)?;
    for field in NONEMPTY_FIELDS {
        if required(row, field)?.is_empty() {
            return Err(format!("row {index} empty {field}"));
        }
    }
    if required(row, "contract_justification")?.chars().count() < 40 {
        return Err(format!("row {index} short justification"));
    }
    if required(row, "implementation_status")? == "not-applicable"
        && !required(row, "implementation_evidence")?.starts_with("Final release disposition:")
    {
        return Err(format!(
            "row {index} lacks a precise final release disposition"
        ));
    }
    if !required(row, "design_evidence")?.starts_with("docs/ARCHITECTURE.md#") {
        return Err(format!("row {index} bad design evidence"));
    }
    for field in ["behavior_links", "manifest_links"] {
        let links = row
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("row {index} empty {field}"))?;
        if links.is_empty()
            || links
                .iter()
                .any(|link| link.as_str().is_none_or(str::is_empty))
        {
            return Err(format!("row {index} empty {field}"));
        }
    }
    Ok(())
}

fn validate_fields(index: usize, object: &Map<String, Value>) -> Result<(), String> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let required = REQUIRED_FIELDS.iter().copied().collect::<BTreeSet<_>>();
    let missing = required.difference(&actual).copied().collect::<Vec<_>>();
    let extra = actual.difference(&required).copied().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "row {index} missing fields: {}",
            missing.join(", ")
        ));
    }
    if !extra.is_empty() {
        return Err(format!(
            "row {index} has unknown fields: {}",
            extra.join(", ")
        ));
    }
    Ok(())
}

fn validate_final_status(index: usize, row: &Value) -> Result<(), String> {
    let status = (
        required(row, "implementation_status")?,
        required(row, "test_status")?,
        required(row, "evidence_status")?,
    );
    if !matches!(
        status,
        ("implemented", "passing", "rust-tested")
            | ("not-applicable", "not-applicable", "go-inventoried")
    ) {
        return Err(format!("row {index} has inconsistent final status"));
    }
    Ok(())
}

fn validate_expected(rows: &[Value], expected: &[Value]) -> Result<(), String> {
    let expected = by_key(expected)?;
    let actual = by_key(rows)?;
    if expected.keys().collect::<Vec<_>>() != actual.keys().collect::<Vec<_>>() {
        return Err("disposition key-set mismatch".into());
    }
    for (key, wanted) in expected {
        if actual.get(key) != Some(&wanted) {
            return Err(format!("disposition row differs for {key}"));
        }
    }
    Ok(())
}

fn by_key(rows: &[Value]) -> Result<BTreeMap<&str, &Value>, String> {
    rows.iter()
        .map(|row| Ok((required(row, "source_key")?, row)))
        .collect()
}

fn validate_source_paths(root: &Path, rows: &[Value]) -> Result<(), String> {
    let implemented = rows
        .iter()
        .filter(|row| row["implementation_status"] == "implemented")
        .collect::<Vec<_>>();
    for row in &implemented {
        if row["rust_crate"] == "rustleaks-sources" {
            let path = required(row, "rust_path")?;
            if path.contains("SourceOptions") || path.ends_with("::run_source") {
                return Err(format!(
                    "implemented source disposition references stale Rust path: {path}"
                ));
            }
        }
    }
    for (symbol, relative, needle) in [
        (
            "rustleaks_sources::FileSource",
            "file.rs",
            "pub struct FileSource",
        ),
        (
            "rustleaks_sources::DirectorySource",
            "directory.rs",
            "pub struct DirectorySource",
        ),
        (
            "rustleaks_sources::SourceRunner",
            "runner.rs",
            "pub struct SourceRunner",
        ),
        (
            "rustleaks_sources::ArchiveLimits::new",
            "archive.rs",
            "pub fn new(",
        ),
        (
            "rustleaks_sources::DirectoryOptions::follow_symlinks",
            "directory.rs",
            "pub const fn follow_symlinks(",
        ),
    ] {
        if implemented.iter().any(|row| row["rust_path"] == symbol) {
            let path = root.join("crates/rustleaks-sources/src").join(relative);
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            if !source.contains(needle) {
                return Err(format!("implemented source symbol disappeared: {symbol}"));
            }
        }
    }
    Ok(())
}

fn expect(index: usize, row: &Value, field: &str, wanted: &str, label: &str) -> Result<(), String> {
    if required(row, field)? != wanted {
        return Err(format!("row {index} bad {label}"));
    }
    Ok(())
}

fn member(index: usize, row: &Value, field: &str, allowed: &[&str]) -> Result<(), String> {
    if !allowed.contains(&required(row, field)?) {
        return Err(format!("row {index} invalid {field}"));
    }
    Ok(())
}

fn required<'a>(row: &'a Value, field: &str) -> Result<&'a str, String> {
    row.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("row lacks string {field}"))
}
