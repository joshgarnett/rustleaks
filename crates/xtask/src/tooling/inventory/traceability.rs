use std::collections::BTreeSet;

use serde_json::Value;

use super::records::{json_string, json_strings, required, section_records};

const FINAL_BEHAVIOR_STATUSES: &[&str] = &[
    "traceability-complete",
    "explicit-cli-polish-follow-up",
    "implemented",
    "implemented-native-linux-windows-runtime-follow-up",
    "implemented-normalized-diagnostics",
    "implemented-pending-native-ci",
    "implemented-pending-native-windows",
    "implemented-raw",
    "implemented-safe-boundary",
    "implemented-safe-disclosure-disposition",
    "implemented-safe-error-disposition",
    "implemented-safe-error-dispositions",
    "implemented-safe-filesystem-disposition",
    "implemented-safe-in-memory-spool",
    "implemented-safe-numeric-disposition",
    "implemented-safe-overflow-disposition",
    "implemented-safe-process-disposition",
    "implemented-safe-profile",
    "implemented-timeout-ctrl-c-follow-up",
];

pub(super) fn verify(manifest: &str, behavior_matrix: &str, api_jsonl: &str) -> Result<(), String> {
    let behavior_records = section_records(behavior_matrix, "behavior");
    let mut behavior_ids = BTreeSet::new();
    for record in &behavior_records {
        let id = json_string(required(record, "id", "behavior row")?, "behavior id")?;
        if !behavior_ids.insert(id.clone()) {
            return Err(format!("behavior ID {id} is duplicated"));
        }
        let status = json_string(
            required(record, "status", &format!("behavior {id}"))?,
            &format!("behavior {id} status"),
        )?;
        if !FINAL_BEHAVIOR_STATUSES.contains(&status.as_str()) {
            return Err(format!("behavior {id} has non-final status {status}"));
        }
    }
    if behavior_ids.is_empty() {
        return Err("behavior IDs are empty".into());
    }

    let required_sections = [
        "api_package",
        "test_file",
        "case",
        "benchmark",
        "git_intention",
        "generator_constructor",
        "fixture",
    ];
    let mut section_ids = BTreeSet::new();
    let mut status_count = 0;
    for section in required_sections {
        for record in section_records(manifest, section) {
            let identity_key = ["id", "name", "path"]
                .into_iter()
                .find(|key| record.contains_key(*key))
                .ok_or_else(|| format!("{section} row has no identity field"))?;
            let identity = json_string(
                required(&record, identity_key, section)?,
                &format!("{section} identity"),
            )?;
            let status = json_string(
                required(&record, "status", &format!("{section} {identity}"))?,
                &format!("{section} {identity} status"),
            )?;
            if !matches!(status.as_str(), "implemented" | "final-disposition") {
                return Err(format!(
                    "{section} {identity} has non-final status {status}"
                ));
            }
            status_count += 1;
            if section != "api_package" && section != "test_file" {
                section_ids.insert(identity);
            }
        }
    }
    if status_count != 765 {
        return Err(format!(
            "required manifest traceability status count mismatch: expected 765, got {status_count}"
        ));
    }
    let namespace = behavior_ids
        .iter()
        .chain(&section_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    for record in section_records(manifest, "api_package") {
        let mapping = json_string(
            required(&record, "mapping_id", "api_package")?,
            "api_package mapping_id",
        )?;
        if !behavior_ids.contains(&mapping) {
            return Err(format!("api_package has dangling mapping_id {mapping}"));
        }
    }
    for record in section_records(manifest, "case") {
        let id = json_string(required(&record, "id", "case")?, "case id")?;
        let links = json_strings(
            required(&record, "behavior_ids", &format!("case {id}"))?,
            &format!("case {id} behavior_ids"),
        )?;
        if links.is_empty() {
            return Err(format!("case {id} has no behavior_ids"));
        }
        for link in links {
            if !behavior_ids.contains(&link) {
                return Err(format!("case {id} has dangling behavior_id {link}"));
            }
        }
    }

    let api_rows = api_jsonl
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("invalid API disposition row {}: {error}", index + 1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    verify_api_rows(&api_rows, &behavior_ids, &namespace)
}

fn verify_api_rows(
    rows: &[Value],
    behavior_ids: &BTreeSet<String>,
    namespace: &BTreeSet<String>,
) -> Result<(), String> {
    if rows.len() != 607 {
        return Err(format!(
            "API disposition count mismatch: expected 607, got {}",
            rows.len()
        ));
    }
    for (index, row) in rows.iter().enumerate() {
        let context = format!("API disposition row {}", index + 1);
        let source_key = string_field(row, "source_key", &context)?;
        let implementation = string_field(row, "implementation_status", &context)?;
        let test = string_field(row, "test_status", &context)?;
        let evidence = string_field(row, "evidence_status", &context)?;
        let final_status =
            (implementation == "implemented" && test == "passing" && evidence == "rust-tested")
                || (implementation == "not-applicable"
                    && test == "not-applicable"
                    && evidence == "go-inventoried");
        if !final_status {
            return Err(format!(
                "API {source_key} has non-final status {implementation}/{test}/{evidence}"
            ));
        }
        if implementation == "not-applicable"
            && !string_field(row, "implementation_evidence", &context)?
                .starts_with("Final release disposition:")
        {
            return Err(format!(
                "API {source_key} lacks a precise final release disposition"
            ));
        }
        let behavior_links = string_array(row, "behavior_links", &context)?;
        let manifest_links = string_array(row, "manifest_links", &context)?;
        if behavior_links.is_empty() {
            return Err(format!("API {source_key} has no behavior links"));
        }
        if manifest_links.is_empty() {
            return Err(format!("API {source_key} has no manifest links"));
        }
        for link in behavior_links {
            if !behavior_ids.contains(link) {
                return Err(format!(
                    "API {source_key} has dangling behavior link {link}"
                ));
            }
        }
        for link in manifest_links {
            if !namespace.contains(link) {
                return Err(format!(
                    "API {source_key} has dangling manifest link {link}"
                ));
            }
        }
    }
    Ok(())
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} lacks string {key}"))
}

fn string_array<'a>(value: &'a Value, key: &str, context: &str) -> Result<Vec<&'a str>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{context} lacks array {key}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| format!("{context} {key} contains a non-string"))
        })
        .collect()
}
