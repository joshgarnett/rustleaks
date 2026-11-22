//! Structural checks for CLI corpus requests.

use std::collections::BTreeSet;

use serde_json::Value;

use super::newline_records;
use super::validation::{required_array, required_str, required_u64};

/// Parses `requests-v1.jsonl` and rejects malformed rows.
///
/// Case IDs must run `CLI-BB-001`, `CLI-BB-002` and so on without gaps, and
/// variant IDs must be unique within their case.
pub(super) fn validate_requests(requests: &[u8]) -> Result<Vec<Value>, String> {
    let lines = newline_records(requests, "CLI requests")?;
    let mut rows = Vec::with_capacity(lines.len());
    for (number, line) in (1..).zip(lines) {
        let row: Value = serde_json::from_slice(line)
            .map_err(|e| format!("invalid CLI request {number}: {e}"))?;
        let expected_id = format!("CLI-BB-{number:03}");
        if required_u64(&row, "protocol_version", &expected_id)? != 1
            || required_str(&row, "id", "CLI request")? != expected_id
            || required_str(&row, "title", &expected_id)?.is_empty()
        {
            return Err(format!("{expected_id}: malformed request envelope"));
        }
        let variants = required_array(&row, "variants", &expected_id)?;
        if variants.is_empty() {
            return Err(format!("{expected_id}: request has no variants"));
        }
        let mut ids = BTreeSet::new();
        for variant in variants {
            let id = required_str(variant, "id", &expected_id)?;
            if !ids.insert(id) {
                return Err(format!("{expected_id}: duplicate variant {id}"));
            }
            validate_variant(variant, &format!("{expected_id}/{id}"))?;
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err("CLI requests are empty".into());
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
        || !(value["finding_source"].is_string() || value["finding_source"].is_null())
        || !(value["prepare"].is_string() || value["prepare"].is_null())
    {
        return Err(format!("{label}: malformed variant"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_requests;

    fn row(number: u32, variants: &str) -> String {
        format!(
            "{{\"protocol_version\":1,\"id\":\"CLI-BB-{number:03}\",\"title\":\"t\",\"variants\":[{variants}]}}\n"
        )
    }

    const VARIANT: &str = r#"{"id":"a","setup":"empty","args":[],"stdin_base64":"","env":{},"report_path":null,"finding_source":null,"prepare":null,"expectation":{}}"#;

    #[test]
    fn requests_need_sequential_cases_and_unique_variants() {
        let first = row(1, VARIANT);
        assert_eq!(validate_requests(first.as_bytes()).unwrap().len(), 1);
        let gap = format!("{first}{}", row(3, VARIANT));
        assert!(validate_requests(gap.as_bytes()).is_err());
        let duplicate = row(1, &format!("{VARIANT},{VARIANT}"));
        assert!(validate_requests(duplicate.as_bytes()).is_err());
        assert!(validate_requests(row(1, "").as_bytes()).is_err());
        let malformed = row(1, &VARIANT.replace("\"env\":{}", "\"env\":[]"));
        assert!(validate_requests(malformed.as_bytes()).is_err());
        assert!(validate_requests(b"").is_err());
    }
}
