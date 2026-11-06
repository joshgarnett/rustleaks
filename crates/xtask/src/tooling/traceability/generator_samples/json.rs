//! JSONL parsing plus stable insertion-order compatible serialization.

use std::fmt::Write as _;
use std::{fs, path::Path};

use serde_json::Value;

pub(super) fn read_jsonl(path: &Path) -> Result<Vec<Value>, String> {
    let bytes = fs::read(path).map_err(|_| format!("missing corpus file: {}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("{}: invalid UTF-8: {error}", path.display()))?;
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            if line.trim().is_empty() {
                return Err(format!(
                    "{}:{}: blank JSONL record",
                    path.display(),
                    index + 1
                ));
            }
            serde_json::from_str(line)
                .map_err(|error| format!("{}:{}: {error}", path.display(), index + 1))
        })
        .collect()
}

fn write_dependencies(value: &Value, output: &mut String) -> Result<(), String> {
    let fields = [
        "entropy",
        "keyword_base64",
        "rule_allowlist_count",
        "has_path",
        "secret_group",
        "global_allowlist",
    ];
    write_object_fields(value, &fields, output)
}

fn write_object_fields(value: &Value, fields: &[&str], output: &mut String) -> Result<(), String> {
    output.push('{');
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{}:{}",
            quote(field)?,
            serde_json::to_string(required(value, field)?)
                .map_err(|error| format!("cannot serialize JSON: {error}"))?
        )
        .expect("writing to String cannot fail");
    }
    output.push('}');
    Ok(())
}

pub(super) fn identity_bytes(row: &Value) -> Result<Vec<u8>, String> {
    let fields = [
        "case_id",
        "constructor",
        "rule_id",
        "selected_default",
        "helper",
        "polarity",
        "ordinal",
        "contract",
        "source_file",
        "constructor_line",
        "helper_line",
        "source_occurrence",
        "constructor_source_sha256",
        "origin_kind",
        "origin_source_file",
        "origin_line",
        "template_key",
        "path_present",
        "path_base64",
        "dependencies",
    ];
    let mut output = String::new();
    write_object_fields(row, &fields[..19], &mut output)?;
    output.pop();
    output.push(',');
    write!(output, "{}:", quote("dependencies")?).expect("writing to String cannot fail");
    write_dependencies(required(row, "dependencies")?, &mut output)?;
    output.push('}');
    Ok(output.into_bytes())
}

pub(super) fn required<'a>(row: &'a Value, field: &str) -> Result<&'a Value, String> {
    row.get(field).ok_or_else(|| format!("missing {field}"))
}

pub(super) fn string<'a>(row: &'a Value, field: &str) -> Result<&'a str, String> {
    required(row, field)?
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))
}

fn quote(value: &str) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("cannot serialize JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::read_jsonl;
    use crate::tooling::support::TempDir;

    #[test]
    fn jsonl_rejects_blank_and_malformed_records() {
        let temporary = TempDir::new("generator samples malformed ü").unwrap();
        let blank = temporary.path.join("blank records.jsonl");
        fs::write(&blank, b"{}\n\n").unwrap();
        assert!(
            read_jsonl(&blank)
                .unwrap_err()
                .contains("blank JSONL record")
        );

        let malformed = temporary.path.join("malformed records.jsonl");
        fs::write(&malformed, b"{\n").unwrap();
        assert!(read_jsonl(&malformed).is_err());
    }

    #[test]
    fn jsonl_accepts_spaces_and_non_ascii_paths() {
        let temporary = TempDir::new("generator samples path ü").unwrap();
        let path = temporary.path.join("sample path ü.jsonl");
        fs::write(&path, "{\"value\":\"ü\"}\n").unwrap();
        let rows = read_jsonl(&path).unwrap();
        assert_eq!(rows[0]["value"], "ü");
    }
}
