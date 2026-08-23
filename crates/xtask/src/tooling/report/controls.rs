//! Format-specific negative and byte-boundary controls retained across the tooling migration.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use super::validation::{error_class, outcome_for, output_for};

pub(super) fn validate(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    validate_empty_and_json(outcomes)?;
    validate_csv_and_junit(outcomes)?;
    validate_sarif_and_templates(outcomes)?;
    validate_errors(outcomes)
}

fn validate_empty_and_json(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    if !output_for(outcomes, "csv-empty")?.is_empty() {
        return Err("empty CSV emitted bytes".into());
    }
    let empty_sarif: Value = serde_json::from_slice(&output_for(outcomes, "sarif-empty")?)
        .map_err(|error| format!("sarif-empty output is invalid JSON: {error}"))?;
    if empty_sarif.pointer("/runs/0/tool/driver/rules") != Some(&Value::Array(vec![]))
        || empty_sarif.pointer("/runs/0/results") != Some(&Value::Array(vec![]))
    {
        return Err("empty SARIF lost explicit arrays".into());
    }
    let bytes = output_for(outcomes, "json-link-symlink-tags-nil")?;
    let json: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("JSON edge output is invalid: {error}"))?;
    let edge = json
        .as_array()
        .and_then(|values| values.first())
        .and_then(Value::as_object)
        .ok_or("JSON edge finding is missing")?;
    if edge.get("Link").and_then(Value::as_str) != Some("https://example.test/?a=<x>&b=1")
        || edge.get("Tags") != Some(&Value::Null)
        || edge.contains_key("Line")
        || edge.get("Entropy").and_then(Value::as_f64) != Some(3.5)
        || !contains(&bytes, br#""Secret": "\ufffd\u003c\u0026"#)
        || !contains(&bytes, br"\u2028\u2029")
    {
        return Err("JSON escaping, omission, tags, Link, or float32 control changed".into());
    }
    decoded_field(
        outcomes,
        "json-redact-75-repeated",
        "/redacted_findings/0/line_base64",
        b"se.../se...",
    )?;
    decoded_field(
        outcomes,
        "json-redact-75-repeated",
        "/redacted_findings/0/match_base64",
        b"se...+se...",
    )?;
    decoded_field(
        outcomes,
        "json-redact-100",
        "/redacted_findings/0/secret_base64",
        b"REDACTED",
    )?;
    decoded_field(
        outcomes,
        "json-redact-zero",
        "/redacted_findings/0/secret_base64",
        b"abc...",
    )?;
    decoded_field(
        outcomes,
        "json-redact-round-even",
        "/redacted_findings/0/secret_base64",
        b"ab...",
    )?;
    if !contains(
        &output_for(outcomes, "json-redact-unicode-byte-split")?,
        br"\ufffd...",
    ) {
        return Err("Unicode byte-split redaction changed".into());
    }
    let nan = outcome_for(outcomes, "json-nan-error")?;
    if error_class(nan) != Some("writer")
        || !nan
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("unsupported value"))
    {
        return Err("NaN JSON failure changed".into());
    }
    Ok(())
}

fn validate_csv_and_junit(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let without_link = output_for(outcomes, "csv-first-link-absent")?;
    if contains(&without_link, b"Link") || contains(&without_link, b"omitted.example") {
        return Err("CSV first-finding Link quirk changed".into());
    }
    let with_link = output_for(outcomes, "csv-first-link-present")?;
    let header = with_link
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if !header.ends_with(b"Tags,Link")
        || !contains(&with_link, b"second.example")
        || !with_link.contains(&0xff)
    {
        return Err("CSV Link column or raw-byte behavior changed".into());
    }
    let plain = output_for(outcomes, "csv-unicode-leading-space-backslash-dot")?;
    let second = plain
        .split(|byte| *byte == b'\n')
        .nth(1)
        .unwrap_or_default();
    if !second.starts_with("\"\u{a0}leading\",".as_bytes())
        || !contains(&plain, b",\"\\.\",")
        || !contains(&plain, "\"\u{2003}é💩\"".as_bytes())
    {
        return Err("CSV Unicode-leading-space/backslash-dot quoting changed".into());
    }
    let control = output_for(outcomes, "junit-control-replacement")?;
    if !outcome_for(outcomes, "junit-control-replacement")?
        .get("error")
        .is_some_and(Value::is_null)
        || !contains(&control, "bad�control".as_bytes())
    {
        return Err("JUnit XML-invalid-control replacement changed".into());
    }
    let unicode = output_for(outcomes, "junit-unicode-escaping")?;
    if !contains(&unicode, b"&#34;Entropy&#34;: 3.5")
        || !contains(&unicode, br"\u003c\u0026")
        || !contains(&unicode, br"\u2028\u2029")
    {
        return Err("JUnit embedded escaping or float32 rendering changed".into());
    }
    if !contains(
        &output_for(outcomes, "junit-invalid-byte-replacement")?,
        "�".as_bytes(),
    ) {
        return Err("JUnit invalid-byte replacement changed".into());
    }
    Ok(())
}

fn validate_sarif_and_templates(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let ordered: Value =
        serde_json::from_slice(&output_for(outcomes, "sarif-rule-order-duplicates")?)
            .map_err(|error| format!("ordered SARIF is invalid JSON: {error}"))?;
    let order = ordered
        .pointer("/runs/0/tool/driver/rules")
        .and_then(Value::as_array)
        .ok_or("ordered SARIF rules are missing")?
        .iter()
        .map(|rule| {
            rule.get("id")
                .and_then(Value::as_str)
                .ok_or("SARIF rule id is missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if order != ["z", "a", "z"] {
        return Err("SARIF ordered rules changed".into());
    }
    let symlink: Value = serde_json::from_slice(&output_for(outcomes, "sarif-symlink-no-commit")?)
        .map_err(|error| format!("symlink SARIF is invalid JSON: {error}"))?;
    if symlink
        .pointer("/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri")
        .and_then(Value::as_str)
        != Some("link/💩.txt")
        || symlink
            .pointer("/runs/0/results/0/message/text")
            .and_then(Value::as_str)
            != Some("test-rule has detected secret for file real/<&.txt.")
    {
        return Err("SARIF symlink or no-commit message changed".into());
    }
    let invalid = output_for(outcomes, "sarif-invalid-byte-message")?;
    if !contains(&invalid, br"\ufffd\u003c\u0026") || !contains(&invalid, br"\u2028\u2029") {
        return Err("SARIF invalid-byte/HTML/Unicode escaping changed".into());
    }
    if output_for(outcomes, "template-raw-bytes")? != b"\0\xff<&\xf0\x9f\x92\xa9" {
        return Err("template raw bytes changed".into());
    }
    if !output_for(outcomes, "template-safe-helpers")?
        .starts_with(b"TEST-RULE|\"a secret\"|2d711642b726b044")
    {
        return Err("safe template helpers changed".into());
    }
    for id in [
        "template-block-env",
        "template-block-expandenv",
        "template-block-host",
    ] {
        let outcome = outcome_for(outcomes, id)?;
        if error_class(outcome) != Some("template-parse")
            || !outcome
                .pointer("/error/message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains("not defined"))
        {
            return Err(format!("{id}: dangerous helper was accepted"));
        }
    }
    for id in ["template-allow-now-parse", "template-allow-random-parse"] {
        if !outcome_for(outcomes, id)?
            .get("error")
            .is_some_and(Value::is_null)
            || !output_for(outcomes, id)?.is_empty()
        {
            return Err(format!("{id}: allowed helper was rejected or executed"));
        }
    }
    Ok(())
}

fn validate_errors(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    for (id, class) in [
        ("json-writer-error", "writer"),
        ("csv-writer-error", "writer"),
        ("junit-writer-error", "writer"),
        ("sarif-writer-error", "writer"),
        ("template-writer-error", "writer"),
        ("template-parse-error", "template-parse"),
        ("template-execute-error", "template-execute"),
        ("template-empty-path", "template-path"),
        ("template-missing-path", "template-read"),
        ("unknown-format", "format"),
        ("bad-finding-base64", "request"),
        ("bad-rule-base64", "request"),
        ("negative-writer-limit", "request"),
        ("wrong-protocol", "protocol"),
    ] {
        if error_class(outcome_for(outcomes, id)?) != Some(class) {
            return Err(format!("{id}: expected error class {class}"));
        }
    }
    Ok(())
}

fn decoded_field(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
    pointer: &str,
    expected: &[u8],
) -> Result<(), String> {
    let encoded = outcome_for(outcomes, id)?
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{id}: missing {pointer}"))?;
    let actual = BASE64
        .decode(encoded)
        .map_err(|error| format!("{id}: invalid base64 at {pointer}: {error}"))?;
    if actual != expected {
        return Err(format!("{id}: decoded {pointer} changed"));
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::validate_errors;

    #[test]
    fn error_controls_reject_a_mutated_class() {
        let ids = [
            ("json-writer-error", "writer"),
            ("csv-writer-error", "writer"),
            ("junit-writer-error", "writer"),
            ("sarif-writer-error", "writer"),
            ("template-writer-error", "writer"),
            ("template-parse-error", "template-parse"),
            ("template-execute-error", "template-execute"),
            ("template-empty-path", "template-path"),
            ("template-missing-path", "template-read"),
            ("unknown-format", "format"),
            ("bad-finding-base64", "request"),
            ("bad-rule-base64", "request"),
            ("negative-writer-limit", "request"),
            ("wrong-protocol", "protocol"),
        ];
        let values = ids
            .iter()
            .map(|(id, class)| ((*id).to_owned(), json!({"error":{"class":class}})))
            .collect::<BTreeMap<_, _>>();
        let borrowed = values
            .iter()
            .map(|(id, value)| (id.as_str(), value))
            .collect();
        validate_errors(&borrowed).unwrap();
        let mut mutated = values;
        mutated.get_mut("wrong-protocol").unwrap()["error"]["class"] = json!("request");
        let borrowed = mutated
            .iter()
            .map(|(id, value)| (id.as_str(), value))
            .collect();
        assert!(validate_errors(&borrowed).is_err());
    }
}
