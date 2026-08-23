//! Ruby-compatible JSON formatting and private-probe response synthesis.

use serde_json::Value;

use super::spec::{DEFAULT_SHA256, REVISION};

const FINDING_KEYS: &[&str] = &[
    "rule_id",
    "description_base64",
    "start_line",
    "end_line",
    "start_column",
    "end_column",
    "line_base64",
    "match_base64",
    "secret_base64",
    "file_base64",
    "symlink_file_base64",
    "commit_base64",
    "link_base64",
    "entropy_bits",
    "author_base64",
    "email_base64",
    "date_base64",
    "message_base64",
    "tags_base64",
    "fingerprint_base64",
    "required_findings",
];
const REQUIRED_KEYS: &[&str] = &[
    "rule_id",
    "start_line",
    "end_line",
    "start_column",
    "end_column",
    "line_base64",
    "match_base64",
    "secret_base64",
];

pub(super) struct Template {
    pub(super) go_version: String,
}

pub(super) fn template(value: &Value) -> Result<Template, String> {
    if value["protocol_version"] != 1
        || value["oracle_mode"] != "composite"
        || value["upstream_revision"] != REVISION
        || value["default_config_sha256"] != DEFAULT_SHA256
    {
        return Err("fresh composite template pins changed".into());
    }
    let go_version = value["go_version"]
        .as_str()
        .filter(|version| version.starts_with("go1.25."))
        .ok_or("fresh composite template Go version changed")?
        .to_owned();
    Ok(Template { go_version })
}

pub(super) fn filter_input(request: &Value) -> Result<Vec<u8>, String> {
    ordered_array(&request["filter_inputs"], FINDING_KEYS, true)
}

pub(super) fn synthesized(
    request: &Value,
    template: &Template,
    input_sha256: &str,
    findings_json: &[u8],
    mask_secret_base64: &str,
) -> Result<Vec<u8>, String> {
    let id = string(request, "id")?;
    let operation = string(request, "operation")?;
    let findings: Value = serde_json::from_slice(findings_json)
        .map_err(|error| format!("{id}: private Go findings are invalid JSON: {error}"))?;
    if !findings.is_array() {
        return Err(format!("{id}: private Go findings are not an array"));
    }
    let redact_percent = request["redact_percent"].as_u64().unwrap_or(0);
    let line = format!(
        concat!(
            "{{\"protocol_version\":1,\"oracle_mode\":\"composite\",",
            "\"id\":{},\"behavior_ids\":{},\"test_case_ids\":{},",
            "\"upstream_revision\":{},\"default_config_sha256\":{},",
            "\"go_version\":{},\"operation\":{},\"input_sha256\":{},",
            "\"config_sha256\":\"\",\"redact_percent\":{},\"findings\":{},",
            "\"original\":null,\"redacted\":null,\"mask_secret_base64\":{},\"error\":null}}\n"
        ),
        json(id)?,
        compact(&request["behavior_ids"])?,
        compact(&request["test_case_ids"])?,
        json(REVISION)?,
        json(DEFAULT_SHA256)?,
        json(&template.go_version)?,
        json(operation)?,
        json(input_sha256)?,
        redact_percent,
        std::str::from_utf8(findings_json)
            .map_err(|error| format!("{id}: private findings are not UTF-8: {error}"))?,
        json(mask_secret_base64)?,
    );
    Ok(line.into_bytes())
}

pub(super) fn ruby_json_number_format(line: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(line.len() + 8);
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < line.len() {
        let byte = line[index];
        if in_string {
            output.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
        } else if byte == b'"' {
            in_string = true;
            output.push(byte);
            index += 1;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < line.len()
                && matches!(line[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                index += 1;
            }
            let number = &line[start..index];
            if let Some(at) = number.iter().position(|byte| matches!(byte, b'e' | b'E')) {
                let mantissa = &number[..at];
                output.extend_from_slice(mantissa);
                if !mantissa.contains(&b'.') {
                    output.extend_from_slice(b".0");
                }
                output.push(b'e');
                let exponent = &number[at + 1..];
                let (sign, digits) = exponent
                    .first()
                    .filter(|byte| matches!(byte, b'+' | b'-'))
                    .map_or((b'+', exponent), |sign| (*sign, &exponent[1..]));
                output.push(sign);
                if digits.len() < 2 {
                    output.push(b'0');
                }
                output.extend_from_slice(digits);
            } else {
                output.extend_from_slice(number);
            }
        } else {
            output.push(byte);
            index += 1;
        }
    }
    if in_string || escaped {
        return Err("composite oracle returned unterminated JSON".into());
    }
    Ok(output)
}

fn ordered_array(value: &Value, keys: &[&str], nested: bool) -> Result<Vec<u8>, String> {
    let values = value.as_array().ok_or("filter_inputs is not an array")?;
    let mut output = Vec::new();
    output.push(b'[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        output.extend_from_slice(&ordered_object(value, keys, nested)?);
    }
    output.push(b']');
    Ok(output)
}

fn ordered_object(value: &Value, keys: &[&str], nested: bool) -> Result<Vec<u8>, String> {
    let object = value.as_object().ok_or("filter finding is not an object")?;
    let expected = object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let allowed = keys
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if !expected.is_subset(&allowed) {
        return Err(format!(
            "filter finding contains unexpected fields: {expected:?}"
        ));
    }
    let mut output = Vec::new();
    output.push(b'{');
    let mut first = true;
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };
        if !first {
            output.push(b',');
        }
        first = false;
        output.extend_from_slice(json(key)?.as_bytes());
        output.push(b':');
        if nested && *key == "required_findings" {
            output.extend_from_slice(&ordered_array(value, REQUIRED_KEYS, false)?);
        } else {
            output.extend_from_slice(compact(value)?.as_bytes());
        }
    }
    output.push(b'}');
    Ok(output)
}

fn compact(value: &Value) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("cannot serialize compact JSON: {error}"))
}

fn json(value: &str) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("cannot serialize JSON string: {error}"))
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("private composite request has no {field}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{filter_input, ruby_json_number_format};

    #[test]
    fn filter_input_restores_ruby_field_order() {
        let request =
            json!({"filter_inputs":[{"secret_base64":"Uw==","rule_id":"r","start_line":1}]});
        assert_eq!(
            filter_input(&request).unwrap(),
            br#"[{"rule_id":"r","start_line":1,"secret_base64":"Uw=="}]"#
        );
    }

    #[test]
    fn exponent_format_matches_ruby_without_touching_strings() {
        assert_eq!(
            ruby_json_number_format(b"{\"x\":5e-7,\"s\":\"5e-7\"}\n").unwrap(),
            b"{\"x\":5.0e-07,\"s\":\"5e-7\"}\n"
        );
    }
}
