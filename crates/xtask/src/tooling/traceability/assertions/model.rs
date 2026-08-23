//! Insertion-ordered JSON and narrow Go-string recovery for assertion rows.

use std::{fs, path::Path};

use base64::Engine as _;

use super::PIN;

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Json {
    Null,
    Bool(bool),
    Integer(u64),
    Float(f64),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub(super) fn get(&self, key: &str) -> Option<&Self> {
        let Self::Object(fields) = self else {
            return None;
        };
        fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    pub(super) fn set(&mut self, key: &str, value: Self) -> Result<(), String> {
        let Self::Object(fields) = self else {
            return Err("cannot update non-object JSON".into());
        };
        let (_, current) = fields
            .iter_mut()
            .find(|(name, _)| name == key)
            .ok_or_else(|| format!("JSON object lacks field {key}"))?;
        *current = value;
        Ok(())
    }

    pub(super) fn as_text(&self) -> Option<&str> {
        if let Self::Text(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(super) fn as_array(&self) -> Option<&[Self]> {
        if let Self::Array(value) = self {
            Some(value)
        } else {
            None
        }
    }

    fn write(&self, output: &mut String) -> Result<(), String> {
        match self {
            Self::Null => output.push_str("null"),
            Self::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Self::Integer(value) => output.push_str(&value.to_string()),
            Self::Float(value) => output.push_str(
                &serde_json::to_string(value)
                    .map_err(|error| format!("cannot serialize float: {error}"))?,
            ),
            Self::Text(value) => output.push_str(
                &serde_json::to_string(value)
                    .map_err(|error| format!("cannot serialize string: {error}"))?,
            ),
            Self::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    value.write(output)?;
                }
                output.push(']');
            }
            Self::Object(fields) => {
                output.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    output.push_str(
                        &serde_json::to_string(key)
                            .map_err(|error| format!("cannot serialize key: {error}"))?,
                    );
                    output.push(':');
                    value.write(output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }
}

pub(super) fn text(value: impl Into<String>) -> Json {
    Json::Text(value.into())
}
pub(super) fn boolean(value: bool) -> Json {
    Json::Bool(value)
}
pub(super) fn integer(value: usize) -> Json {
    Json::Integer(value as u64)
}
pub(super) fn float(value: f64) -> Json {
    Json::Float(value)
}
pub(super) fn array(values: impl IntoIterator<Item = Json>) -> Json {
    Json::Array(values.into_iter().collect())
}
pub(super) fn object<const N: usize>(fields: [(&str, Json); N]) -> Json {
    Json::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
pub(super) fn strings(values: &[&str]) -> Json {
    array(values.iter().map(|value| text(*value)))
}
pub(super) fn byte_text(value: impl AsRef<[u8]>) -> Json {
    object([
        ("encoding", text("base64")),
        (
            "data",
            text(base64::engine::general_purpose::STANDARD.encode(value.as_ref())),
        ),
    ])
}
pub(super) fn deep_bytes(value: Json) -> Json {
    match value {
        Json::Text(value) => byte_text(value.as_bytes()),
        Json::Array(values) => array(values.into_iter().map(deep_bytes)),
        Json::Object(fields) => Json::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, deep_bytes(value)))
                .collect(),
        ),
        other => other,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record(
    id: &str,
    parent: &str,
    source: &str,
    line: usize,
    occurrence: &str,
    domain: &str,
    observation: &str,
    input: Json,
    expected: Json,
    fixtures: Vec<Json>,
) -> Json {
    object([
        ("schema_version", integer(1)),
        ("id", text(id)),
        ("parent_case_id", text(parent)),
        ("upstream_revision", text(PIN)),
        ("mapping_id", text("M1-ASSERTIONS-002")),
        ("source_file", text(source)),
        ("source_line", integer(line)),
        ("source_occurrence", text(occurrence)),
        ("domain", text(domain)),
        ("observation", text(observation)),
        ("comparison", text("exact")),
        ("input", deep_bytes(input)),
        ("expected", deep_bytes(expected)),
        ("fixture_ids", array(fixtures)),
        ("rust_test", Json::Null),
        ("rust_evidence", Json::Null),
        ("status", text("pending")),
    ])
}

pub(super) fn jsonl(rows: &[Json]) -> Result<Vec<u8>, String> {
    let mut output = String::new();
    for row in rows {
        row.write(&mut output)?;
        output.push('\n');
    }
    Ok(output.into_bytes())
}

pub(super) fn source_lines(
    upstream: &Path,
    relative: &str,
    first_line: usize,
    last_line: usize,
    values: &[&str],
) -> Result<Vec<usize>, String> {
    let source = fs::read(upstream.join(relative))
        .map_err(|error| format!("cannot read {relative}: {error}"))?;
    let mut remaining = go_string_tokens(&source, relative, first_line, last_line)?;
    values.iter().map(|value| {
        let index = remaining.iter().position(|(token, _)| token == value.as_bytes())
            .ok_or_else(|| format!("source literal not found in {relative}:{first_line}..{last_line}: {value:?}"))?;
        let line = remaining[index].1;
        remaining.drain(..=index);
        Ok(line)
    }).collect()
}

fn go_string_tokens(
    source: &[u8],
    path: &str,
    first: usize,
    last: usize,
) -> Result<Vec<(Vec<u8>, usize)>, String> {
    let mut tokens = Vec::new();
    let (mut index, mut line) = (0, 1);
    while index < source.len() {
        if source.get(index..index + 2) == Some(b"//") {
            index = source[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(source.len(), |offset| index + offset);
        } else if source.get(index..index + 2) == Some(b"/*") {
            let offset = source[index + 2..]
                .windows(2)
                .position(|bytes| bytes == b"*/")
                .ok_or_else(|| format!("unterminated comment in {path}"))?;
            let end = index + 2 + offset + 2;
            line += newline_count(&source[index..end]);
            index = end;
        } else if source[index] == b'`' {
            let start_line = line;
            let offset = source[index + 1..]
                .iter()
                .position(|byte| *byte == b'`')
                .ok_or_else(|| format!("unterminated raw string in {path}"))?;
            let end = index + 1 + offset;
            let raw = source[index + 1..end].to_vec();
            if (first..=last).contains(&start_line) {
                tokens.push((raw.clone(), start_line));
            }
            line += newline_count(&raw);
            index = end + 1;
        } else if source[index] == b'"' {
            let start_line = line;
            let mut end = index + 1;
            loop {
                match source.get(end).copied() {
                    None => return Err(format!("unterminated string in {path}")),
                    Some(b'\\') => end += 2,
                    Some(b'"') => break,
                    Some(_) => end += 1,
                }
            }
            if (first..=last).contains(&start_line) {
                let decoded: String =
                    serde_json::from_slice(&source[index..=end]).map_err(|error| {
                        format!("cannot decode Go string in {path}:{start_line}: {error}")
                    })?;
                tokens.push((decoded.into_bytes(), start_line));
            }
            index = end + 1;
        } else {
            if source[index] == b'\n' {
                line += 1;
            }
            index += 1;
        }
    }
    Ok(tokens)
}

// These inputs are small pinned source slices; a dependency for SIMD byte counting
// would add more surface than this non-hot extraction path warrants.
#[allow(clippy::naive_bytecount)]
fn newline_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

#[cfg(test)]
mod tests {
    use super::{go_string_tokens, jsonl, object, text};

    #[test]
    fn lexer_skips_comments_and_decodes_raw_and_interpreted_strings() {
        let source = b"// \"comment\"\n`raw\nvalue` /* `block` */ \"line\\nvalue\"\n";
        let tokens = go_string_tokens(source, "probe.go", 1, 10).unwrap();
        assert_eq!(
            tokens,
            [(b"raw\nvalue".to_vec(), 2), (b"line\nvalue".to_vec(), 3)]
        );
    }

    #[test]
    fn ordered_jsonl_retains_insertion_order_and_final_newline() {
        let rows = [object([("second", text("b")), ("first", text("a"))])];
        assert_eq!(
            jsonl(&rows).unwrap(),
            br#"{"second":"b","first":"a"}
"#
        );
    }
}
