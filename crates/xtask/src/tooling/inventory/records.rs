use std::collections::BTreeMap;

pub(super) type Record = BTreeMap<String, String>;

pub(super) fn section_records(text: &str, section: &str) -> Vec<Record> {
    let mut records = Vec::new();
    let mut current = None;
    for line in text.lines() {
        if line.trim() == format!("[[{section}]]") {
            records.push(Record::new());
            current = Some(records.len() - 1);
        } else if line.starts_with('[') {
            current = None;
        } else if let Some(index) = current {
            if let Some((key, value)) = line.split_once(" = ") {
                if key.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                }) {
                    records[index].insert(key.to_owned(), value.trim().to_owned());
                }
            }
        }
    }
    records
}

pub(super) fn table(text: &str, name: &str) -> Result<String, String> {
    let marker = format!("[{name}]\n");
    let start = text
        .find(&marker)
        .ok_or_else(|| format!("manifest lacks [{name}]"))?
        + marker.len();
    let tail = &text[start..];
    let end = tail.find("\n[").unwrap_or(tail.len());
    Ok(tail[..end].to_owned())
}

pub(super) fn json_string(raw: &str, context: &str) -> Result<String, String> {
    serde_json::from_str(raw).map_err(|error| format!("{context} is not a JSON string: {error}"))
}

pub(super) fn json_strings(raw: &str, context: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(raw)
        .map_err(|error| format!("{context} is not a JSON string array: {error}"))
}

pub(super) fn required<'a>(
    record: &'a Record,
    key: &str,
    context: &str,
) -> Result<&'a str, String> {
    record
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("{context} lacks {key}"))
}
