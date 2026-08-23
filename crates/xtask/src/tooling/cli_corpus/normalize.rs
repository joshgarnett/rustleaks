//! Host-independent stdout, stderr-event, usage, and finding normalization.

use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use crate::tooling::support::sha256_bytes;

pub(super) struct Event {
    pub(super) severity: String,
    pub(super) class: String,
    pub(super) fields: Vec<(String, Value)>,
    pub(super) message: Vec<u8>,
}

pub(super) fn normalize_bytes(bytes: &[u8], root: &Path, executable_names: &[&str]) -> Vec<u8> {
    let mut value = bytes.to_vec();
    let root_bytes = root.to_string_lossy();
    if cfg!(target_os = "macos") && root_bytes.starts_with("/var/") {
        value = replace(&value, format!("/private{root_bytes}").as_bytes(), b"<TMP>");
    }
    value = replace(&value, root_bytes.as_bytes(), b"<TMP>");
    if cfg!(windows) {
        value = replace(&value, b"<TMP>\\", b"<TMP>/");
    }
    let mut names = executable_names.to_vec();
    names.sort_by_key(|name| std::cmp::Reverse(name.len()));
    for name in names {
        value = replace(&value, name.as_bytes(), b"gitleaks");
        let mut capitalized = name.as_bytes().to_vec();
        if let Some(first) = capitalized.first_mut() {
            first.make_ascii_uppercase();
        }
        value = replace(&value, &capitalized, b"Gitleaks");
    }
    strip_ansi(&value)
}

pub(super) fn events(bytes: &[u8], root: &Path, names: &[&str]) -> Vec<Event> {
    let normalized = normalize_bytes(bytes, root, names);
    let text = String::from_utf8_lossy(&normalized);
    let mut in_usage = false;
    let mut result = Vec::new();
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }
        if stripped == "Usage:" {
            in_usage = true;
        }
        if in_usage && stripped != "Usage:" && rendered_log_line(stripped) {
            in_usage = false;
        }
        if in_usage && versioned_usage_line(stripped) {
            continue;
        }
        result.push(event_for(stripped));
    }
    result
}

pub(super) fn usage(bytes: &[u8], root: &Path, names: &[&str]) -> Option<Vec<u8>> {
    let normalized = normalize_bytes(bytes, root, names);
    let text = String::from_utf8_lossy(&normalized);
    let lines = text.lines().collect::<Vec<_>>();
    let start = lines.iter().position(|line| line.trim() == "Usage:")?;
    let mut kept = Vec::new();
    for line in &lines[start..] {
        let stripped = line.trim();
        if !kept.is_empty() && rendered_log_line(stripped) {
            break;
        }
        if !versioned_usage_line(stripped) {
            kept.push(*line);
        }
    }
    let mut value = kept
        .join("\n")
        .trim_end()
        .replace("Gitleaks", "gitleaks")
        .into_bytes();
    value.push(b'\n');
    Some(value)
}

pub(super) fn canonical_findings(bytes: &[u8]) -> Result<Vec<String>, String> {
    let parsed: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid JSON findings report: {error}"))?;
    if !parsed.is_array() {
        return Err("JSON report is not a finding array".into());
    }
    let compact = compact_json(bytes)?;
    let compact = unescape_html_json(&compact);
    let mut findings = split_array(&compact)?;
    findings.sort();
    Ok(findings)
}

pub(super) fn event_json(event: &Event) -> String {
    let fields = event
        .fields
        .iter()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                quote(key),
                serde_json::to_string(value).expect("JSON value")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"severity\":{},\"class\":{},\"fields\":{{{fields}}},\"normalized_message_base64\":{}}}",
        quote(&event.severity),
        quote(&event.class),
        quote(&BASE64.encode(&event.message))
    )
}

#[allow(clippy::too_many_lines)] // Keep the ordered diagnostic classification policy reviewable.
fn event_for(line: &str) -> Event {
    let (severity, text) = severity_and_text(line);
    let text = normalize_dynamic(text);
    let lower = text.to_ascii_lowercase();
    let mut fields = Vec::new();
    let class = if let Some((bytes, human)) = scanned_fields(&text) {
        fields.push(("bytes".into(), Value::from(bytes)));
        fields.push(("human".into(), Value::from(human)));
        "summary.scanned"
    } else if lower.contains("partial scan completed") {
        "summary.partial"
    } else if let Some(count) = finding_count(&lower, " leaks found in partial scan") {
        fields.push(("count".into(), Value::from(count)));
        "summary.partial-findings"
    } else if lower.contains("no leaks found in partial scan") {
        "summary.partial-empty"
    } else if let Some(count) = finding_count(&lower, "leaks found:") {
        fields.push(("count".into(), Value::from(count)));
        "summary.findings"
    } else if lower.contains("no leaks found") {
        "summary.empty"
    } else if let Some(count) = finding_count(&lower, " commits scanned") {
        fields.push(("count".into(), Value::from(count)));
        "git.commits"
    } else if lower.contains("unknown shorthand") {
        "parser.unknown-short"
    } else if lower.contains("unknown flag") {
        "parser.unknown-long"
    } else if lower.contains("unknown command") {
        "parser.unknown-command"
    } else if lower.contains("accepts at most")
        || lower.contains("accepts no")
        || lower.contains("accept no")
        || lower.contains("argument")
    {
        "parser.arity"
    } else if lower.contains("invalid value")
        || lower.contains("requires a value")
        || lower.contains("out of range")
        || lower.contains("overflow")
    {
        "parser.value"
    } else if lower.contains("baseline") {
        "baseline.error"
    } else if lower.contains("gitleaksignore") || lower.contains("ignore file") {
        "ignore.warning"
    } else if (lower.contains("git standard error")
        || lower.contains("git standard output")
        || lower.contains("git"))
        && (lower.contains("byte ceiling") || lower.contains("output limit"))
    {
        "source.git-error"
    } else if lower.starts_with("stat ") || lower.contains("during config selection") {
        "config.source-stat-error"
    } else if lower.contains("config") || lower.contains("toml") {
        "config.error"
    } else if report_error(&lower) {
        "report.error"
    } else if lower.contains("quoted")
        || lower.contains("quote characters")
        || lower.contains("log-opts")
    {
        "git.log-options"
    } else if lower.contains("enable") || lower.contains("custom regex") || lower.contains("rule") {
        "rules.selection"
    } else if lower.contains("unknown scm")
        || lower.contains("unknown host")
        || lower.contains("remote")
    {
        "scm.event"
    } else if lower.contains("partial")
        || lower.contains("cancel")
        || lower.contains("timeout")
        || lower.contains("timed out")
    {
        "source.partial"
    } else if ["git", "repository", "revision", "patch", "child"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "source.git-error"
    } else if lower.contains("skipping")
        || text.contains("source Metadata")
        || ["archive", "symlink", "read", "decode", "corrupt"]
            .iter()
            .any(|word| lower.contains(word))
    {
        "source.issue"
    } else if ["source", "directory", "walk", "stat"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "source.error"
    } else {
        fields.push((
            "message_sha256".into(),
            Value::from(sha256_bytes(text.as_bytes())),
        ));
        "diagnostic.other"
    };
    Event {
        severity,
        class: class.into(),
        fields,
        message: text.into_bytes(),
    }
}

fn severity_and_text(line: &str) -> (String, &str) {
    let levels = [
        ("TRC", "trace"),
        ("DBG", "debug"),
        ("INF", "info"),
        ("WRN", "warn"),
        ("ERR", "error"),
        ("FTL", "fatal"),
    ];
    for (token, level) in levels {
        if let Some(index) = line.find(&format!("{token} ")) {
            let prefix = &line[..index];
            if prefix.is_empty()
                || prefix
                    .chars()
                    .all(|c| c.is_ascii_digit() || ": AMPMapm".contains(c))
            {
                return (level.into(), &line[index + 4..]);
            }
        }
    }
    for level in ["trace", "debug", "info", "warn", "error", "fatal"] {
        if line.len() > level.len()
            && line
                .get(..level.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(level))
            && line.as_bytes()[level.len()] == b' '
        {
            return (level.into(), &line[level.len() + 1..]);
        }
    }
    ("error".into(), line)
}

fn normalize_dynamic(text: &str) -> String {
    let mut result = text.to_owned();
    for pattern in [
        "No such file or directory",
        "The system cannot find the file specified.",
        "The system cannot find the file specified",
        "The system cannot find the path specified.",
        "The system cannot find the path specified",
    ] {
        result = replace_ascii_case_insensitive(&result, pattern, "<os:not-found>");
    }
    let bytes = result.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
                index += 1;
            }
            let unit_start = index;
            while index < bytes.len()
                && matches!(
                    bytes[index],
                    b'n' | b's' | b'\xc2' | b'\xb5' | b'u' | b'm' | b'h'
                )
            {
                index += 1;
            }
            let unit = &result[unit_start..index];
            if ["ns", "µs", "us", "ms", "s", "m", "h"].contains(&unit) {
                ranges.push((start, index));
            }
        } else {
            index += 1;
        }
    }
    for (start, end) in ranges.into_iter().rev() {
        result.replace_range(start..end, "<DURATION>");
    }
    result
}

fn replace_ascii_case_insensitive(text: &str, pattern: &str, replacement: &str) -> String {
    let mut result = text.to_owned();
    loop {
        let lowercase = result.to_ascii_lowercase();
        let Some(index) = lowercase.find(&pattern.to_ascii_lowercase()) else {
            return result;
        };
        result.replace_range(index..index + pattern.len(), replacement);
    }
}

fn rendered_log_line(line: &str) -> bool {
    let (_, text) = severity_and_text(line);
    text != line
}

fn versioned_usage_line(line: &str) -> bool {
    (line.starts_with("completion") || line.starts_with("help")) && line.contains("  ")
        || line.contains("Generate the autocompletion script")
        || line.starts_with("--diagnostics ")
        || line.starts_with("--diagnostics-dir")
        || line.contains("--gitleaks-ignore-path")
        || line.contains("--ignore-gitleaks-allow")
        || line.starts_with("order of precedence:")
        || (line.len() > 2
            && line.as_bytes()[0].is_ascii_digit()
            && line.as_bytes()[1] == b'.'
            && line.as_bytes()[2] == b' ')
        || line.contains("If none of the four options")
        || line.contains("Otherwise Gitleaks")
}

fn report_error(lower: &str) -> bool {
    lower.contains("report format")
        || lower.contains("report path")
        || lower.contains("report template")
        || lower.contains("template report")
        || lower.contains("template")
        || (["open", "write", "flush"]
            .iter()
            .any(|word| lower.contains(word))
            && lower.contains("report"))
}

fn scanned_fields(text: &str) -> Option<(u64, String)> {
    let start = text.find("scanned ~")? + 9;
    let end = text[start..].find(' ')? + start;
    let bytes = text[start..end].parse().ok()?;
    let open = text[end..].find('(')? + end + 1;
    let close = text[open..].find(')')? + open;
    Some((bytes, text[open..close].into()))
}

fn finding_count(text: &str, marker: &str) -> Option<u64> {
    if marker == "leaks found:" {
        let start = text.find(marker)? + marker.len();
        return text[start..].split_whitespace().next()?.parse().ok();
    }
    let end = text.find(marker)?;
    text[..end].split_whitespace().last()?.parse().ok()
}

fn replace(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return bytes.to_vec();
    }
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(from) {
            out.extend_from_slice(to);
            index += from.len();
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

fn strip_ansi(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"\x1b[") {
            index += 2;
            while index < bytes.len() && !(b'@'..=b'~').contains(&bytes[index]) {
                index += 1;
            }
            index += usize::from(index < bytes.len());
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

fn compact_json(bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("report is not UTF-8: {e}"))?;
    let mut out = String::new();
    let mut string = false;
    let mut escaped = false;
    for c in text.chars() {
        if string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                string = false;
            }
        } else if c == '"' {
            string = true;
            out.push(c);
        } else if !c.is_whitespace() {
            out.push(c);
        }
    }
    Ok(out)
}

fn split_array(compact: &str) -> Result<Vec<String>, String> {
    if compact == "[]" {
        return Ok(Vec::new());
    }
    let body = compact
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or("findings are not an array")?;
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0;
    let mut string = false;
    let mut escaped = false;
    for (index, c) in body.char_indices() {
        if string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                string = false;
            }
        } else {
            match c {
                '"' => string = true,
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    result.push(body[start..index].to_owned());
                    start = index + 1;
                }
                _ => {}
            }
        }
    }
    result.push(body[start..].to_owned());
    Ok(result)
}

fn quote(value: &str) -> String {
    unescape_html_json(&serde_json::to_string(value).expect("string JSON"))
}

fn unescape_html_json(value: &str) -> String {
    value
        .replace("\\u0026", "&")
        .replace("\\u003c", "<")
        .replace("\\u003e", ">")
}
