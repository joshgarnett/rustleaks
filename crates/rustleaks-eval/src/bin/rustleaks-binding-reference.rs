//! Writes the findings that `rustleaks-core` reports for a list of files,
//! for the Go and Python binding tests, which scan the same files through
//! their packages and require the same findings.
//!
//! Usage: `rustleaks-binding-reference OUTPUT SAMPLES SAMPLES_OUTPUT
//! SAMPLES_PATH FILE...`
//!
//! The files of this repository hold few key-shaped values, so the tool
//! also writes the inputs of the generator corpus (`SAMPLES`, a
//! `samples-v1.jsonl` file) to `SAMPLES_OUTPUT`, each followed by `\n`, and
//! scans that file with the path `SAMPLES_PATH`, the path under which the
//! binding tests find it.
//!
//! Each file is scanned with every built-in rule and the options that the
//! bindings use by default, with the file's path as the scan path. A file
//! that is valid UTF-8, has a line break and has no carriage return is also
//! scanned in two changed forms: `crlf`, with every `\n` replaced by
//! `\r\n`, and `no-final-newline`, without its last byte when that byte is
//! `\n`. The binding tests make the same changes.
//!
//! The output is JSON: `{"inputs": [...]}`. Each input has
//! `path`, `variant` (`file`, `crlf` or `no-final-newline`) and `findings`
//! in report order. Byte fields are hex.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::process::ExitCode;

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Base64Mode, Finding, FindingRange, Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use serde_json::{Value, json};

/// The finding record budget that the bindings use by default.
const MAX_FINDING_RECORDS: usize = 100_000;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustleaks-binding-reference: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let usage =
        "usage: rustleaks-binding-reference OUTPUT SAMPLES SAMPLES_OUTPUT SAMPLES_PATH FILE...";
    let mut next = || args.next().ok_or(usage);
    let (output, samples, samples_output, samples_path) = (next()?, next()?, next()?, next()?);
    // Bazel passes `$(execpaths ...)` as one argument with the paths
    // separated by spaces.
    let mut files = args
        .flat_map(|arg| {
            arg.split(' ')
                .filter(|path| !path.is_empty())
                .map(|path| (path.to_owned(), path.to_owned()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if files.is_empty() {
        return Err("no files to scan".to_owned());
    }
    files.sort();
    files.dedup();
    write_samples(&samples, &samples_output)?;
    files.push((samples_path, samples_output));

    let config = ConfigLoader::new()
        .load_default()
        .map_err(|error| format!("built-in rules: {error}"))?;
    let engine = Engine::builder(config)
        .build()
        .map_err(|error| format!("engine: {error}"))?;
    let options = ScanOptions::builder()
        .max_decode_depth(0)
        .base64_mode(Base64Mode::Compatible)
        .redaction_percent(0)
        .honor_allow_markers(true)
        .build();
    let control = ScanControl::unlimited()
        .with_budget(ScanBudget::unlimited().max_finding_records(MAX_FINDING_RECORDS));

    let mut inputs = Vec::new();
    for (path, file) in &files {
        let bytes = std::fs::read(file).map_err(|error| format!("{file}: {error}"))?;
        for (variant, content) in variants(&bytes) {
            let fragment = Fragment::builder(content).file_path(path.clone()).build();
            let outcome = engine.scan_fragment_controlled(&fragment, &options, &control);
            if let Some(termination) = outcome.termination() {
                return Err(format!(
                    "{path} ({variant}): scan ended early: {termination:?}"
                ));
            }
            let findings = outcome.findings().iter().map(finding).collect::<Vec<_>>();
            inputs.push(json!({"path": path, "variant": variant, "findings": findings}));
        }
    }
    let document = json!({"inputs": inputs});
    let mut text = serde_json::to_string(&document).map_err(|error| error.to_string())?;
    text.push('\n');
    std::fs::write(&output, text).map_err(|error| format!("{output}: {error}"))
}

/// Writes the input of every generator sample, each followed by `\n`.
fn write_samples(samples: &str, output: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(samples).map_err(|error| format!("{samples}: {error}"))?;
    let mut bytes = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let sample: Value =
            serde_json::from_str(line).map_err(|error| format!("{samples}: {error}"))?;
        let input = sample["input_base64"]
            .as_str()
            .ok_or_else(|| format!("{samples}: a sample has no input_base64"))?;
        bytes.extend_from_slice(&base64(input)?);
        bytes.push(b'\n');
    }
    std::fs::write(output, bytes).map_err(|error| format!("{output}: {error}"))
}

/// Decodes standard base64 with padding.
fn base64(text: &str) -> Result<Vec<u8>, String> {
    let value = |byte: u8| match byte {
        b'A'..=b'Z' => Ok(u32::from(byte - b'A')),
        b'a'..=b'z' => Ok(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Ok(u32::from(byte - b'0') + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        other => Err(format!("not a base64 byte: {other:#04x}")),
    };
    let text = text.as_bytes();
    if !text.len().is_multiple_of(4) {
        return Err("base64 text without padding".to_owned());
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for chunk in text.chunks(4) {
        let padding = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        let mut bits = 0;
        for (index, byte) in chunk[..4 - padding].iter().enumerate() {
            bits |= value(*byte)? << (18 - 6 * index);
        }
        out.extend_from_slice(&u32::to_be_bytes(bits)[1..4 - padding]);
    }
    Ok(out)
}

/// The forms of a file that are scanned. See the module documentation.
fn variants(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut forms = vec![("file", bytes.to_vec())];
    let text = std::str::from_utf8(bytes).is_ok() && bytes.contains(&b'\n');
    if text && !bytes.contains(&b'\r') {
        let mut crlf = Vec::with_capacity(bytes.len() * 2);
        for byte in bytes {
            if *byte == b'\n' {
                crlf.push(b'\r');
            }
            crlf.push(*byte);
        }
        forms.push(("crlf", crlf));
        if let Some(stripped) = bytes.strip_suffix(b"\n") {
            forms.push(("no-final-newline", stripped.to_vec()));
        }
    }
    forms
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn utf8(text: &rustleaks_core::model::ByteText) -> String {
    String::from_utf8(text.as_bytes().to_vec()).expect("built-in rule text is UTF-8")
}

fn range(range: FindingRange) -> Value {
    range
        .exact()
        .map_or(Value::Null, |range| json!([range.start(), range.end()]))
}

fn finding(finding: &Finding) -> Value {
    let location = finding.location();
    json!({
        "rule_id": utf8(finding.rule_id()),
        "description": utf8(finding.description()),
        "tags": finding.tags().iter().map(utf8).collect::<Vec<_>>(),
        "secret": hex(finding.secret().as_bytes()),
        "match": hex(finding.match_text().as_bytes()),
        "line": hex(finding.line().as_bytes()),
        "start_line": location.start_line(),
        "end_line": location.end_line(),
        "start_column": location.start_column(),
        "end_column": location.end_column(),
        "secret_range": range(finding.secret_range()),
        "match_range": range(finding.match_range()),
        "entropy": f64::from(finding.entropy()),
    })
}
