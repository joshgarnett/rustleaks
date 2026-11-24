//! Shared helpers for the tests that read the corpora under `testdata/`.
//!
//! `CanonicalFinding` is the finding record that the corpora store. Its
//! coordinates are `i64` because some composite-corpus records hold negative
//! lines; every other corpus holds only non-negative values.

use std::fs;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustleaks_core::model::{Finding, RequiredFinding};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFinding {
    pub rule_id: String,
    pub description_base64: String,
    pub start_line: i64,
    pub end_line: i64,
    pub start_column: i64,
    pub end_column: i64,
    pub line_base64: String,
    pub match_base64: String,
    pub secret_base64: String,
    pub file_base64: String,
    pub symlink_file_base64: String,
    pub commit_base64: String,
    pub link_base64: String,
    pub entropy_bits: u32,
    pub author_base64: String,
    pub email_base64: String,
    pub date_base64: String,
    pub message_base64: String,
    pub tags_base64: Vec<String>,
    pub fingerprint_base64: String,
    pub fragment: Option<CanonicalFragment>,
    pub required_findings: Vec<CanonicalRequiredFinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFragment {
    pub raw_base64: String,
    pub bytes_base64: String,
    pub file_base64: String,
    pub windows_file_base64: String,
    pub symlink_file_base64: String,
    pub commit_base64: String,
    pub start_line: i64,
    pub inherited_from_finding: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRequiredFinding {
    pub rule_id: String,
    pub start_line: i64,
    pub end_line: i64,
    pub start_column: i64,
    pub end_column: i64,
    pub line_base64: String,
    pub match_base64: String,
    pub secret_base64: String,
}

fn coordinate(value: usize) -> i64 {
    i64::try_from(value).unwrap()
}

pub fn canonical_finding(finding: &Finding) -> CanonicalFinding {
    CanonicalFinding {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        description_base64: encode_base64(finding.description().as_bytes()),
        start_line: coordinate(finding.location().start_line()),
        end_line: coordinate(finding.location().end_line()),
        start_column: coordinate(finding.location().start_column()),
        end_column: coordinate(finding.location().end_column()),
        line_base64: encode_base64(finding.line().as_bytes()),
        match_base64: encode_base64(finding.match_text().as_bytes()),
        secret_base64: encode_base64(finding.secret().as_bytes()),
        file_base64: encode_base64(finding.file().as_bytes()),
        symlink_file_base64: encode_base64(finding.symlink_file().as_bytes()),
        commit_base64: encode_base64(finding.commit().as_bytes()),
        link_base64: encode_base64(finding.link().as_bytes()),
        entropy_bits: finding.entropy().to_bits(),
        author_base64: encode_base64(finding.author().as_bytes()),
        email_base64: encode_base64(finding.email().as_bytes()),
        date_base64: encode_base64(finding.date().as_bytes()),
        message_base64: encode_base64(finding.message().as_bytes()),
        tags_base64: finding
            .tags()
            .iter()
            .map(|tag| encode_base64(tag.as_bytes()))
            .collect(),
        fingerprint_base64: encode_base64(finding.fingerprint().as_bytes()),
        fragment: finding.fragment().map(|fragment| CanonicalFragment {
            raw_base64: encode_base64(fragment.content().as_bytes()),
            // Rust has one byte-first content representation, so the
            // Go-compatible `Fragment.Bytes` projection is always empty.
            bytes_base64: String::new(),
            file_base64: encode_base64(fragment.file_path().as_bytes()),
            windows_file_base64: encode_base64(fragment.windows_file_path().as_bytes()),
            symlink_file_base64: encode_base64(fragment.symlink_file().as_bytes()),
            commit_base64: encode_base64(fragment.commit().as_bytes()),
            start_line: coordinate(fragment.start_line()),
            inherited_from_finding: fragment.inherited_from_finding(),
        }),
        required_findings: finding
            .required_findings()
            .iter()
            .map(canonical_required_finding)
            .collect(),
    }
}

pub fn canonical_required_finding(finding: &RequiredFinding) -> CanonicalRequiredFinding {
    CanonicalRequiredFinding {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        start_line: coordinate(finding.location().start_line()),
        end_line: coordinate(finding.location().end_line()),
        start_column: coordinate(finding.location().start_column()),
        end_column: coordinate(finding.location().end_column()),
        line_base64: encode_base64(finding.line().as_bytes()),
        match_base64: encode_base64(finding.match_text().as_bytes()),
        secret_base64: encode_base64(finding.secret().as_bytes()),
    }
}

/// Reads one JSON value per non-blank line.
pub fn json_lines<T: for<'de> Deserialize<'de>>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Reads one JSON value per non-blank line, keeping only the values with no
/// `operation` field or with `operation` equal to `operation`.
pub fn json_lines_with_operation<T: for<'de> Deserialize<'de>>(
    path: &Path,
    operation: &str,
) -> Vec<T> {
    json_lines::<serde_json::Value>(path)
        .into_iter()
        .filter(|value| {
            value
                .get("operation")
                .is_none_or(|value| value == operation)
        })
        .map(|value| serde_json::from_value(value).unwrap())
        .collect()
}

/// Decodes standard base64 with padding.
pub fn decode_base64(encoded: &str) -> Vec<u8> {
    STANDARD.decode(encoded).unwrap()
}

/// Encodes standard base64 with padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
