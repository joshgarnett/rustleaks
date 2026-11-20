//! Shared helpers for the tests that replay the frozen corpora under `compat/`.
//!
//! `CanonicalFinding` is the finding record that the corpora store. Its
//! coordinates are `i64` because some composite-corpus records hold negative
//! lines; every other corpus holds only non-negative values.

use std::fs;
use std::path::Path;

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

/// Decodes standard base64. Decoding stops at the first `=`.
pub fn decode_base64(encoded: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(encoded.len() / 4 * 3);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in encoded.bytes().take_while(|byte| *byte != b'=') {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid frozen base64 fixture"),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    output
}

/// Encodes standard base64 with padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(TABLE[((value >> 18) & 63) as usize]));
        output.push(char::from(TABLE[((value >> 12) & 63) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[((value >> 6) & 63) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[(value & 63) as usize])
        } else {
            '='
        });
    }
    output
}
