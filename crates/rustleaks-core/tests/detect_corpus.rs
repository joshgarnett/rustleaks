#![allow(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{
    CommitMetadata, Finding, Fragment, Location, RequiredFinding, ScanOptions,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    id: String,
    #[serde(default)]
    scope_disposition: String,
    #[serde(default)]
    config_base64: String,
    #[serde(default)]
    config_fixture: String,
    fragment: RequestFragment,
    options: RequestOptions,
}

#[derive(Deserialize)]
struct RequestFragment {
    content_base64: String,
    file_base64: String,
    windows_file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    start_line: usize,
    author_base64: String,
    email_base64: String,
    date_base64: String,
    message_base64: String,
    inherited_from_finding: bool,
}

#[derive(Deserialize)]
struct RequestOptions {
    #[serde(default)]
    max_decode_depth: i64,
    max_target_megabytes: i64,
    ignore_allow_marker: bool,
}

#[derive(Deserialize)]
struct Response {
    id: String,
    findings: Vec<CanonicalFinding>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalFinding {
    rule_id: String,
    description_base64: String,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    line_base64: String,
    match_base64: String,
    secret_base64: String,
    file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    link_base64: String,
    entropy_bits: u32,
    author_base64: String,
    email_base64: String,
    date_base64: String,
    message_base64: String,
    tags_base64: Vec<String>,
    fingerprint_base64: String,
    fragment: Option<CanonicalFragment>,
    required_findings: Vec<CanonicalRequiredFinding>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalFragment {
    raw_base64: String,
    bytes_base64: String,
    file_base64: String,
    windows_file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    start_line: usize,
    inherited_from_finding: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRequiredFinding {
    rule_id: String,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    line_base64: String,
    match_base64: String,
    secret_base64: String,
}

#[test]
fn canonical_adapter_preserves_every_nested_protocol_field() {
    let fragment = Fragment::builder([0xff, b'r', b'a', b'w'])
        .file_path(b"path/file".to_vec())
        .windows_file_path(b"path\\file".to_vec())
        .symlink_file(b"link".to_vec())
        .commit(b"commit".to_vec())
        .start_line(17)
        .inherited_from_finding(true)
        .build();
    let required = RequiredFinding::builder()
        .rule_id(b"required".to_vec())
        .location(Location::new(3, 4, 5, 6).unwrap())
        .line([0xfe, b'l'])
        .match_text(b"match".to_vec())
        .secret(b"secret".to_vec())
        .build()
        .unwrap();
    let finding = Finding::builder()
        .rule_id(b"primary".to_vec())
        .location(Location::new(1, 1, 1, 1).unwrap())
        .fragment(fragment)
        .required_findings([required])
        .build()
        .unwrap();

    let canonical = canonical_finding(&finding);
    assert_eq!(
        canonical.fragment,
        Some(CanonicalFragment {
            raw_base64: encode_base64(&[0xff, b'r', b'a', b'w']),
            bytes_base64: String::new(),
            file_base64: encode_base64(b"path/file"),
            windows_file_base64: encode_base64(b"path\\file"),
            symlink_file_base64: encode_base64(b"link"),
            commit_base64: encode_base64(b"commit"),
            start_line: 17,
            inherited_from_finding: true,
        })
    );
    assert_eq!(
        canonical.required_findings,
        vec![CanonicalRequiredFinding {
            rule_id: "required".to_owned(),
            start_line: 3,
            end_line: 4,
            start_column: 5,
            end_column: 6,
            line_base64: encode_base64(&[0xfe, b'l']),
            match_base64: encode_base64(b"match"),
            secret_base64: encode_base64(b"secret"),
        }]
    );
}

#[test]
fn frozen_direct_detector_corpus_matches_go() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/detect-corpus");
    replay_detector_corpus(&corpus);
}

#[test]
fn frozen_decoder_detector_corpus_matches_go() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/decoder-corpus");
    replay_detector_corpus(&corpus);
}

fn replay_detector_corpus(corpus: &Path) {
    let requests = detector_json_lines::<Request>(&corpus.join("requests-v1.jsonl"));
    let responses = detector_json_lines::<Response>(&corpus.join("outcomes-v1.jsonl"));
    assert_eq!(requests.len(), responses.len());

    for (request, response) in requests.into_iter().zip(responses) {
        assert_eq!(request.id, response.id);
        if request.config_base64.is_empty() && request.config_fixture.is_empty() {
            continue;
        }
        assert!(response.error.is_none(), "{}: Go oracle error", request.id);
        assert!(
            !request.scope_disposition.contains("deferred"),
            "{}",
            request.id
        );
        let config_bytes = if request.config_fixture.is_empty() {
            decode_base64(&request.config_base64)
        } else {
            let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../compat/fixtures/upstream/testdata/config")
                .join(&request.config_fixture);
            fs::read(fixture).unwrap()
        };
        let config_text = std::str::from_utf8(&config_bytes).unwrap();
        let config = ConfigLoader::new().load_toml(config_text).unwrap();
        let engine = Engine::builder(config).build().unwrap();

        let content = decode_base64(&request.fragment.content_base64);
        let file = decode_base64(&request.fragment.file_base64);
        let windows_file = decode_base64(&request.fragment.windows_file_base64);
        let symlink_file = decode_base64(&request.fragment.symlink_file_base64);
        let commit = decode_base64(&request.fragment.commit_base64);
        let author = decode_base64(&request.fragment.author_base64);
        let email = decode_base64(&request.fragment.email_base64);
        let date = decode_base64(&request.fragment.date_base64);
        let message = decode_base64(&request.fragment.message_base64);
        let has_metadata = [&author, &email, &date, &message]
            .into_iter()
            .any(|value| !value.is_empty());
        let mut fragment = Fragment::builder(content)
            .file_path(file)
            .windows_file_path(windows_file)
            .symlink_file(symlink_file)
            .commit(commit)
            .start_line(request.fragment.start_line)
            .inherited_from_finding(request.fragment.inherited_from_finding);
        if has_metadata {
            fragment = fragment.commit_metadata(
                CommitMetadata::builder()
                    .author_name(author)
                    .author_email(email)
                    .date(date)
                    .message(message)
                    .build(),
            );
        }

        // Upstream truncates len/1_000_000 before comparing its megabyte
        // setting. Express that inclusive effective boundary in the Rust
        // API's exact-byte option.
        let maximum = (request.options.max_target_megabytes > 0).then(|| {
            usize::try_from(request.options.max_target_megabytes)
                .unwrap()
                .saturating_add(1)
                .saturating_mul(1_000_000)
                .saturating_sub(1)
        });
        let options = ScanOptions::builder()
            .max_decode_depth(canonical_decode_depth(request.options.max_decode_depth))
            .max_target_bytes(maximum)
            .honor_gitleaks_allow(!request.options.ignore_allow_marker)
            .build();
        let mut actual = engine
            .scan_fragment(&fragment.build(), &options)
            .findings()
            .iter()
            .map(canonical_finding)
            .collect::<Vec<_>>();
        actual.sort_by_cached_key(|finding| serde_json::to_string(finding).unwrap());
        let mut expected = response.findings;
        expected.sort_by_cached_key(|finding| serde_json::to_string(finding).unwrap());
        assert_eq!(actual, expected, "detector corpus case {}", request.id);
    }
}

fn canonical_decode_depth(depth: i64) -> usize {
    usize::try_from(depth).unwrap_or(0)
}

#[test]
fn go_nonpositive_decode_depths_map_to_raw_only() {
    assert_eq!(canonical_decode_depth(i64::MIN), 0);
    assert_eq!(canonical_decode_depth(-1), 0);
    assert_eq!(canonical_decode_depth(0), 0);
    assert_eq!(canonical_decode_depth(1), 1);
}

fn canonical_finding(finding: &Finding) -> CanonicalFinding {
    CanonicalFinding {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        description_base64: encode_base64(finding.description().as_bytes()),
        start_line: finding.location().start_line(),
        end_line: finding.location().end_line(),
        start_column: finding.location().start_column(),
        end_column: finding.location().end_column(),
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
            // Rust intentionally has one byte-first content representation;
            // its Go-compatible Fragment.Bytes projection is nil.
            bytes_base64: String::new(),
            file_base64: encode_base64(fragment.file_path().as_bytes()),
            windows_file_base64: encode_base64(fragment.windows_file_path().as_bytes()),
            symlink_file_base64: encode_base64(fragment.symlink_file().as_bytes()),
            commit_base64: encode_base64(fragment.commit().as_bytes()),
            start_line: fragment.start_line(),
            inherited_from_finding: fragment.inherited_from_finding(),
        }),
        required_findings: finding
            .required_findings()
            .iter()
            .map(canonical_required_finding)
            .collect(),
    }
}

fn canonical_required_finding(finding: &RequiredFinding) -> CanonicalRequiredFinding {
    CanonicalRequiredFinding {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        start_line: finding.location().start_line(),
        end_line: finding.location().end_line(),
        start_column: finding.location().start_column(),
        end_column: finding.location().end_column(),
        line_base64: encode_base64(finding.line().as_bytes()),
        match_base64: encode_base64(finding.match_text().as_bytes()),
        secret_base64: encode_base64(finding.secret().as_bytes()),
    }
}

fn detector_json_lines<T: for<'de> Deserialize<'de>>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|value| {
            value
                .get("operation")
                .is_none_or(|operation| operation == "detect")
        })
        .map(|value| serde_json::from_value(value).unwrap())
        .collect()
}

fn decode_base64(encoded: &str) -> Vec<u8> {
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

fn encode_base64(bytes: &[u8]) -> String {
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
