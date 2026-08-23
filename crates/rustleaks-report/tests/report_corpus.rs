#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use base64::Engine as _;
use rustleaks_core::model::{Finding, Location};
use rustleaks_report::{
    CsvReporter, JsonReporter, JunitReporter, ReportRule, Reporter, SarifReporter,
};
use serde_json::Value;

#[test]
fn every_representable_builtin_report_case_replays_exact_oracle_bytes() {
    let root = std::env::var_os("RUSTLEAKS_REPORT_CORPUS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/report-corpus"),
        PathBuf::from,
    );
    let outcomes = json_lines(&root.join("outcomes-v1.jsonl"))
        .into_iter()
        .map(|value| (text(&value, "id").to_owned(), value))
        .collect::<BTreeMap<_, _>>();
    let mut replayed = Vec::new();
    let mut dispositions = Vec::new();
    let mut delegated_templates = Vec::new();

    for request in json_lines(&root.join("requests-v1.jsonl")) {
        let format = text(&request, "format");
        let id = text(&request, "id");
        if format == "template" {
            delegated_templates.push(id.to_owned());
            continue;
        }
        if !matches!(format, "json" | "csv" | "junit" | "sarif") {
            assert_eq!(id, "unknown-format");
            assert_eq!(format, "yaml");
            assert_eq!(outcomes[id]["error"]["class"], "format");
            continue;
        }
        if matches!(
            id,
            "bad-finding-base64" | "bad-rule-base64" | "negative-writer-limit" | "wrong-protocol"
        ) {
            dispositions.push(id.to_owned());
            continue;
        }
        if request["findings"]
            .as_array()
            .is_some_and(|findings| findings.iter().any(|finding| finding["tags_nil"] == true))
        {
            // Rust's public Finding has an owned Vec and cannot represent a
            // programmatic nil Go slice. The production detector emits [] and
            // the declared compatibility domain records this one disposition.
            dispositions.push(id.to_owned());
            continue;
        }
        let mut findings = request["findings"]
            .as_array()
            .map_or_else(Vec::new, |values| {
                values.iter().map(build_finding).collect::<Vec<_>>()
            });
        if let Some(percent) = request["redact_percent"].as_u64() {
            findings = findings
                .into_iter()
                .map(|finding| finding.redacted(usize::try_from(percent).unwrap()))
                .collect();
        }
        let reporter: Box<dyn Reporter> = match format {
            "json" => Box::new(JsonReporter),
            "csv" => Box::new(CsvReporter),
            "junit" => Box::new(JunitReporter),
            "sarif" => Box::new(
                SarifReporter::try_new(request["ordered_rules"].as_array().map_or_else(
                    Vec::new,
                    |rules| {
                        rules
                            .iter()
                            .map(|rule| {
                                let id =
                                    String::from_utf8(decode(text(rule, "id_base64"))).unwrap();
                                let description =
                                    String::from_utf8(decode(text(rule, "description_base64")))
                                        .unwrap();
                                ReportRule::try_new(&id, &description).unwrap()
                            })
                            .collect()
                    },
                ))
                .unwrap(),
            ),
            _ => unreachable!(),
        };
        let outcome = &outcomes[id];
        let expected = decode(text(outcome, "output_base64"));
        let limit = request["fail_after_bytes"]
            .as_u64()
            .map(|value| usize::try_from(value).unwrap());
        let mut destination = FailingWriter::new(limit);
        let result = reporter.write(&mut destination, &findings);
        if id == "junit-writer-error" {
            // The pinned writer ignores its XML-header error and continues;
            // Rust returns the first destination error immediately.
            assert!(result.is_err());
            assert!(destination.bytes.is_empty());
            assert_eq!(expected.len(), 39);
            dispositions.push(id.to_owned());
            continue;
        }
        assert_eq!(destination.bytes, expected, "{id}");
        let expected_error = outcome["error"].is_object();
        assert_eq!(result.is_err(), expected_error, "{id}");
        replayed.push(id.to_owned());
    }

    replayed.sort();
    dispositions.sort();
    delegated_templates.sort();
    assert_corpus_accounting(&replayed, &dispositions, &delegated_templates);
}

fn assert_corpus_accounting(
    replayed: &[String],
    dispositions: &[String],
    delegated_templates: &[String],
) {
    assert_eq!(replayed.len(), 27);
    assert_eq!(
        dispositions,
        [
            "bad-finding-base64",
            "bad-rule-base64",
            "json-link-symlink-tags-nil",
            "junit-writer-error",
            "negative-writer-limit",
            "wrong-protocol",
        ]
    );
    assert_eq!(
        delegated_templates,
        [
            "template-allow-now-parse",
            "template-allow-random-parse",
            "template-block-env",
            "template-block-expandenv",
            "template-block-host",
            "template-empty",
            "template-empty-path",
            "template-execute-error",
            "template-jsonextra",
            "template-markdown",
            "template-missing-path",
            "template-parse-error",
            "template-raw-bytes",
            "template-safe-helpers",
            "template-writer-error",
        ]
    );
}

fn build_finding(value: &Value) -> Finding {
    Finding::builder()
        .rule_id(bytes(value, "rule_id_base64"))
        .description(bytes(value, "description_base64"))
        .location(
            Location::new(
                number(value, "start_line"),
                number(value, "end_line"),
                number(value, "start_column"),
                number(value, "end_column"),
            )
            .unwrap(),
        )
        .line(bytes(value, "line_base64"))
        .match_text(bytes(value, "match_base64"))
        .secret(bytes(value, "secret_base64"))
        .file(bytes(value, "file_base64"))
        .symlink_file(bytes(value, "symlink_file_base64"))
        .commit(bytes(value, "commit_base64"))
        .link(bytes(value, "link_base64"))
        .entropy(f32::from_bits(
            u32::try_from(value["entropy_bits"].as_u64().unwrap()).unwrap(),
        ))
        .author(bytes(value, "author_base64"))
        .email(bytes(value, "email_base64"))
        .date(bytes(value, "date_base64"))
        .message(bytes(value, "message_base64"))
        .tags(
            value["tags_base64"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tag| decode(tag.as_str().unwrap())),
        )
        .fingerprint(bytes(value, "fingerprint_base64"))
        .build()
        .unwrap()
}

fn json_lines(path: &std::path::Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn number(value: &Value, key: &str) -> usize {
    usize::try_from(value[key].as_u64().unwrap()).unwrap()
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    decode(text(value, key))
}

fn decode(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

struct FailingWriter {
    bytes: Vec<u8>,
    remaining: Option<usize>,
}

impl FailingWriter {
    const fn new(limit: Option<usize>) -> Self {
        Self {
            bytes: Vec::new(),
            remaining: limit,
        }
    }
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(remaining) = &mut self.remaining {
            if *remaining == 0 {
                return Err(io::Error::other("injected writer failure"));
            }
            let count = bytes.len().min(*remaining);
            self.bytes.extend_from_slice(&bytes[..count]);
            *remaining -= count;
            return Ok(count);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
