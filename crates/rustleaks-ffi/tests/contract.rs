#![forbid(unsafe_code)]
#![allow(missing_docs)]
//! Runs every case of the shared binding corpus in `testdata/bindings/`
//! through the C ABI. The Go and Python tests read the same cases.

use std::path::{Path, PathBuf};

use rustleaks_ffi::abi::{
    ERROR_CONFIG, ERROR_INPUT_TOO_LARGE, ERROR_RULE_SELECTION, OPTION_ALLOW_COMMENTS,
    OPTION_DECODE_DEPTH, OPTION_MAX_FINDING_RECORDS, OPTION_MAX_INPUT_BYTES, TERMINATION_BUDGET,
    TERMINATION_COMPLETE,
};
use rustleaks_ffi::harness::{Engine, Finding, Options, scan_args};
use serde_json::Value;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/bindings")
}

/// Concatenates segments: JSON strings are UTF-8 text, `{"hex": "..."}` are
/// raw bytes.
fn segments(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    for segment in value.as_array().expect("a list of segments") {
        match segment {
            Value::String(text) => bytes.extend_from_slice(text.as_bytes()),
            Value::Object(object) => {
                let hex = object["hex"].as_str().expect("a hex segment");
                assert!(object.len() == 1 && hex.len() % 2 == 0, "{segment}");
                for pair in hex.as_bytes().chunks(2) {
                    let pair = std::str::from_utf8(pair).unwrap();
                    bytes.push(u8::from_str_radix(pair, 16).expect("hex digits"));
                }
            }
            other => panic!("not a segment: {other}"),
        }
    }
    bytes
}

/// The corpus name of a library error kind.
fn error_name(kind: i32) -> &'static str {
    match kind {
        ERROR_CONFIG => "config",
        ERROR_RULE_SELECTION => "rule_selection",
        ERROR_INPUT_TOO_LARGE => "input_too_large",
        other => panic!("no corpus name for error kind {other}"),
    }
}

fn engine(spec: &Value) -> Result<Engine, String> {
    let mut options = Options::new().unwrap();
    if let Some(config) = spec["config"].as_str() {
        let text = std::fs::read(corpus().join(config)).expect("corpus config");
        options.set_config(&text).unwrap();
    }
    if let Some(rules) = spec["rules"].as_array() {
        for rule in rules {
            options
                .add_rule_id(rule.as_str().expect("a rule ID").as_bytes())
                .unwrap();
        }
    }
    if let Some(allow) = spec.get("allow_comments").and_then(Value::as_bool) {
        options
            .set_bool(OPTION_ALLOW_COMMENTS, u8::from(allow))
            .unwrap();
    }
    for (key, name) in [
        (OPTION_DECODE_DEPTH, "decode_depth"),
        (OPTION_MAX_INPUT_BYTES, "max_input_bytes"),
        (OPTION_MAX_FINDING_RECORDS, "max_finding_records"),
    ] {
        if let Some(value) = spec.get(name).and_then(Value::as_u64) {
            options.set_u64(key, value).unwrap();
        }
    }
    Engine::new(&options).map_err(|error| {
        assert!(!error.message.is_empty());
        error_name(error.kind).to_owned()
    })
}

/// The outcome of one case: the corpus error name or the findings.
fn run(case: &Value) -> Result<Vec<Finding>, String> {
    let engine = engine(&case["engine"])?;
    let scan = &case["scan"];
    let input = segments(&scan["input"]);
    let path = scan["path"].as_str().unwrap_or("").as_bytes().to_vec();
    let outcome = engine
        .scan(&input, Some(&scan_args(&path)), None)
        .map_err(|error| error_name(error.kind).to_owned())?;
    match outcome.status.termination {
        TERMINATION_COMPLETE => Ok(outcome.findings),
        TERMINATION_BUDGET => Err("budget_exceeded".to_owned()),
        other => panic!("unexpected termination {other}"),
    }
}

fn check_finding(name: &str, index: usize, actual: &Finding, expected: &Value, path: &[u8]) {
    let context = format!("{name} finding {index}");
    assert_eq!(
        actual.rule_id,
        expected["rule_id"].as_str().unwrap().as_bytes(),
        "{context}"
    );
    assert_eq!(
        actual.secret,
        segments(&expected["secret"]),
        "{context} secret"
    );
    assert_eq!(
        actual.match_text,
        segments(&expected["match"]),
        "{context} match"
    );
    if let Some(line) = expected.get("line") {
        assert_eq!(actual.line, segments(line), "{context} line");
    }
    let number = |field: &str| expected[field].as_u64().expect(field);
    assert_eq!(
        (
            actual.start_line,
            actual.end_line,
            actual.start_column,
            actual.end_column
        ),
        (
            number("start_line"),
            number("end_line"),
            number("start_column"),
            number("end_column")
        ),
        "{context} location"
    );
    let range = expected["secret_range"]
        .as_array()
        .map(|range| (range[0].as_u64().unwrap(), range[1].as_u64().unwrap()));
    assert_eq!(actual.secret_range, range, "{context} secret range");
    assert_eq!(actual.path, path, "{context} path");
}

#[test]
fn every_binding_case_holds_through_the_c_abi() {
    let text = std::fs::read_to_string(corpus().join("cases.json")).expect("cases.json");
    let corpus: Value = serde_json::from_str(&text).expect("valid JSON");
    let cases = corpus["cases"].as_array().expect("a case list");
    assert!(cases.len() >= 30, "{}", cases.len());
    let mut names = Vec::new();
    for case in cases {
        let name = case["name"].as_str().expect("a case name");
        assert!(!names.contains(&name), "duplicate case {name}");
        names.push(name);
        let expect = &case["expect"];
        let findings = expect["findings"].as_array().expect("a finding list");
        match (run(case), expect["error"].as_str()) {
            (Ok(actual), None) => {
                assert_eq!(actual.len(), findings.len(), "{name} finding count");
                let path = case["scan"]["path"].as_str().unwrap_or("").as_bytes();
                for (index, (actual, expected)) in actual.iter().zip(findings).enumerate() {
                    check_finding(name, index, actual, expected, path);
                }
            }
            (Err(actual), Some(expected)) => {
                assert_eq!(actual, expected, "{name} error");
                assert!(findings.is_empty(), "{name} lists findings with an error");
            }
            (actual, expected) => {
                panic!(
                    "{name}: expected error {expected:?}, got {:?}",
                    actual.err()
                );
            }
        }
    }
}
