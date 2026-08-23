//! Immutable report-corpus schema, provenance, and canonical-input checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use super::process;
use super::validation::{required_object, required_str, required_u64, string_array};
use super::{TempDir, newline_records, read};
use crate::tooling::support::sha256_bytes;

pub(super) const PROTOCOL_VERSION: u64 = 1;
pub(super) const CASE_COUNT: usize = 49;
pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const DEFAULT_CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";

const BEHAVIORS: &[(&str, &str)] = &[
    (
        "RPT-001",
        "Report format selection is explicit and unknown formats fail structurally.",
    ),
    (
        "RPT-002",
        "JSON output preserves the pinned field order, indentation, omission, escaping, and terminal newline.",
    ),
    (
        "RPT-003",
        "CSV output preserves columns, quoting, raw bytes, tags, first-finding Link selection, and empty behavior.",
    ),
    (
        "RPT-004",
        "JUnit output preserves XML shape, messages, embedded finding JSON, escaping, and empty behavior.",
    ),
    (
        "RPT-005",
        "SARIF output preserves ordered rules, findings, metadata, symlink locations, constants, and empty arrays.",
    ),
    (
        "RPT-006",
        "Templates preserve pinned finding fields and deterministic allowed Sprig helpers.",
    ),
    (
        "RPT-007",
        "Templates reject env, expandenv, and getHostByName while parse-allowing pinned benign helpers.",
    ),
    (
        "RPT-008",
        "Report redaction mutates Line, Match, and Secret with pinned byte-length and RoundToEven semantics.",
    ),
    (
        "RPT-009",
        "Unicode, invalid UTF-8, controls, HTML, CSV, JSON, XML, and template byte boundaries are explicit.",
    ),
    (
        "RPT-010",
        "Writer, JSON value, template path/read/parse/execute, request, and format failures are observable.",
    ),
    (
        "RPT-011",
        "Empty JSON, CSV, JUnit, SARIF, and template reports retain format-specific exact bytes.",
    ),
    (
        "RPT-012",
        "Link and symlink fields retain their format-specific inclusion and precedence.",
    ),
    (
        "RPT-013",
        "Report bytes are deterministic for deterministic findings, rules, and templates.",
    ),
];

const SOURCE_HASHES: &[(&str, &str)] = &[
    (
        "report/constants.go",
        "7b340a90e47a2bdb55fed6a80644b7e8682f12d4706d20efdabccd43043e4ba4",
    ),
    (
        "report/csv.go",
        "c51f7575fcf542de8b3a897fa98093aaed697b28e0af44f4bec19a66ef9d4b91",
    ),
    (
        "report/csv_test.go",
        "2585824350ac030e0751aeb8af0a1103654d9ee14821358caa96410c76784f9e",
    ),
    (
        "report/finding.go",
        "a1ecd3837f6d89b8ddf95f2b0a6c301103b8d3e67f84e1b3520ffc6f7d7751a6",
    ),
    (
        "report/finding_test.go",
        "60f6950823fd227c77d65c630b540fdb3dba46b947bda5bf98f5a72d9d513874",
    ),
    (
        "report/json.go",
        "7cce5d031a4b6fde50e52bd9cd551781a0f00f9a0de79852cfa10ac3385ff733",
    ),
    (
        "report/json_test.go",
        "7f4172d7ff38ef224f88fdaf103187d68a8dd43eaefcd0e2bcbd933849ee2367",
    ),
    (
        "report/junit.go",
        "de628ab9afb6ab5aee6a36e172485ca84f9f9625eeedaa7fa39c62a9754ab4b1",
    ),
    (
        "report/junit_test.go",
        "dc298993221456d5b023b6af4d200e6ade47bab1272b92d441d29f27124da558",
    ),
    (
        "report/report.go",
        "109c5fc946faa5af35ac784815644b4fe5b1ec7b27e3f1f2540c6306a2876f30",
    ),
    (
        "report/report_test.go",
        "16763fa5d4794ce1bb11292a2d4d47a90c6fa1fd661d9b621230b25d53835d89",
    ),
    (
        "report/sarif.go",
        "703eff736c567fb14133dd24cb814bca8f2626fb63d6b969c1fd967ff58e01ed",
    ),
    (
        "report/sarif_test.go",
        "94dc9b2c5745bbcf705721310ff0be680f606458f6bf7d438fde804c263ae28e",
    ),
    (
        "report/template.go",
        "0e324cc75ffeff1ccd3210dc4df88daa72bc5458c49a945db68ade53b80a0a13",
    ),
    (
        "report/template_test.go",
        "d2df3b6b51dfd6d2970b0348cd36c318d0147a6bfa5fc5e761798d20f3102e3c",
    ),
];

const FIXTURE_HASHES: &[(&str, &str)] = &[
    (
        "testdata/expected/report/csv_simple.csv",
        "5de23941d15e7a24937cd469aaad57a980639dba613cd2f8e300b027a7b710c6",
    ),
    (
        "testdata/expected/report/empty.json",
        "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570",
    ),
    (
        "testdata/expected/report/json_simple.json",
        "009af704252257862ee56642a9711189b6f70ec039a3531255d154664968b7ba",
    ),
    (
        "testdata/expected/report/junit_empty.xml",
        "05219f7bf8d7624e2c21f8e17fe1bbda6d83c915b2716aaaeb0bd6c1d92ac5b3",
    ),
    (
        "testdata/expected/report/junit_simple.xml",
        "02fa6b90965f73a02ecc1fb015317ba4785742bea7460086c7d6b143322e58f3",
    ),
    (
        "testdata/expected/report/sarif_simple.sarif",
        "501d60363f7f8963e44eb976785818282898a5f4c46fa454ff6f9b47572ed083",
    ),
    (
        "testdata/expected/report/template_jsonextra.json",
        "bfd4437153905ab8ce814e7aa38cfed6d385bbffaa5829b8bc8fc6c58104acda",
    ),
    (
        "testdata/expected/report/template_markdown.md",
        "0badcf1d17d701a9693d5daf93dab64e07b685814815eec6ed36944686c430aa",
    ),
    (
        "testdata/report/jsonextra.tmpl",
        "5510863d4e65c22344ef54a06be93411282e9ab4630efab54cd38da68816c67d",
    ),
    (
        "testdata/report/markdown.tmpl",
        "de9fc3354c93675f1cc2ce72ccbe5197f785879e6490f1a9b1fe2e2cf8940d29",
    ),
];

pub(super) fn validate_inputs(requests: &[u8], coverage: &Value) -> Result<Vec<Value>, String> {
    if required_u64(coverage, "protocol_version", "coverage")? != PROTOCOL_VERSION
        || required_str(coverage, "upstream_revision", "coverage")? != REVISION
        || required_str(coverage, "default_config_sha256", "coverage")? != DEFAULT_CONFIG_SHA256
    {
        return Err("report coverage provenance changed".into());
    }
    if required_u64(coverage, "case_count", "coverage")? != CASE_COUNT as u64 {
        return Err(format!(
            "report coverage must describe exactly {CASE_COUNT} cases"
        ));
    }
    if required_str(coverage, "requests_sha256", "coverage")? != sha256_bytes(requests) {
        return Err("report request bytes do not match coverage requests_sha256".into());
    }
    validate_string_map(coverage, "behavior_definitions", BEHAVIORS)?;
    validate_string_map(coverage, "source_sha256", SOURCE_HASHES)?;
    validate_string_map(coverage, "fixture_sha256", FIXTURE_HASHES)?;
    let behavior_ids = BEHAVIORS.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    if string_array(coverage, "behavior_ids", "coverage")? != behavior_ids {
        return Err("report coverage behavior_ids changed".into());
    }
    let required_tests = (251..=268)
        .map(|number| format!("TM-{number:04}"))
        .collect::<Vec<_>>();
    if string_array(coverage, "required_report_test_case_ids", "coverage")? != required_tests {
        return Err("required report test identities changed".into());
    }

    let lines = newline_records(requests, "report requests")?;
    if lines.len() != CASE_COUNT {
        return Err(format!(
            "report corpus has {} requests, expected {CASE_COUNT}",
            lines.len()
        ));
    }
    let mut values = Vec::with_capacity(lines.len());
    let mut ids = BTreeSet::new();
    let mut formats: BTreeMap<String, u64> = BTreeMap::new();
    let mut tests = BTreeSet::new();
    let mut behaviors = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let request: Value = serde_json::from_slice(line)
            .map_err(|error| format!("invalid report request {}: {error}", index + 1))?;
        let id = required_str(&request, "id", "request")?.to_owned();
        let protocol = required_u64(&request, "protocol_version", &id)?;
        if protocol != PROTOCOL_VERSION && id != "wrong-protocol" {
            return Err(format!("{id}: unexpected request protocol {protocol}"));
        }
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate report request id {id}"));
        }
        *formats
            .entry(required_str(&request, "format", &id)?.to_owned())
            .or_default() += 1;
        for test in string_array(&request, "test_case_ids", &id)? {
            tests.insert(test.to_owned());
        }
        for behavior in string_array(&request, "behavior_ids", &id)? {
            if !BEHAVIORS.iter().any(|(expected, _)| *expected == behavior) {
                return Err(format!("{id}: unknown behavior id {behavior}"));
            }
            behaviors.insert(behavior.to_owned());
        }
        if !request.get("findings").is_some_and(Value::is_array) {
            return Err(format!("{id}: findings must be an array"));
        }
        values.push(request);
    }
    let covered_formats = required_object(coverage, "format_counts", "coverage")?;
    if covered_formats.len() != formats.len()
        || formats.iter().any(|(format, count)| {
            covered_formats.get(format).and_then(Value::as_u64) != Some(*count)
        })
    {
        return Err("report request format counts differ from coverage".into());
    }
    if string_array(coverage, "test_case_ids", "coverage")?
        != tests.iter().map(String::as_str).collect::<Vec<_>>()
        || required_tests
            .iter()
            .any(|required| !tests.contains(required))
    {
        return Err("report test identity coverage is incomplete".into());
    }
    if behaviors != behavior_ids.iter().map(|id| (*id).to_owned()).collect() {
        return Err("report behavior coverage is incomplete".into());
    }
    Ok(values)
}

pub(super) fn validate_upstream(
    upstream: &Path,
    coverage: &Value,
    temporary: &TempDir,
) -> Result<(), String> {
    let mut command = Command::new("git");
    command.current_dir(upstream).args(["rev-parse", "HEAD"]);
    let revision = process::capture(
        &mut command,
        temporary,
        "upstream-revision",
        Duration::from_secs(30),
    )?;
    if trim_ascii(&revision) != REVISION.as_bytes() {
        return Err(format!(
            "pinned upstream revision changed in {}",
            upstream.display()
        ));
    }
    if sha256_bytes(&read(&upstream.join("config/gitleaks.toml"))?) != DEFAULT_CONFIG_SHA256 {
        return Err("pinned upstream default config changed".into());
    }
    for field in ["source_sha256", "fixture_sha256"] {
        for (path, expected) in required_object(coverage, field, "coverage")? {
            if expected.as_str() != Some(sha256_bytes(&read(&upstream.join(path))?).as_str()) {
                return Err(format!("pinned upstream file {path} changed"));
            }
        }
    }
    Ok(())
}

fn validate_string_map(
    value: &Value,
    field: &str,
    expected: &[(&str, &str)],
) -> Result<(), String> {
    let object = required_object(value, field, "coverage")?;
    if object.len() != expected.len()
        || expected
            .iter()
            .any(|(key, wanted)| object.get(*key).and_then(Value::as_str) != Some(*wanted))
    {
        return Err(format!("report coverage {field} changed"));
    }
    Ok(())
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
