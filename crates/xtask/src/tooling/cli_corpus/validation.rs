//! Exact Rust observation checks against immutable historical expectations.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value, json};

use super::{newline_records, spec};
use crate::tooling::support::sha256_bytes;

pub(super) struct Variant {
    pub(super) case_id: String,
    pub(super) id: String,
    pub(super) request: Value,
    pub(super) expected: Value,
}

pub(super) fn bind_expected(requests: &[Value], bytes: &[u8]) -> Result<Vec<Variant>, String> {
    let outcomes = newline_records(bytes, "CLI outcomes")?
        .into_iter()
        .map(|line| serde_json::from_slice::<Value>(line).map_err(|_| "invalid CLI outcome JSON"))
        .collect::<Result<Vec<_>, _>>()?;
    if outcomes.len() != requests.len() {
        return Err("CLI request/outcome case counts differ".into());
    }
    let mut result = Vec::new();
    let mut identities = BTreeSet::new();
    for (request, outcome) in requests.iter().zip(&outcomes) {
        let case_id = required_str(request, "id", "CLI request")?;
        if outcome["id"] != request["id"] || outcome["title"] != request["title"] {
            return Err(format!("{case_id}: outcome identity or title changed"));
        }
        let variants = required_array(request, "variants", case_id)?;
        let expected = required_array(outcome, "variants", case_id)?;
        if variants.len() != expected.len() {
            return Err(format!("{case_id}: outcome variant count changed"));
        }
        for (variant, frozen) in variants.iter().zip(expected) {
            let id = required_str(variant, "id", case_id)?;
            let label = format!("{case_id}/{id}");
            if frozen["id"] != variant["id"] || !identities.insert(label.clone()) {
                return Err(format!("{label}: missing, duplicate or reordered outcome"));
            }
            let observation = frozen
                .get("rust")
                .ok_or_else(|| format!("{label}: missing Rust observation"))?;
            if required_str(observation, "implementation", &label)? != "rust" {
                return Err(format!("{label}: expected implementation changed"));
            }
            result.push(Variant {
                case_id: case_id.into(),
                id: label,
                request: variant.clone(),
                expected: observation.clone(),
            });
        }
    }
    if result.len() != spec::VARIANT_COUNT {
        return Err("CLI observation identity total changed".into());
    }
    Ok(result)
}

pub(super) fn inapplicable(request: &Value, windows: bool, linux: bool) -> Option<&'static str> {
    if request
        .pointer("/expectation/linux_only")
        .and_then(Value::as_bool)
        == Some(true)
        && !linux
    {
        Some("requires native Linux byte paths")
    } else if windows
        && (request
            .pointer("/expectation/unix_only")
            .and_then(Value::as_bool)
            == Some(true)
            || request["id"] == "windows-logical-name")
    {
        Some("requires a Unix filename unavailable on Windows")
    } else {
        None
    }
}

pub(super) fn native_disposition(id: &str, windows: bool) -> Option<&'static str> {
    if !windows {
        return None;
    }
    match id {
        "CLI-BB-013/outside-baseline" => Some("CLI-NATIVE-WINDOWS-001"),
        "CLI-BB-030/corrupt-archive-and-broken-symlink" => Some("CLI-NATIVE-WINDOWS-002"),
        _ => None,
    }
}

pub(super) fn compare(
    id: &str,
    actual: &Value,
    frozen: &Value,
    windows: bool,
) -> Result<(), String> {
    let expected = expected_observations(id, frozen, windows)?;
    if expected.contains(actual) {
        return Ok(());
    }
    // Report field names, never finding values, paths or captured output.
    let fields = actual
        .as_object()
        .ok_or("CLI observation is not an object")?
        .keys()
        .chain(
            expected[0]
                .as_object()
                .ok_or("CLI expectation is not an object")?
                .keys(),
        )
        .filter(|key| actual.get(*key) != expected[0].get(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    Err(format!(
        "{id}: Rust observation differs in {}",
        fields.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

fn expected_observations(id: &str, frozen: &Value, windows: bool) -> Result<Vec<Value>, String> {
    match native_disposition(id, windows) {
        Some("CLI-NATIVE-WINDOWS-001") => windows_baseline(frozen),
        Some("CLI-NATIVE-WINDOWS-002") => {
            let mut expected = frozen.clone();
            let events = expected["stderr_events"]
                .as_array_mut()
                .ok_or("missing issue events")?;
            if events.len() != 4
                || events[0]["normalized_message_base64"] != BASE64.encode(b"source Decode/Decode scan/bad.gz: invalid gzip header")
                || events[1]["normalized_message_base64"] != BASE64.encode(b"source Symlink/DanglingSymlink scan/broken-link: <os:not-found> (os error 2)") {
                return Err("historical CLI issue fixture changed".into());
            }
            // The Windows fixture cannot create the dangling symlink. Its
            // remaining physical file path is rendered with the native separator.
            events.remove(1);
            events[0]["normalized_message_base64"] =
                json!(BASE64.encode(b"source Decode/Decode scan\\bad.gz: invalid gzip header"));
            Ok(vec![expected])
        }
        None => Ok(vec![frozen.clone()]),
        Some(other) => Err(format!("unknown CLI native disposition {other}")),
    }
}

fn windows_baseline(frozen: &Value) -> Result<Vec<Value>, String> {
    let mut expected = frozen.clone();
    let findings = expected["findings"]
        .as_array_mut()
        .ok_or("missing baseline findings")?;
    if findings.len() != 1 || findings[0]["File"] != "secret.txt" {
        return Err("historical CLI baseline fixture changed".into());
    }
    // The Windows source spelling prevents excluding other/baseline.json.
    // Its synthetic contents are [{"Extra":"token=AB12"}] followed by LF.
    // The second token begins at byte 11, hence columns 12 through 21.
    let mut extra = findings[0].clone();
    extra["File"] = json!("other/baseline.json");
    extra["Fingerprint"] = json!("other/baseline.json:fixture-token:1");
    extra["StartColumn"] = json!(12);
    extra["EndColumn"] = json!(21);
    findings.push(extra);
    let findings_bytes =
        serde_json::to_vec(findings).map_err(|_| "cannot encode baseline expectation")?;
    if sha256_bytes(&findings_bytes)
        != "5c47e6a449ce6e905ae112eef094907de2e1af89e1409e2d86fb6e7cf367c90d"
    {
        return Err(
            "independent Windows finding expectation disagrees with historical ledger".into(),
        );
    }
    expected["finding_count"] = json!(2);
    expected["stderr_events"][1] = json!({
        "severity": "warn", "class": "summary.findings", "fields": {"count": 2},
        "normalized_message_base64": BASE64.encode(b"leaks found: 2")
    });
    let report = BASE64
        .decode(required_str(
            &frozen["report"],
            "bytes_base64",
            "baseline report",
        )?)
        .map_err(|_| "invalid historical report bytes")?;
    let text =
        std::str::from_utf8(&report).map_err(|_| "historical baseline report is not UTF-8")?;
    let first = text
        .strip_prefix("[\n")
        .and_then(|body| body.strip_suffix("\n]\n"))
        .ok_or("historical baseline report framing changed")?;
    let mut second = first.to_owned();
    for (from, to) in [
        ("\"StartColumn\": 1,", "\"StartColumn\": 12,"),
        ("\"EndColumn\": 10,", "\"EndColumn\": 21,"),
        (
            "\"File\": \"secret.txt\"",
            "\"File\": \"other/baseline.json\"",
        ),
        (
            "\"Fingerprint\": \"secret.txt:fixture-token:1\"",
            "\"Fingerprint\": \"other/baseline.json:fixture-token:1\"",
        ),
    ] {
        if second.matches(from).count() != 1 {
            return Err("historical baseline report field changed".into());
        }
        second = second.replacen(from, to, 1);
    }
    // Only the two complete finding orders are permitted. Every byte in each
    // object, report framing and all remaining observation fields stay exact.
    [
        format!("[\n{first},\n{second}\n]\n"),
        format!("[\n{second},\n{first}\n]\n"),
    ]
    .into_iter()
    .map(|report| {
        if report.len() != 796 {
            return Err("Windows report extent changed".into());
        }
        let mut alternative = expected.clone();
        alternative["report"] = json!({
            "state": "present", "bytes_base64": BASE64.encode(report.as_bytes()),
            "bytes": report.len(), "sha256": sha256_bytes(report.as_bytes())
        });
        Ok(alternative)
    })
    .collect()
}

pub(super) fn required_array<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Vec<Value>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: {field} is not an array"))
}

pub(super) fn required_object<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label}: {field} is not an object"))
}

pub(super) fn required_str<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: {field} is not a string"))
}

pub(super) fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label}: {field} is not unsigned"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<Value>, Vec<Variant>, Vec<u8>) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/cli-corpus");
        let requests = std::fs::read(root.join("requests-v1.jsonl")).unwrap();
        let rows = newline_records(&requests, "requests")
            .unwrap()
            .into_iter()
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect::<Vec<Value>>();
        let bytes = std::fs::read(root.join("outcomes-v1.jsonl")).unwrap();
        let variants = bind_expected(&rows, &bytes).unwrap();
        (rows, variants, bytes)
    }

    #[test]
    fn missing_swapped_and_duplicate_identities_are_rejected() {
        use std::fmt::Write as _;

        let (rows, _, bytes) = fixture();
        let mut outcomes = newline_records(&bytes, "outcomes")
            .unwrap()
            .into_iter()
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        outcomes[0]["variants"].as_array_mut().unwrap().swap(0, 1);
        let encode = |rows: &[Value]| {
            rows.iter().fold(String::new(), |mut output, row| {
                writeln!(output, "{row}").unwrap();
                output
            })
        };
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes()).is_err());
        outcomes.swap(0, 1);
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes()).is_err());
        outcomes.remove(0);
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes()).is_err());
        let mut duplicated = rows.clone();
        duplicated[0]["variants"][1] = duplicated[0]["variants"][0].clone();
        assert!(bind_expected(&duplicated, &bytes).is_err());
    }

    #[test]
    fn all_declared_material_mutations_fail_exact_comparison() {
        let (_, variants, _) = fixture();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/cli-corpus");
        let controls: Value =
            serde_json::from_slice(&std::fs::read(root.join("negative-controls-v1.json")).unwrap())
                .unwrap();
        for control in controls["controls"].as_array().unwrap() {
            let id = format!(
                "{}/{}",
                control["case_id"].as_str().unwrap(),
                control["variant_id"].as_str().unwrap()
            );
            let frozen = &variants
                .iter()
                .find(|variant| variant.id == id)
                .unwrap()
                .expected;
            compare(&id, frozen, frozen, false).unwrap();
            let mut changed = frozen.clone();
            match control["expected_failure_class"].as_str().unwrap() {
                "selected-findings" => {
                    // Selecting the matching environment config instead of the
                    // explicit no-match config introduces this fixture finding.
                    changed["findings"] = variants
                        .iter()
                        .find(|variant| variant.id == "CLI-BB-002/dir")
                        .unwrap()
                        .expected["findings"]
                        .clone();
                }
                "complete-findings" => {
                    let removed = changed["findings"].as_array_mut().unwrap().pop();
                    assert!(removed.is_some(), "{id}: no finding available to remove");
                }
                "safe-arity"
                | "stdout-format"
                | "terminal-exit"
                | "report-open-failure"
                | "persistent-grammar"
                | "shorthand-grammar"
                | "raw-template-grammar"
                | "exit" => changed["exit"] = json!(99),
                "dormant-report" | "report-before-exit" | "safe-preflight" | "report-bytes" => {
                    changed["report"] = json!({"state": "mutated"});
                }
                "non-disclosure" => changed["stderr_contains_disclosure_marker"] = json!(true),
                "help-golden" => changed["stdout_base64"] = json!(BASE64.encode(b"changed help")),
                "stderr-severity" => changed["stderr_events"][0]["severity"] = json!("fatal"),
                "process-cleanup" => changed["child_reaped"] = json!(false),
                unknown => panic!("unmapped control {unknown}"),
            }
            assert!(
                &changed != frozen,
                "{id}: mutation did not change its observation"
            );
            assert!(compare(&id, &changed, frozen, false).is_err(), "{id}");
        }
    }

    #[test]
    fn native_expectations_preserve_every_unaffected_field() {
        let (_, variants, _) = fixture();
        for id in [
            "CLI-BB-013/outside-baseline",
            "CLI-BB-030/corrupt-archive-and-broken-symlink",
        ] {
            let frozen = &variants
                .iter()
                .find(|variant| variant.id == id)
                .unwrap()
                .expected;
            for expected in expected_observations(id, frozen, true).unwrap() {
                compare(id, &expected, frozen, true).unwrap();
                for field in expected.as_object().unwrap().keys() {
                    let mut changed = expected.clone();
                    changed[field] = json!({"mutation": true});
                    assert!(
                        compare(id, &changed, frozen, true).is_err(),
                        "{id}: {field}"
                    );
                }
            }
        }
        let outside_i32 = variants
            .iter()
            .find(|v| v.id == "CLI-BB-019/outside-i32")
            .unwrap();
        assert_eq!(outside_i32.expected["exit"], 1);
        compare(
            &outside_i32.id,
            &outside_i32.expected,
            &outside_i32.expected,
            true,
        )
        .unwrap();
        let mut changed = outside_i32.expected.clone();
        changed["exit"] = json!(-2_147_483_648_i64);
        assert!(compare(&outside_i32.id, &changed, &outside_i32.expected, true).is_err());
    }

    #[test]
    fn platform_accounting_never_calls_archived_rows_executed() {
        let (_, variants, _) = fixture();
        for (windows, linux, expected) in [(false, true, 0), (false, false, 1), (true, false, 3)] {
            assert_eq!(
                variants
                    .iter()
                    .filter(|v| inapplicable(&v.request, windows, linux).is_some())
                    .count(),
                expected
            );
        }
    }
}
