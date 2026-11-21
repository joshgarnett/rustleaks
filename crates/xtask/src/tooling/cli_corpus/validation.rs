//! Binding of expected observations to requests and exact comparison.

use std::collections::BTreeSet;

use serde_json::Value;

use super::newline_records;

pub(super) struct Variant {
    pub(super) case_id: String,
    pub(super) id: String,
    pub(super) request: Value,
    /// Accepted observations on this platform. Most variants accept one.
    pub(super) expected: Vec<Value>,
}

/// Pairs each request variant with its expected observation in
/// `outcomes-v1.jsonl`, in order.
///
/// On Windows a variant with `expected_windows` uses that list of accepted
/// observations instead of `expected`.
pub(super) fn bind_expected(
    requests: &[Value],
    bytes: &[u8],
    windows: bool,
) -> Result<Vec<Variant>, String> {
    let outcomes = newline_records(bytes, "CLI outcomes")?
        .into_iter()
        .map(|line| serde_json::from_slice::<Value>(line).map_err(|_| "invalid CLI outcome JSON"))
        .collect::<Result<Vec<_>, _>>()?;
    if outcomes.len() != requests.len() {
        return Err("CLI request and outcome case counts differ".into());
    }
    let mut result = Vec::new();
    let mut identities = BTreeSet::new();
    for (request, outcome) in requests.iter().zip(&outcomes) {
        let case_id = required_str(request, "id", "CLI request")?;
        if outcome["id"] != request["id"] || outcome["title"] != request["title"] {
            return Err(format!("{case_id}: outcome identity or title differs"));
        }
        let variants = required_array(request, "variants", case_id)?;
        let outcome_variants = required_array(outcome, "variants", case_id)?;
        if variants.len() != outcome_variants.len() {
            return Err(format!("{case_id}: outcome variant count differs"));
        }
        for (variant, outcome) in variants.iter().zip(outcome_variants) {
            let id = required_str(variant, "id", case_id)?;
            let label = format!("{case_id}/{id}");
            if outcome["id"] != variant["id"] || !identities.insert(label.clone()) {
                return Err(format!("{label}: missing, duplicate or reordered outcome"));
            }
            result.push(Variant {
                case_id: case_id.into(),
                request: variant.clone(),
                expected: accepted(outcome, windows, &label)?,
                id: label,
            });
        }
    }
    Ok(result)
}

fn accepted(outcome: &Value, windows: bool, label: &str) -> Result<Vec<Value>, String> {
    let expected = outcome
        .get("expected")
        .filter(|value| value.is_object())
        .ok_or_else(|| format!("{label}: expected is not an object"))?;
    let alternatives = match outcome.get("expected_windows") {
        None => None,
        Some(Value::Array(values)) if !values.is_empty() && values.iter().all(Value::is_object) => {
            Some(values)
        }
        Some(_) => {
            return Err(format!(
                "{label}: expected_windows is not a list of observations"
            ));
        }
    };
    if outcome
        .as_object()
        .is_some_and(|object| object.len() != 2 + usize::from(alternatives.is_some()))
    {
        return Err(format!("{label}: outcome has unknown members"));
    }
    Ok(match alternatives {
        Some(values) if windows => values.clone(),
        _ => vec![expected.clone()],
    })
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

/// Requires the observation to equal one accepted expectation exactly.
pub(super) fn compare(id: &str, actual: &Value, expected: &[Value]) -> Result<(), String> {
    if expected.contains(actual) {
        return Ok(());
    }
    let first = expected
        .first()
        .and_then(Value::as_object)
        .ok_or("CLI expectation is not an object")?;
    // Report field names, never finding values, paths or captured output.
    let fields = actual
        .as_object()
        .ok_or("CLI observation is not an object")?
        .keys()
        .chain(first.keys())
        .filter(|key| actual.get(*key) != first.get(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    Err(format!(
        "{id}: Rust observation differs in {}",
        fields.into_iter().collect::<Vec<_>>().join(", ")
    ))
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
    use std::fmt::Write as _;

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use serde_json::json;

    use super::super::{observe, spec};
    use super::*;

    fn corpus() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/cli-corpus")
    }

    fn fixture(windows: bool) -> (Vec<Value>, Vec<Variant>, Vec<u8>) {
        let requests = std::fs::read(corpus().join("requests-v1.jsonl")).unwrap();
        let rows = spec::validate_requests(&requests).unwrap();
        let bytes = std::fs::read(corpus().join("outcomes-v1.jsonl")).unwrap();
        let variants = bind_expected(&rows, &bytes, windows).unwrap();
        (rows, variants, bytes)
    }

    fn find<'a>(variants: &'a [Variant], id: &str) -> &'a Variant {
        variants.iter().find(|variant| variant.id == id).unwrap()
    }

    fn encode(rows: &[Value]) -> String {
        rows.iter().fold(String::new(), |mut output, row| {
            writeln!(output, "{row}").unwrap();
            output
        })
    }

    #[test]
    fn missing_swapped_and_duplicate_identities_are_rejected() {
        let (rows, _, bytes) = fixture(false);
        let mut outcomes = newline_records(&bytes, "outcomes")
            .unwrap()
            .into_iter()
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        let mut extra = outcomes.clone();
        extra[0]["variants"][0]["rust"] = json!({});
        assert!(bind_expected(&rows, encode(&extra).as_bytes(), false).is_err());
        let mut windows = outcomes.clone();
        windows[0]["variants"][0]["expected_windows"] = json!([]);
        assert!(bind_expected(&rows, encode(&windows).as_bytes(), true).is_err());
        outcomes[0]["variants"].as_array_mut().unwrap().swap(0, 1);
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes(), false).is_err());
        outcomes.swap(0, 1);
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes(), false).is_err());
        outcomes.remove(0);
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes(), false).is_err());
        let mut duplicated = rows.clone();
        duplicated[0]["variants"][1] = duplicated[0]["variants"][0].clone();
        assert!(bind_expected(&duplicated, &bytes, false).is_err());
    }

    /// The expected data holds only compared fields, in Rustleaks terms.
    #[test]
    fn expected_observations_hold_only_compared_fields() {
        let (_, variants, _) = fixture(false);
        let (_, windows, _) = fixture(true);
        for variant in variants.iter().chain(&windows) {
            for expected in &variant.expected {
                let help = observe::help_stdout(&variant.request);
                let mut keys = vec![
                    "exit",
                    "stderr_events",
                    "stderr_usage_printed",
                    "stderr_contains_disclosure_marker",
                    "report",
                    "findings",
                    "finding_count",
                    "child_reaped",
                ];
                if !help {
                    keys.extend(["stdout_base64", "stdout_bytes", "stdout_sha256"]);
                }
                let actual = expected.as_object().unwrap().keys().map(String::as_str);
                assert_eq!(
                    actual.collect::<BTreeSet<_>>(),
                    keys.into_iter().collect(),
                    "{}",
                    variant.id
                );
                for event in expected["stderr_events"].as_array().unwrap() {
                    let event = event.as_object().unwrap();
                    assert_eq!(
                        event.keys().map(String::as_str).collect::<BTreeSet<_>>(),
                        BTreeSet::from(["class", "fields", "severity"]),
                        "{}",
                        variant.id
                    );
                    assert!(
                        !event["fields"]
                            .as_object()
                            .unwrap()
                            .contains_key("message_sha256")
                    );
                }
                let stdout = expected.get("stdout_base64").and_then(Value::as_str);
                let report = expected
                    .pointer("/report/bytes_base64")
                    .and_then(Value::as_str);
                for text in stdout.into_iter().chain(report) {
                    let bytes = BASE64.decode(text).unwrap();
                    let text = String::from_utf8_lossy(&bytes);
                    assert!(!text.contains("gitleaks version"), "{}", variant.id);
                    assert!(!text.contains("\"name\": \"gitleaks\""), "{}", variant.id);
                    assert!(!text.contains(" name=\"gitleaks\" "), "{}", variant.id);
                    assert!(!text.contains(env!("CARGO_PKG_VERSION")), "{}", variant.id);
                }
            }
        }
    }

    #[test]
    fn version_output_uses_the_version_token() {
        let (_, variants, _) = fixture(false);
        for (id, stdout) in [
            ("CLI-BB-001/version-command", "<VERSION>\n"),
            ("CLI-BB-001/version-flag", "rustleaks version <VERSION>\n"),
            ("CLI-BB-001/version-persistent-flag", "<VERSION>\n"),
        ] {
            let expected = &find(&variants, id).expected[0];
            let text = BASE64
                .decode(expected["stdout_base64"].as_str().unwrap())
                .unwrap();
            assert_eq!(text, stdout.as_bytes(), "{id}");
        }
    }

    #[test]
    fn windows_expectations_change_only_their_named_fields() {
        let (_, portable, _) = fixture(false);
        let (_, windows, _) = fixture(true);
        let mut native = Vec::new();
        for (portable, windows) in portable.iter().zip(&windows) {
            if portable.expected == windows.expected {
                continue;
            }
            native.push(portable.id.as_str());
            let changed = match portable.id.as_str() {
                // Windows spells the baseline path natively, so the baseline
                // file is not excluded and is scanned as a second finding. The
                // raw report may list the two findings in either order.
                "CLI-BB-013/outside-baseline" => {
                    vec!["findings", "finding_count", "stderr_events", "report"]
                }
                // Windows cannot create the dangling symlink, so its issue
                // event is absent.
                "CLI-BB-030/corrupt-archive-and-broken-symlink" => vec!["stderr_events"],
                other => panic!("unexpected Windows expectation for {other}"),
            };
            for expected in &windows.expected {
                for (key, value) in expected.as_object().unwrap() {
                    if !changed.contains(&key.as_str()) {
                        assert_eq!(*value, portable.expected[0][key], "{}: {key}", portable.id);
                    }
                }
            }
        }
        assert_eq!(
            native,
            [
                "CLI-BB-013/outside-baseline",
                "CLI-BB-030/corrupt-archive-and-broken-symlink"
            ]
        );
        let baseline = find(&windows, "CLI-BB-013/outside-baseline");
        assert_eq!(baseline.expected.len(), 2);
        for expected in &baseline.expected {
            assert_eq!(expected["finding_count"], 2);
            assert_eq!(expected["stderr_events"][1]["fields"]["count"], 2);
        }
        let issues = find(&windows, "CLI-BB-030/corrupt-archive-and-broken-symlink");
        let portable_issues = find(&portable, &issues.id);
        assert_eq!(
            issues.expected[0]["stderr_events"]
                .as_array()
                .unwrap()
                .len()
                + 1,
            portable_issues.expected[0]["stderr_events"]
                .as_array()
                .unwrap()
                .len()
        );
    }

    #[test]
    fn exact_comparison_rejects_any_changed_field() {
        let (_, variants, _) = fixture(false);
        for variant in &variants {
            let expected = &variant.expected[0];
            compare(&variant.id, expected, &variant.expected).unwrap();
            for field in expected.as_object().unwrap().keys() {
                let mut changed = expected.clone();
                changed[field] = json!({"mutation": true});
                assert!(compare(&variant.id, &changed, &variant.expected).is_err());
            }
            let mut extra = expected.clone();
            extra["stderr_events"]
                .as_array_mut()
                .unwrap()
                .push(json!({"severity": "warn", "class": "diagnostic.other", "fields": {}}));
            assert!(compare(&variant.id, &extra, &variant.expected).is_err());
        }
    }

    #[test]
    fn all_declared_material_mutations_fail_exact_comparison() {
        let (_, variants, _) = fixture(false);
        let controls: Value = serde_json::from_slice(
            &std::fs::read(corpus().join("negative-controls-v1.json")).unwrap(),
        )
        .unwrap();
        let controls = controls["controls"].as_array().unwrap();
        assert!(!controls.is_empty());
        let mut ids = BTreeSet::new();
        for control in controls {
            let control_id = control["id"].as_str().unwrap();
            assert!(control_id.starts_with("MUT-CLI-") && ids.insert(control_id));
            let id = format!(
                "{}/{}",
                control["case_id"].as_str().unwrap(),
                control["variant_id"].as_str().unwrap()
            );
            let expected = &find(&variants, &id).expected;
            compare(&id, &expected[0], expected).unwrap();
            let mut changed = expected[0].clone();
            mutate_for_control(
                control["expected_failure_class"].as_str().unwrap(),
                &mut changed,
                &variants,
            );
            assert!(
                changed != expected[0],
                "{id}: mutation did not change its observation"
            );
            assert!(compare(&id, &changed, expected).is_err(), "{id}");
        }
    }

    fn mutate_for_control(class: &str, changed: &mut Value, variants: &[Variant]) {
        match class {
            "selected-findings" => {
                // Selecting the matching environment config instead of the
                // explicit no-match config introduces this fixture finding.
                changed["findings"] =
                    find(variants, "CLI-BB-002/dir").expected[0]["findings"].clone();
            }
            "complete-findings" => {
                let removed = changed["findings"].as_array_mut().unwrap().pop();
                assert!(removed.is_some(), "no finding available to remove");
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
            "stderr-severity" => changed["stderr_events"][0]["severity"] = json!("fatal"),
            "process-cleanup" => changed["child_reaped"] = json!(false),
            unknown => panic!("unmapped control {unknown}"),
        }
    }

    #[test]
    fn platform_accounting_counts_inapplicable_variants() {
        let (_, variants, _) = fixture(false);
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
