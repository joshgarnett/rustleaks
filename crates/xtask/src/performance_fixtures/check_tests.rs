use serde_json::json;

use super::super::{Fixture, boundaries, density, pat};
use super::*;

const STATUS: &str = "rustleaks_scan_status version=1 status=incomplete reason=resource_exhaustion source_scope=directory_targets findings=0 reports=partial decode_depth=5 archive_depth=0 resource=work_units budget_scope=fragment limit=10000000 consumed=10000000 requested=1 usage=available work_units=10000000";

fn status(fields: &str) -> Status {
    parse_status(&format!("{STATUS_PREFIX} {fields} work_units=1")).unwrap()
}

fn value(ordinal: usize) -> String {
    String::from_utf8(pat("check-test", ordinal)).unwrap()
}

fn key(case: &str, ordinal: usize, line: u64, depth: u64) -> Key {
    Key {
        case: case.into(),
        value: value(ordinal),
        line,
        depth,
    }
}

fn input_unit(id: &str, expected: Vec<Key>) -> Unit {
    Unit {
        name: id.into(),
        target: Target::Input(id.into()),
        cases: vec![id.into()],
        expected,
    }
}

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn status_parsing_skips_warnings_and_requires_exactly_one_status_line() {
    let parsed = parse_status(&format!("warn leaks found: 2\n{STATUS}\n")).unwrap();
    assert_eq!(parsed.get("status"), "incomplete");
    assert_eq!(parsed.get("resource"), "work_units");
    assert_eq!(parsed.get("budget_scope"), "fragment");
    assert_eq!(parsed.get("work_units"), "10000000");
    assert_eq!(parsed.get("absent"), "none");
    assert_eq!(
        parse_status("warn leaks found: 2\n").unwrap_err(),
        "no status line"
    );
    assert_eq!(parse_status("").unwrap_err(), "no status line");
    assert_eq!(
        parse_status(&format!("{STATUS}\nwarn other\n{STATUS}\n")).unwrap_err(),
        "more than one status line"
    );
    assert!(parse_status(&format!("{STATUS_PREFIX} status=complete")).is_err());
    assert!(parse_status(&format!("{STATUS} status=complete")).is_err());
    assert!(parse_status(&format!("{STATUS} malformed")).is_err());
    // A status prefix inside another word is not a status line.
    assert!(parse_status(&format!("{STATUS_PREFIX}x status=complete")).is_err());
}

#[test]
fn expected_keys_use_plaintext_lines_unencoded_and_carrier_lines_when_decoded() {
    let raw = json!({
        "id": "raw-case",
        "decode_depth": 0,
        "plants": [{
            "value": value(0),
            "plaintext_position": {"start": {"line": 3, "byte_column": 9}},
            "source_carrier_position": {"start": {"line": 7, "byte_column": 1}},
        }],
    });
    assert_eq!(expected_keys(&raw).unwrap(), [key("raw-case", 0, 3, 0)]);
    let encoded = json!({
        "id": "encoded-case",
        "decode_depth": 2,
        "plants": [{
            "value": value(1),
            "plaintext_position": {"start": {"line": 5, "byte_column": 11}},
            "source_carrier_position": {"start": {"line": 1, "byte_column": 13}},
        }],
    });
    assert_eq!(
        expected_keys(&encoded).unwrap(),
        [key("encoded-case", 1, 1, 2)]
    );
    let mut negative = raw.clone();
    negative["plants"] = json!([]);
    assert!(expected_keys(&negative).unwrap().is_empty());
    let mut broken = raw;
    broken["plants"][0]["plaintext_position"] = json!(null);
    assert!(expected_keys(&broken).is_err());
}

#[test]
fn observed_keys_judge_only_the_planted_rule_and_map_files_to_cases() {
    let unit = input_unit("single", Vec::new());
    let report = json!([
        {"RuleID": "github-pat", "File": "/x/inputs/single/input.txt", "Secret": value(0), "StartLine": 4, "Tags": []},
        {"RuleID": "github-pat", "File": "/x/inputs/single/input.txt", "Secret": value(1), "StartLine": 1, "Tags": ["decoded:base64", "decode-depth:2"]},
        {"RuleID": "generic-api-key", "File": "/elsewhere/other.txt", "Secret": "unjudged"},
        {"RuleID": "rustleaks.example", "Secret": "unjudged"},
    ]);
    assert_eq!(
        observed_keys(&report, &unit).unwrap(),
        Observed {
            keys: vec![key("single", 0, 4, 0), key("single", 1, 1, 2)],
            other_rules: 2,
        }
    );
    let view = Unit {
        name: "boundary-raw-4096".into(),
        target: Target::View,
        cases: vec!["case-a".into(), "case-b".into()],
        expected: Vec::new(),
    };
    let report = json!([
        {"RuleID": "github-pat", "File": "/bundle/view/case-b.txt", "Secret": value(2), "StartLine": 2},
    ]);
    assert_eq!(
        observed_keys(&report, &view).unwrap().keys,
        [key("case-b", 2, 2, 0)]
    );
    for file in [
        "/bundle/view/case-c.txt",
        "/bundle/view/case-a.json",
        "/bundle/view/input.txt",
    ] {
        let report =
            json!([{"RuleID": "github-pat", "File": file, "Secret": value(0), "StartLine": 1}]);
        assert_eq!(
            observed_keys(&report, &view).unwrap_err(),
            "finding names a file outside the scan unit"
        );
    }
    let report = json!([{"RuleID": "github-pat", "File": "/x/inputs/single/other.txt", "Secret": value(0), "StartLine": 1}]);
    assert!(observed_keys(&report, &unit).is_err());
    let report = json!([{"RuleID": "github-pat", "File": "/x/input.txt", "Secret": value(0), "StartLine": 1, "Tags": ["decode-depth:two"]}]);
    assert!(observed_keys(&report, &unit).is_err());
    assert_eq!(
        observed_keys(&json!({"findings": []}), &unit).unwrap_err(),
        "report is not a JSON array"
    );
    assert_eq!(
        observed_keys(&json!(null), &unit).unwrap_err(),
        "report is not a JSON array"
    );
}

#[test]
fn comparison_counts_missing_and_extra_occurrences_as_multisets() {
    let repeated = key("case", 0, 1, 0);
    let other = key("case", 1, 2, 0);
    assert_eq!(compare(&[], &[]), (0, 0));
    assert_eq!(
        compare(
            &[repeated.clone(), repeated.clone(), other.clone()],
            &[other.clone(), repeated.clone(), repeated.clone()]
        ),
        (0, 0)
    );
    assert_eq!(
        compare(
            &[repeated.clone(), repeated.clone()],
            std::slice::from_ref(&repeated)
        ),
        (1, 0)
    );
    assert_eq!(
        compare(
            std::slice::from_ref(&repeated),
            &[repeated.clone(), repeated.clone(), other]
        ),
        (0, 2)
    );
    let mut moved = repeated.clone();
    moved.line = 2;
    assert_eq!(compare(&[repeated], &[moved]), (1, 1));
}

#[test]
fn classification_accepts_only_exact_completion_or_a_named_resource_stop() {
    let complete = status("status=complete reason=complete resource=none budget_scope=none");
    let stopped = status(
        "status=incomplete reason=resource_exhaustion resource=work_units budget_scope=fragment",
    );
    let unnamed =
        status("status=incomplete reason=resource_exhaustion resource=none budget_scope=none");
    let unknown =
        status("status=incomplete reason=resource_exhaustion resource=unknown budget_scope=none");
    let cancelled = status("status=incomplete reason=cancelled resource=none budget_scope=none");
    let rows = [
        (Some(1), Some(&complete), 0, 0, Outcome::Exact),
        (Some(0), Some(&complete), 0, 0, Outcome::Exact),
        (Some(2), Some(&stopped), 7, 0, Outcome::Stopped),
        (Some(1), Some(&complete), 1, 0, Outcome::Failed),
        (Some(1), Some(&complete), 0, 1, Outcome::Failed),
        (Some(2), Some(&stopped), 0, 1, Outcome::Failed),
        (Some(2), Some(&unnamed), 3, 0, Outcome::Failed),
        (Some(2), Some(&unknown), 3, 0, Outcome::Failed),
        (Some(2), Some(&cancelled), 3, 0, Outcome::Failed),
        (Some(2), Some(&complete), 0, 0, Outcome::Failed),
        (Some(1), Some(&stopped), 3, 0, Outcome::Failed),
        (None, Some(&stopped), 3, 0, Outcome::Failed),
        (Some(1), None, 0, 0, Outcome::Failed),
    ];
    for (exit, status, missing, extra, outcome) in rows {
        assert_eq!(classify(exit, status, missing, extra), outcome);
    }
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "evaluate takes the stderr read result"
)]
fn stderr(text: &str) -> Result<String, String> {
    Ok(text.to_owned())
}

fn finding(ordinal: usize, line: u64, tags: &[&str]) -> Value {
    json!({"RuleID": "github-pat", "File": "/x/input.txt", "Secret": value(ordinal), "StartLine": line, "Tags": tags})
}

#[test]
fn evaluation_fails_a_unit_without_a_readable_report_or_status() {
    let unit = input_unit("single", vec![key("single", 0, 1, 0)]);
    let report = json!([finding(0, 1, &[])]);
    let complete = STATUS.replace(
        "status=incomplete reason=resource_exhaustion",
        "status=complete reason=complete",
    );
    let exact = evaluate(&unit, Some(1), stderr(&complete), Ok(report.clone()));
    assert_eq!(exact.outcome, Outcome::Exact);
    let missing = evaluate(&unit, Some(1), stderr("warn only\n"), Ok(report.clone()));
    assert_eq!(missing.outcome, Outcome::Failed);
    assert_eq!(missing.problem.as_deref(), Some("no status line"));
    let unreadable = evaluate(
        &unit,
        Some(2),
        stderr(STATUS),
        Err("no bounded report file".into()),
    );
    assert_eq!(unreadable.outcome, Outcome::Failed);
    assert_eq!((unreadable.missing, unreadable.extra), (1, 0));
    // An oversized or unreadable stderr fails this unit only.
    let oversized = evaluate(
        &unit,
        Some(1),
        Err("stderr is not a bounded regular file".into()),
        Ok(report),
    );
    assert_eq!(oversized.outcome, Outcome::Failed);
    assert_eq!(
        oversized.problem.as_deref(),
        Some("stderr is not a bounded regular file")
    );
    // A status line without work fields still names its reason.
    let partial = evaluate(
        &unit,
        Some(2),
        stderr(&format!(
            "{STATUS_PREFIX} status=incomplete reason=setup_failure resource=none budget_scope=none"
        )),
        Ok(json!([])),
    );
    assert_eq!(partial.outcome, Outcome::Failed);
    assert_eq!(
        partial.problem.as_deref(),
        Some("status line lacks work_units; reason=setup_failure")
    );
}

#[test]
fn a_stop_is_accepted_only_when_every_reported_token_was_planted() {
    let unit = input_unit(
        "single",
        vec![
            key("single", 0, 1, 0),
            key("single", 1, 2, 1),
            key("single", 2, 3, 0),
        ],
    );
    let subset = evaluate(
        &unit,
        Some(2),
        stderr(STATUS),
        Ok(json!([
            finding(0, 1, &[]),
            finding(1, 2, &["decoded:base64", "decode-depth:1"])
        ])),
    );
    assert_eq!(subset.outcome, Outcome::Stopped);
    assert_eq!((subset.observed, subset.missing, subset.extra), (2, 1, 0));
    for wrong in [
        finding(0, 4, &[]),
        finding(0, 1, &["decoded:base64", "decode-depth:1"]),
    ] {
        let evaluation = evaluate(&unit, Some(2), stderr(STATUS), Ok(json!([wrong])));
        assert_eq!(evaluation.outcome, Outcome::Failed);
        assert_eq!((evaluation.missing, evaluation.extra), (3, 1));
    }
    let single = input_unit("single", vec![key("single", 0, 1, 0)]);
    let moved = evaluate(
        &single,
        Some(2),
        stderr(STATUS),
        Ok(json!([finding(0, 2, &[])])),
    );
    assert_eq!(moved.outcome, Outcome::Failed);
    assert_eq!((moved.missing, moved.extra), (1, 1));
    let deeper = evaluate(
        &single,
        Some(2),
        stderr(STATUS),
        Ok(json!([finding(0, 1, &["decode-depth:2"])])),
    );
    assert_eq!(deeper.outcome, Outcome::Failed);
    assert_eq!((deeper.missing, deeper.extra), (1, 1));
}

#[test]
fn output_lines_show_counts_and_fixed_names_but_never_a_token() {
    let unit = input_unit("single", vec![key("single", 0, 1, 0)]);
    let stopped = evaluate(&unit, Some(2), stderr(STATUS), Ok(json!([])));
    assert_eq!(stopped.outcome, Outcome::Stopped);
    let shown_line = line(&unit, &stopped, Some(2), 0.5);
    assert_eq!(
        shown_line,
        "fixture-check single outcome=stopped status=incomplete reason=resource_exhaustion resource=work_units budget_scope=fragment expected=1 observed=0 missing=1 extra=0 other_rules=0 work_units=10000000 seconds=0.50"
    );
    let failed = evaluate(&unit, None, stderr("warn only\n"), Ok(json!([])));
    assert_eq!(
        line(&unit, &failed, None, 1.0),
        "fixture-check single outcome=failed status=none reason=none resource=none budget_scope=none expected=1 observed=0 missing=1 extra=0 other_rules=0 work_units=none seconds=1.00 exit=none problem=\"no status line\""
    );
    let leaked = STATUS.replace("resource=work_units", &format!("resource={}", value(0)));
    let evaluation = evaluate(&unit, Some(2), stderr(&leaked), Ok(json!([])));
    let leaked_line = line(&unit, &evaluation, Some(2), 0.5);
    assert!(leaked_line.contains(" resource=invalid "));
    assert!(leaked_line.contains(" exit=2"));
    assert!(!leaked_line.contains(&value(0)));
    for field in ["status", "reason", "resource", "budget_scope", "work_units"] {
        assert_eq!(shown(field, &value(0)), "invalid");
        assert_eq!(shown(field, &value(0).to_ascii_lowercase()), "invalid");
        assert_eq!(shown(field, ""), "invalid");
    }
    assert_eq!(
        shown("resource", "finding_payload_bytes"),
        "finding_payload_bytes"
    );
    assert_eq!(shown("work_units", "10000000"), "10000000");
    assert_eq!(shown("work_units", "none"), "none");
    assert_eq!(shown("resource", "10000000"), "invalid");
    assert_eq!(shown("work_units", "work_units"), "invalid");
}

fn select(family: &str, generate: impl FnOnce(&mut Selection) -> Result<(), String>) -> Vec<Unit> {
    let mut selection = Selection::new(family).unwrap();
    generate(&mut selection).unwrap();
    selection.units
}

#[test]
fn units_cover_each_boundary_kind_and_anchor_and_the_largest_cases() {
    let units = select("boundaries", |selection| {
        boundaries::generate(&mut |fixture: Fixture| selection.add(&fixture.manifest()))
    });
    assert_eq!(units.len(), 12);
    for unit in &units {
        assert_eq!(unit.target, Target::View);
        let (expected_cases, expected_plants) = if unit.name.starts_with("boundary-raw-") {
            (41 * 3 + 3 * 3, 41 + 3 * 3)
        } else {
            (57 * 3 + 5 * 3, 57 + 5 * 3)
        };
        assert_eq!(unit.cases.len(), expected_cases, "{}", unit.name);
        assert_eq!(unit.expected.len(), expected_plants, "{}", unit.name);
        let prefix = format!("{}-", unit.name);
        assert!(unit.cases.iter().all(|case| case.starts_with(&prefix)));
    }
    assert_eq!(units[0].name, "boundary-raw-4096");
    assert_eq!(units[1].name, "boundary-base64-4096");

    let units = select("density", |selection| {
        density::generate(&mut |fixture: Fixture| selection.add(&fixture.manifest()))
    });
    assert_eq!(units.len(), 24);
    for unit in &units {
        assert!(unit.name.starts_with("dense-524288-") || unit.name.starts_with("dense-2097152-"));
        assert_eq!(unit.target, Target::Input(unit.name.clone()));
        assert_eq!(unit.cases, std::slice::from_ref(&unit.name));
    }
    let largest = units
        .iter()
        .find(|unit| unit.name == "dense-2097152-positive-unique-lf")
        .unwrap();
    assert_eq!(largest.expected.len(), 32_768);
    assert_eq!(largest.expected[1].line, 2);

    let units = select("decoded-carrier", |selection| {
        density::generate_decoded(&mut |fixture: Fixture| selection.add(&fixture.manifest()))
    });
    assert_eq!(units.len(), 8);
    for unit in &units {
        assert!(unit.name.starts_with("one-carrier-4096-depth-"));
        let positive = unit.name.ends_with("-positive");
        assert_eq!(unit.expected.len(), if positive { 4_096 } else { 0 });
        let depth = if unit.name.contains("-depth-1-") {
            1
        } else {
            2
        };
        assert!(unit.name.contains(&format!("-depth-{depth}-")));
        assert!(
            unit.expected
                .iter()
                .all(|key| key.line == 1 && key.depth == depth)
        );
    }
    assert_eq!(
        units
            .iter()
            .filter(|unit| unit.expected.iter().any(|key| key.depth == 2))
            .count(),
        2
    );

    for family in ["connections", "partitions", "unknown"] {
        assert_eq!(
            Selection::new(family).err().unwrap(),
            "no check subset for this family"
        );
    }
}

#[test]
fn original_limits_equal_the_documented_example_profile() {
    let path = crate::workspace_root()
        .unwrap()
        .join("docs/user/complete-scanning.md");
    let document = fs::read_to_string(path).unwrap();
    let start = document
        .find("```text\n# Example profile.")
        .expect("documented example profile")
        + "```text\n".len();
    let length = document[start..].find("```").unwrap();
    assert_eq!(&document[start..start + length], ORIGINAL_LIMITS);
}

#[test]
fn check_arguments_require_one_absolute_directory_and_known_flags() {
    // Absolute paths differ by platform, so build them from the temp folder.
    let absolute = |name: &str| {
        std::env::temp_dir()
            .join(name)
            .to_str()
            .expect("UTF-8 temp path")
            .to_owned()
    };
    let (fixtures, cli, limits) = (
        absolute("fixtures"),
        absolute("rustleaks"),
        absolute("limits"),
    );
    let (a, b) = (absolute("a"), absolute("b"));
    assert_eq!(
        Request::parse(&arguments(&["--check", &fixtures])).unwrap(),
        Request {
            directory: fixtures.clone().into(),
            cli: None,
            profile: None,
        }
    );
    assert_eq!(
        Request::parse(&arguments(&[
            "--cli",
            &cli,
            "--check",
            &fixtures,
            "--profile",
            &limits,
        ]))
        .unwrap(),
        Request {
            directory: fixtures.clone().into(),
            cli: Some(cli.clone().into()),
            profile: Some(limits.clone().into()),
        }
    );
    for invalid in [
        &["--check"][..],
        &["--cli", &cli],
        &["--check", &a, "--check", &b],
        &["--check", &a, "--family", "density"],
        &["--check", &a, "--verify", &a],
    ] {
        assert_eq!(Request::parse(&arguments(invalid)).unwrap_err(), USAGE);
    }
    for (invalid, message) in [
        (
            &["--check", "relative"][..],
            "--check requires an absolute path",
        ),
        (
            &["--check", &a, "--cli", "rustleaks"],
            "--cli requires an absolute path",
        ),
        (
            &["--check", &a, "--profile", "x.limits"],
            "--profile requires an absolute path",
        ),
    ] {
        assert_eq!(Request::parse(&arguments(invalid)).unwrap_err(), message);
    }
}

#[test]
fn selection_requires_manifests_that_expect_the_judged_rule() {
    let fixture = density::dense(524_288, density::Density::Positive, false, true);
    let mut manifest = fixture.manifest();
    let mut selection = Selection::new("density").unwrap();
    selection.add(&manifest).unwrap();
    for family in [json!(null), json!("generic-api-key")] {
        manifest["expected_canonical_family"] = family;
        let mut selection = Selection::new("density").unwrap();
        assert_eq!(
            selection.add(&manifest).unwrap_err(),
            "case dense-524288-positive-unique-lf does not expect the judged rule"
        );
    }
}
