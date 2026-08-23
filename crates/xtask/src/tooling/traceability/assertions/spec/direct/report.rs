//! Finding-redaction and report-output assertion rows.

use super::super::super::{Json, array, boolean, integer, object, record, text};

use super::implemented;

pub(super) fn add_report_rows(rows: &mut Vec<Json>) {
    add_redaction(rows);
    add_junit(rows);
    add_stdout(rows);
}

fn add_redaction(rows: &mut Vec<Json>) {
    rows.push(implemented(
        record(
            "AS-REPORT-REDACT-01",
            "TM-0250",
            "report/finding_test.go",
            14,
            "tests[0]",
            "report-finding-redaction",
            "public-api",
            object([
                (
                    "finding",
                    object([
                        ("match", text("line containing secret")),
                        ("secret", text("secret")),
                    ]),
                ),
                ("redact_percent", integer(100)),
            ]),
            object([
                ("kind", text("finding-fields")),
                ("secret", text("REDACTED")),
                ("match", text("line containing REDACTED")),
            ]),
            Vec::new(),
        ),
        "frozen_composite_and_redaction_corpus_matches_go",
        "crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check",
    ));
}

fn add_junit(rows: &mut Vec<Json>) {
    let findings = junit_findings();
    rows.push(record(
        "AS-REPORT-JUNIT-SIMPLE",
        "TM-0262",
        "report/junit_test.go",
        19,
        "tests[0]",
        "report-junit",
        "public-api",
        object([("findings", array(findings))]),
        object([
            ("kind", text("golden")),
            ("normalization", text("upstream-lineEndingReplacer")),
            ("fixture_id", text("FIX-0073")),
        ]),
        vec![text("FIX-0073")],
    ));
    rows.push(record(
        "AS-REPORT-JUNIT-EMPTY",
        "TM-0262",
        "report/junit_test.go",
        61,
        "tests[1]",
        "report-junit",
        "public-api",
        object([("findings", array([]))]),
        object([
            ("kind", text("golden")),
            ("normalization", text("upstream-lineEndingReplacer")),
            ("fixture_id", text("FIX-0072")),
        ]),
        vec![text("FIX-0072")],
    ));
}

fn junit_findings() -> [Json; 2] {
    [
        object([
            ("description", text("Test Rule")),
            ("rule_id", text("test-rule")),
            ("match", text("line containing secret")),
            ("secret", text("a secret")),
            ("start_line", integer(1)),
            ("end_line", integer(2)),
            ("start_column", integer(1)),
            ("end_column", integer(2)),
            ("message", text("opps")),
            ("file", text("auth.py")),
            ("commit", text("0000000000000000")),
            ("author", text("John Doe")),
            ("email", text("johndoe@gmail.com")),
            ("date", text("10-19-2003")),
            ("tags", array([])),
        ]),
        object([
            ("description", text("Test Rule")),
            ("rule_id", text("test-rule")),
            ("match", text("line containing secret")),
            ("secret", text("a secret")),
            ("start_line", integer(2)),
            ("end_line", integer(3)),
            ("start_column", integer(1)),
            ("end_column", integer(2)),
            ("message", text("")),
            ("file", text("auth.py")),
            ("commit", text("")),
            ("author", text("")),
            ("email", text("")),
            ("date", text("")),
            ("tags", array([])),
        ]),
    ]
}

fn add_stdout(rows: &mut Vec<Json>) {
    rows.push(record(
        "AS-REPORT-STDOUT-01",
        "TM-0265",
        "report/report_test.go",
        15,
        "single-test",
        "report-json",
        "public-api",
        object([
            (
                "findings",
                array([object([("rule_id", text("test-rule"))])]),
            ),
            ("writer", text("closable-buffer")),
        ]),
        object([
            ("kind", text("no-error-and-nonempty-bytes")),
            ("error", Json::Null),
            ("nonempty", boolean(true)),
        ]),
        Vec::new(),
    ));
}
